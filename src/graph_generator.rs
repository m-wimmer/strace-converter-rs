
use crate::syscall_parser;
use std::collections::HashSet;
use std::sync::LazyLock;
use regex::Regex;
use std::borrow::Cow;

pub enum NodeType {

    Process,
    File,
    Socket,

}

enum EntityPatterns{
    DirfdFile,
    FileDesc,
    PathName,
    Sockets
}

impl NodeType{

    pub fn as_str(&self) -> &'static str{
        match self{

        NodeType::Process => "Process",
        NodeType::File => "File",
        NodeType::Socket => "Socket",
        }

    }

}

const PROC_CREATE: [&str;3] = [ "clone", "clone3", "fork" ];

struct Edge<'a>{
    process: String,
    target: &'a str,
    call_name: &'a str,
    timestamp: u64,
    successful: bool,
}


use std::io::{BufWriter, Write};
use std::fs::File;


pub fn check_and_write_edge(writer_vec: &mut Vec<BufWriter<File>>,event: &syscall_parser::SystemCall, node_vec: &mut HashSet<String>)
{


        // depending on if you have a writer count of 2 or three there is one reserved for tef
        // tef-csv writer (count 3)
        // tef 0
        // nodes 1
        // edges 2
        // -------
        // just csv (count 2)
        // nodes 0
        // edges 1
        let node_writer_idx = writer_vec.len()-2;
        let edge_writer_idx = writer_vec.len()-1;

    // handling relations for system calls which create process ids
        if  PROC_CREATE.iter().any( |&s| s == event.name && event.successful == "successful")
        {

            let ret = event.ret.clone()
                .expect("return value was null when extracting target out of proc create call");

            let Some((pid,name)) = ret.split_once('<')else{println!("splitting for < failed"); todo!()};
            let name = name.replace(">", "");
            let mut ret_node_name = pid.to_owned() + "-" + &name;
            
            // check if new pid is already in store
            check_node_store(&mut ret_node_name,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

            // check if old name is in store
            let mut source = event.pid.to_string().to_owned() + "-" + &event.procname.to_string();
            check_node_store(&mut source,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

            write_edge(Edge { 
                process: source,
                target: &ret_node_name,
                call_name: &event.name,
                timestamp: event.timestamp,
                successful: if &event.successful == "successful" {true} else{false}
            } , &mut writer_vec[edge_writer_idx]);

            // return early when its one of these 3 system calls 
            return;
        }

        // lazy initialize of regex so it only compiles once instead of every line 
        static RE: LazyLock<(Regex, Regex, Regex, Regex)> = LazyLock::new(||  
            (
                // regex to catch openat and newfstatat before creating duplicate relations 
                Regex::new(r#"dirfd=(\d+|AT_FDCWD)<(?<dirfd>/[^>]*)>, pathname="(?<file>[/\S\s]*?)","#).unwrap(), 

                // captures files ( file descriptors )
                Regex::new(r"\d+<(?<file>/[^>]*)>").unwrap(), 

                //  execve(pathname="/usr/binary", ...
                Regex::new(r#"pathname="(?<file>[/\S\s]*?)","#).unwrap(), 

                // captues sockets
                Regex::new(r"<(?<network>(TCP|UDP|TCPv6|UDPv6):\[\S*\])>").unwrap(), 

            ));
            let (files_dirfd_pattern,files_pattern,pathname_pattern,sockets_pattern) = &*RE;
            let regex_patterns = [ 
                (EntityPatterns::DirfdFile, files_dirfd_pattern),
                 (EntityPatterns::FileDesc, files_pattern),
                 (EntityPatterns::PathName, pathname_pattern),
                   (EntityPatterns::Sockets, sockets_pattern) ];

            // only search if argument string exists
            let argument_string = if event.args_string.is_some(){
            event.args_string.to_owned().unwrap()
            }
            else{
                // println!("Cannot generate relations or nodes if no args are provided");
                // println!("{:?}", event);
                return;
            };

        for (pattern,regex) in regex_patterns {

            if let Some(caps) = regex.captures(&argument_string) { 

                    let target: Cow<'_, str> = match pattern {
                        // if path is absolute we dont merge, if not we do
                        // examples:
                            // openat(dirfd=AT_FDCWD</home/user>, pathname="file.txt", .... -> merge
                            // newfstatat(dirfd=4</home/user/folder>, pathname="file.txt", .... -> merge
                            // openat(dirfd=AT_FDCWD</home/user>, pathname="/etc/passwd", .... -> dont merge

                        EntityPatterns::DirfdFile => {
                            let file = if caps["file"].starts_with('/') {
                                caps["file"].to_string()
                            }
                            else {
                                format!("{}/{}", &caps["dirfd"], &caps["file"])
                            };
                            check_node_store(&file, node_vec,&mut writer_vec[node_writer_idx],NodeType::File);
                            // own here due to combining the slices
                            Cow::Owned(file)
                        },
                        EntityPatterns::FileDesc | EntityPatterns::PathName => {
                           let file = &caps["file"];
                           check_node_store(file, node_vec,&mut writer_vec[node_writer_idx],NodeType::File);
                           Cow::Borrowed(file)
                        },
                        EntityPatterns::Sockets => {
                           let socket = &caps["network"];
                           check_node_store(socket, node_vec,&mut writer_vec[node_writer_idx],NodeType::Socket);
                           Cow::Borrowed(socket)
                        }
                    };

                    let mut source = event.pid.to_string() + "-" + &event.procname.to_string();
                    check_node_store(&mut source,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

                    write_edge(Edge {
                        process: source,
                        target: &target,
                        call_name: &event.name,
                        timestamp: event.timestamp,
                        successful: if &event.successful == "successful" {true} else{false},
                    }, &mut writer_vec[edge_writer_idx]);
                    break;

                }
            // println!("No pattern matched");

        }


}

fn write_edge(edge: Edge,writer: &mut BufWriter<File>)
{
    writeln!(writer,"\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"", edge.process,edge.target,edge.call_name,edge.timestamp,edge.successful).expect("writing of relation failed");
}

fn write_node(node_name: &str, writer: &mut BufWriter<File>,node_type: NodeType)
{
    writeln!(writer,"\"{}\",\"{}\"",&node_name,node_type.as_str()).expect("Writing node failed");
}

fn check_node_store(node_name: &str, node_vec: &mut HashSet<String>,writer: &mut BufWriter<File>,node_type: NodeType){

    if !node_vec.contains(node_name){
        
        write_node(&node_name, writer, node_type);
        if !node_vec.insert(node_name.to_string()) {
            println!("ERR: {node_name} already stored");
        }
    } else{
        // println!("{node_name} already stored");

    }

}




