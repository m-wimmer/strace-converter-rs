
use crate::syscall_parser;
use std::collections::HashSet;
use std::sync::LazyLock;
use regex::Regex;

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

struct Edge{
    process: String,
    target: String,
    call_name: String,
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
                .expect("return value was null when extracting node out of proc create call");

            let Some((pid,name)) = ret.split_once('<')else{println!("splitting for < failed"); todo!()};
            let name = name.replace(">", "");
            let mut ret_node_name = pid.to_owned() + "-" + &name;
            
            // check if new pid is already in store
            check_node_store(&mut ret_node_name,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

            // check if old name is in store
            let mut node_name = event.pid.to_string().to_owned() + "-" + &event.procname.to_string();
            check_node_store(&mut node_name,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

            write_edge(Edge { 
                process: event.pid.to_string() + "-" + &event.procname.to_string(),
                target: ret_node_name,
                call_name: event.name.to_owned(),
                timestamp: event.timestamp,
                successful: if &event.successful == "successful" {true} else{false}
            } , &mut writer_vec[edge_writer_idx]);
            return;
        }

        // lazy initialize of regex so it only compiles once instead of every line 
        static RE: LazyLock<(Regex,Regex, Regex, Regex)> = LazyLock::new(||  
            (
                // regex to catch openat and newfstatat before creating duplicate relations 
                Regex::new(r#"dirfd=\d+<(?<dirfd>/[^>]*)>, pathname="(?<file>[/\S\s]*?)","#).unwrap(), 

                // captures files ( file descriptors )
                Regex::new(r"\d+<(?<file>/[^>]*)>").unwrap(), 
                // we need pathname like this for execve
                Regex::new(r#"pathname="(?<file>[/\S\s]*?)","#).unwrap(), 

                // captues sockets
                Regex::new(r"<(?<network>(TCP|UDP|TCPv6|UDPv6):\[\S*\])>").unwrap(), 

            ));
            let (files_dirfd_pattern,files_pattern,path_pattern,sockets_pattern) = &*RE;
            let regex_patterns = [ 
                (EntityPatterns::DirfdFile, files_dirfd_pattern),
                 (EntityPatterns::FileDesc, files_pattern),
                  (EntityPatterns::PathName, path_pattern),
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
                    let valid_relation;
                    let node;

                    (valid_relation,node) = if caps.name("dirfd").is_some() && caps.name("file").is_some(){
                        let mut file = format!("{}/{}", &caps["dirfd"], &caps["file"]);
                        check_node_store(&mut file, node_vec,&mut writer_vec[node_writer_idx],NodeType::File);
                        (true,file)
                    }
                    else if caps.name("file").is_some(){

                        check_node_store(&mut caps["file"].to_string(), node_vec,&mut writer_vec[node_writer_idx],NodeType::File);
                        (true,caps["file"].to_string())

                    }
                    else if caps.name("network").is_some(){

                            check_node_store(&mut caps["network"].to_string(), node_vec,&mut writer_vec[node_writer_idx],NodeType::Socket);
                        (true,caps["network"].to_string())

                    }else{(false,"no match".to_string())};

                    if valid_relation{ 

                            let mut node_name = event.pid.to_string().to_owned() + "-" + &event.procname.to_string();
                            check_node_store(&mut node_name,node_vec,&mut writer_vec[node_writer_idx],NodeType::Process);

                            write_edge(Edge {
                                process: event.pid.to_string() + "-" + &event.procname.to_string(),
                                target: node,
                                call_name: event.name.to_owned(),
                                timestamp: event.timestamp,
                                successful: if &event.successful == "successful" {true} else{false},
                            }, &mut writer_vec[edge_writer_idx]);
                            

                        match pattern {
                            EntityPatterns::DirfdFile => {
                                break;
                                // exit for loop of regexes to prevent new relations without the
                                // full path
                            }
                            _ => {}
                        }
                    }

                }

        }


}

fn write_edge(edge: Edge,writer: &mut BufWriter<File>)
{
    writeln!(writer,"\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"", edge.process,edge.target,edge.call_name,edge.timestamp,edge.successful).expect("writing of relation failed");
}

fn write_node(node_name: &String, writer: &mut BufWriter<File>,node_type: NodeType)
{
    writeln!(writer,"\"{}\",\"{}\"",&node_name,node_type.as_str()).expect("Writing node failed");
}

fn check_node_store(node_name: &mut String, node_vec: &mut HashSet<String>,writer: &mut BufWriter<File>,node_type: NodeType){

    if !node_vec.contains(node_name){
        
        write_node(&node_name, writer, node_type);
        if !node_vec.insert(node_name.to_string()) {
            println!("ERR: {node_name} already stored");
        }
    } else{
        // println!("{node_name} already stored");

    }

}




