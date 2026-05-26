// strace -yy --decode-pids=all --always-show-pid -T -tttN -s 100 -f -qqq curl example.com
// -qqq to prevent status messages -> trace only signals and system calls
//
//


mod graph_generator;
use std::collections::HashSet;
use std::path::Path;
use std::fs::File;
use std::io::{self, BufRead};
use std::process::exit;
mod syscall_parser;
mod tef_converter;
use clap::Parser;
use std::io::{BufWriter, Write};


#[derive(Parser)]
struct Cli { 
    
    #[arg(short, long)]
    input_file: String,
    #[arg(short, long)]
    format: String,
    #[arg(short, long)]
    output_file: String,
    #[arg(short, long)]
    parse_arguments: bool,
    #[arg(long)]
    log_file: Option<String>,
}

#[derive(PartialEq)]
#[derive(Debug)]
enum FormatType{
    Json,
    Tef, 
    Csv,
    TefCsv,
    NoFormat,
} 


fn main() -> Result<(), Box<dyn std::error::Error>>{
    // Parse Commandline arguments
    let args = Cli::parse(); 


    let write_format; // format arg 
    let mut writer_count=0;                    

    if !Path::new(&args.input_file).exists(){
        println!("Could not read strace log");
        exit(4);
    }

    if args.format.to_lowercase() == "json" {
        write_format = FormatType::Json;
        writer_count=1;                    
        // 1 writer
    }
    else if args.format.to_lowercase() == "tef" {
        write_format = FormatType::Tef;
        writer_count=1;                    
        // 1 writer
    }
    else if args.format.to_lowercase() == "csv" {
        write_format = FormatType::Csv;
        writer_count=2;                    
        // 2 writers 
    }
    else if args.format.to_lowercase() == "tef-csv" || args.format == "csv-tef" {
        write_format = FormatType::TefCsv;
        writer_count=3;                    
        // 3 writers 
    }
    else{
        write_format = FormatType::NoFormat;
    }

    let mut writer_vec = writers_init(&write_format, &args.output_file, writer_count);


    // vector for merging of unfinished and resumed calls
    let mut syscall_store : Vec<syscall_parser::SystemCall> = Vec::new(); 
    // vec for nodes which are already stored inside the nodes.csv file
    let mut node_store: HashSet<String> = HashSet::new(); 

    // METRIC: count resumed system calls
    let mut resumed_calls_count = 0;
    // METRIC: count unfinished system calls
    let mut unfinished_calls_count = 0;
    // METRIC: count merged system calls
    let mut merge_count = 0;

    // read file line by line
    if let Ok(lines) = read_lines(args.input_file) {
        
        for (i, line) in lines.map_while(Result::ok).enumerate() {

            // parse system call into struct
            let event = syscall_parser::parse(i+1, &line,&mut unfinished_calls_count,&mut resumed_calls_count);

            // function to check and or add unfinished or resumed calls
            let event = tef_converter::handle_partial_system_call(&mut syscall_store,event,&mut merge_count);

            if event.as_ref().unwrap().call_type == syscall_parser::CallType::UnfinishedCall{continue} // do not print out unfinished calls until they are finished (drawback is that the order is
                                                                                       // not correct anymore). However: "The events do not have to be in timestamp-sorted order" 
                                                                                       // -> https://docs.google.com/document/d/1CvAClvFfyA5R-PhYUmn5OOQtYMH4h6I0nSsKchNAySU/preview?tab=t.0

           // write functions according to the selected format
            match write_format {
                FormatType::Json => {write_json(&mut writer_vec[0],&event);},
                FormatType::Tef =>{write_tef(&mut writer_vec[0],&event);} ,
                FormatType::TefCsv =>{
                    write_tef(&mut writer_vec[0],&event);
                    write_csv(&mut writer_vec,&event,&mut node_store);
                },
                FormatType::NoFormat=>{
                    println!("No valid format selected. Exiting");
                    exit(5)} ,
                FormatType::Csv => {
                    write_csv(&mut writer_vec,&event,&mut node_store);
                },
            }

        }

    // store all unfinished system calls which were not mapped to resumed calls as instant
    // events in TEF or just as nodes and relations in nodes after log was read.
    for event in &syscall_store {

        let event = &Some(event.to_owned());

        match write_format {
            FormatType::Json => {write_json(&mut writer_vec[0],event);},
            FormatType::Tef =>{write_tef(&mut writer_vec[0],&event);} ,
            FormatType::TefCsv =>{
                write_tef(&mut writer_vec[0],&event);
                write_csv(&mut writer_vec,&event,&mut node_store);
            },
            FormatType::NoFormat=>{
                println!("No valid format selected. Exiting");
                exit(5)} ,
            FormatType::Csv => {
                write_csv(&mut writer_vec,&event,&mut node_store);
            },
            }

    }

        // for json and TEF we need to end the JSON 
        if write_format == FormatType::Json || write_format == FormatType::Tef || write_format== FormatType::TefCsv{
            writeln!(writer_vec[0],"]").expect("Writing ] to file failed");
            writer_vec[0].flush().expect("Flushing writer failed");
        }
        // flush all remaining writers 
        for mut writer in writer_vec{
            writer.flush().expect("Flushing of a writer failed");
        }
    }
    else {
        println!("Could not read lines of provided file!!");
        exit(1);

    }
    // after reading the stored system calls which were not able to be merged are printed
    println!("INFO: Still stored unfinished syscalls: {}", syscall_store.iter().count());

    if syscall_store.iter().count() != 0 {
    println!("INFO: Stored unfinished syscalls START:"); 
    for syscall in &syscall_store {
        println!("{:?}",syscall);
    }
    println!("INFO: Stored unfinished syscalls END:"); 
    }
    println!("INFO: UNFINISHED syscalls, RESUMED syscalls, MERGED syscalls");
    println!("{},{},{}",unfinished_calls_count ,resumed_calls_count, merge_count);


    if args.log_file.is_some() {
        // addition to extract metrics
        let mut writer = writer_init(&args.log_file.unwrap());
        writeln!(writer,"UNFINISHED syscalls, RESUMED syscalls, MERGED syscalls").expect("Writing log data to file failed");
        writeln!(writer,"{},{},{}",unfinished_calls_count ,resumed_calls_count, merge_count).expect("Writing log data to file failed");
        writer.flush().expect("Flushing of a writer failed");
    }
    Ok(())
}

// reading the trace file
fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::with_capacity(8*1024*1024,file).lines())
}


// generic initialize writer
fn writer_init(output_file: &String) -> BufWriter<File>{
    let output_file_path = Path::new(output_file);
    let file = File::create(output_file_path).expect("File was not able to be created");
    let writer = BufWriter::with_capacity(8*1024*1024,file);
    writer
}


// sets up writers for each format based on the selection of the user
fn writers_init(format: &FormatType, output_file: &String,writer_count: usize) -> Vec<BufWriter<File>>{

    // make vec of writers 
    let mut vec = Vec::with_capacity(writer_count);

    // match against the format and create the necessary writers (i.e., files) 
    match format {
        FormatType::Json => {
            let output_file = output_file.to_string() + ".json";
            let mut writer = writer_init(&output_file);
            writeln!(writer,"[").expect("Writing [ to file failed");
            vec.push(writer);
        },
        FormatType::Tef => {
            let output_file = output_file.to_string() + ".tef";
            let mut writer = writer_init(&output_file);
            writeln!(writer,"[").expect("Writing [ to file failed");
            vec.push(writer);
        },
        FormatType::Csv => {
            let output_file_nodes = output_file.to_string() + "-nodes.csv";
            let mut writer_node = writer_init(&output_file_nodes);
            writeln!(writer_node,"name,type").expect("Writing header to file failed");
            vec.push(writer_node);
            let output_file_edges = output_file.to_string() + "-edges.csv";
            let mut writer_edge = writer_init(&output_file_edges);
            writeln!(writer_edge,"from_id,to_id,call_name,timestamp,success_flag").expect("Writing header to file failed");
            vec.push(writer_edge);
        },
        FormatType::TefCsv => {
            let output_file_tef = output_file.to_string() + ".tef";
            let mut writer = writer_init(&output_file_tef);
            writeln!(writer,"[").expect("Writing [ to file failed");
            vec.push(writer);
            let output_file_nodes = output_file.to_string() + "-nodes.csv";
            let mut writer_node = writer_init(&output_file_nodes);
            writeln!(writer_node,"name,type").expect("Writing header to file failed");
            vec.push(writer_node);
            let output_file_edges = output_file.to_string() + "-edges.csv";
            let mut writer_edge = writer_init(&output_file_edges);
            writeln!(writer_edge,"from_id,to_id,call_name,timestamp,success_flag").expect("Writing header to file failed");
            vec.push(writer_edge);
        },
        FormatType::NoFormat => {
            exit(5);
        },
    }
    vec
}

// write functions for each log file
fn write_json(writer: &mut BufWriter<File>, event: &Option<syscall_parser::SystemCall>){
    serde_json::to_writer(&mut *writer,&event).expect("Failed to write JSON");
    writeln!(writer,",").expect("Writing , to file failed");
}
fn write_tef(writer: &mut BufWriter<File>, event: &Option<syscall_parser::SystemCall>){
    let tef_event = tef_converter::build_trace_event_format(event);
    serde_json::to_writer(&mut *writer,&tef_event).expect("Failed to write JSON");
    writeln!(writer,",").expect("Writing , to file failed");
}
fn write_csv(writer_vec: &mut Vec<BufWriter<File>>, event: &Option<syscall_parser::SystemCall>,node_store: &mut HashSet<String>){
    graph_generator::check_and_write_edge(writer_vec,&event,node_store);
}

// debug print that outputs line and system call 
fn _debug_print(line: &str, event: &Option<syscall_parser::SystemCall>){
    println!("{}",&line);
    if let Some(event) = &event {
        println!("{:?}",event.call_type);
    }
}


