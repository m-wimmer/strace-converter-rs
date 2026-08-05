/* System call parser component
 *
 * Parses system calls and signals with regex and generates structs for them. 
 *
 */

use regex::Regex;
use std::collections::{BTreeMap};
use std::str;
use std::sync::LazyLock;
use std::time::Duration;

use crate::Config;


#[derive(Debug)]
#[derive(serde::Serialize)]
#[derive(Clone)]
pub struct SystemCall{
    pub timestamp: u64,
    pub pid: usize,
    pub name: String,
    pub args: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing)]
    pub args_string: Option<String>,
    pub dur: Option<u128>,
    pub ret: Option<String>,
    #[serde(skip_serializing)]
    pub call_type: CallType,
    pub successful: String,
    #[serde(skip_serializing)]
    pub procname: String,
}


// call types which are mapped to different regex patterns
#[repr(u8)]
#[derive(Debug)]
#[derive(serde::Serialize)]
#[derive(PartialEq, Eq,Clone)]
pub enum CallType {
    RegularSyscall,
    UnfinishedCall,
    ResumedCallWithArgs,
    ResumedCallWithoutArgs,
    CallWithoutArgs,
    CallWithoutArgsNoDur,
    SignalOrInformational,
    ResumedWithoutDur,
    UnfResCall,
}


pub fn parse(config: &Config,line_num: usize, log_line: &str,resumed_call_cnt: &mut usize, unfinished_call_cnt: &mut usize) -> SystemCall 
{
    let (pid,timestamp,rest,pname) = parse_pid_pidname_timestamp(&log_line);
    if rest == ""{
        println!("Parsing of timestamp or PID failed for line {}: {}", line_num + 1, &log_line);
    }
    let system_call = parse_syscall(config,line_num,pid,timestamp,rest.to_owned(),pname.to_owned(),resumed_call_cnt,unfinished_call_cnt);
    if system_call.is_some() {
        system_call.unwrap()
    }else{
        println!("failed to parse line {}: {:?}",line_num, log_line);
        std::process::exit(3);
    }
}


fn make_syscall_struct(config: &Config,pid:usize, timestamp:u64,procname:String,caps: &regex::Captures, call_type: CallType) -> SystemCall{

    let mut syscall = SystemCall {
        timestamp: timestamp,
        pid: pid,
        name: caps.name("call").expect("System calls should consist of a name").as_str().to_string(),
        args: None,
        args_string: None,
        dur: None,
        ret: None,
        call_type: call_type,
        successful: "unknown".to_string(),
        procname: procname,
    };


    if caps.name("args").is_some() {
        let arg_str = caps.name("args").unwrap().as_str();

        // check if user wants to parse args or not
        // if not, store whole arg string in one key
        if config.arg_parse_val==true {
            syscall.args = Some(parse_args(&arg_str).to_owned());
        }
        else {
            let mut map = BTreeMap::new();
            map.insert("args".to_owned(), arg_str.to_owned());
            syscall.args = Some(map);
        }
        syscall.args_string = Some(arg_str.to_owned());

    }
    else {//println!("INFO: LINE {}: No args in: {:?}",line_num,&syscall.call_type)
          }


    if caps.name("ret").is_some() {
        let ret_str = caps.name("ret").unwrap().as_str().to_owned();
        if ret_str.starts_with("-") {
            syscall.successful = "unsuccessful".to_string();
        }
        else if !ret_str.starts_with("?"){
            syscall.successful = "successful".to_string();
        }
        syscall.ret = Some(ret_str);
    }
    else {
        //println!("INFO: LINE {}: NO ret in: {:?}",line_num,&syscall.call_type)
    }

    if caps.name("dur").is_some() {
        let dur = caps.name("dur").unwrap().as_str();
        let dur: f64 = dur.parse().unwrap(); 
        let duration = Duration::from_secs_f64(dur);
        let microseconds = duration.as_micros();
        syscall.dur = Some(microseconds);
    }
    else {
        //println!("INFO: LINE {}: Duration does not exist for {:?}",line_num,&syscall.call_type)
        }

    syscall
}

fn make_signal_struct(pid:usize,timestamp:u64,procname:String,caps: &regex::Captures, call_type: CallType) -> SystemCall {

    let text_hashmap = Some(BTreeMap::from([ ("text".to_owned(), caps.name("text").expect("No Signal text found").as_str().to_owned()),]));

    let siginfo = SystemCall {
        timestamp: timestamp,
        pid: pid,
        name: "Signal".to_owned(),
        args: text_hashmap,
        args_string: None,
        dur: None,
        ret: None,
        call_type: call_type,
        successful: "unknown".to_string(),
        procname: procname,
    };
    siginfo

}

// parses pid,pidname and timestamp and merges the rest into one slice again
fn parse_pid_pidname_timestamp(log_line: &str) -> (usize,u64,&str,&str){

    // prev
    // 84321 328512.584321045 openat(...) = 1
    // now
    // 84321<curl> 328512.584321045 openat(...) = 1

    let Some((pid_name,rest)) = log_line.split_once('>') else {println!("splitting for > failed"); todo!()};
    let Some((pid,name)) = pid_name.split_once('<')else{println!("splitting for < failed"); todo!()};
    let mut split = rest.split_whitespace();
    let timestamp = split.next();

    // https://gemini.google.com/share/362dbfa33b7c
    let rest = match timestamp {
        Some(n) => {
            let pos = n.as_ptr() as usize - log_line.as_ptr() as usize + n.len();
            log_line[pos..].trim_start()
        }
        None => ""

    };

    let pid: usize = pid.parse().unwrap();
    let timestamp = format_ts(timestamp.expect("Timestamp field was empty"));
    return (pid,timestamp,&rest,&name);
}

// function to actually parse the rest of the system call (arguments, return values, system call name, duration)
fn parse_syscall(config: &Config,line_num: usize,pid: usize, timestamp: u64, syscall_string: String, procname: String,resumed_call_cnt: &mut usize, unfinished_call_cnt: &mut usize) -> Option<SystemCall>{

    // lazy initialize of regex so it only compiles once regexes instead of every line (due to loop)
    static RE: LazyLock<(Regex, Regex, Regex,Regex, Regex, Regex, Regex, Regex,Regex)> = LazyLock::new(||
        (
            Regex::new(r"^(?<call>\S+?)\((?<args>.*?)\)\s*=\s*(?<ret>.*) <(?<dur>[\d.]*)>").unwrap(),
            // captures system calls with normal
            // example: execve(pathname="/usr/bin/curl", argv=["curl", "https://example.com"], envp=0x7ffe106f6e08 /* 63 vars */) = 0 <0.000372>

            Regex::new(r"^(?<call>\S+?)\((?<args>.*?)\s<unfinished\s\.\.\.>").unwrap(),
            // matches unfinished system calls
            // example: setsockopt(sockfd=6<UDP:[379858]>, level=SOL_IP, optname=IP_RECVERR, optval=[1], optlen=4 <unfinished ...>

            Regex::new(r"<\.\.\. (?<call>\S*) resumed>.(?<args>.*\)) = (?<ret>.*) <(?<dur>[\d.]*)>").unwrap(),
            // resumed with args
            // example:  <... rt_sigaction resumed>, oldact=NULL, sigsetsize=8) = 0 <0.000013>

            Regex::new(r"<\.\.\. (?<call>\S*) resumed>\)\s= (?<ret>.*) <(?<dur>[\d.]*)>").unwrap(),
            // resumed without args
            // example:  <... rseq resumed>) = 0 <0.000015>

            Regex::new(r"^(?<call>\S*)\(\)\s*= (?<ret>.*) <(?<dur>[\d.]*)>").unwrap(),
            // parsing syscalls without args
            // getpid()       = 118315 <0.000002>

            Regex::new(r"(?<call>\S+?)\((?<args>.*?)\)\s=\s*(?<ret>.*)").unwrap(),
            // captures regular system calls without duration
            // exit_group(status=0) = ?

            Regex::new(r"^[+-]{3} (?<text>.*) [+-]{3}").unwrap(),
            // capturing signals and informational messages
            // examples:
            // +++ exited with 0 +++
            // --- SIGINT {si_signo=SIGINT, si_code=SI_KERNEL} ---

            Regex::new(r"<\.\.\. (?<call>\S*) resumed>\)\s= (?<ret>.*)").unwrap(),
            // resumed without dur and args
            // example: <... exit resumed>) = ?

            Regex::new(r"<\.\.\. (?<call>\S*) resumed>\s*<unfinished \.\.\.>\) = (?<ret>.*)").unwrap(),
            // example 130929 0 <... ppoll resumed> <unfinished ...>) = ?
            // unfinished and resumed call (:
            //
            //
            // fixme merge all resumed system calls into this pattern: <\.\.\. (?<call>\S*) resumed>.(?<args>.*\))? = (?<ret>.*)( <(?<dur>[\d.]*)>)?
            // Note: requires handling when ? or nothing is returned

            ));

    let (syscall_regular, syscall_unfinished, syscall_resumed_args, syscall_resumed_without_args, syscall_without_args,syscall_wihout_args_and_duration, signals_informational,resumed_without_dur,unf_res_call) = &*RE;

    // regex capture routine
    if let Some(caps) = syscall_regular.captures(&syscall_string){ 
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::RegularSyscall));
    }
    else if let Some(caps) = syscall_unfinished.captures(&syscall_string){ 
        *unfinished_call_cnt = *unfinished_call_cnt +1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::UnfinishedCall));
    }
    else if let Some(caps) = syscall_resumed_args.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::ResumedCallWithArgs));
    }
    else if let Some(caps) = syscall_resumed_without_args.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::ResumedCallWithoutArgs));
    }
    else if let Some(caps) = syscall_without_args.captures(&syscall_string){ 
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::CallWithoutArgs));
    }
    else if let Some(caps) = syscall_wihout_args_and_duration.captures(&syscall_string){ 
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::CallWithoutArgsNoDur));
    }
    else if let Some(caps) = resumed_without_dur.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::ResumedWithoutDur));
    }
    else if let Some(caps) = unf_res_call.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        *unfinished_call_cnt = *unfinished_call_cnt +1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,&caps,CallType::UnfResCall)); //fixme unfrescall not ideal
    }
    else if let Some(caps) = signals_informational.captures(&syscall_string){ 
        // handle signals and strace informational messages seperately since they look different
        return Some(make_signal_struct(pid,timestamp,procname,&caps,CallType::SignalOrInformational));
    }
    println!("ERR: No Regex matched for line {}: {} {} {}", line_num, pid, timestamp, &syscall_string);
    return None;

}

// format timestamps into microseconds to comply with TEF specification 
fn format_ts(timestamp: &str)-> u64{ 
    let Some((secs, us)) = &timestamp.split_once('.') else {return 0};
    let secs: u64 = secs.parse().unwrap();
    let secs_in_us = secs * 1_000_000;
    let mut us_str = us.to_string();
    while us_str.len() < 6{
        us_str.push('0');
    }
    let microseconds: u64 = us_str.parse().unwrap();
    let total_time: u64 = secs_in_us + microseconds;
    return total_time;
}

// basic argument parsing logic including the argument names
fn parse_args(arg_str: &str) -> BTreeMap<String, String>
{
    
    let mut map = BTreeMap::new();
    let mut in_quotes = false;
    let mut start = 0;
    let mut key = "".to_string();
    let mut is_nested = false;
    let mut argname_stored = false;

    let args = arg_str.as_bytes();
    let len = arg_str.len();

    // edge case could happen with resumed calls that start with " -> reference out of index if " is 0 and we check args[i-1]
    if len >1
    {
        for (i,&char) in args.iter().enumerate(){

            if char == b'"' && args[i-1] != b'\\'{ // check if we read chars in quotes "" important, so no }] are interpreted in this section


                in_quotes = !in_quotes; 

        }
        if in_quotes == false{


            if char == b'=' && is_nested == false{ // detect arg_name
                if args[i+1] == b'{' || args[i+1] == b'[' { // check for nested args 
                    is_nested = true;
                }
                key = str::from_utf8(&args[start..i]).unwrap().to_owned(); // always happens, for unnested
                argname_stored = true; // arg_names
                start = i+1;
                }
            if argname_stored == true{


                if char == b',' && is_nested == false { // detect arg_val
                    map.insert(key.to_owned(),str::from_utf8(&args[start..i]).unwrap().to_owned());
                    argname_stored = false;
                    start = i+1;
                }
                if (char == b']' || char == b'}') && i != len -1 && is_nested == true && args[i+1] == b','{
                    map.insert(key.to_owned(),str::from_utf8(&args[start+1..i]).unwrap().to_owned());
                    argname_stored = false; // needed to not overwrite 
                    is_nested = false;
                    start = i+1;
                }

                if i == len - 1 {  
                                   
                                   
                    map.insert(key.to_owned(),str::from_utf8(&args[start..i+1]).unwrap().to_owned()); // last args 
                    argname_stored = false;
                }

            }

        }

    }
}
map
}
