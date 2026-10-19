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
use std::borrow::Cow;


use crate::{Config, argument_iterator,arg_values::ArgValue,arg_values::OwnedArgValue};


#[derive(Debug)]
#[derive(serde::Serialize)]
#[derive(Clone)]
pub struct SystemCall<'a> {
    pub timestamp: u64,
    pub pid: usize,
    pub name: &'a str,
    pub args: BTreeMap<&'a str, ArgValue<'a>>,
    // argstring is Cow because when we merge syscalls we need to add two &str together
    // FIXME arg_string merging not implemented yet
    #[serde(skip_serializing)]
    pub args_string: Option<Cow<'a, str>>,
    pub dur: Option<u128>,
    pub ret: Option<&'a str>,
    #[serde(skip_serializing)]
    pub call_type: CallType,
    pub successful: &'a str,
    #[serde(skip_serializing)]
    pub procname: &'a str,
}

impl<'b> From<&'b OwnedSystemCall> for SystemCall<'b> {
    fn from(syscall: &'b OwnedSystemCall) -> Self {
        Self {
            timestamp: syscall.timestamp,
            pid: syscall.pid,
            name: &syscall.name,
            // convert from stored system call to one that is just referenced
            args: syscall.args.iter().map(|(key,value)| {
            let key = key.as_str();
            let value = match value {
                OwnedArgValue::One(single) => ArgValue::One(single.as_str()),
                OwnedArgValue::Many(items) => ArgValue::Many(items.into_iter().map(|v| v.as_str()).collect(),)
                    };
            (key,value)
        }).collect(),
            args_string: syscall.args_string.as_deref().map(Cow::Borrowed),
            dur: syscall.dur,
            ret: syscall.ret.as_deref(),
            call_type: syscall.call_type.clone(),
            successful: &syscall.successful,
            procname: &syscall.procname,
        }
    }
}

#[derive(Debug)]
#[derive(serde::Serialize)]
#[derive(Clone)]
pub struct OwnedSystemCall {
    pub timestamp: u64,
    pub pid: usize,
    pub name: String,
    pub args: BTreeMap<String,OwnedArgValue>,
    #[serde(skip_serializing)]
    pub args_string: Option<String>,
    pub dur: Option<u128>,
    pub ret: Option<String>,
    #[serde(skip_serializing)]
    pub call_type: CallType,
    pub successful: String,
    #[serde(skip_serializing)]
    pub procname: String,
    // flag that is set when an owned system call can be removed after merging. checked when system
    // call is written
    pub merged: bool,
}

impl From<SystemCall<'_>> for OwnedSystemCall {
    fn from(syscall: SystemCall) -> Self {
        Self {
            timestamp: syscall.timestamp,
            pid: syscall.pid,
            name: syscall.name.to_owned(),
            // own all arguments and the map itself
            args: syscall.args.into_iter().map(|(key,value)| {
            let key = key.to_owned();
            let value = match value {
                ArgValue::One(single) => OwnedArgValue::One(single.to_owned()),
                ArgValue::Many(items) => OwnedArgValue::Many(items.into_iter().map(|v| v.to_owned()).collect(),)
                    };
            (key,value)
        }).collect(),
            args_string: syscall.args_string.map(Cow::into_owned),
            dur: syscall.dur,
            ret: syscall.ret.map(|value| value.to_owned()),
            call_type: syscall.call_type,
            successful: syscall.successful.to_owned(),
            procname: syscall.procname.to_owned(),
            merged: false,
        }
    }
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


pub fn parse<'a>(config: &Config,line_num: usize, log_line: &'a str,resumed_call_cnt: &mut usize, unfinished_call_cnt: &mut usize) -> SystemCall<'a>
{
    let (pid,timestamp,rest,pname) = parse_pid_pidname_timestamp(&log_line);
    if rest == ""{
        println!("Parsing of timestamp or PID failed for line {}: {}", line_num + 1, &log_line);
    }
    let system_call = parse_syscall(config,line_num,pid,timestamp,rest,pname,resumed_call_cnt,unfinished_call_cnt);
    if system_call.is_some() {
        system_call.unwrap()
    }else{
        println!("failed to parse line {}: {:?}",line_num, log_line);
        std::process::exit(3);
    }
}


fn make_syscall_struct<'a>(config: &Config,pid:usize, timestamp:u64,procname:&'a str,caps: regex::Captures<'a>, call_type: CallType) -> SystemCall<'a>{

    let mut syscall = SystemCall {
        timestamp: timestamp,
        pid: pid,
        name: caps.name("call").expect("System calls should consist of a name").as_str(),
        args: BTreeMap::new(),
        args_string: None,
        dur: None,
        ret: None,
        call_type: call_type,
        successful: "unknown",
        procname: procname,
    };


    if caps.name("args").is_some() {
        let arg_str = caps.name("args").unwrap().as_str();

        // check if user wants to parse args or not
        // if not, store whole arg string in one key
        if config.arg_parse_val==true {
            parse_args(arg_str.as_bytes());
            syscall.args = parse_args(&arg_str.as_bytes());
            // FIXME make this an option or keep it. currently has a bug where on merged calls only
            // the part of the resumed call is stored.
            syscall.args.insert("args", ArgValue::One(arg_str));
        }
        else {
            let mut map = BTreeMap::new();
            map.insert("args", ArgValue::One(arg_str));
            syscall.args = map;
        }
        syscall.args_string = Some(Cow::Borrowed(arg_str));

    }
    else {
        // empty treemap
        // Note: needs to happen since args are not an Option in the struct
        syscall.args = BTreeMap::new()

        }


    if caps.name("ret").is_some() {
        let ret_str = caps.name("ret").unwrap().as_str();
        if ret_str.starts_with("-") {
            syscall.successful = "unsuccessful";
        }
        else if !ret_str.starts_with("?"){
            syscall.successful = "successful";
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

fn make_signal_struct<'a> (pid:usize,timestamp:u64,procname:&'a str,caps: regex::Captures<'a>, call_type: CallType) -> SystemCall<'a> {

    let text_hashmap = BTreeMap::from([ ("text", ArgValue::One(caps.name("text").expect("No Signal text found").as_str())),]);

    let siginfo = SystemCall {
        timestamp: timestamp,
        pid: pid,
        name: "Signal",
        args: text_hashmap,
        args_string: None,
        dur: None,
        ret: None,
        call_type: call_type,
        successful: "unknown",
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
fn parse_syscall<'a>(config: &Config,line_num: usize,pid: usize, timestamp: u64, syscall_string: &'a str, procname: &'a str,resumed_call_cnt: &mut usize, unfinished_call_cnt: &mut usize) -> Option<SystemCall<'a>>{

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
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::RegularSyscall));
    }
    else if let Some(caps) = syscall_unfinished.captures(&syscall_string){ 
        *unfinished_call_cnt = *unfinished_call_cnt +1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::UnfinishedCall));
    }
    else if let Some(caps) = syscall_resumed_args.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::ResumedCallWithArgs));
    }
    else if let Some(caps) = syscall_resumed_without_args.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::ResumedCallWithoutArgs));
    }
    else if let Some(caps) = syscall_without_args.captures(&syscall_string){ 
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::CallWithoutArgs));
    }
    else if let Some(caps) = syscall_wihout_args_and_duration.captures(&syscall_string){ 
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::CallWithoutArgsNoDur));
    }
    else if let Some(caps) = resumed_without_dur.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::ResumedWithoutDur));
    }
    else if let Some(caps) = unf_res_call.captures(&syscall_string){ 
        *resumed_call_cnt = *resumed_call_cnt+1;
        *unfinished_call_cnt = *unfinished_call_cnt +1;
        return Some(make_syscall_struct(config,pid,timestamp,procname,caps,CallType::UnfResCall)); //fixme unfrescall not ideal
    }
    else if let Some(caps) = signals_informational.captures(&syscall_string){ 
        // handle signals and strace informational messages seperately since they look different
        return Some(make_signal_struct(pid,timestamp,procname,caps,CallType::SignalOrInformational));
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

// ARGUMENT LOGIC
// 1. loop through whole arg string
// 2. use custom iterator to go through each argument in the line (unescaped commas ',' indicate
//    it). e.g., key1={key11=val11}, key2=val2
// 3. get key in each block with get_key
//  3.1 find last unescaped '=' character 
//  3.2 dont take any [ or { or other characters BEFORE the key e.g., key1={key11=val11} --> drop: key1={ keep: key11=val11}
//  3.3 only return the key and not the key-value-pair: key11
// 4. get value (get_value) using the position where the key ended (key_end_pos). -> val11
// ( we dont need to remove brackets and such AFTER the value, since the iterator already has the
// logic for that ) 
// 5. store key-value pair if key exists 
//
fn parse_args<'a>(input_string: &'a [u8]) -> BTreeMap<&'a str,ArgValue<'a>>{

    let mut map = BTreeMap::new();
    argument_iterator::parse(input_string).into_iter().for_each(|item| {
        //println!("{}",std::str::from_utf8(item).unwrap());
        match get_key(item) {
            Some((key,key_end_pos)) => {
                let key = str::from_utf8(key).unwrap();
                let value = str::from_utf8(get_value(item, key_end_pos+1)).unwrap();
                if !map.contains_key(key) {
                    map.insert(key, ArgValue::One(value));
                }
                else {
                    // 1. check if its a one or a many 
                    // either store the one and push both to a many
                    // or add the new value to the many
                    match map.get_mut(key){
                        Some(ArgValue::One(s)) => {
                            let mut vec: Vec<&str> = Vec::new();
                            vec.push(s);
                            vec.push(value);
                            map.insert(key, ArgValue::Many(vec));
                        },
                        Some(ArgValue::Many(v)) => {
                            v.push(value)
                        },
                        // none should not exist because we have an entry for the key
                        None => todo!(),
                    }
                }
            },
            // if a section does not have any key (a '=' character), we land here. right now this
            // case is not handled yet, but one could just increment a key for it
            None => {
                // println!("no key found")
            },
        };
        
    });
    map
}

fn get_key(separated_arg_string: &[u8]) -> Option<(&[u8],usize)>{
    // find last = and take everything before it
    match last_unescaped_equal_char(separated_arg_string){
        Some(key_end_pos) => {
            // strip anything before actual key. e.g., abc={[key=val -> strip abc={[ and keep key
            // if we found no special chars, we just get the whole key (alphanumeric does not work because keys can have underscores_
            match separated_arg_string[..key_end_pos].iter().rposition(|byte| matches!(byte, b' ' | b'[' |  b'{' | b'=')) {
                Some(key_start_pos) => {
                    return Some((&separated_arg_string[key_start_pos+1..key_end_pos],key_end_pos));
                }
                None => {
                    return Some((&separated_arg_string[..key_end_pos],key_end_pos));
                },
            }
        },
        // FIXME check if NONE actually is happening when there was no value
        None => return None,
    }
}

fn get_value(separated_arg_string: &[u8],value_start_pos:usize) -> &[u8]{
        return &separated_arg_string[value_start_pos..];
}

// we need this logic instead of iter().rposition(|&b| b == b'=') because buffers could have = signs in them which are unescaped (or rpos would not know about it)
fn last_unescaped_equal_char(input_string: &[u8]) -> Option<usize>{
    let mut in_quotes = false;
    let mut in_arrows = false;
    let last_idx = input_string.len()-1;

    for (i,&byte) in input_string.iter().rev().enumerate(){
        // check if we have a value encased in " -> check for \ to see if the " was escaped
        // itself (then it is part of the value: e.g., " some\"string "
        if byte == b'"'{
            if i == last_idx || input_string[last_idx-i-1] != b'\\'{
                in_quotes = !in_quotes; 
            }
        }
        // everything very similar to iterator, but here we reverse, so < and > are swapped
        if (!in_quotes && byte == b'>' && !in_arrows) || (!in_quotes && byte == b'<' && in_arrows) {
            in_arrows = !in_arrows;
        }

        if !in_quotes && !in_arrows {
            if byte == b'='{ 
                return Some(last_idx-i);
            }
        }
        // eol check 
        if i == input_string.len()-1 {
            return None;
        }
    }

    return None;
}



