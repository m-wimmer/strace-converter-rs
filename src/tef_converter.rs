use std::collections::BTreeMap;
use std::collections::HashMap;
use std::str;
use crate::CONFIG;
use crate::keys::ARGS_STRING;
use crate::syscall_parser::OwnedSystemCall;
use crate::syscall_parser::SystemCall;
use crate::syscall_parser::CallType;
use crate::{arg_values::ArgValue,arg_values::OwnedArgValue};

#[derive(serde::Serialize)]
#[derive(Debug,PartialEq)]
pub struct TEFSystemCall<'a>{ // make struct according to tef
    name: &'a str,
    cat: &'a str,
    ph: &'a str,
    pid: usize,
    tid: usize,
    ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dur: Option<u128>,
    // #[serde(skip_serializing_if = "Option::is_none")]
    args: &'a BTreeMap<&'a str,ArgValue<'a>>,
}

// partial system calls (unfinished) are merged with their continuation (resumed) based on their
// PID, timestamps and call names. In TEF the event is set to be an instant event if no duration
// was supplied by strace. The timestamp for the merged call is set to the timestamp of the partial
// invocation (unfinished call)
pub fn handle_partial_system_call<'a>(syscall_store: &'a mut Vec<OwnedSystemCall>,call: SystemCall<'a>,counter: &mut usize) -> SystemCall<'a>{

        if call.call_type == CallType::UnfinishedCall{
            // convert reference call to owned call, get stored owned call to return a reference
            // call
            let stored_call = call.into();
            syscall_store.push(stored_call); 
            return syscall_store.last().unwrap().into();
        }
        else if call.call_type == CallType::ResumedCallWithArgs || call.call_type == CallType::ResumedCallWithoutArgs || call.call_type == CallType::ResumedWithoutDur{
            // receives merged call as ret
            let call = check_storage(syscall_store, call,counter);
            return call;
        }
        return call;
}

// System calls that are unfinished are temporarily stored in a vec until the matching resumed call
// is found
// System calls are transferred to a struct that owns the strings when we need to store them (i.e., unfinished calls)
// Normally system calls do not own them (struct contains mostly references) to avoid unnecessary allocations
fn check_storage<'a>(syscall_store: &'a mut Vec<OwnedSystemCall>,mut resumed_call: SystemCall<'a>,counter: &mut usize) -> SystemCall<'a>{

    for (_i,stored_syscall) in syscall_store.iter_mut().enumerate()
    {

        if stored_syscall.tid == resumed_call.tid &&
            stored_syscall.timestamp < resumed_call.timestamp &&
            stored_syscall.name == resumed_call.name{
                // we merge into old call to make timestamp and duration make more sense
                // timestamp when syscall started, duration and such is supplied by the resumed
                // call
            // if to catch calls which are resumed but have no duration
            // 47618<IPC I/O Child> 1773146848.562631 <... recvmsg resumed>) = ? <unavailable> 
            //
            if resumed_call.dur.is_some() {stored_syscall.call_type = CallType::RegularSyscall; }
            else {stored_syscall.call_type = CallType::ResumedWithoutDur}

            // println!("INFO: Merged two trace entries!");
            *counter = *counter + 1;

            merge_arg_string_argument(stored_syscall,&mut resumed_call);

            let merged_call = SystemCall{
                timestamp: stored_syscall.timestamp,
                tid: stored_syscall.tid,
                name: &stored_syscall.name,
                args: stored_syscall.args.iter().map(|(key,value)| {
                    let key = key.as_str();
                    let value = match value {
                        OwnedArgValue::One(single) => ArgValue::One(single.as_str()),
                        OwnedArgValue::Many(items) => ArgValue::Many(items.into_iter().map(|v| v.as_str()).collect(),)
                            };
                    (key,value)
                }).chain(resumed_call.args.into_iter()).collect(),
                dur: resumed_call.dur,
                ret: resumed_call.ret,
                call_type: stored_syscall.call_type.clone(),
                successful: resumed_call.successful,
                procname: &stored_syscall.procname,
            };

            // set flag to delete merged calls after being written in main. 
            stored_syscall.merged = true;
            return merged_call;
                
        }

    }
    
    // println!("Resumed call could not be matched to unfinished one.. Returned as is: {:?}", resumed_call);
    return resumed_call;

}

fn merge_arg_string_argument(unf_call: &mut OwnedSystemCall, res_call: &mut SystemCall){
    // if unfinished syscall had any args
    if let Some(OwnedArgValue::One(unf_string)) = unf_call.args.get_mut(ARGS_STRING) {

        // if resumed syscall had any args
        if let Some(ArgValue::One(res_string)) = res_call.args.get(ARGS_STRING) {
            unf_string.push_str(", ");
            unf_string.push_str(res_string);
        }
        // else: resumed call had no extra args -> 
        // remove args_string key either way from resumed call so it does not overwrite 
        res_call.args.remove(ARGS_STRING);
    }
    // else: unfinished call had no args -> do nothing
}


// creates complete (X) or instant (i) TEF events based on the data which could be extracted. All
// calls without a duration are stored as instant events
pub fn build_trace_event_format_impl<'a>(conf: &crate::Cli,event: &'a mut SystemCall,thread_pid_tid_map: &mut HashMap<usize,usize>)-> TEFSystemCall<'a>{


    let ph_type = match event.call_type {
        CallType::RegularSyscall 
            | CallType::ResumedCallWithArgs 
            | CallType::ResumedCallWithoutArgs 
            | CallType::CallWithoutArgs => {
                "X"
            }

        //instant events for signals and unfinished calls which were not matched or calls without duration
        CallType::SignalOrInformational 
            | CallType::CallWithoutArgsNoDur 
            | CallType::UnfinishedCall 
            | CallType::ResumedWithoutDur 
            | CallType::UnfResCall => { 
                "i"
            }
    };

    if event.ret.is_some() {
        event.args.insert("ret",ArgValue::One(event.ret.unwrap()));
    }

    let tef_event = TEFSystemCall{

        name: &event.name,
        cat: &event.successful, 
        ph: ph_type,
        ts: event.timestamp,
        pid: {
                // if thread_aware option is set, we check for clone3 or mappings
                // system calls and map them
                if conf.thread_aware_tef {
                    crate::threads::check_for_thread(event, thread_pid_tid_map)
                }
                else
                {
                    event.tid
                }
        },
        tid: event.tid,
        args: &event.args,
        dur: event.dur,


    };
    return tef_event;

}
// abstraction to simplify testing due to oncelock
pub fn build_trace_event_format<'a>(event: &'a mut SystemCall,thread_pid_tid_map: &mut HashMap<usize,usize>) -> TEFSystemCall<'a>{
    return build_trace_event_format_impl(CONFIG.get().expect("Config not initialized"),event,thread_pid_tid_map);
}

#[cfg(test)]
mod tests {

    use crate::Cli;
    use super::*;

    #[test]
    fn test_build_trace_event_format(){
        let mut thread_map = HashMap::from([
            (27864,27863),
            (47679,27864),
        ]);
        let arg_map = BTreeMap::from([
            ("flags", ArgValue::One("MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE")),
        ]);
        let arg_map_tef = BTreeMap::from([
            ("flags", ArgValue::One("MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE")),
            ("ret", ArgValue::One("32")),
        ]);
        let arg_map_tef_no_ret = BTreeMap::from([
            ("flags", ArgValue::One("MAP_PRIVATE|MAP_FIXED|MAP_DENYWRITE")),
        ]);

        let conf = Cli { 
            input_file: "test_config".to_string(),
            format: "test_config".to_string(),
            output_file: "tef".to_string(),
            parse_arguments: true,
            log_file: None,
            no_arg_str_parse: false,
            disable_syscall_merge: false,
            thread_aware_tef: false 
        };

        // system call with return value
        let mut syscall_with_ret = SystemCall { timestamp: 1766681383946697, tid: 47679, name: "getrandom", args: arg_map.clone(), dur: Some(31), ret: Some("32"), call_type: CallType::RegularSyscall, successful: "successful", procname: "curl" };
        let tef_event = TEFSystemCall { name: "getrandom", cat: "successful", ph: "X", pid: 47679, tid: 47679, ts: 1766681383946697, dur: Some(31), args: &arg_map_tef };
        assert_eq!(build_trace_event_format_impl(&conf,&mut syscall_with_ret,&mut thread_map),tef_event);

        // system call without return value
        let mut syscall_without_ret = SystemCall { timestamp: 1766681383946697, tid: 47679, name: "getrandom", args: arg_map.clone(), dur: Some(31), ret: None, call_type: CallType::RegularSyscall, successful: "successful", procname: "curl" };
        let tef_event = TEFSystemCall { name: "getrandom", cat: "successful", ph: "X", pid: 47679, tid: 47679, ts: 1766681383946697, dur: Some(31), args: &arg_map_tef_no_ret };
        assert_eq!(build_trace_event_format_impl(&conf,&mut syscall_without_ret,&mut thread_map),tef_event);

        // unfinished call stored as instant event
        syscall_without_ret.call_type = CallType::UnfinishedCall;
        let tef_event = TEFSystemCall { name: "getrandom", cat: "successful", ph: "i", pid: 47679, tid: 47679, ts: 1766681383946697, dur: Some(31), args: &arg_map_tef_no_ret };
        assert_eq!(build_trace_event_format_impl(&conf,&mut syscall_without_ret,&mut thread_map),tef_event);

        // remapping correct pid for threads
        /* 
         * tid -> pid
            27864->27863
            47679->27864
        */
        let conf = Cli { 
            input_file: "test_config".to_string(),
            format: "test_config".to_string(),
            output_file: "tef".to_string(),
            parse_arguments: true,
            log_file: None,
            no_arg_str_parse: false,
            disable_syscall_merge: false,
            thread_aware_tef: true
        };
        let mut syscall_with_ret = SystemCall { timestamp: 1766681383946697, tid: 47679, name: "getrandom", args: arg_map.clone(), dur: Some(31), ret: Some("32"), call_type: CallType::RegularSyscall, successful: "successful", procname: "curl" };
        let tef_event = TEFSystemCall { name: "getrandom", cat: "successful", ph: "X", pid: 27863, tid: 47679, ts: 1766681383946697, dur: Some(31), args: &arg_map_tef };
        assert_eq!(build_trace_event_format_impl(&conf,&mut syscall_with_ret,&mut thread_map),tef_event);
    }

    #[test]
    fn test_handle_partial_system_call(){

        // unfinished and resumed arg strings (fictional arguments)
        let unf_syscall = SystemCall { 
            timestamp: 1766681383946697,
            tid: 47679,
            name: "getrandom",
            args: BTreeMap::from([
            ("args_string", ArgValue::One("uaddr=0xFF, futex_op=FUTEX_WAKE_PRIVATE, val=1")),
            ("uaddr", ArgValue::One("0xFF")),
            ("futex_op", ArgValue::One("FUTEX_WAKE_PRIVATE")),
            ("val", ArgValue::One("1")),
            ("sigsetsize", ArgValue::One("8)")),
        ]),
            dur: None,
            ret: None,
            call_type: CallType::UnfinishedCall,
            successful: "unknown",
            procname: "curl",
        };

        let arg_map_res = BTreeMap::from([
            ("args_string", ArgValue::One(" oldset=NULL, sigsetsize=8)")),
            ("oldset", ArgValue::One("NULL")),
            ("ret", ArgValue::One("32")),
        ]);
        let resumed_call = SystemCall { 
            timestamp: 1766681383946698,
            tid: 47679,
            name: "getrandom",
            args: arg_map_res.clone(),
            dur: Some(31),
            ret: Some("32"),
            call_type: CallType::ResumedCallWithArgs,
            successful: "successful",
            procname: "curl" 
        };

        let mut merge_count = 0;
        let mut syscall_store = Vec::new();

        // nothing matching in store, return resumed call as is
        assert_eq!(handle_partial_system_call(&mut syscall_store, resumed_call.clone(), &mut merge_count),resumed_call);
        assert_eq!(merge_count,0);

        // nothing in store, add unf call to store and return it again
        assert_eq!(handle_partial_system_call(&mut syscall_store, unf_syscall.clone(), &mut merge_count),unf_syscall);
        assert_eq!(merge_count,0);


        let merged_call = SystemCall { 
            timestamp: 1766681383946697,
            tid: 47679,
            name: "getrandom",
            args: BTreeMap::from([
            // merged arg string 
            ("args_string", ArgValue::One("uaddr=0xFF, futex_op=FUTEX_WAKE_PRIVATE, val=1,  oldset=NULL, sigsetsize=8)")),
            ("uaddr", ArgValue::One("0xFF")),
            ("futex_op", ArgValue::One("FUTEX_WAKE_PRIVATE")),
            ("val", ArgValue::One("1")),
            ("sigsetsize", ArgValue::One("8)")),
            // res call args
            ("oldset", ArgValue::One("NULL")),
            ("ret", ArgValue::One("32")),
        ]),
            dur: Some(31),
            ret: Some("32"),
            call_type: CallType::RegularSyscall,
            successful: "successful",
            procname: "curl" 
        };

        // matching syscalls found (timestamp, pid and call name), returned merged call
        assert_eq!(handle_partial_system_call(&mut syscall_store, resumed_call.clone(), &mut merge_count),merged_call);
        assert_eq!(merge_count,1);

    }


}




