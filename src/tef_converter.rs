use std::borrow::Cow;
use std::collections::BTreeMap;
use std::str;
use crate::syscall_parser::OwnedSystemCall;
use crate::syscall_parser::SystemCall;
use crate::syscall_parser::CallType;
use crate::{arg_values::ArgValue,arg_values::OwnedArgValue};

#[derive(serde::Serialize)]
#[derive(Debug)]
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
fn check_storage<'a>(syscall_store: &'a mut Vec<OwnedSystemCall>,resumed_call: SystemCall<'a>,counter: &mut usize) -> SystemCall<'a>{


    for (_i,stored_syscall) in syscall_store.iter_mut().enumerate()
    {

        if stored_syscall.pid == resumed_call.pid &&
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

            //FIXME arg merging works, but the syscall.args_string field is bugged. see
            //syscallsparser.rs
            let merged_call = SystemCall{
                timestamp: stored_syscall.timestamp,
                pid: stored_syscall.pid,
                name: &stored_syscall.name,
                args: stored_syscall.args.iter().map(|(key,value)| {
                    let key = key.as_str();
                    let value = match value {
                        OwnedArgValue::One(single) => ArgValue::One(single.as_str()),
                        OwnedArgValue::Many(items) => ArgValue::Many(items.into_iter().map(|v| v.as_str()).collect(),)
                            };
                    (key,value)
                }).chain(resumed_call.args.into_iter()).collect(),
                //FIXME implement arg_string merging
                args_string: stored_syscall.args_string.as_deref().map(Cow::Borrowed),
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


// creates complete (X) or instant (i) TEF events based on the data which could be extracted. All
// calls without a duration are stored as instant events
pub fn build_trace_event_format<'a>(event: &'a mut SystemCall)-> TEFSystemCall<'a>{

    match event.call_type {

        CallType::RegularSyscall | CallType::ResumedCallWithArgs | CallType::ResumedCallWithoutArgs | CallType::CallWithoutArgs => {


            if event.ret.is_some() {
                event.args.insert("ret",ArgValue::One(event.ret.unwrap()));
            }


            let tef_event = TEFSystemCall{

                name: &event.name,
                cat: &event.successful, 
                ph: "X",
                ts: event.timestamp,
                pid: event.pid,
                tid: event.pid,
                args: &event.args,
                dur: event.dur,


            };
            return tef_event;

        }

        CallType::SignalOrInformational | CallType::CallWithoutArgsNoDur | CallType::UnfinishedCall | CallType::ResumedWithoutDur | CallType::UnfResCall => { //instant events for signals and unfinished calls which were not matched or calls without duration

            if event.ret.is_some() {
                event.args.insert("ret",ArgValue::One(event.ret.clone().unwrap()));
            }

            let tef_event = TEFSystemCall{

                name: &event.name,
                cat: &event.successful,
                ph: "i",
                ts: event.timestamp,
                pid: event.pid,
                tid: event.pid,
                args: &event.args,
                dur: event.dur,


            };
            return tef_event;
       }

    }

}



