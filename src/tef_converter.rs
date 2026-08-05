use std::collections::BTreeMap;
use std::str;
use crate::syscall_parser::SystemCall;
use crate::syscall_parser::CallType;

#[derive(serde::Serialize)]
#[derive(Debug)]
pub struct TEFSystemCall<'a>{ // make struct according to tef
    name: &'a str,
    cat: &'a str,
    ph: String,
    pid: usize,
    tid: usize,
    ts: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    dur: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    args: Option<BTreeMap<String,String>>,
}

// partial system calls (unfinished) are merged with their continuation (resumed) based on their
// PID, timestamps and call names. In TEF the event is set to be an instant event if no duration
// was supplied by strace. The timestamp for the merged call is set to the timestamp of the partial
// invocation (unfinished call)
pub fn handle_partial_system_call(syscall_store: &mut Vec<SystemCall>,call: SystemCall,counter: &mut usize) -> SystemCall{

        if call.call_type == CallType::UnfinishedCall{
            syscall_store.push(call.clone()); 
            return call;
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
fn check_storage(syscall_store: &mut Vec<SystemCall>,resumed_call: SystemCall,counter: &mut usize) -> SystemCall{


    for (i,stored_syscall) in syscall_store.iter_mut().enumerate()
    {

        if stored_syscall.pid == resumed_call.pid &&
            stored_syscall.timestamp < resumed_call.timestamp &&
            stored_syscall.name == resumed_call.name{


                // we merge into old call to make timestamp and duration make more sense
                // timestamp when syscall started, duration and such is supplied by the resumed
                // call
            stored_syscall.ret = resumed_call.ret.to_owned(); 
            stored_syscall.dur = resumed_call.dur.to_owned();
            stored_syscall.successful = resumed_call.successful.to_owned();
            // if to catch calls which are resumed but have no duration
            // 47618<IPC I/O Child> 1773146848.562631 <... recvmsg resumed>) = ? <unavailable> 
            if resumed_call.dur.is_some() {stored_syscall.call_type = CallType::RegularSyscall; }
            else {stored_syscall.call_type = CallType::ResumedWithoutDur}
            let merged_call = stored_syscall.clone();
            // println!("INFO: Merged two trace entries!");
            *counter = *counter + 1;

            syscall_store.remove(i);
            return merged_call;
                
        }

    }
    
    // println!("Resumed call could not be matched to unfinished one.. Returned as is: {:?}", resumed_call);
    return resumed_call;

}


// creates complete (X) or instant (i) TEF events based on the data which could be extracted. All
// calls without a duration are stored as instant events
pub fn build_trace_event_format(event: &SystemCall)-> TEFSystemCall<'_>{

    match event.call_type {


        CallType::RegularSyscall | CallType::ResumedCallWithArgs | CallType::ResumedCallWithoutArgs | CallType::CallWithoutArgs => {

            let event = event;

            let arguments = if event.args.is_some(){

                let mut arguments = event.args.clone().unwrap();
                arguments.insert("ret".to_string(),event.ret.clone().unwrap());
                arguments
            }else{
                let mut arguments = BTreeMap::new();
                // println!("Empty args for signal");
                arguments.insert("ret".to_string(),event.ret.clone().unwrap());
                arguments
            };


            let tef_event = TEFSystemCall{

                name: &event.name,
                cat: &event.successful, 
                ph: "X".to_string(),
                ts: event.timestamp,
                pid: event.pid,
                tid: event.pid,
                args: Some(arguments),
                dur: event.dur,


            };
            return tef_event;

        }

        CallType::SignalOrInformational | CallType::CallWithoutArgsNoDur | CallType::UnfinishedCall | CallType::ResumedWithoutDur | CallType::UnfResCall => { //instant events for signals and unfinished calls which were not matched or calls without duration


            let arguments = if event.args.is_some(){

                let mut arguments = event.args.clone().unwrap();
                if event.ret.is_some() {arguments.insert("ret".to_string(),event.ret.clone().unwrap());}
                arguments
            }else{
                let mut arguments = BTreeMap::new();
                // println!("Empty args for signal");
                if event.ret.is_some() {arguments.insert("ret".to_string(),event.ret.clone().unwrap());}
                arguments
            };

            let tef_event = TEFSystemCall{

                name: &event.name,
                cat: &event.successful,
                ph: "i".to_string(),
                ts: event.timestamp,
                pid: event.pid,
                tid: event.pid,
                args: Some(arguments),
                dur: event.dur,


            };
            // if event.call_type == CallType::SignalOrInformational{
                // println!("signal converted {:?}",tef_event)
// 
            // }
                                          //  
            // println!("{:?}",tef_event);
            return tef_event;
       }

    }

}



