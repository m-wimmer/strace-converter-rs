/*
 * Component for the linux thread aware option. Essentially we check for flags in the clone and clone3
 * calls and set pid values to the caller of the clone call if CLONE_THREAD is set.
 *  otherwise we always set pid = tid, since fork and the clone calls without the flag create a new
 *  process with the first main thread 
 */

use std::collections::HashMap;

use crate::{arg_values::ArgValue, syscall_parser::SystemCall};


// checks arg flag field system calls if a thread was spawned or a process
// if a thread was spawned with CLONE_THREAD, we store a mapping of the tid and pid in the map to rewrite later
// returns either the pid for the thread for the syscall or the same as before (determine pid is
// called since we may have a thread that created a thread -> see comments for determine_pid)
pub fn check_for_thread(syscall :&mut SystemCall, pid_tid_map: &mut HashMap<usize,usize>) -> usize{

    let flag_str = "flags";
    let new_thread_str = "CLONE_THREAD";

    if syscall.name == "clone" || syscall.name == "clone3" && syscall.successful == "successful" {
        if let Some(ArgValue::One(syscall_flags)) = syscall.args.get(flag_str) {
            if let Some(ret_str) = syscall.ret {
                if let Some(ret_tid) = get_ret_tid(ret_str){
                    if syscall_flags.contains(new_thread_str) {
                        // new thread: store mapping key: tid (return value); value : pid (caller)
                        pid_tid_map.insert(ret_tid, syscall.tid);
                        return determine_pid(syscall.tid, pid_tid_map);
                    }
                }
            };
            // else its a new process: return ret value (new pid = tid)
        };
    }
    return determine_pid(syscall.tid, pid_tid_map);
}

// checks hashmap for matching tid key and rewrites pid field to the initial caller (the pid)
pub fn determine_pid(syscall_tid :usize, pid_tid_map: &HashMap<usize,usize>) -> usize{
    // issue: if a thread spawns a thread, pid is that of the initial process and not that of the caller
    // in the log
        // e.g., 
        // 27863   27863 a.out
        // 27863   27864 a.out
        // 27863   27865 a.out
        // 1. 27863 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f23e51ffce8, parent_tid=0x7f23e51ff990, exit_signal=0, stack=0x7f23e49ff000, stack_size=0x7fff80, tls=0x7f23e51ff6c0}strace: Process 27864 attached
        // 2. 27864 clone3({flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x7f23e49fece8, parent_tid=0x7f23e49fe990, exit_signal=0, stack=0x7f23e41fe000, stack_size=0x7fff80, tls=0x7f23e49fe6c0}strace: Process 27865 attached
    //  if process -> pid = caller tid
    //  if thread -> pid = original first process tid
    // result -> we need to know if the caller was a thread or a process
    //  solution: search for tid in hashmap. search for resulting pid aswell in hashmap. if pid
    //  is also a tid key -> get that value and search it until no match. last match wins as the pid
    let mut final_pid = syscall_tid;

    while let Some(&mapped_pid) = pid_tid_map.get(&final_pid){
        final_pid = mapped_pid;
    };
    return final_pid;
}


fn get_ret_tid(ret_str: &str) -> Option<usize>{

    if let Some((tid_str,_)) = ret_str.split_once('<'){
        let tid : Option<usize> = match tid_str.trim().parse(){
            Ok(tid_parsed) => Some(tid_parsed),
            Err(_) => {
                println!("Error parsing ret value for clone call");
                None
            },
        };
        return tid;
    };
    None
}


// FIXME fn for deleting mappings on threads that finished with e.g., exit()

