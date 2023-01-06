//! Implementation of [`Processor`] and Intersection of control flow
//!
//! Here, the continuous operation of user apps in CPU is maintained,
//! the current running state of CPU is recorded,
//! and the replacement and transfer of control flow of different applications are executed.


use super::__switch;
use super::{fetch_task, TaskStatus};
use super::{TaskContext, TaskControlBlock};
use crate::sync::UPSafeCell;
use crate::trap::TrapContext;
use alloc::sync::Arc;
use lazy_static::*;
use crate::config::{MAX_SYSCALL_NUM, PAGE_SIZE};
use alloc::vec::Vec;
use crate::timer::get_time_us;
use crate::mm::{VirtAddr, VirtPageNum, MapPermission, MemorySet, VPNRange};
/// Processor management structure
pub struct Processor {
    /// The task currently executing on the current processor
    current: Option<Arc<TaskControlBlock>>,
    /// The basic control flow of each core, helping to select and switch process
    idle_task_cx: TaskContext,
}

impl Processor {
    pub fn new() -> Self {
        Self {
            current: None,
            idle_task_cx: TaskContext::zero_init(),
        }
    }
    fn get_idle_task_cx_ptr(&mut self) -> *mut TaskContext {
        &mut self.idle_task_cx as *mut _
    }
    pub fn take_current(&mut self) -> Option<Arc<TaskControlBlock>> {
        self.current.take()
    }
    pub fn current(&self) -> Option<Arc<TaskControlBlock>> {
        self.current.as_ref().map(|task| Arc::clone(task))
    }
    fn get_current_task_status(&self) -> TaskStatus {
        let current_task = self.current.as_ref().unwrap();
        current_task.inner_exclusive_access().task_status
    }
    fn get_current_task_first_time(&self) -> usize {
        let current_task = self.current.as_ref().unwrap();
        current_task.inner_exclusive_access().first_running_time
    }
    fn update_current_task_syscall_times(&mut self, syscall_id: usize) {
        let mut current_task = self.current.as_mut().unwrap();
        current_task.inner_exclusive_access().syscall_times[syscall_id] += 1
    }
    fn get_current_task_times(&self) -> Vec<u32> {
        let current_task = self.current.as_ref().unwrap();
        current_task.inner_exclusive_access().syscall_times.clone()
    }

    fn mmap(&mut self, start: usize, len: usize, port: usize) -> isize {
        if start & (PAGE_SIZE - 1) != 0 {
            return -1;
        }
        // port最低三位[x w r]，其他位必须为0
        if port > 7usize || port == 0 {
            return -1;
        }

        let mut current_task = self.current.as_mut().unwrap();
        let memory_set = &mut current_task.inner_exclusive_access().memory_set;
  
        // check valid
        let start_vpn = VirtPageNum::from(VirtAddr(start));
        let end_vpn = VirtPageNum::from(VirtAddr(start + len).ceil());
        for vpn in start_vpn.0 .. end_vpn.0 {
            if let Some(pte) = memory_set.translate(VirtPageNum(vpn)) {
                if pte.is_valid() {
                    return -1;
                }
            }
        }
        let permission = MapPermission::from_bits((port as u8) << 1).unwrap() | MapPermission::U;
        memory_set.insert_framed_area(VirtAddr(start), VirtAddr(start+len), permission);
        0
    }

    fn munmap(&mut self, start: usize, len: usize) -> isize {
        if start & (PAGE_SIZE - 1) != 0 {
            return -1;
        }
      
        let mut current_task = self.current.as_mut().unwrap();
        let memory_set = &mut current_task.inner_exclusive_access().memory_set;

        // check valid
        let start_vpn = VirtPageNum::from(VirtAddr(start));
        let end_vpn = VirtPageNum::from(VirtAddr(start + len).ceil());
        for vpn in start_vpn.0 .. end_vpn.0 {
            if let Some(pte) = memory_set.translate(VirtPageNum(vpn)) {
                if !pte.is_valid() {
                    return -1;
                }
            }
        }
        
        let vpn_range = VPNRange::new(start_vpn, end_vpn);
        memory_set.munmap(vpn_range);
        0
    }
}

lazy_static! {
    /// PROCESSOR instance through lazy_static!
    pub static ref PROCESSOR: UPSafeCell<Processor> = unsafe { UPSafeCell::new(Processor::new()) };
}

/// The main part of process execution and scheduling
///
/// Loop fetch_task to get the process that needs to run,
/// and switch the process through __switch
pub fn run_tasks() {
    loop {
        let mut processor = PROCESSOR.exclusive_access();
        if let Some(task) = fetch_task() {
            let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
            // access coming task TCB exclusively
            let mut task_inner = task.inner_exclusive_access();
            let next_task_cx_ptr = &task_inner.task_cx as *const TaskContext;
            task_inner.task_status = TaskStatus::Running;
            if task_inner.first_running_time == 0 {
                task_inner.first_running_time = get_time_us() / 1000;
            }
            drop(task_inner);
            // release coming task TCB manually
            processor.current = Some(task);
            // release processor manually
            drop(processor);
            unsafe {
                __switch(idle_task_cx_ptr, next_task_cx_ptr);
            }
        }
    }
}

/// Get current task through take, leaving a None in its place
pub fn take_current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().take_current()
}

/// Get a copy of the current task
pub fn current_task() -> Option<Arc<TaskControlBlock>> {
    PROCESSOR.exclusive_access().current()
}

/// Get token of the address space of current task
pub fn current_user_token() -> usize {
    let task = current_task().unwrap();
    let token = task.inner_exclusive_access().get_user_token();
    token
}

/// Get the mutable reference to trap context of current task
pub fn current_trap_cx() -> &'static mut TrapContext {
    current_task()
        .unwrap()
        .inner_exclusive_access()
        .get_trap_cx()
}

/// Return to idle control flow for new scheduling
pub fn schedule(switched_task_cx_ptr: *mut TaskContext) {
    let mut processor = PROCESSOR.exclusive_access();
    let idle_task_cx_ptr = processor.get_idle_task_cx_ptr();
    drop(processor);
    unsafe {
        __switch(switched_task_cx_ptr, idle_task_cx_ptr);
    }
}

pub fn get_current_task_status() -> TaskStatus {
    let processor = PROCESSOR.exclusive_access();
    processor.get_current_task_status()
}
pub fn get_current_task_first_time() -> usize {
    let processor = PROCESSOR.exclusive_access();
    processor.get_current_task_first_time()
}
pub fn update_current_task_syscall_times(syscall_id: usize) {
    let mut processor = PROCESSOR.exclusive_access();
    processor.update_current_task_syscall_times(syscall_id);
}
pub fn get_syscall_times() -> [u32; MAX_SYSCALL_NUM] {
    let processor = PROCESSOR.exclusive_access();
    let syscall_times = processor.get_current_task_times();
    let mut res: [u32; MAX_SYSCALL_NUM] = [0; MAX_SYSCALL_NUM];
    let mut index: usize = 0;
    while index < MAX_SYSCALL_NUM {
        res[index] = syscall_times[index];
        index += 1;
    }
    res
}
pub fn current_task_mmap(start: usize, len: usize, port: usize) -> isize {
    let mut processor = PROCESSOR.exclusive_access();
    processor.mmap(start, len, port)
}
pub fn current_task_munmap(start: usize, len: usize) -> isize {
    let mut processor = PROCESSOR.exclusive_access();
    processor.munmap(start, len)
}

pub fn set_task_priority(prio: usize) {
    let mut processor = PROCESSOR.exclusive_access();
    let task = processor.current.as_mut().unwrap();
    let mut task_inner = task.inner_exclusive_access();
    task_inner.task_priority = prio;
}
