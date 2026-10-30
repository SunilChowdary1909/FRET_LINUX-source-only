use super::{TargetSystem, SystemState, SystemTraceData, TaskControlBlock, ExecInterval, RTOSJob};
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::fmt::Debug;
use libafl_bolts::prelude::{SerdeAny, HasRefCnt};

// Import the ported analyzer logic
// We will need to create a mod.rs in analyzer/ to expose these
pub mod analyzer;
pub mod qemu_module;
pub mod ftrace_module;
 

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct LinuxTask {
    pub pid: u32,
    pub comm: String,
    pub state: u64,
    pub parent_pid: u32,
    pub cpu: u32,
}

impl TaskControlBlock for LinuxTask {
    fn task_name(&self) -> &String {
        &self.comm
    }
    // We shouldn't mutate task name in fuzzing state usually?
    fn task_name_mut(&mut self) -> &mut String {
        &mut self.comm
    }
}
libafl_bolts::impl_serdeany!(LinuxTask);


#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LinuxSystemState {
    pub current_pid: u32,
    pub current_comm: String,
    pub current_task: LinuxTask,  // Store current task directly
    // Add more state as needed (e.g., active tasks map)
    pub tasks: HashMap<u32, LinuxTask>,
}

lazy_static::lazy_static! {
    static ref EMPTY_VEC: Vec<LinuxTask> = Vec::new();
    static ref EMPTY_JOBS: Vec<RTOSJob> = Vec::new();
}

impl Default for LinuxSystemState {
    fn default() -> Self {
        Self {
            current_pid: 0,
            current_comm: String::from("unknown"),
            current_task: LinuxTask { pid: 0, comm: String::from("unknown"), state: 0, parent_pid: 0, cpu: 0 },
            tasks: HashMap::new(),
        }
    }
}

// Custom Hash implementation that excludes the tasks HashMap
impl Hash for LinuxSystemState {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.current_pid.hash(state);
        self.current_comm.hash(state);
        self.current_task.hash(state);
        // Intentionally skip tasks HashMap as it doesn't implement Hash
    }
}

impl SystemState for LinuxSystemState {
    type TCB = LinuxTask;

    fn current_task(&self) -> &Self::TCB {
        &self.current_task
    }
    
    fn current_task_mut(&mut self) -> &mut Self::TCB {
        &mut self.current_task
    }

    fn get_ready_lists(&self) -> &Vec<Self::TCB> {
         &EMPTY_VEC
    }
    
    fn get_delay_list(&self) -> &Vec<Self::TCB> {
         &EMPTY_VEC
    }

    fn print_lists(&self) -> String {
        format!("Current: {} ({})", self.current_comm, self.current_pid)
    }
}
libafl_bolts::impl_serdeany!(LinuxSystemState);


#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LinuxTraceData {
    pub states: Vec<LinuxSystemState>,
    pub jobs: Vec<RTOSJob>,
    pub intervals: Vec<ExecInterval>,
    pub mem_reads: Vec<Vec<(libafl_qemu::GuestAddr, u8)>>,
    pub states_map: HashMap<u64, LinuxSystemState>,
    ref_cnt: isize,
}

impl HasRefCnt for LinuxTraceData {
    fn refcnt(&self) -> isize {
        self.ref_cnt
    }
    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.ref_cnt
    }
}

impl SystemTraceData for LinuxTraceData {
    type State = LinuxSystemState;

    fn states(&self) -> Vec<&Self::State> {
        self.states.iter().collect()
    }
    fn states_map(&self) -> &HashMap<u64, Self::State> {
        &self.states_map
    }
    fn intervals(&self) -> &Vec<ExecInterval> {
        &self.intervals
    }
    fn mem_reads(&self) -> &Vec<Vec<(libafl_qemu::GuestAddr, u8)>> {
        &self.mem_reads
    }
    fn jobs(&self) -> &Vec<RTOSJob> {
        &self.jobs
    }
    fn trace_length(&self) -> usize {
        self.states.len()
    }
    fn need_to_debug(&self) -> bool {
        false
    }
}
libafl_bolts::impl_serdeany!(LinuxTraceData);


#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct LinuxSystem {
}

impl TargetSystem for LinuxSystem {
    type State = LinuxSystemState;
    type TCB = LinuxTask;
    type TraceData = LinuxTraceData;
}
libafl_bolts::impl_serdeany!(LinuxSystem);
