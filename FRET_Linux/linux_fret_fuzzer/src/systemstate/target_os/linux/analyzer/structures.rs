use serde::{Deserialize, Serialize, Serializer, Deserializer};
use std::fmt;

// capture point in execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureEvent {
    SchedulerHook,
    SyscallEntry(u64), 
    IrqEntry,
    IrqExit,           
    SyscallExit,
    ExecutionEnd,
    Unknown,
}

impl fmt::Display for CaptureEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaptureEvent::SchedulerHook => write!(f, "Scheduler"),
            CaptureEvent::SyscallEntry(nr) => write!(f, "Syscall_Entry({})", nr),
            CaptureEvent::IrqEntry => write!(f, "IRQ_Entry"),
            CaptureEvent::IrqExit => write!(f, "IRQ_Exit"),
            CaptureEvent::SyscallExit => write!(f, "Syscall_Exit"),
            CaptureEvent::ExecutionEnd => write!(f, "End"),
            CaptureEvent::Unknown => write!(f, "Unknown"),
        }
    }
}

// atomic Basic Block (ABB) Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ABBType {
    UserSpace,
    Syscall(u64),   // Syscall number
    IRQ(u32),       // Hardware IRQ number from GIC IAR register (e.g. 30=timer, 48+=SPI devices)
    ContextSwitch,
}

impl fmt::Display for ABBType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ABBType::UserSpace => write!(f, "UserSpace"),
            ABBType::Syscall(nr) => write!(f, "Syscall({})", nr),
            ABBType::IRQ(nr) => write!(f, "IRQ({})", nr),
            ABBType::ContextSwitch => write!(f, "ContextSwitch"),
        }
    }
}

// atomic Basic Block (ABB) Instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ABB {
    pub start_timestamp: u64,
    pub end_timestamp: u64,
    pub abb_type: ABBType,
    pub pid: u32,
    pub cpu: u32,
}

impl fmt::Display for ABB {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ABB {{ {}, pid: {}, time: {}-{} }}",
            self.abb_type, self.pid, self.start_timestamp, self.end_timestamp
        )
    }
}

// complete system state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxTask {
    pub pid: u32,
    pub comm: String,
    pub state: u64,
    pub parent_pid: u32,
    pub cpu: u32,
}

impl fmt::Display for LinuxTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Task {{ pid: {}, comm: \"{}\", state: 0x{:x} }}",
            self.pid, self.comm, self.state
        )
    }
}

// complete system state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawS32G3SystemState {
    pub timestamp: u64,
    pub capture_point: CaptureEvent,
    pub current_task: Option<LinuxTask>,
    pub current_abb: Option<ABB>, // New field for FRET analysis
}

impl fmt::Display for RawS32G3SystemState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "=== System State @ {} ===", self.capture_point)?;
        writeln!(f, "  Timestamp: {}", self.timestamp)?;
        if let Some(task) = &self.current_task {
            writeln!(f, "  Current Task: {}", task)?;
        }
        if let Some(abb) = &self.current_abb {
            writeln!(f, "  Current ABB: {}", abb)?;
        }
        Ok(())
    }
}

// TaskState removed

