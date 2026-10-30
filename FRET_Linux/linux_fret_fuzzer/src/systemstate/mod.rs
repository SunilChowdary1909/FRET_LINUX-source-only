//! systemstate referes to the State of a FreeRTOS fuzzing target
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use hashbrown::HashSet;
use libafl_bolts::HasRefCnt;
use libafl_qemu::GuestAddr;
use std::hash::Hasher;
use std::hash::Hash;
use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use itertools::Itertools;
use std::borrow::Cow;

pub mod helpers;
pub mod feedbacks;
pub mod schedulers;
pub mod stg;
pub mod mutational;
pub mod report;
pub mod target_os;  

//============================= Struct definitions

#[derive(Debug, Default, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CaptureEvent {
    APIStart, /// src,dst
    APIEnd, /// src,dst
    ISRStart, /// _,dst
    ISREnd, /// src,_
    End, /// src,_
    #[default]
    Undefined,
}

/*
    Hierarchy of tracing data:
    - RawFreeRTOSSystemState: Raw data from Qemu, represents a particular instant
        - ReducedFreeRTOSSystemState: Generalized state of the system, without execution context
    - ExecInterval: Some interval of execution between instants
        - AtomicBasicBlock: A single-entry multiple-exit region between api calls. May be used referenced in multiple intervals.
    - RTOSJob: A single execution of a task, records the place and input read
        - RTOSTask: Generalized Job instance, records the worst inputs seen so far
*/

// ============================= Interval info

// #[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
// pub enum ExecLevel {
//     APP = 0,
//     API = 1,
//     ISR = 2,
// }

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub struct ExecInterval {
    pub start_tick: u64,
    pub end_tick: u64,
    // hash of the start state
    pub start_state: u64,
    // hash of the end state
    pub end_state: u64,
    // the event that started this interval
    pub start_capture: (CaptureEvent, Cow<'static, str>),
    // the event that ended this interval
    pub end_capture: (CaptureEvent, Cow<'static, str>),
    // execution level: 0 = APP, 1 = API, 2 = ISR
    pub level: u8,
    // tick_spend_preempted: u64,
    pub abb: Option<AtomicBasicBlock>
}

impl ExecInterval {
    pub fn get_exec_time(&self) -> u64 {
        (self.end_tick - self.start_tick) // TODO: subtract tick_spend_preempted when preemption tracking is enabled
    }
    pub fn is_valid(&self) -> bool {
        self.start_tick != 0 || self.end_tick != 0
    }
    pub fn invaildate(&mut self) {
        self.start_tick = 0;
        self.end_tick = 0;
    }

    // attach this interval to the later one, keep a record of the time spend preempted
    // pub fn try_unite_with_later_interval(&mut self, later_interval : &mut Self) -> bool {
    //     if self.end_state!=later_interval.start_state || self.abb!=later_interval.abb || !self.is_valid() || !later_interval.is_valid() {
    //         return false;
    //     }
    //     // assert_eq!(self.end_state, later_interval.start_state);
    //     // assert_eq!(self.abb, later_interval.abb);
    //     later_interval.tick_spend_preempted += self.tick_spend_preempted + (later_interval.start_tick-self.end_tick);
    //     later_interval.start_tick = self.start_tick;
    //     later_interval.start_state = self.start_state;
    //     self.invaildate();
    //     return true;
    // }

    pub fn get_hash_index(&self) -> (u64, u64) {
        return (self.start_state, self.abb.as_ref().expect("ABB not set").get_hash())
    }

    pub fn get_task_name(&self) -> Option<Cow<'static, str>> {
        self.abb.as_ref().map(|x| x.instance_name.clone()).flatten()
    }
    pub fn get_task_name_unchecked(&self) -> Cow<'static, str> {
        self.get_task_name().unwrap_or_else(|| Cow::Owned("unknown".to_owned()))
    }

    pub fn is_abb_end(&self) -> bool {
        match self.end_capture.0 {
            CaptureEvent::APIStart | CaptureEvent::APIEnd | CaptureEvent::ISREnd | CaptureEvent::End => true,
            _ => false
        }
    }
}

// ============================= Atomic Basic Block

// a single-entry multiple-exit region between api calls. May be used referenced in multiple intervals
#[derive(Default, Serialize, Deserialize, Clone)]
pub struct AtomicBasicBlock {
    pub start: GuestAddr,
    pub ends: HashSet<GuestAddr>,
    pub level: u8,
    pub instance_id: usize,
    pub instance_name: Option<Cow<'static, str>>,
}

impl PartialEq for AtomicBasicBlock {
    fn eq(&self, other: &Self) -> bool {
        self.start == other.start && self.ends == other.ends && self.level == other.level && self.instance_name == other.instance_name
    }
}

impl Eq for AtomicBasicBlock {}

impl Hash for AtomicBasicBlock {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use a combination of the start address and the set of ending addresses to compute the hash value
        self.start.hash(state);
        let mut keys : Vec<_> = self.ends.iter().collect();
        keys.sort();
        self.level.hash(state);
        self.instance_name.hash(state);
        keys.hash(state);
    }
}

impl fmt::Display for AtomicBasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ends_str = String::new();
        for end in &self.ends {
            ends_str.push_str(&format!("0x{:#x}, ", end));
        }
        write!(f, "ABB {} {{ level: {}, start: 0x{:#x}, ends: [{}]}}", &self.instance_name.as_ref().unwrap_or(&Cow::Owned("".to_owned())), self.level, self.start, ends_str.trim().trim_matches(','))
    }
}
impl fmt::Debug for AtomicBasicBlock {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut ends_str = String::new();
        for end in &self.ends {
            ends_str.push_str(&format!("{:#x}, ", end));
        }
        write!(f, "ABB {} {{ level: {}, start: 0x{:#x}, ends: [{}]}}", &self.instance_name.as_ref().unwrap_or(&Cow::Owned("".to_owned())), self.level, self.start, ends_str.trim().trim_matches(','))
    }
}

impl PartialOrd for AtomicBasicBlock {
    fn partial_cmp(&self, other: &AtomicBasicBlock) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AtomicBasicBlock {
    fn cmp(&self, other: &AtomicBasicBlock) -> std::cmp::Ordering {
        if self.start.cmp(&other.start) == std::cmp::Ordering::Equal {
            if self.level.cmp(&other.level) != std::cmp::Ordering::Equal {
                return self.level.cmp(&other.level);
            }
            // If the start addresses are equal, compare by 'ends'
            let end1 = if self.ends.len() == 1 { *self.ends.iter().next().unwrap() as u64 } else {
                let mut temp = self.ends.iter().collect::<Vec<_>>().into_iter().collect::<Vec<&GuestAddr>>();
                temp.sort_unstable();
                let mut h = DefaultHasher::new();
                temp.hash(&mut h);
                h.finish()
            };
            let end2 = if other.ends.len() == 1 { *self.ends.iter().next().unwrap() as u64 } else {
                let mut temp = other.ends.iter().collect::<Vec<_>>().into_iter().collect::<Vec<&GuestAddr>>();
                temp.sort_unstable();
                let mut h = DefaultHasher::new();
                temp.hash(&mut h);
                h.finish()
            };
            end1.cmp(&end2)
        } else {
            // If the start addresses are not equal, compare by 'start'
            self.start.cmp(&other.start)
        }
    }
}

impl AtomicBasicBlock {
    pub fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.hash(&mut s);
        s.finish()
    }

    pub fn instance_eq(&self, other: &Self) -> bool {
        self == other && self.instance_id == other.instance_id
    }

    pub fn get_start(&self) -> GuestAddr {
        self.start
    }
}



libafl_bolts::impl_serdeany!(AtomicBasicBlock);

// ============================= Job instances

// represents a single execution of a task, recording the place and input read
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RTOSJob {
    pub name: String,
    pub mem_reads: Vec<(GuestAddr, u8)>,
    pub release: u64,
    pub response: u64,
    pub exec_ticks: u64,
    pub ticks_per_abb: Vec<u64>,
    pub abbs: Vec<AtomicBasicBlock>,
    hash_cache: u64
}

impl PartialEq for RTOSJob {
    fn eq(&self, other: &Self) -> bool {
        self.abbs == other.abbs
    }
}
impl Eq for RTOSJob {}
impl Hash for RTOSJob {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.abbs.hash(state);
    }
}
impl RTOSJob {
    pub fn get_hash(&mut self) -> u64 {
        if self.hash_cache == 0 {
            let mut s = DefaultHasher::new();
            self.hash(&mut s);
            self.hash_cache = s.finish();
        }
        self.hash_cache
    }
    pub fn get_hash_cached(&self) -> u64 {
        if self.hash_cache == 0 {
            let mut s = DefaultHasher::new();
            self.hash(&mut s);
            s.finish()
        } else {
            self.hash_cache
        }
    }
    pub fn response_time(&self) -> u64 {
        self.response-self.release
    }
}

// ============================= Generalized job instances

#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct RTOSTask {
    pub name: String,
    pub woet_bytes: Vec<u8>,
    pub woet_ticks: u64,
    pub woet_per_abb: Vec<u64>,
    pub abbs: Vec<AtomicBasicBlock>,
    pub wort_ticks: u64,
    hash_cache: u64
}

impl PartialEq for RTOSTask {
    fn eq(&self, other: &Self) -> bool {
        self.abbs == other.abbs
    }
}
impl Eq for RTOSTask {}
impl Hash for RTOSTask {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.abbs.hash(state); 
    }
}
impl RTOSTask {
    // returns the hash value for the task, computing it if not cached
    pub fn get_hash(&mut self) -> u64 {
        if self.hash_cache == 0 {
            let mut s = DefaultHasher::new();
            self.hash(&mut s);
            self.hash_cache = s.finish();
        }
        self.hash_cache
    }
    // returns the cached hash value for the task
    pub fn get_hash_cached(&self) -> u64 {
        if self.hash_cache == 0 {
            let mut s = DefaultHasher::new();
            self.hash(&mut s);
            s.finish()
        } else {
            self.hash_cache
        }
    }
    // update WOET (time, inputs) and WORT (time only) if the new instance is better
    pub fn try_update(&mut self, other: &RTOSJob) -> bool {
        assert_eq!(self.get_hash(), other.get_hash_cached());
        let mut ret = false;
        if other.exec_ticks > self.woet_ticks {
            self.woet_ticks = other.exec_ticks;
            self.woet_per_abb = other.ticks_per_abb.clone();
            self.woet_bytes = other.mem_reads.iter().sorted_by(|a,b| a.0.cmp(&b.0)).map(|x| x.1).collect();
            ret |= true;
        }
        if other.response_time() > self.wort_ticks {
            self.wort_ticks = other.response_time();
            ret |= true;
        }
        ret
    }
    // creates a RTOSTask instance from a given RTOSJob instance
    pub fn from_instance(input: &RTOSJob) -> Self {
        let c = input.get_hash_cached();
        Self {
            name: input.name.clone(),
            woet_bytes: input.mem_reads.iter().map(|x| x.1.clone()).collect(),
            woet_ticks: input.exec_ticks,
            woet_per_abb: input.ticks_per_abb.clone(),
            abbs: input.abbs.clone(),
            wort_ticks: input.response_time(),
            hash_cache: c
        }
    }
    // maps bytes onto a given RTOSJob instance, returning the differences
    pub fn map_bytes_onto(&self, input: &RTOSJob, offset: Option<GuestAddr>) -> Vec<(GuestAddr, u8)> {
        if input.mem_reads.len() == 0 {
            return vec![];
        }
        let ret = input
            .mem_reads
            .iter()
            .take(self.woet_bytes.len())
            .enumerate()
            .filter_map(|(idx, (addr, oldbyte))| {
                if self.woet_bytes[idx] != *oldbyte {
                    Some((*addr - offset.unwrap_or_default(), self.woet_bytes[idx]))
                } else {
                    None
                }
            })
            .collect();
        // eprintln!("Mapped: {:?}", ret);
        ret
    }
}


// ============================= Per testcase metadata
