
use hashbrown::HashSet;
use libafl::inputs::Input;
// feedbacks organizing SystemStates as a graph
use libafl_bolts::prelude::SerdeAny;
use libafl_bolts::ownedref::OwnedMutSlice;
use log::Metadata;
use petgraph::graph::EdgeIndex;
use libafl::prelude::UsesInput;
use libafl::common::HasNamedMetadata;
use libafl::state::UsesState;
use libafl::prelude::State;
use libafl::schedulers::MinimizerScheduler;
use libafl_bolts::HasRefCnt;
use serde::de::DeserializeOwned;
use std::path::PathBuf;
use libafl::corpus::Testcase;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::hash::Hash;
use libafl::events::EventFirer;
use libafl::state::MaybeHasClientPerfMonitor;
use libafl::feedbacks::Feedback;
use libafl_bolts::Named;
use libafl_bolts::tuples::MatchName;
use libafl::Error;
use hashbrown::HashMap;
use libafl::{executors::ExitKind, observers::ObserversTuple, common::HasMetadata};
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use super::helpers::metadata_insert_or_update_get;
use super::target_os::SystemState;
use super::AtomicBasicBlock;
use super::CaptureEvent;
use super::ExecInterval;
use super::RTOSJob;
use super::RTOSTask;
use petgraph::prelude::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::Direction;

use crate::time::clock::QemuClockObserver;
use crate::time::clock::FUZZ_START_TIMESTAMP;
use crate::time::worst::MaxTimeFavFactor;
use std::time::SystemTime;
use std::{fs::OpenOptions, io::Write};
use std::borrow::Cow;
use std::ops::Deref;
use std::ops::DerefMut;
use std::rc::Rc;
use petgraph::visit::EdgeRef;
use crate::systemstate::target_os::*;

use libafl::prelude::StateInitializer;

//============================= Data Structures
#[derive(Serialize, Deserialize, Clone, Debug, Default, Hash)]
#[serde(bound = "SYS: Serialize, for<'de2> SYS: Deserialize<'de2>")]
pub struct STGNode<SYS>
where
    SYS: TargetSystem,
    for<'de2> SYS: Deserialize<'de2>,
{
    //base: SYS::State,
    state: u64,
    abb: AtomicBasicBlock,
    _phantom: PhantomData<SYS>
}
impl<SYS> STGNode<SYS>
where SYS: TargetSystem {
    pub fn _pretty_print(&self, map: &HashMap<u64, SYS::State>) -> String {
        format!("{}\nl{} {:x}-{:x}\n{}", map[&self.state].current_task().task_name(), self.abb.level, self.abb.start, self.abb.ends.iter().next().unwrap_or_else(||&0xFFFF), map[&self.state].print_lists())
    }
    pub fn color_print(&self, map: &HashMap<u64, SYS::State>) -> String {
        let color = match self.abb.level {
            1 => "\", shape=box, style=filled, fillcolor=\"lightblue",
            2 => "\", shape=box, style=filled, fillcolor=\"yellow",
            0 => "\", shape=box, style=filled, fillcolor=\"white",
            _ => "\", style=filled, fillcolor=\"lightgray",
        };
        let message = match self.abb.level {
            1 => format!("API Call"),
            2 => format!("ISR"),
            0 => format!("Task: {}",map[&self.state].current_task().task_name()),
            _ => format!(""),
        };
        let mut label = format!("{}\nABB: {:x}-{:x}\nHash:{:X}\n{}", message, self.abb.start, self.abb.ends.iter().next().unwrap_or_else(||&0xFFFF), self.state>>48, map[&self.state].print_lists());
        label.push_str(color);
        label
    }
    fn get_hash(&self) -> u64 {
        let mut s = DefaultHasher::new();
        self.state.hash(&mut s);
        self.abb.hash(&mut s);
        s.finish()
    }
}
impl<SYS> PartialEq for STGNode<SYS> 
where
    SYS: TargetSystem,
{
    fn eq(&self, other: &STGNode<SYS>) -> bool {
        self.state==other.state
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct STGEdge
{
    pub event: CaptureEvent,
    pub name: Cow<'static, str>,
    pub worst: Option<(u64, Vec<(libafl_qemu::GuestAddr, u8)>)>,
}

impl STGEdge {
    pub fn _pretty_print(&self) -> String {
        let mut short = match self.event {
            CaptureEvent::APIStart => "Call: ",
            CaptureEvent::APIEnd => "Ret: ",
            CaptureEvent::ISRStart => "Int: ",
            CaptureEvent::ISREnd => "IRet: ",
            CaptureEvent::End => "End: ",
            CaptureEvent::Undefined => "",
        }.to_string();
        short.push_str(&self.name);
        short
    }
    pub fn color_print(&self) -> String {
        let mut short = self.name.to_string();
        short.push_str(match self.event {
            CaptureEvent::APIStart => "\", color=\"blue",
            CaptureEvent::APIEnd => "\", color=\"black",
            CaptureEvent::ISRStart => "\", color=red, style=\"dashed",
            CaptureEvent::ISREnd => "\", color=red, style=\"solid",
            CaptureEvent::End => "",
            CaptureEvent::Undefined => "",
        });
        short
    }
    pub fn is_abb_end(&self) -> bool {
        match self.event {
            CaptureEvent::APIStart | CaptureEvent::APIEnd | CaptureEvent::ISREnd | CaptureEvent::End => true,
            _ => false
        }
    }
}

impl Hash for STGEdge {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.event.hash(state);
        self.name.hash(state);
    }
}

// shared Metadata for a systemstateFeedback
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(bound = "SYS: Serialize, for<'de2> SYS: Deserialize<'de2>")]
pub struct STGFeedbackState<SYS>
where 
    SYS: TargetSystem,
    for<'de2> SYS: Deserialize<'de2>,
{
    name: Cow<'static, str>,
    // aggregated traces as a graph
    pub graph: DiGraph<STGNode<SYS>, STGEdge>,
    pub systemstate_index: HashMap<u64, SYS::State>,
    pub state_abb_hash_index: HashMap<(u64, u64), NodeIndex>,
    stgnode_index: HashMap<u64, NodeIndex>,
    entrypoint: NodeIndex,
    exitpoint: NodeIndex,
    // Metadata about aggregated traces. aggegated meaning, order has been removed
    wort: u64,
    wort_per_aggegated_path: HashMap<Vec<AtomicBasicBlock>,u64>,
    wort_per_abb_path: HashMap<u64,u64>,
    wort_per_stg_path: HashMap<u64,u64>,
    worst_abb_exec_count: HashMap<AtomicBasicBlock, usize>,
    // Metadata about job instances
    pub worst_task_jobs: HashMap<u64, RTOSTask>,
    pub worst_task_crpd_ticks: HashMap<u64, u64>,
}

libafl_bolts::impl_serdeany!(STGFeedbackState<SYS: SerdeAny+TargetSystem>);

impl<SYS> Default for STGFeedbackState<SYS>
where 
    SYS: TargetSystem,
    for<'de2> SYS: Deserialize<'de2>,
{
    fn default() -> STGFeedbackState<SYS> {
        let mut graph = DiGraph::new();
        let mut entry_state = SYS::State::default();
        let mut exit_state = SYS::State::default();
        *(entry_state.current_task_mut().task_name_mut())="Start".to_string();
        *(exit_state.current_task_mut().task_name_mut())="End".to_string();
        let mut entry : STGNode<SYS> = STGNode::default();
        let mut exit : STGNode<SYS> = STGNode::default();
        entry.state=compute_hash(&entry_state);
        exit.state=compute_hash(&exit_state);
        

        let systemstate_index = HashMap::from([(entry.state, entry_state), (exit.state, exit_state)]);

        let h_entry = entry.get_hash();
        let h_exit = exit.get_hash();

        let entrypoint = graph.add_node(entry.clone());
        let exitpoint = graph.add_node(exit.clone());

        let state_abb_hash_index = HashMap::from([((entry.state, entry.abb.get_hash()), entrypoint), ((exit.state, exit.abb.get_hash()), exitpoint)]);

        let index = HashMap::from([(h_entry, entrypoint), (h_exit, exitpoint)]);

        STGFeedbackState {
            name: Cow::from("stgfeedbackstate".to_string()),
            graph,
            stgnode_index: index,
            entrypoint,
            exitpoint,
            wort: 0,
            wort_per_aggegated_path: HashMap::new(),
            wort_per_abb_path: HashMap::new(),
            wort_per_stg_path: HashMap::new(),
            worst_abb_exec_count: HashMap::new(),
            systemstate_index,
            state_abb_hash_index,
            worst_task_jobs: HashMap::new(),
            worst_task_crpd_ticks: HashMap::new(),
        }
    }
}

impl<SYS> Named for STGFeedbackState<SYS>
where 
    SYS: TargetSystem,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

// Wrapper around Vec<RefinedFreeRTOSSystemState> to attach as Metadata
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct STGNodeMetadata {
    nodes: Vec<NodeIndex>,
    edges: Vec<EdgeIndex>,
    abbs: u64,
    aggregate: u64,
    top_abb_counts: Vec<u64>,
    intervals: Vec<ExecInterval>,
    jobs: Vec<RTOSJob>,
    indices: Vec<usize>,
    tcref: isize,
}
impl STGNodeMetadata {
    pub fn new(nodes: Vec<NodeIndex>, edges: Vec<EdgeIndex>, abb_trace: Vec<AtomicBasicBlock>, abbs_pathhash: u64, aggregate: u64, top_abb_counts: Vec<u64>, intervals: Vec<ExecInterval>, jobs: Vec<RTOSJob>) -> Self {
        #[allow(unused)]
        let mut indices : Vec<_> = vec![];
        #[cfg(feature = "sched_stg_edge")]
        {
            indices = edges.iter().map(|x| x.index()).collect();
            indices.sort_unstable();
            indices.dedup();
        }
        #[cfg(feature = "sched_stg_pathhash")]
        {
            indices.push(get_generic_hash(&edges) as usize);
        }
        #[cfg(feature = "sched_stg_abbhash")]
        {
            indices.push(abbs_pathhash as usize);
        }
        #[cfg(feature = "sched_stg_aggregatehash")]
        {
            // indices.push(aggregate as usize);
            indices = top_abb_counts.iter().map(|x| (*x) as usize).collect();
        }
        Self {indices, intervals, jobs, nodes, abbs: abbs_pathhash, aggregate, top_abb_counts, edges, tcref: 0}
    }

    pub fn nodes(&self) -> &Vec<NodeIndex> {
        &self.nodes
    }

    pub fn edges(&self) -> &Vec<EdgeIndex> {
        &self.edges
    }

    pub fn abbs(&self) -> u64 {
        self.abbs
    }

    pub fn aggregate(&self) -> u64 {
        self.aggregate
    }

    pub fn top_abb_counts(&self) -> &Vec<u64> {
        &self.top_abb_counts
    }

    pub fn intervals(&self) -> &Vec<ExecInterval> {
        &self.intervals
    }

    pub fn jobs(&self) -> &Vec<RTOSJob> {
        &self.jobs
    }
}

impl Deref for STGNodeMetadata {
    type Target = [usize];
    // convert to a slice
    fn deref(&self) -> &[usize] {
        &self.indices
    }
}

impl DerefMut for STGNodeMetadata {
    // convert to a slice
    fn deref_mut(&mut self) -> &mut [usize] {
        &mut self.indices
    }
}

impl HasRefCnt for STGNodeMetadata {
    fn refcnt(&self) -> isize {
        self.tcref
    }

    fn refcnt_mut(&mut self) -> &mut isize {
        &mut self.tcref
    }
}

libafl_bolts::impl_serdeany!(STGNodeMetadata);

pub type GraphMaximizerCorpusScheduler<CS, O> =
    MinimizerScheduler<CS, MaxTimeFavFactor,STGNodeMetadata,O>;

// AI generated, human verified
// count the occurrences of each element in a vector, assumes the vector is sorted
fn count_occurrences_sorted<T>(vec: &Vec<T>) -> HashMap<&T, usize>
where
    T: PartialEq + Eq + Hash + Clone,
{
    let mut counts = HashMap::new();
    
    if vec.is_empty() {
        return counts;
    }
    
    let mut current_obj = &vec[0];
    let mut current_count = 1;
    
    for obj in vec.iter().skip(1) {
        if obj == current_obj {
            current_count += 1;
        } else {
            counts.insert(current_obj, current_count);
            current_obj = obj;
            current_count = 1;
        }
    }
    
    // Insert the count of the last object
    counts.insert(current_obj, current_count);
    
    counts
}

//============================= Graph Feedback

pub const STG_MAP_SIZE: usize = 1<<20;
pub static mut STG_MAP: [u16; STG_MAP_SIZE] = [0; STG_MAP_SIZE];
pub static mut MAX_STG_NUM: usize = 0;
pub unsafe fn stg_map_mut_slice<'a>() -> OwnedMutSlice<'a, u16> {
    OwnedMutSlice::from_raw_parts_mut(STG_MAP.as_mut_ptr(), STG_MAP.len())
}

// a Feedback reporting novel System-State Transitions. Depends on [`QemuSystemStateObserver`]
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(bound = "SYS: Serialize, for<'de2> SYS: Deserialize<'de2>")]
pub struct StgFeedback<SYS>
where 
    SYS: TargetSystem,
    for<'de2> SYS: Deserialize<'de2>,
{
    name: Cow<'static, str>,
    last_node_trace: Option<Vec<NodeIndex>>,
    last_edge_trace: Option<Vec<EdgeIndex>>,
    last_intervals: Option<Vec<ExecInterval>>,
    last_abb_trace: Option<Vec<AtomicBasicBlock>>,
    last_abbs_hash: Option<u64>,    // only set, if it was interesting
    last_aggregate_hash: Option<u64>, // only set, if it was interesting
    last_top_abb_hashes: Option<Vec<u64>>, // only set, if it was interesting
    last_job_trace: Option<Vec<RTOSJob>>, // only set, if it was interesting
    dump_path: Option<PathBuf>,
    select_task: Option<String>,
    _phantom_data: PhantomData<SYS>,
}
#[cfg(feature = "feed_stg")]
const INTEREST_EDGE : bool = true;
#[cfg(feature = "feed_stg_abb_woet")]
const INTEREST_EDGE_WEIGHT : bool = true;
#[cfg(feature = "feed_stg")]
const INTEREST_NODE : bool = true;
#[cfg(feature = "feed_stg_pathhash")]
const INTEREST_PATH : bool = true;
#[cfg(feature = "feed_stg_abbhash")]
const INTEREST_ABBPATH : bool = true;
#[cfg(feature = "feed_stg_aggregatehash")]
const INTEREST_AGGREGATE : bool = true;
#[cfg(feature = "feed_job_wort")]
pub const INTEREST_JOB_RT : bool = true;
#[cfg(feature = "feed_job_woet")]
pub const INTEREST_JOB_ET : bool = true;
#[cfg(feature = "feed_job_crpd")]
pub const INTEREST_JOB_CRPD : bool = true;

#[cfg(not(feature = "feed_stg"))]
const INTEREST_EDGE : bool = false;
#[cfg(not(feature = "feed_stg_abb_woet"))]
const INTEREST_EDGE_WEIGHT : bool = false;
#[cfg(not(feature = "feed_stg"))]
const INTEREST_NODE : bool = false;
#[cfg(not(feature = "feed_stg_pathhash"))]
const INTEREST_PATH : bool = false;
#[cfg(not(feature = "feed_stg_abbhash"))]
const INTEREST_ABBPATH : bool = false;
#[cfg(not(feature = "feed_stg_aggregatehash"))]
const INTEREST_AGGREGATE : bool = false;
#[cfg(not(feature = "feed_job_wort"))]
pub const INTEREST_JOB_RT : bool = false;
#[cfg(not(feature = "feed_job_woet"))]
pub const INTEREST_JOB_ET : bool = false;
#[cfg(not(feature = "feed_job_crpd"))]
pub const INTEREST_JOB_CRPD : bool = false;

fn set_observer_map(trace : &Vec<EdgeIndex>) {
    // dbg!(trace);
    unsafe {
        for i in 0..MAX_STG_NUM {
            STG_MAP[i] = 0;
        }
        for i in trace {
            if MAX_STG_NUM < i.index() {
                MAX_STG_NUM = i.index();
            }
            STG_MAP[i.index()] = STG_MAP[i.index()].saturating_add(1);
        }
    }
}

fn get_generic_hash<H>(input: &H) -> u64
    where
        H: Hash,
{
    let mut s = DefaultHasher::new();
    input.hash(&mut s);
    s.finish()
}

#[cfg(feature = "trace_job_response_times")]
fn estimate_job_crpd_ticks(job: &RTOSJob) -> u64 {
    const CRPD_ALPHA_NUM: u64 = 1;
    const CRPD_ALPHA_DEN: u64 = 4;
    const CRPD_BASE_RELOAD_TICKS: u64 = 256;

    let response_time = job.response_time();
    let preemption_time = response_time.saturating_sub(job.exec_ticks);
    if preemption_time == 0 {
        return 0;
    }

    let proportional = preemption_time.saturating_mul(CRPD_ALPHA_NUM) / CRPD_ALPHA_DEN;
    let capacity_bound = job.exec_ticks / 3 + CRPD_BASE_RELOAD_TICKS;

    proportional
        .saturating_add(CRPD_BASE_RELOAD_TICKS)
        .min(preemption_time)
        .min(capacity_bound)
}

// takes: trace of intervals
// returns: hashmap of abb instance id to (execution time, memory accesses)
fn execinterval_to_abb_instances(trace: &Vec<ExecInterval>, read_trace: &Vec<Vec<(libafl_qemu::GuestAddr, u8)>>) -> HashMap<usize, (u64, Vec<(libafl_qemu::GuestAddr, u8)>)>{
    let mut instance_time: HashMap<usize, (u64, Vec<(libafl_qemu::GuestAddr, u8)>)> = HashMap::new();
    let empty_reads: Vec<(libafl_qemu::GuestAddr, u8)> = Vec::new();
    for (_i,interval) in trace.iter().enumerate() { // Iterate intervals
        // sum up execution time and accesses per ABB
        let reads = read_trace.get(_i).unwrap_or(&empty_reads);
        let temp = interval.abb.as_ref().map(|abb| abb.instance_id).unwrap_or(usize::MAX);
        match instance_time.get_mut(&temp) {
            Some(x) => {
                x.0 += interval.get_exec_time();
                x.1.extend(reads.clone());
            },
            None => {
                if temp != usize::MAX {
                    instance_time.insert(temp, (interval.get_exec_time(), reads.clone()));
                }
            }
        };
    }
    return instance_time;
}

impl<SYS> StgFeedback<SYS>
where 
    SYS: TargetSystem,
{
    pub fn new(select_task: Option<String>, dump_name: Option<PathBuf>) -> Self {
        // Self {name: String::from("STGFeedback"), last_node_trace: None, last_edge_trace: None, last_intervals: None }
        let mut s = Self::default();
        unsafe{libafl_bolts::prelude::RegistryBuilder::register::<STGFeedbackState<SYS>>()};
        s.dump_path = dump_name.map(|x| x.with_extension("stgsize"));
        s.select_task = select_task;
        s
    }

    // params:
    // tarce of intervals
    // hashtable of states
    // feedbackstate
    // produces:
    // tarce of node indexes representing the path trough the graph
    // newly discovered node?
    // side effect:
    // the graph gets new nodes and edge
    fn update_stg_interval(trace: &Vec<ExecInterval>, read_trace: &Vec<Vec<(libafl_qemu::GuestAddr, u8)>>, table: &HashMap<u64, SYS::State>, fbs: &mut STGFeedbackState<SYS>) -> (Vec<(NodeIndex, u64)>, Vec<(EdgeIndex, u64)>, bool, bool) {
        let mut return_node_trace = vec![(fbs.entrypoint, 0)]; // Assuming entrypoint timestamp is 0
        let mut return_edge_trace = vec![];
        let mut interesting = false;
        let mut updated = false;
        if trace.is_empty() {
            return (return_node_trace, return_edge_trace, interesting, updated);
        }
        let mut instance_time = execinterval_to_abb_instances(trace, read_trace);
        // add all missing state+abb combinations to the graph
        for (_i,interval) in trace.iter().enumerate() { // Iterate intervals
            let start_s = table[&interval.start_state].clone();
            let start_h = compute_hash(&start_s);
            fbs.systemstate_index.insert(start_h, start_s);


            let node : STGNode<SYS> = STGNode {state: start_h, abb: interval.abb.as_ref().unwrap().clone(), _phantom: PhantomData};
            let h_node = node.get_hash();
            let next_idx = if let Some(idx) = fbs.stgnode_index.get(&h_node) {
                // already present
                *idx
            } else {
                // not present
                let h = (start_h, node.abb.get_hash());
                let idx = fbs.graph.add_node(node);
                fbs.stgnode_index.insert(h_node, idx);
                fbs.state_abb_hash_index.insert(h, idx);
                interesting |= INTEREST_NODE;
                updated = true;
                idx
            };
            // connect in graph if edge not present
            let e = fbs.graph.edges_directed(return_node_trace[return_node_trace.len()-1].0, Direction::Outgoing).find(|x| petgraph::visit::EdgeRef::target(x) == next_idx);
            if let Some(e_) = e {
                return_edge_trace.push((petgraph::visit::EdgeRef::id(&e_), interval.start_tick));
                if let Some((time, accesses)) = instance_time.get_mut(&interval.abb.as_ref().unwrap().instance_id) {
                    let ref_ = &mut fbs.graph.edge_weight_mut(e_.id()).unwrap().worst;
                    if ref_.is_some() {
                        let w = ref_.as_mut().unwrap();
                        if w.0 < *time {
                            *w = (*time, accesses.clone());
                            interesting |= INTEREST_EDGE_WEIGHT;
                        };
                    } else {
                        *ref_ = Some((*time, accesses.clone()));
                    }
                }
            } else {
                let mut e__ = STGEdge{event: interval.start_capture.0, name: interval.start_capture.1.clone(), worst: None};
                if e__.is_abb_end() {
                    if let Some((time,accesses)) = instance_time.get_mut(&interval.abb.as_ref().unwrap().instance_id) {
                        e__.worst = Some((*time, accesses.clone()));
                    }
                }
                let e_ = fbs.graph.add_edge(return_node_trace[return_node_trace.len()-1].0, next_idx, e__);
                return_edge_trace.push((e_, interval.start_tick));
                interesting |= INTEREST_EDGE;
                updated = true;
            }
            return_node_trace.push((next_idx, interval.start_tick));
        }
        // every path terminates at the end
        if !fbs.graph.neighbors_directed(return_node_trace[return_node_trace.len()-1].0, Direction::Outgoing).any(|x| x == fbs.exitpoint) {
            let mut e__ = STGEdge { event: CaptureEvent::End, name: Cow::Borrowed("End"), worst: None };
            if let Some((time, accesses)) = instance_time.get_mut(&trace[trace.len()-1].abb.as_ref().unwrap().instance_id) {
                e__.worst = Some((*time, accesses.clone()));
            }
            let e_ = fbs.graph.add_edge(return_node_trace[return_node_trace.len()-1].0, fbs.exitpoint, e__);
            return_edge_trace.push((e_, trace[trace.len()-1].start_tick));
            interesting |= INTEREST_EDGE;
            updated = true;
        }
        return_node_trace.push((fbs.exitpoint, trace[trace.len()-1].start_tick));
        (return_node_trace, return_edge_trace, interesting, updated)
    }

    fn abbs_in_exec_order(trace: &Vec<ExecInterval>) -> Vec<AtomicBasicBlock> {
        let mut ret = Vec::new();
        for i in 0..trace.len() {
            if trace[i].abb != None &&
            (trace[i].end_capture.0 == CaptureEvent::APIStart || trace[i].end_capture.0 == CaptureEvent::APIEnd || trace[i].end_capture.0 == CaptureEvent::End  || trace[i].end_capture.0 == CaptureEvent::ISREnd) {
                ret.push(trace[i].abb.as_ref().unwrap().clone());
            }
        }
        ret
    }
}

impl<S, SYS> StateInitializer<S> for StgFeedback<SYS>
where 
    SYS: TargetSystem,
{}

impl<EM, I, OT, S, SYS> Feedback<EM, I, OT, S> for StgFeedback<SYS>
where
    S: State + UsesInput + MaybeHasClientPerfMonitor + HasNamedMetadata + HasMetadata,
    S::Input: Default,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
    SYS: TargetSystem,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        <S as UsesInput>::Input: Default,
    {
        // TODO: don't remove metadata. work around ownership issues
        let trace: SYS::TraceData = match state.remove_metadata::<SYS::TraceData>() {
            Some(data) => {
                log::info!("StgFeedback: TraceData found! intervals={} jobs={}", data.intervals().len(), data.jobs().len());
                *data
            },
            None => {
                log::warn!("StgFeedback: TraceData NOT found in state metadata!");
                return Ok(false);
            },
        };
        let clock_observer = observers.match_name::<QemuClockObserver<SYS>>("clocktime")
            .expect("QemuClockObserver not found");
        let last_runtime = clock_observer.last_runtime();

        #[cfg(feature = "trace_job_response_times")]
        let worst_jobs_rt = trace.worst_jobs_per_task_by_response_time();
        #[cfg(feature = "trace_job_response_times")]
        let worst_jobs_et = trace.worst_jobs_per_task_by_exec_time();
        #[cfg(feature = "trace_job_response_times")]
        let worst_select_job = if let Some(t) = self.select_task.as_ref() {worst_jobs_rt.get(t)} else {None};
        #[cfg(feature = "trace_job_response_times")]
        let last_runtime = if let Some(t) = self.select_task.as_ref() {worst_select_job.map_or(0, |x| x.response_time())} else {last_runtime};

        let feedbackstate = state.metadata_map_mut().get_or_insert_with(||{
                STGFeedbackState::<SYS>::default()
            });

        // --------------------------------- Update STG
        let (mut nodetrace, mut edgetrace, mut interesting, mut updated) = StgFeedback::update_stg_interval(trace.intervals(), &trace.mem_reads(), trace.states_map(), feedbackstate);

        #[cfg(feature = "feed_job_wort")]
        // the longest running case is always intersting
        if last_runtime > feedbackstate.wort {
            feedbackstate.wort = last_runtime;
            interesting |= true;
        }

        #[cfg(feature = "trace_job_response_times")]
        if let Some(worst_instance) = worst_select_job {
            edgetrace = edgetrace.into_iter().filter(|x| x.1 <= worst_instance.response && x.1 >= worst_instance.release ).collect();
            nodetrace = nodetrace.into_iter().filter(|x| x.1 <= worst_instance.response && x.1 >= worst_instance.release ).collect();
        } else {
            if self.select_task.is_some() { // if nothing was selected, just take the whole trace, otherwise there is nothing interesting here
                edgetrace = Vec::new();
                nodetrace = Vec::new();
            }
        }

        #[cfg(feature = "feed_stg")]
        set_observer_map(&edgetrace.iter().map(|x| x.0).collect::<Vec<_>>());

        // --------------------------------- Update job instances
        #[cfg(feature = "trace_job_response_times")]
        for i in worst_jobs_rt.iter() {
            interesting |= INTEREST_JOB_RT & if let Some(x) = feedbackstate.worst_task_jobs.get_mut(&i.1.get_hash_cached()) {
                // eprintln!("Job instance already present");
                x.try_update(i.1)
            } else {
                // eprintln!("New Job instance");
                feedbackstate.worst_task_jobs.insert(i.1.get_hash_cached(), RTOSTask::from_instance(&i.1));
                true
            }
        };
        #[cfg(feature = "trace_job_response_times")]
        for i in worst_jobs_et.iter() {
            interesting |= INTEREST_JOB_ET & if let Some(x) = feedbackstate.worst_task_jobs.get_mut(&i.1.get_hash_cached()) {
                x.try_update(i.1)
            } else {
                feedbackstate.worst_task_jobs.insert(i.1.get_hash_cached(), RTOSTask::from_instance(&i.1));
                true
            }
        };
        #[cfg(feature = "trace_job_response_times")]
        for i in worst_jobs_rt.iter() {
            let job_hash = i.1.get_hash_cached();
            let estimated_crpd = estimate_job_crpd_ticks(i.1);
            let improved = if let Some(current) = feedbackstate.worst_task_crpd_ticks.get_mut(&job_hash) {
                if estimated_crpd > *current {
                    *current = estimated_crpd;
                    true
                } else {
                    false
                }
            } else {
                feedbackstate.worst_task_crpd_ticks.insert(job_hash, estimated_crpd);
                true
            };
            interesting |= INTEREST_JOB_CRPD & improved;
        }
        self.last_job_trace = Some(trace.jobs().clone());
        // dbg!(&observer.job_instances);

        {
            let h = get_generic_hash(&edgetrace);
            if let Some(x) = feedbackstate.wort_per_stg_path.get_mut(&h) {
                let t = last_runtime;
                if t > *x {
                    *x = t;
                    interesting |= INTEREST_PATH;
                }
            } else {
                feedbackstate.wort_per_stg_path.insert(h, last_runtime);
                updated = true;
                interesting |= INTEREST_PATH;
            }
        }

        #[cfg(not(feature = "trace_job_response_times"))]
        let tmp = StgFeedback::<SYS>::abbs_in_exec_order(&trace.intervals());
        #[cfg(feature = "trace_job_response_times")]
        let tmp = {
            if let Some(worst_instance) = worst_select_job {
                let t = trace.intervals().iter().filter(|x| x.start_tick < worst_instance.response && x.end_tick > worst_instance.release ).cloned().collect();
                StgFeedback::<SYS>::abbs_in_exec_order(&t)
            } else {
                if self.select_task.is_none() { // if nothing was selected, just take the whole trace, otherwise there is nothing interesting here
                    StgFeedback::<SYS>::abbs_in_exec_order(trace.intervals())
                } else {
                    Vec::new()
                }
            }
        };
        if INTEREST_AGGREGATE || INTEREST_ABBPATH {
            if INTEREST_ABBPATH {
                let h = get_generic_hash(&tmp);
                self.last_abbs_hash = Some(h);
                // order of execution is relevant
                if let Some(x) = feedbackstate.wort_per_abb_path.get_mut(&h) {
                    let t = last_runtime;
                    if t > *x {
                        *x = t;
                        interesting |= INTEREST_ABBPATH;
                    }
                } else {
                    feedbackstate.wort_per_abb_path.insert(h, last_runtime);
                    interesting |= INTEREST_ABBPATH;
                }
            }
            if INTEREST_AGGREGATE {
                // aggegation by sorting, order of states is not relevant
                let mut _tmp = tmp.clone();
                _tmp.sort();    // use sort+count, because we need the sorted trace anyways
                let counts = count_occurrences_sorted(&_tmp);
                let mut top_indices = Vec::new();
                if last_runtime >= feedbackstate.wort {
                    top_indices.push(u64::MAX); // pseudo trace to keep worts
                }
                for (k,c) in counts {
                    if let Some(reference) = feedbackstate.worst_abb_exec_count.get_mut(k) {
                        if *reference < c {
                            *reference = c;
                            top_indices.push(get_generic_hash(k));
                        }
                    } else {
                        top_indices.push(get_generic_hash(k));
                        feedbackstate.worst_abb_exec_count.insert(k.clone(), c);
                    }
                }
                self.last_top_abb_hashes = Some(top_indices);

                self.last_aggregate_hash = Some(get_generic_hash(&_tmp));
                if let Some(x) = feedbackstate.wort_per_aggegated_path.get_mut(&_tmp) {
                    let t = last_runtime;
                    if t > *x {
                        *x = t;
                        interesting |= INTEREST_AGGREGATE;
                    }
                } else {
                    feedbackstate.wort_per_aggegated_path.insert(_tmp, last_runtime);
                    interesting |= INTEREST_AGGREGATE;
                }
            }
        }

        // let out = feedbackstate.graph.map(|i,x| x.pretty_print(), |_,_| "");
        // let outs = Dot::with_config(&out, &[Config::EdgeNoLabel]).to_string();
        // let outs = outs.replace(';',"\\n");
        // fs::write("./mystg.dot",outs).expect("Failed to write graph");
        self.last_node_trace = Some(nodetrace.into_iter().map(|x| x.0).collect::<Vec<_>>());
        self.last_edge_trace = Some(edgetrace.into_iter().map(|x| x.0).collect::<Vec<_>>());
        self.last_intervals = Some(trace.intervals().clone());
        self.last_abb_trace = Some(tmp);

        if let Some(dp) = &self.dump_path {
            if updated {
                let timestamp = SystemTime::now().duration_since(unsafe {FUZZ_START_TIMESTAMP}).unwrap().as_millis();
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(dp).expect("Could not open stgsize");
                    writeln!(file, "{},{},{},{},{}", feedbackstate.graph.edge_count(), feedbackstate.graph.node_count(), feedbackstate.wort_per_aggegated_path.len(),feedbackstate.wort_per_stg_path.len(), timestamp).expect("Write to dump failed");
            }
        }
        // Re-add trace data
        state.add_metadata(trace);
        Ok(interesting)
    }

    // append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(&mut self, _state: &mut S, _manager: &mut EM, _observers: &OT, testcase: &mut Testcase<I>) -> Result<(), Error> {
        let meta = STGNodeMetadata::new(self.last_node_trace.take().unwrap_or_default(), self.last_edge_trace.take().unwrap_or_default(), self.last_abb_trace.take().unwrap_or_default(), self.last_abbs_hash.take().unwrap_or_default(), self.last_aggregate_hash.take().unwrap_or_default(), self.last_top_abb_hashes.take().unwrap_or_default(), self.last_intervals.take().unwrap_or_default(), self.last_job_trace.take().unwrap_or_default());
        testcase.metadata_map_mut().insert(meta);
        Ok(())
    }

    // discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}
impl<SYS> Named for StgFeedback<SYS>
where 
    SYS: TargetSystem,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}