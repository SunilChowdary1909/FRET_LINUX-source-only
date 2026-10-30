use libafl::{
    inputs::UsesInput,
    prelude::{ExitKind, ObserversTuple}, HasMetadata,
};
use libafl_qemu::{
    modules::{EmulatorModule, EmulatorModuleTuple, NopAddressFilter, NopPageFilter},
    sys::TCGTemp,
    EmulatorModules, GuestAddr, Hook, MemAccessInfo,
};
use std::ops::Range;
use crate::systemstate::{
    target_os::linux::analyzer::{module::S32G3SystemStateModule, structures::*},
    target_os::linux::{LinuxTask, LinuxSystemState, LinuxTraceData},
    ExecInterval, RTOSJob, AtomicBasicBlock,
};
use std::borrow::Cow;
use hashbrown::{HashMap, HashSet};

// ── Global for read-hook accumulation (single-threaded QEMU execution) ──────
static mut INPUT_MEM: Range<GuestAddr> = 0..0;
// Each entry: (guest_addr, byte_value, icount_at_read)
// icount allows per-job scoping: assign reads to the job whose [release_time, response] bracket them.
pub static mut MEM_READ: Option<Vec<(GuestAddr, u8, u64)>> = None;

// generation hook: only instrument reads whose PC falls inside userspace
// (address < 0xffff_0000_0000_0000 on ARM64 — kernel addresses are above)
pub fn gen_read_filter<QT, S>(
    _hooks: &mut EmulatorModules<QT, S>,
    _state: Option<&mut S>,
    pc: GuestAddr,
    _addr: *mut TCGTemp,
    _info: MemAccessInfo,
) -> Option<u64>
where
    S: UsesInput,
    QT: EmulatorModuleTuple<S>,
{
    // ARM64: user-space PCs are below the kernel/EL1 boundary
    if pc < 0xffff_0000_0000_0000 {
        Some(1)
    } else {
        None
    }
}

// execution hook: record the byte value + current icount if the read address is inside INPUT_MEM
// icount is used in convert_to_jobs() to assign reads to the job that was running at the time
pub fn trace_reads_linux<QT, S>(
    hooks: &mut EmulatorModules<QT, S>,
    _state: Option<&mut S>,
    _id: u64,
    addr: GuestAddr,
    _size: usize,
)
where
    S: UsesInput,
    QT: EmulatorModuleTuple<S>,
{
    unsafe {
        if INPUT_MEM.contains(&addr) {
            let mut buf = [0u8; 1];
            let _ = hooks.qemu().read_mem(addr, &mut buf);
            extern "C" {
                fn libafl_qemu_icount_get_raw_safe() -> u64;
            }
            let icount = libafl_qemu_icount_get_raw_safe();
            match MEM_READ.as_mut() {
                Some(v) => v.push((addr, buf[0], icount)),
                None => MEM_READ = Some(vec![(addr, buf[0], icount)]),
            }
        }
    }
}

#[derive(Debug)]
pub struct LinuxSystemStateHelper {
    pub module: S32G3SystemStateModule,
    // range of guest virtual addresses that are fuzz input (FUZZ_INPUT buffer)
    // set from `harness_input_addr` at construction time
    pub input_mem: Range<GuestAddr>,
    /// Task whose job may span blocking intervals (from --select-task).
    pub span_task: Option<String>,
    af: NopAddressFilter,
    pf: NopPageFilter,
}

impl LinuxSystemStateHelper {
    pub fn new(module: S32G3SystemStateModule) -> Self {
        Self { module, input_mem: 0..0, span_task: None, af: NopAddressFilter, pf: NopPageFilter }
    }

    pub fn with_input_mem(module: S32G3SystemStateModule, input_addr: GuestAddr, input_len: usize) -> Self {
        Self {
            module,
            input_mem: input_addr..input_addr + input_len as GuestAddr,
            span_task: None,
            af: NopAddressFilter,
            pf: NopPageFilter,
        }
    }
}

impl<S, I> EmulatorModule<S> for LinuxSystemStateHelper
where
    S: UsesInput<Input = I> + Unpin + HasMetadata,
{
    fn first_exec<ET>(&mut self, emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
        // Install hooks using the wrapped module's logic
        self.module.install_hooks(&emulator_modules.qemu()).expect("Failed to install Linux hooks");

        // Install fuzz-input read-tracking hook (mirrors FreeRTOS trace_reads).
        // Only active when a valid input range is configured (input_mem is non-empty).
        if !self.input_mem.is_empty() {
            unsafe { INPUT_MEM = self.input_mem.clone(); }
            emulator_modules.reads(
                Hook::Function(gen_read_filter::<ET, S>),
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Empty,
                Hook::Function(trace_reads_linux::<ET, S>),
            );
            log::info!("[LinuxSystemStateHelper] mem_reads tracking enabled for {:#x}..{:#x}",
                self.input_mem.start, self.input_mem.end);
        }
    }

    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        // Reset state before each run
        self.module.reset();
        // Clear the read accumulator for the new iteration
        unsafe { MEM_READ = None; }
    }

    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
        // Convert captured states to LinuxTraceData
        // We act on the internal buffer of the module
        let raw_states = &self.module.states_captured; 
        
        log::info!("post_exec called: {} states captured, exit_kind={:?}", raw_states.len(), _exit_kind);
        
        if raw_states.is_empty() {
            log::warn!("post_exec: No states captured in this iteration!");
            return;
        }

        // Convert raw states to system states and jobs
        let jobs = convert_to_jobs(raw_states, self.span_task.as_deref());
        let (intervals, states_map, system_states) = convert_to_intervals(raw_states);

        // Drain the per-iteration read accumulator.
        // Strip the icount field — LinuxTraceData.mem_reads only needs (addr, byte).
        // Per-job scoping has already been applied in convert_to_jobs(); the full
        // stripped list is kept here for interval-level STG correlation.
        let collected_reads: Vec<(GuestAddr, u8)> = unsafe {
            MEM_READ.take().unwrap_or_default().into_iter().map(|(a, b, _t)| (a, b)).collect()
        };

        let trace_data = LinuxTraceData {
            states: system_states,
            jobs,
            intervals,
            mem_reads: vec![collected_reads],
            states_map,
            ref_cnt: 0,
        };
        
        // state.add_metadata(trace_data); // TODO: We need a specific metadata type wrapping trait object? 
        // No, we usually add the concrete type implementing SystemTraceData.
        // But SystemTraceData is a trait.
        // We usually add a struct that implements HasMetadata.
        // LinuxTraceData implements SerdeAny (via macro), so it can be metadata?
        // Yes, libafl_bolts::impl_serdeany!(LinuxTraceData).
        state.add_metadata(trace_data);
    }

    type ModuleAddressFilter = NopAddressFilter;
    type ModulePageFilter = NopPageFilter;

    fn address_filter(&self) -> &Self::ModuleAddressFilter { &self.af }
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter { &mut self.af }
    fn page_filter(&self) -> &Self::ModulePageFilter { &self.pf }
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter { &mut self.pf }
}

fn convert_to_intervals(states: &[RawS32G3SystemState]) -> (Vec<ExecInterval>, HashMap<u64, LinuxSystemState>, Vec<LinuxSystemState>) {
    let mut intervals = Vec::new();
    let mut states_map = HashMap::new();
    let mut system_states = Vec::new();
    
    if states.is_empty() {
        return (intervals, states_map, system_states);
    }
    
    // We need to convert consecutive raw states into intervals.
    // Interval i is between state[i] and state[i+1].
    
    for i in 0..states.len().saturating_sub(1) {
        let s1 = &states[i];
        let s2 = &states[i+1];
        
        let sys_state1 = raw_to_system_state(s1);
        let sys_state2 = raw_to_system_state(s2);
        
        let hash1 = compute_state_hash(&sys_state1);
        let hash2 = compute_state_hash(&sys_state2);
        
        states_map.insert(hash1, sys_state1.clone());
        states_map.insert(hash2, sys_state2.clone());
        
        system_states.push(sys_state1);
        if i == states.len() - 2 {
            system_states.push(sys_state2);
        }

        // Map ABB if present: s2 contains the execution block that just completed
        let abb = if let Some(a) = &s2.current_abb {
            Some(AtomicBasicBlock {
                start: abb_type_to_addr(&a.abb_type),
                ends: HashSet::new(),
                level: 0,
                instance_id: 0,
                instance_name: Some(Cow::Owned(a.abb_type.to_string())),
            })
        } else {
            None
        };

        intervals.push(ExecInterval {
            start_tick: s1.timestamp,
            end_tick: s2.timestamp,
            start_state: hash1,
            end_state: hash2,
            start_capture: (capture_event_to_libafl(&s1.capture_point), Cow::Borrowed("")),
            end_capture: (capture_event_to_libafl(&s2.capture_point), Cow::Borrowed("")),
            level: 0, // Approx
            abb,
        });
    }
    
    (intervals, states_map, system_states)
}

fn raw_to_system_state(raw: &RawS32G3SystemState) -> LinuxSystemState {
    if let Some(task) = &raw.current_task {
        let linux_task = LinuxTask {
            pid: task.pid,
            comm: task.comm.clone(),
            state: task.state,
            parent_pid: task.parent_pid,
            cpu: task.cpu,
        };
        LinuxSystemState {
            current_pid: task.pid,
            current_comm: task.comm.clone(),
            current_task: linux_task,
            tasks: HashMap::<u32, LinuxTask>::new(),
        }
    } else {
        LinuxSystemState::default()
    }
}

fn compute_state_hash(state: &LinuxSystemState) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    let mut hasher = DefaultHasher::new();
    state.hash(&mut hasher);
    hasher.finish()
}

fn capture_event_to_libafl(evt: &CaptureEvent) -> crate::systemstate::CaptureEvent {
    // Map analyzer::CaptureEvent to systemstate::CaptureEvent
    // systemstate::CaptureEvent has: APIStart, APIEnd, ISRStart, ISREnd, End, Undefined
    match evt {
        CaptureEvent::SchedulerHook => crate::systemstate::CaptureEvent::APIStart,
        CaptureEvent::SyscallEntry(_) => crate::systemstate::CaptureEvent::APIStart,
        CaptureEvent::SyscallExit => crate::systemstate::CaptureEvent::APIEnd,
        CaptureEvent::IrqEntry => crate::systemstate::CaptureEvent::ISRStart,
        CaptureEvent::IrqExit => crate::systemstate::CaptureEvent::ISREnd,  // NEW: matched IRQ exit
        CaptureEvent::ExecutionEnd => crate::systemstate::CaptureEvent::End,
        CaptureEvent::Unknown => crate::systemstate::CaptureEvent::Undefined,
    }
}

fn convert_to_jobs(states: &[RawS32G3SystemState], span_task: Option<&str>) -> Vec<RTOSJob> {
    let mut jobs = Vec::new();
    let mut active_jobs: HashMap<u32, JobBuilder> = HashMap::new();

    struct JobBuilder {
        pid: u32,
        comm: String,
        release_time: u64,
        execution_time: u64,
        start_index: usize,
    }

    let mut prev_timestamp = 0;
    // In span mode, only the first thread matching the selected name is measured.
    // avfusion's worker threads share the same comm, so matching on comm alone
    // would suppress job closure for all of them.
    let mut span_pid: Option<u32> = None;
    // Syscall marking the measured task's completion checkpoint (getpid),
    // the same completion convention chain_mtx uses via fuzz_checkpoint().
    const CYCLE_END_SYSCALL: u64 = 172;
    // We assume states are sorted by timestamp (captured sequentially)
    
    for (i, state) in states.iter().enumerate() {
        let timestamp = state.timestamp;
        let duration = if timestamp >= prev_timestamp { timestamp - prev_timestamp } else { 0 };
        prev_timestamp = timestamp;
        
        if let Some(task) = &state.current_task {
            // Check state: Running (0) or Sleeping (>0)
            // Note: This logic depends on kernel specific state values.
            // 0 is usually TASK_RUNNING.
            let is_running = task.state == 0;
            let is_sleeping = !is_running;

            // Latch the first matching thread as the measured task.
            if span_pid.is_none() {
                if span_task.map_or(false, |t| task.comm.contains(t)) {
                    span_pid = Some(task.pid);
                }
            }
            let spans = span_pid == Some(task.pid);

            // In span mode the job closes on the cycle-end syscall instead of on
            // a sleep, so the response window covers the blocking in between.
            let cycle_end = spans && state.current_abb.as_ref().map_or(false, |a| {
                a.pid == task.pid && matches!(a.abb_type, ABBType::Syscall(n) if n == CYCLE_END_SYSCALL)
            });

            if (is_sleeping && !spans) || cycle_end {
                // Job complete?
                if let Some(builder) = active_jobs.remove(&task.pid) {
                    // Collect ABBs from builder.start_index to i
                    let mut abbs = Vec::new();
                    // Also ticks breakdown per abb?
                    let mut ticks_per_abb = Vec::new();
                    
                    let slice = &states[builder.start_index..=i];
                    for s in slice {
                        if let Some(abb) = &s.current_abb {
                            // Filter to this PID?
                            if abb.pid == task.pid {
                                // Convert to libafl AtomicBasicBlock
                                // Note: analyzer::structures::ABB is different from systemstate::AtomicBasicBlock
                                // We need to map.
                                let mapped_abb = AtomicBasicBlock {
                                     start: abb_type_to_addr(&abb.abb_type),
                                     ends: HashSet::new(), // Not tracked
                                     level: 0, // Approx
                                     instance_id: 0,
                                     instance_name: Some(Cow::Owned(abb.abb_type.to_string())),
                                };
                                abbs.push(mapped_abb);
                                
                                // Calculate duration
                                let dur = if abb.end_timestamp >= abb.start_timestamp {
                                    abb.end_timestamp - abb.start_timestamp
                                } else { 0 };
                                ticks_per_abb.push(dur);
                            }
                        }
                    }

                    // Assign only reads whose icount falls within this job's
                    // execution window [builder.release_time, timestamp].
                    // This correctly handles interleaved tasks on the same CPU.
                    let job_reads: Vec<(GuestAddr, u8)> = unsafe {
                        MEM_READ.as_ref().map(|v| {
                            v.iter()
                                .filter(|(_, _, t)| *t >= builder.release_time && *t <= timestamp)
                                .map(|(a, b, _)| (*a, *b))
                                .collect()
                        }).unwrap_or_default()
                    };

                    // Create RTOSJob
                    let job = RTOSJob {
                         name: builder.comm,
                         mem_reads: job_reads,
                         release: builder.release_time,
                         response: timestamp, // Completion time
                         exec_ticks: builder.execution_time + duration,
                         ticks_per_abb,
                         abbs,
                         hash_cache: 0, // Will be computed
                    };
                    jobs.push(job);
                }
            } else {
                // Task Running
                active_jobs.entry(task.pid)
                    .and_modify(|b| {
                        b.execution_time += duration;
                        b.comm = task.comm.clone();
                    })
                    .or_insert_with(|| JobBuilder {
                        pid: task.pid,
                        comm: task.comm.clone(),
                        release_time: timestamp,
                        execution_time: duration,
                        start_index: i,
                    });
            }
        }
    }
    // Drop any job still open at end of execution: it never reached a cycle
    // boundary, so its response time is not a completed measurement.
    active_jobs.clear();
    jobs
}

// Helper to map ABBType to fixed address for STG identity
// Each distinct IRQ number gets a unique address: 0x2000 + nr*0x10
fn abb_type_to_addr(abb_type: &ABBType) -> libafl_qemu::GuestAddr {
    match abb_type {
        ABBType::UserSpace => 0x1000,
        ABBType::IRQ(nr) => (0x2000u64 + (*nr as u64 * 0x10)),  // Unique address per IRQ source
        ABBType::ContextSwitch => 0x3000,
        ABBType::Syscall(nr) => (0x4000u64 + (*nr * 0x10)),
    }
}
