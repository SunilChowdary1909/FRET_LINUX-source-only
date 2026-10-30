//! Interrupt timing mutation and direct memory injection for the Linux FRET fuzzer.
//!
//! This module adapts the interrupt-shift idea from FreeRTOS FRET to ARM64 Linux.
//! It has two main parts:
//!
//! 1. Interrupt schedule mutation (`LinuxIrqScheduleStage`):
//!    - Each GIC SPI source uses its own multipart input field, `isr_{source}_times`.
//!    - The stage keeps trying mutations while the recent success rate stays high.
//!    - It uses three simple strategies:
//!      a. Random placement across the available window.
//!      b. STG-guided placement into intervals that do not already lead to an ISR.
//!      c. Trace-based shifting to nearby execution intervals while keeping spacing constraints.
//!    - Whenever a useful change is found, the input is evaluated again immediately.
//!
//! 2. Direct memory injection (`DirectMemoryMutatorStage`):
//!    - The fuzzer writes the mutated bytes into the target daemon buffer.
//!    - It then sets the ready flag so the daemon can continue processing.
//!
//! Interrupt sources are read from CSV column 6 in the form
//! `source#min_us;source#min_us;...`.

use core::marker::PhantomData;
use core::cmp::min;
use libafl::{
    common::HasNamedMetadata,
    corpus::{Corpus, HasCurrentCorpusId, Testcase},
    events::{Event, EventFirer, LogSeverity},
    fuzzer::Evaluator,
    inputs::{HasMutatorBytes, HasTargetBytes, Input, MultipartInput},
    prelude::{AggregatorOps, MutationResult, UserStats, UserStatsValue},
    stages::Stage,
    state::{HasCorpus, HasCurrentTestcase, HasRand, MaybeHasClientPerfMonitor, UsesState},
    Error,
};
use libafl::prelude::UsesInput;
use libafl::common::HasMetadata;
use libafl::prelude::State;
use libafl_bolts::Named;
use libafl_bolts::rands::{Rand, StdRand};
use libafl_qemu::GuestAddr;
use std::borrow::Cow;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZero;
use std::sync::atomic::{AtomicU64, Ordering};
use simple_moving_average::{SMA, SingleSumSMA};

use crate::fuzzer::{FIRST_INT, MAX_NUM_INTERRUPT, NUM_INTERRUPT_SOURCES};
use crate::time::clock::{IcHist, QEMU_ISNS_PER_USEC};
use crate::systemstate::{CaptureEvent, ExecInterval};
use crate::systemstate::stg::{STGFeedbackState, STGNodeMetadata};
use crate::systemstate::target_os::{linux::LinuxSystem, TargetSystem};
use crate::systemstate::RTOSJob;

#[allow(unused)]
extern "C" {
    static mut libafl_interrupt_offsets: [[u32; MAX_NUM_INTERRUPT]; NUM_INTERRUPT_SOURCES];
    static mut libafl_num_interrupts: [u64; NUM_INTERRUPT_SOURCES];
}

// ============================================================================
// Interrupt timing helpers (ported from FreeRTOS FRET)
// ============================================================================

// convert raw input bytes into sorted interrupt timing offsets
//
// the input is read in 4-byte chunks and interpreted as little-endian `u32`
// values. Values below `FIRST_INT` are dropped, and entries that are too close
// together are removed based on the configured minimum spacing
//
// # Arguments
// * `buf` - Raw bytes from the `isr_{source}_times` multipart part
// * `config` - `(source_idx, min_inter_arrival_us)` from the CSV file
pub fn input_bytes_to_interrupt_times(buf: &[u8], config: (usize, u32)) -> Vec<u32> {
    let len = buf.len();
    let mut ret = Vec::with_capacity(min(MAX_NUM_INTERRUPT, len / 4));
    for i in 0..MAX_NUM_INTERRUPT {
        let mut buf4b: [u8; 4] = [0, 0, 0, 0];
        if len >= (i + 1) * 4 {
            for j in 0usize..4usize {
                buf4b[j] = buf[i * 4 + j];
            }
            let mut start_tick = u32::from_le_bytes(buf4b);
            if start_tick < FIRST_INT {
                start_tick = 0;
            }
            ret.push(start_tick);
        } else {
            break;
        }
    }
    ret.sort_unstable();
    // Keep only interrupts that satisfy the minimum spacing constraint.
    for i in 0..ret.len() {
        if ret[i] == 0 {
            continue;
        }
        for j in i + 1..ret.len() {
            if ret[j] - ret[i] < (config.1 as f32 * QEMU_ISNS_PER_USEC) as u32 {
                ret[j] = 0; // Drop interrupts that are too close together.
                ret.sort_unstable();
                break;
            } else {
                break;
            }
        }
    }
    ret
}

// convert interrupt timing offsets back into raw bytes
pub fn interrupt_times_to_input_bytes(interrupt_times: &[u32]) -> Vec<u8> {
    let mut ret = Vec::with_capacity(interrupt_times.len() * 4);
    for t in interrupt_times {
        ret.extend(u32::to_le_bytes(*t));
    }
    ret
}

// ============================================================================
// try_force_new_branches - STG-guided interrupt placement
//
// This is a Linux version of the FreeRTOS helper. It looks for execution
// intervals that do not already have an outgoing interrupt edge in the STG and
// places a new interrupt inside that interval to explore a different path.
// ============================================================================

pub fn try_force_new_branches(
    interrupt_ticks: &[u32],
    fbs: &STGFeedbackState<LinuxSystem>,
    meta: &STGNodeMetadata,
    config: (usize, u32),
) -> Option<Vec<u32>> {
    let mut new = false;
    let mut new_interrupt_times = Vec::new();

    for (num, &interrupt_time) in interrupt_ticks.iter().enumerate() {
        let lower_bound = if num == 0 {
            FIRST_INT
        } else {
            interrupt_ticks[num - 1]
                .saturating_add((config.1 as f32 * QEMU_ISNS_PER_USEC) as u32)
        };
        let next = if interrupt_ticks.len() > num + 1 {
            interrupt_ticks[num + 1]
        } else {
            u32::MAX
        };

        for exec_interval in meta
            .intervals()
            .iter()
            .filter(|x| x.start_tick >= lower_bound as u64 && x.start_tick < next as u64)
        {
            // Ignore intervals that are already inside an ISR handler.
            if exec_interval.start_capture.0 == CaptureEvent::ISRStart {
                continue;
            }

            // Find the matching node in the STG.
            if exec_interval.abb.is_none() {
                continue;
            }
            let hash_idx = exec_interval.get_hash_index();
            if let Some(&node_index) = fbs.state_abb_hash_index.get(&hash_idx) {
                // Check whether this node already has an outgoing ISR edge.
                let already_interrupted = fbs
                    .graph
                    .edges_directed(node_index, petgraph::Direction::Outgoing)
                    .any(|e| e.weight().event == CaptureEvent::ISRStart);

                if !already_interrupted {
                    // Place the interrupt near the start of the interval.
                    let new_time = exec_interval
                        .start_tick
                        .saturating_add((exec_interval.end_tick - exec_interval.start_tick) / 4);
                    let new_time_u32 = new_time.try_into().unwrap_or(u32::MAX);

                    new_interrupt_times.push(new_time_u32);

                    // Keep the remaining interrupts if the new one leaves enough room.
                    if (new_time + config.1 as u64) < next as u64 {
                        new_interrupt_times.extend(interrupt_ticks.iter().skip(num).cloned());
                    } else {
                        // Otherwise, skip the next interrupt to preserve spacing.
                        new_interrupt_times.extend(interrupt_ticks.iter().skip(num + 1).cloned());
                    }
                    new = true;
                    break;
                }
            }
        }
        if new {
            break;
        }
        new_interrupt_times.push(interrupt_time);
    }

    if new { Some(new_interrupt_times) } else { None }
}

// ============================================================================
// LinuxIrqScheduleStage - interrupt scheduling for Linux
//
// This follows the same general idea as the FreeRTOS interrupt stage, but it
// uses Linux system state, GIC SPI sources, and the Linux STG structure.
// ============================================================================

// Global statistics counters (mirrors FreeRTOS FRET)
static mut NUM_STAGE_EXECS: u64 = 0;
static mut SUM_RERUNS: u64 = 0;
static mut SUM_INTERESTING_RERUNS: u64 = 0;

#[derive(Clone, Debug)]
pub struct LinuxIrqScheduleStage<E, EM, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z)>,
    // interrupt configuration loaded from the CSV file
    interrupt_config: Vec<(usize, u32)>,
    // a small moving average used to adapt how many mutations the stage tries
    success: SingleSumSMA<f32, f32, 50>,
}

impl<E, EM, Z> LinuxIrqScheduleStage<E, EM, Z> {
    pub fn new(config: &[(usize, u32)]) -> Self {
        Self {
            phantom: PhantomData,
            interrupt_config: config.to_vec(),
            success: SingleSumSMA::from_zero(1.0),
        }
    }
}

impl<E, EM, Z> LinuxIrqScheduleStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State> + EventFirer,
    Z: Evaluator<E, EM>,
    Z::State: State + HasRand + HasCorpus + HasMetadata + HasNamedMetadata + MaybeHasClientPerfMonitor,
{
    fn report_stats(&self, state: &mut Z::State, manager: &mut EM) {
        unsafe {
            let _ = manager.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::from("LinuxIrqScheduleStage"),
                    value: UserStats::new(
                        UserStatsValue::String(Cow::from(format!(
                            "{} -> {}/{} {:.1}%",
                            NUM_STAGE_EXECS,
                            SUM_INTERESTING_RERUNS,
                            SUM_RERUNS,
                            if SUM_RERUNS > 0 {
                                SUM_INTERESTING_RERUNS as f32 * 100.0 / SUM_RERUNS as f32
                            } else {
                                0.0
                            }
                        ))),
                        AggregatorOps::None,
                    ),
                    phantom: PhantomData,
                },
            );
        }
    }
}

impl<E, EM, Z, I> Stage<E, EM, Z> for LinuxIrqScheduleStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State> + EventFirer,
    Z: Evaluator<E, EM>,
    Z::State: State<Input = MultipartInput<I>>
        + HasRand
        + HasCorpus
        + HasCurrentTestcase
        + HasMetadata
        + HasNamedMetadata
        + MaybeHasClientPerfMonitor,
    <<Self as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>,
    I: Default + Input + HasMutatorBytes + From<Vec<u8>> + Clone,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        if self.interrupt_config.is_empty() {
            return Ok(());
        }

        // Use an independent RNG seeded from the main state RNG (FreeRTOS FRET pattern)
        let mut myrand = StdRand::with_seed(state.rand_mut().next());

        unsafe { NUM_STAGE_EXECS += 1; }

        let mut rerun_count: u64 = 0;
        let mut interesting_rerun_count: u64 = 0;

        // Adaptive loop bound: more retries when success rate is high
        let loopbound = std::cmp::max(1, (self.success.get_average() * 100.0) as usize);

        for _ in 0..loopbound {
            // Pick a random interrupt source to mutate
            let config_idx = myrand.below(NonZero::new(self.interrupt_config.len()).unwrap()) as usize;
            let interrup_config = self.interrupt_config[config_idx];
            let part_name = format!("isr_{}_times", interrup_config.0);

            let curr_case: std::cell::Ref<Testcase<MultipartInput<I>>> = state.current_testcase()?;
            let curr_input = curr_case.input().as_ref().unwrap().clone();

            // Build mutable copy of the input
            let mut new_input: MultipartInput<I> = curr_input.clone();

            // Get or create the interrupt timing part for this source
            let part_bytes: Vec<u8> = new_input
                .parts_by_name(&part_name)
                .next()
                .map(|(_, p)| p.bytes().to_vec())
                .unwrap_or_default();
            let old_interrupt_times = input_bytes_to_interrupt_times(&part_bytes, interrup_config);
            let mut new_interrupt_times: Vec<u32> = Vec::with_capacity(MAX_NUM_INTERRUPT);
            let mut do_rerun = false;

            drop(curr_case);

            // Read IcHist maxtick for random-mode upper bound
            let maxtick: u64 = state
                .metadata_map()
                .get::<IcHist>()
                .map(|h| h.1.0)
                .unwrap_or(500_000);

            let choice = myrand.below(NonZero::new(100).unwrap()) as usize + 1;

            if choice <= 25 || old_interrupt_times.first().copied().unwrap_or(u32::MAX) as u64 > maxtick {
                // ── Mode A: Random scatter (25%) ──────────────────────────────
                do_rerun = true;
                let max_count = min(
                    MAX_NUM_INTERRUPT,
                    (maxtick as usize * 3)
                        / (interrup_config.1 as usize * QEMU_ISNS_PER_USEC as usize * 2 + 1),
                );
                let count = myrand.below(NonZero::new(max_count.max(1)).unwrap()) as usize;
                for _ in 0..count {
                    new_interrupt_times.push(
                        myrand.below(NonZero::new(min(maxtick, u32::MAX as u64).max(1) as usize).unwrap()) as u32,
                    );
                }
            } else if choice <= 50 {
                // ── Mode B: STG-guided placement (25%) ───────────────────────
                if let Ok(feedbackstate) = state.metadata::<STGFeedbackState<LinuxSystem>>() {
                    let curr_case2: std::cell::Ref<Testcase<MultipartInput<I>>> = state.current_testcase()?;
                    if let Some(meta) = curr_case2.metadata_map().get::<STGNodeMetadata>() {
                        if let Some(t) = try_force_new_branches(
                            &old_interrupt_times,
                            feedbackstate,
                            meta,
                            interrup_config,
                        ) {
                            do_rerun = true;
                            new_interrupt_times = t;
                        }
                    }
                    drop(curr_case2);
                }
            } else {
                // ── Mode C: Trace-shift (50%) ─────────────────────────────────
                // Walk the stored trace and try to move each interrupt to a
                // different execution interval, respecting min inter-arrival time.
                new_interrupt_times = old_interrupt_times.clone();

                if let Ok(curr_case2) = state.current_testcase() {
                    if let Some(meta) = curr_case2.metadata_map().get::<STGNodeMetadata>() {
                        // Classify each interval: 0 = untouched, 1 = hit by interrupt, 2 = ISR handler
                        let mut marks: Vec<(&ExecInterval, usize, u8)> = Vec::new();
                        let mut last_was_hit = false;
                        for (i, interval) in meta.intervals().iter().enumerate() {
                            let hit = old_interrupt_times
                                .iter()
                                .any(|&t| interval.start_tick < t as u64 && (t as u64) < interval.end_tick);
                            let label = if hit {
                                1u8
                            } else if last_was_hit {
                                2u8
                            } else {
                                0u8
                            };
                            marks.push((interval, i, label));
                            last_was_hit = hit;
                        }

                        for i in 0..old_interrupt_times.len() {
                            let lb = if i > 0 {
                                new_interrupt_times[i - 1]
                                    .saturating_add((interrup_config.1 as f32 * QEMU_ISNS_PER_USEC) as u32)
                            } else {
                                FIRST_INT
                            };
                            let ub = if i + 1 < new_interrupt_times.len() {
                                new_interrupt_times[i + 1]
                                    .saturating_sub((interrup_config.1 as f32 * QEMU_ISNS_PER_USEC) as u32)
                            } else {
                                meta.intervals()
                                    .last()
                                    .map(|x| x.end_tick as u32)
                                    .unwrap_or(u32::MAX)
                            };

                            // Build candidate list: NOT ISR handlers, within [lb, ub]
                            let lb_u64 = lb as u64;
                            let ub_u64 = ub as u64;
                            let alternatives: Vec<_> = marks
                                .iter()
                                .filter(|x| {
                                    x.2 != 2
                                        && ((x.0.start_tick < lb_u64 && lb_u64 < x.0.end_tick)
                                            || (x.0.start_tick > lb_u64
                                                && x.0.start_tick < ub_u64))
                                })
                                .collect();

                            if alternatives.is_empty() {
                                // Fallback: move to a random untouched interval
                                let untouched: Vec<_> =
                                    marks.iter().filter(|x| x.2 == 0).collect();
                                if !untouched.is_empty() {
                                    let choice = myrand.below(NonZero::new(untouched.len()).unwrap()) as usize;
                                    let iv = untouched[choice].0;
                                    if iv.end_tick > iv.start_tick {
                                        let range = (iv.end_tick - iv.start_tick) as usize;
                                        new_interrupt_times[i] = (iv.start_tick as usize
                                            + myrand.below(NonZero::new(range.max(1)).unwrap()) as usize)
                                            as u32;
                                        do_rerun = true;
                                    }
                                }
                                continue;
                            }

                            let choice_idx = myrand.below(NonZero::new(alternatives.len()).unwrap()) as usize;
                            let replacement = alternatives[choice_idx];
                            let old_hit = marks.iter().find(|x| {
                                x.0.start_tick < old_interrupt_times[i] as u64
                                    && (old_interrupt_times[i] as u64) < x.0.end_tick
                            });
                            if old_hit.map_or(false, |oh| std::ptr::eq(oh.0, replacement.0)) {
                                continue; // Same interval, no change
                            }

                            let iv = replacement.0;
                            if iv.end_tick > iv.start_tick {
                                let range = (iv.end_tick - iv.start_tick) as usize;
                                new_interrupt_times[i] = (iv.start_tick as usize
                                    + myrand.below(NonZero::new(range.max(1)).unwrap()) as usize)
                                    as u32;
                                do_rerun = true;
                            }
                        }
                    }
                    drop(curr_case2);
                }
            }

            if do_rerun {
                // Write mutated bytes back into the new_input
                let new_bytes = interrupt_times_to_input_bytes(
                    &input_bytes_to_interrupt_times(
                        &interrupt_times_to_input_bytes(&new_interrupt_times),
                        interrup_config,
                    ),
                );
                {
                    let mut has_part = false;
                    let mut parts_iter = new_input.parts_by_name_mut(&part_name);
                    if let Some((_, part)) = parts_iter.next() {
                        part.drain(..);
                        part.extend(new_bytes.iter());
                        has_part = true;
                    }
                    drop(parts_iter);
                    if !has_part {
                        new_input.add_part(part_name.clone(), I::from(new_bytes));
                    }
                }

                rerun_count += 1;
                let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, new_input)?;
                if corpus_idx.is_some() {
                    unsafe { interesting_rerun_count += 1; }
                } else if loopbound <= 1 {
                    break;
                }
            } else if loopbound <= 1 {
                break;
            }
        }

        unsafe {
            SUM_RERUNS += rerun_count;
            SUM_INTERESTING_RERUNS += interesting_rerun_count;
            if rerun_count > 0 {
                self.success
                    .add_sample(interesting_rerun_count as f32 / rerun_count as f32);
            }
        }

        self.report_stats(state, manager);
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, Z> UsesState for LinuxIrqScheduleStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, Z> Named for LinuxIrqScheduleStage<E, EM, Z> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: std::sync::OnceLock<Cow<'static, str>> = std::sync::OnceLock::new();
        NAME.get_or_init(|| Cow::Borrowed("LinuxIrqScheduleStage"))
    }
}

// ============================================================================
// Global injection statistics — atomic so they are safe even if the fuzzer is
// later moved to a multi-core configuration.
// ============================================================================

static NUM_INJECT_EXECS: AtomicU64 = AtomicU64::new(0);
static NUM_INJECT_INTERESTING: AtomicU64 = AtomicU64::new(0);

// ============================================================================
// DirectMemoryMutatorStage
//
// Injects LibAFL-generated byte mutations directly into the target daemon's
// pre-defined input buffer in guest memory via QEMU, then triggers the
// ready flag so the daemon processes the fuzzed data.
// ============================================================================

// a fuzzing stage that injects bytes directly into a target memory buffer
// inside the QEMU guest OS, bypassing all network/IPC layers
#[derive(Clone, Debug)]
pub struct DirectMemoryMutatorStage<E, EM, Z> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z)>,

    // virtual address of the `fuzz_input_buffer` symbol in the target ELF
    // located once at startup using `goblin` to parse the daemon's ELF file
    pub target_buffer_addr: GuestAddr,

    // size in bytes of the target buffer (`sizeof(fuzz_input_buffer)`)
    pub target_buffer_size: usize,

    // virtual address of the `fuzz_data_ready` flag in the target ELF
    // the fuzzer writes `1u8` here after injecting the payload to wake the daemon
    pub ready_flag_addr: GuestAddr,

    // qEMU handle — used to call `write_mem()` against guest memory
    pub qemu: libafl_qemu::Qemu,
}

impl<E, EM, Z> DirectMemoryMutatorStage<E, EM, Z> {
    // create a new stage
    //
    // # Arguments
    // * `target_buffer_addr` — VADDR of `fuzz_input_buffer` inside the daemon ELF
    // * `target_buffer_size` — byte size of that buffer
    // * `ready_flag_addr`    — VADDR of `fuzz_data_ready` flag inside the daemon ELF
    // * `qemu`               — live QEMU instance (from fuzzer setup)
    pub fn new(
        target_buffer_addr: GuestAddr,
        target_buffer_size: usize,
        ready_flag_addr: GuestAddr,
        qemu: libafl_qemu::Qemu,
    ) -> Self {
        Self {
            phantom: PhantomData,
            target_buffer_addr,
            target_buffer_size,
            ready_flag_addr,
            qemu,
        }
    }
}

impl<E, EM, Z> DirectMemoryMutatorStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State> + EventFirer,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand,
{
    fn report_stats(&self, state: &mut Z::State, manager: &mut EM) {
        let _ = manager.fire(
            state,
            Event::UpdateUserStats {
                name: Cow::from("DirectMemoryMutatorStage"),
                value: UserStats::new(
                    UserStatsValue::String(Cow::from(format!(
                        "injections: {}, interesting: {}",
                        NUM_INJECT_EXECS.load(Ordering::Relaxed),
                        NUM_INJECT_INTERESTING.load(Ordering::Relaxed)
                    ))),
                    AggregatorOps::None,
                ),
                phantom: PhantomData,
            },
        );
    }
}

impl<E, EM, Z, I> Stage<E, EM, Z> for DirectMemoryMutatorStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State> + EventFirer,
    Z: Evaluator<E, EM>,
    Z::State: State<Input = MultipartInput<I>>
        + HasRand
        + HasCorpus
        + HasCurrentTestcase
        + HasMetadata
        + HasNamedMetadata,
    <<Self as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>,
    I: Default + Input + HasMutatorBytes + From<Vec<u8>>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        // Retrieve the current testcase bytes ("bytes" part of multipart input)
        let current_case = state.current_testcase()?;
        let curr_input = match current_case.input().as_ref() {
            Some(i) => i.clone(),
            None => {
                drop(current_case);
                return Ok(());
            }
        };
        drop(current_case);

        // Extract the raw payload bytes from the multipart input
        let raw_bytes: &[u8] = match curr_input.parts_by_name("bytes").next() {
            Some((_, part)) => part.bytes(),
            None => return Ok(()), // No bytes part yet, skip
        };

        // Clamp payload to the target buffer size to avoid overflow
        let payload_len = raw_bytes.len().min(self.target_buffer_size);
        let payload = &raw_bytes[..payload_len];

        // --- INJECTION ---
        // Step 1: Write mutated bytes into `fuzz_input_buffer` in guest memory.
        //         write_mem() translates the virtual address through the *currently active*
        //         page table (TTBR0/CR3).  The daemon must be the scheduled process at this
        //         point so that its page table is live; the scheduler hook in `module.rs`
        //         guarantees this under normal operation.
        unsafe {
            let _ = self.qemu.write_mem(self.target_buffer_addr, payload);
        }

        // Step 1b — Page-table validation: read back the first byte to confirm that the
        // write landed in the daemon's address space.  If the daemon was preempted between
        // leaving the scheduler hook and reaching this point, the active page table would
        // belong to a different process, and the read-back will not match.
        if !payload.is_empty() {
            let mut verify = [0u8; 1];
            unsafe { let _ = self.qemu.read_mem(self.target_buffer_addr, &mut verify); }
            if verify[0] != payload[0] {
                log::warn!(
                    "[DirectMemoryMutator] Buffer write-back mismatch at 0x{:x}: \
                     wrote 0x{:02x}, read back 0x{:02x}. \
                     Daemon was likely preempted — page table no longer active. \
                     Skipping this injection to avoid corrupting another process.",
                    self.target_buffer_addr, payload[0], verify[0]
                );
                return Ok(());
            }
        }

        // Step 2: Write 1 to `fuzz_data_ready` to wake the daemon's polling loop.
        unsafe {
            let _ = self.qemu.write_mem(self.ready_flag_addr, &[1u8]);
        }

        // Step 2b — Verify the ready flag was accepted in the same address space.
        {
            let mut flag_check = [0u8; 1];
            unsafe { let _ = self.qemu.read_mem(self.ready_flag_addr, &mut flag_check); }
            if flag_check[0] != 1 {
                log::warn!(
                    "[DirectMemoryMutator] Ready-flag write-back mismatch at 0x{:x}: \
                     Daemon was preempted between buffer write and flag set. \
                     Clearing flag and skipping injection.",
                    self.ready_flag_addr
                );
                // Best-effort cleanup so the daemon does not see a stale flag later.
                unsafe { let _ = self.qemu.write_mem(self.ready_flag_addr, &[0u8]); }
                return Ok(());
            }
        }

        // Step 3: Let the executor run until the daemon finishes processing.
        let new_input = curr_input.clone();
        let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, new_input)?;

        // Step 4: Reset the ready flag (so the daemon waits for next injection).
        unsafe {
            let _ = self.qemu.write_mem(self.ready_flag_addr, &[0u8]);
        }

        NUM_INJECT_EXECS.fetch_add(1, Ordering::Relaxed);
        if corpus_idx.is_some() {
            NUM_INJECT_INTERESTING.fetch_add(1, Ordering::Relaxed);
        }

        self.report_stats(state, manager);
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, Z> UsesState for DirectMemoryMutatorStage<E, EM, Z>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand,
{
    type State = Z::State;
}

impl<E, EM, Z> Named for DirectMemoryMutatorStage<E, EM, Z> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: std::sync::OnceLock<Cow<'static, str>> = std::sync::OnceLock::new();
        NAME.get_or_init(|| Cow::Borrowed("DirectMemoryMutatorStage"))
    }
}

// ======================================================================
// STGSnippetStage — port of FreeRTOS FRET snippet-based mutation
// Replays the highest-WCET byte snippet from the STG worst-job map onto
// the current input, then re-evaluates if any bytes changed.
// Requires mem_reads tracking to be active (LinuxSystemStateHelper::with_input_mem).
// ======================================================================

static mut NUM_SNIPPET_STAGE_EXECS: u64 = 0;
static mut NUM_SNIPPET_RERUN: u64 = 0;
static mut NUM_SNIPPET_SUCCESS: u64 = 0;

#[derive(Clone, Debug, Default)]
pub struct STGSnippetStage<E, EM, Z, SYS> {
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(E, EM, Z, SYS)>,
    input_addr: GuestAddr,
}

impl<E, EM, Z, SYS> STGSnippetStage<E, EM, Z, SYS>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand,
    SYS: TargetSystem,
{
    pub fn new(input_addr: GuestAddr) -> Self {
        Self { phantom: PhantomData, input_addr }
    }

    fn report_stats(
        &self,
        state: &mut <Self as UsesState>::State,
        manager: &mut EM,
    ) where
        EM: EventFirer,
        Z::State: HasMetadata + HasNamedMetadata,
        <Z::State as UsesInput>::Input: Input,
    {
        unsafe {
            let _ = manager.fire(
                state,
                Event::UpdateUserStats {
                    name: Cow::from("STGSnippetStage"),
                    value: UserStats::new(
                        UserStatsValue::String(Cow::from(format!(
                            "{} -> {}/{} {:.1}%",
                            NUM_SNIPPET_STAGE_EXECS,
                            NUM_SNIPPET_SUCCESS,
                            NUM_SNIPPET_RERUN,
                            if NUM_SNIPPET_RERUN > 0 {
                                NUM_SNIPPET_SUCCESS as f32 * 100.0 / NUM_SNIPPET_RERUN as f32
                            } else { 0.0 }
                        ))),
                        AggregatorOps::None,
                    ),
                    phantom: PhantomData,
                },
            );
        }
    }
}

impl<E, EM, Z, I, SYS> Stage<E, EM, Z> for STGSnippetStage<E, EM, Z, SYS>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State> + EventFirer,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand + HasMetadata + HasNamedMetadata,
    <Z::State as UsesInput>::Input: Input,
    Z::State: UsesInput<Input = MultipartInput<I>>,
    I: HasMutatorBytes + Default,
    Z::State: HasCurrentTestcase + HasCorpus + HasCurrentCorpusId,
    <Z::State as HasCorpus>::Corpus: Corpus<Input = MultipartInput<I>>,
    SYS: TargetSystem,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut Self::State,
        manager: &mut EM,
    ) -> Result<(), Error> {
        let mut do_rerun = false;

        let current_case = state.current_testcase()?;
        let old_input = current_case.input().as_ref().unwrap();
        let mut new_input: MultipartInput<I> = old_input.clone();
        let new_bytes = new_input
            .parts_by_name_mut("bytes")
            .next()
            .expect("bytes not found in multipart input")
            .1
            .bytes_mut();

        if let Some(meta) = current_case.metadata_map().get::<STGNodeMetadata>() {
            let feedbackstate = state
                .metadata::<STGFeedbackState<SYS>>()
                .expect("STGFeedbackState not visible");

            for jobinst in meta.jobs().iter() {
                if let Some(worst) = feedbackstate.worst_task_jobs.get(&jobinst.get_hash_cached()) {
                    let new = worst.map_bytes_onto(jobinst, Some(self.input_addr));
                    do_rerun |= !new.is_empty();
                    for (addr, byte) in new {
                        if (addr as usize) < new_bytes.len() {
                            new_bytes[addr as usize] = byte;
                        }
                    }
                }
            }
        }
        drop(current_case);

        unsafe { NUM_SNIPPET_STAGE_EXECS += 1; }
        if do_rerun {
            unsafe { NUM_SNIPPET_RERUN += 1; }
            let (_, corpus_idx) = fuzzer.evaluate_input(state, executor, manager, new_input)?;
            if corpus_idx.is_some() {
                unsafe { NUM_SNIPPET_SUCCESS += 1; }
            }
        }
        self.report_stats(state, manager);
        Ok(())
    }

    fn should_restart(&mut self, _state: &mut Self::State) -> Result<bool, Error> {
        Ok(true)
    }

    fn clear_progress(&mut self, _state: &mut Self::State) -> Result<(), Error> {
        Ok(())
    }
}

impl<E, EM, Z, SYS> UsesState for STGSnippetStage<E, EM, Z, SYS>
where
    E: UsesState<State = Z::State>,
    EM: UsesState<State = Z::State>,
    Z: Evaluator<E, EM>,
    Z::State: MaybeHasClientPerfMonitor + HasCorpus + HasRand,
    SYS: TargetSystem,
{
    type State = Z::State;
}

impl<E, EM, Z, SYS> Named for STGSnippetStage<E, EM, Z, SYS> {
    fn name(&self) -> &Cow<'static, str> {
        static NAME: std::sync::OnceLock<Cow<'static, str>> = std::sync::OnceLock::new();
        NAME.get_or_init(|| Cow::Borrowed("STGSnippetStage"))
    }
}
