use libafl::{
    common::HasNamedMetadata, executors::ExitKind, observers::Observer, observers::ObserversTuple,
    prelude::UsesInput, Error,
};
use libafl_bolts::Named;
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write};

use core::{fmt::Debug, time::Duration};
use libafl::common::HasMetadata;
use libafl::corpus::testcase::Testcase;
use libafl::events::EventFirer;
use libafl::feedbacks::Feedback;
use libafl::prelude::State;
use libafl::state::MaybeHasClientPerfMonitor;
use libafl_bolts::tuples::MatchNameRef;
use libafl::SerdeAny;
use std::borrow::Cow;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::systemstate::helpers::metadata_insert_or_update_get;
use crate::systemstate::target_os::TargetSystem;
use crate::systemstate::target_os::SystemTraceData;

use libafl::prelude::StateInitializer;

pub static mut FUZZ_START_TIMESTAMP: SystemTime = UNIX_EPOCH;

pub const QEMU_ICOUNT_SHIFT: u32 = 5;
pub const QEMU_ISNS_PER_SEC: u32 = u32::pow(10, 9) / u32::pow(2, QEMU_ICOUNT_SHIFT);
pub const QEMU_ISNS_PER_MSEC: u32 = QEMU_ISNS_PER_SEC / 1000;
pub const QEMU_ISNS_PER_USEC: f32 = QEMU_ISNS_PER_SEC as f32 / 1000000.0;
pub const _QEMU_NS_PER_ISN: u32 = 1 << QEMU_ICOUNT_SHIFT;
pub const _TARGET_SYSCLK_FREQ: u32 = 25 * 1000 * 1000;
pub const _TARGET_MHZ_PER_MIPS: f32 = _TARGET_SYSCLK_FREQ as f32 / QEMU_ISNS_PER_SEC as f32;
pub const _TARGET_MIPS_PER_MHZ: f32 = QEMU_ISNS_PER_SEC as f32 / _TARGET_SYSCLK_FREQ as f32;
pub const _TARGET_SYSCLK_PER_QEMU_SEC: u32 =
    (_TARGET_SYSCLK_FREQ as f32 * _TARGET_MIPS_PER_MHZ) as u32;
pub const _QEMU_SYSCLK_PER_TARGET_SEC: u32 =
    (_TARGET_SYSCLK_FREQ as f32 * _TARGET_MHZ_PER_MIPS) as u32;

pub fn tick_to_time(ticks: u64) -> Duration {
    Duration::from_nanos((ticks * _QEMU_NS_PER_ISN as u64))
}

pub fn tick_to_ms(ticks: u64) -> f32 {
    (tick_to_time(ticks).as_micros() as f32 / 10.0).round() / 100.0
}

pub fn time_to_tick(time: Duration) -> u64 {
    time.as_nanos() as u64 / _QEMU_NS_PER_ISN as u64
}

//========== Metadata
#[derive(Debug, SerdeAny, Serialize, Deserialize)]
pub struct QemuIcountMetadata {
    runtime: u64,
}

/// Metadata for [`QemuClockIncreaseFeedback`]
#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct MaxIcountMetadata {
    pub max_icount_seen: u64,
    pub name: Cow<'static, str>,
}

// impl FeedbackState for MaxIcountMetadata
// {
//     fn reset(&mut self) -> Result<(), Error> {
//         self.max_icount_seen = 0;
//         Ok(())
//     }
// }

impl Named for MaxIcountMetadata {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl MaxIcountMetadata {
    /// Create new `MaxIcountMetadata`
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            max_icount_seen: 0,
            name: Cow::from(name),
        }
    }
}

impl Default for MaxIcountMetadata {
    fn default() -> Self {
        Self::new("MaxClock")
    }
}

/// A piece of metadata tracking all icounts
#[derive(Debug, Default, SerdeAny, Serialize, Deserialize)]
pub struct IcHist(pub Vec<(u64, u128)>, pub (u64, u128));

//========== Observer

/// A simple observer, just overlooking the runtime of the target.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QemuClockObserver<SYS: TargetSystem> {
    name: Cow<'static, str>,
    start_tick: u64,
    end_tick: u64,
    select_task: Option<String>,
    phantom: std::marker::PhantomData<SYS>,
}

impl<SYS: TargetSystem> QemuClockObserver<SYS> {
    /// Creates a new [`QemuClockObserver`] with the given name.
    #[must_use]
    pub fn new(name: &'static str, select_task: &Option<String>) -> Self {
        Self {
            name: Cow::from(name),
            start_tick: 0,
            end_tick: 0,
            select_task: select_task.clone(),
            phantom: std::marker::PhantomData,
        }
    }

    /// Gets the runtime for the last execution of this target.
    #[must_use]
    pub fn last_runtime(&self) -> u64 {
        self.end_tick - self.start_tick
    }
}

impl<I, S, SYS> Observer<I, S> for QemuClockObserver<SYS>
where
    S: UsesInput + HasMetadata,
    SYS: TargetSystem,
{
    fn pre_exec(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.start_tick = 0;
        // Only remember the pre-run ticks if presistent mode ist used
        #[cfg(not(feature = "snapshot_restore"))]
        unsafe {
            self.start_tick = emu::icount_get_raw();
            self.end_tick = self.start_tick;
        }
        Ok(())
    }

    fn post_exec(
        &mut self,
        state: &mut S,
        _input: &I,
        _exit_kind: &ExitKind,
    ) -> Result<(), Error> {
        // Note: We used to return early and zero ticks for non-Ok exits,
        // but with Linux timeout-based harness, exit_kind=Crash has valid data.
        // Only skip for genuinely empty runs.
        #[cfg(feature = "trace_job_response_times")]
        let icount = {
            if let Some(select) = self.select_task.as_ref() {
                match state.metadata::<SYS::TraceData>() {
                    Ok(trace) => trace.wort_of_task(select),
                    Err(_) => {
                        eprintln!("[WARN] TraceData not available in observer, falling back to raw icount");
                        unsafe {libafl_qemu::sys::icount_get_raw()}
                    }
                }
            } else {
                unsafe {libafl_qemu::sys::icount_get_raw()}
            }
        };
        #[cfg(not(feature = "trace_job_response_times"))]
        let icount = unsafe {libafl_qemu::sys::icount_get_raw()};

        self.end_tick = icount;
        Ok(())
    }
}

impl<SYS: TargetSystem> Named for QemuClockObserver<SYS> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS: TargetSystem> Default for QemuClockObserver<SYS> {
    fn default() -> Self {
        Self {
            name: Cow::from(String::from("clock")),
            start_tick: 0,
            end_tick: 0,
            select_task: None,
            phantom: std::marker::PhantomData,
        }
    }
}

//========== Feedback
/// Nop feedback that annotates execution time in the new testcase, if any
/// for this Feedback, the testcase is never interesting (use with an OR).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ClockTimeFeedback<SYS> {
    exec_time: Option<Duration>,
    select_task: Option<String>,
    name: Cow<'static, str>,
    dump_path: Option<PathBuf>,
    phantom: std::marker::PhantomData<SYS>,
}

impl<S, SYS> StateInitializer<S> for ClockTimeFeedback<SYS> where SYS: TargetSystem {}

impl<EM, I, OT, S, SYS> Feedback<EM, I, OT, S> for ClockTimeFeedback<SYS>
where
    S: State + UsesInput + MaybeHasClientPerfMonitor + HasMetadata,
    <S as UsesInput>::Input: Default,
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
    {
        #[cfg(feature = "trace_job_response_times")]
        let icount = {
            if let Some(select) = self.select_task.as_ref() {
                match state.metadata::<SYS::TraceData>() {
                    Ok(trace) => trace.wort_of_task(select),
                    Err(_) => {
                        eprintln!("[WARN] TraceData not available in feedback, falling back to observer");
                        let icount = observers
                            .match_name::<QemuClockObserver<SYS>>(self.name())
                            .map(|observer| observer.last_runtime());
                        if let Some(icount) = icount {
                            icount
                        } else {
                            eprintln!("[WARN] QemuClockObserver not found, falling back to raw icount");
                            unsafe { libafl_qemu::sys::icount_get_raw() }
                        }
                    }
                }
            } else {
                let icount = observers
                    .match_name::<QemuClockObserver<SYS>>(self.name())
                    .map(|observer| observer.last_runtime());
                if let Some(icount) = icount {
                    icount
                } else {
                    eprintln!("[WARN] QemuClockObserver not found, falling back to raw icount");
                    unsafe { libafl_qemu::sys::icount_get_raw() }
                }
            }
        };
        #[cfg(not(feature = "trace_job_response_times"))]
        let icount = {
            let icount = observers
                .match_name::<QemuClockObserver<SYS>>(self.name())
                .map(|observer| observer.last_runtime());
            if let Some(icount) = icount {
                icount
            } else {
                eprintln!("[WARN] QemuClockObserver not found, falling back to raw icount");
                unsafe { libafl_qemu::sys::icount_get_raw() }
            }
        };
        self.exec_time = Some(tick_to_time(icount));
        
        // Dump the icounts to a file
        if let Some(td) = &self.dump_path {
            let metadata = state.metadata_map_mut();
            let timestamp = SystemTime::now()
                .duration_since(unsafe { FUZZ_START_TIMESTAMP })
                .unwrap()
                .as_millis();
            let hist = metadata_insert_or_update_get::<IcHist>(
                metadata,
                || IcHist(
                    vec![(icount, timestamp)],
                    (icount, timestamp),
                ),
                |hist| {
                    hist.0.push((icount, timestamp));
                    if hist.1 .0 < icount {
                        hist.1 = (icount, timestamp);
                    }
                },
            );

            if hist.0.len() >= 100 {
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(td)
                    .expect("Could not open timedump");
                let newv: Vec<(u64, u128)> = Vec::with_capacity(110);
                for i in std::mem::replace(&mut hist.0, newv).into_iter() {
                    writeln!(file, "{},{}", i.0, i.1).expect("Write to dump failed");
                }
            }

            // write out the worst case trace
            if hist.1 == (icount, timestamp) {
                let tracename = td.with_extension("icounttrace.ron");
                match state.metadata::<SYS::TraceData>() {
                    Ok(trace) => {
                        std::fs::write(
                            tracename,
                            ron::to_string(trace)
                                .expect("Error serializing hashmap"),
                        )
                        .expect("Can not dump to file");
                    }
                    Err(_) => {
                        eprintln!("[WARN] TraceData not available for icount trace dump, skipping");
                    }
                }
            }
        }
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        *testcase.exec_time_mut() = self.exec_time;
        self.exec_time = None;
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        self.exec_time = None;
        Ok(())
    }
}

impl<SYS> Named for ClockTimeFeedback<SYS> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS: TargetSystem> ClockTimeFeedback<SYS> {
    /// Creates a new [`ClockFeedback`], deciding if the value of a [`QemuClockObserver`] with the given `name` of a run is interesting.
    #[must_use]
    pub fn new(name: &'static str, select_task: Option<String>, dump_path: Option<PathBuf>) -> Self {
        Self {
            exec_time: None,
            select_task: select_task,
            name: Cow::from(name.to_string()),
            dump_path: dump_path,
            phantom: std::marker::PhantomData,
        }
    }

    /// Creates a new [`ClockFeedback`], deciding if the given [`QemuClockObserver`] value of a run is interesting.
    #[must_use]
    pub fn new_with_observer(observer: &QemuClockObserver<SYS>, select_task: &Option<String>, dump_path: Option<PathBuf>) -> Self {
        Self {
            exec_time: None,
            select_task: select_task.clone(),
            name: observer.name().clone(),
            dump_path: dump_path,
            phantom: std::marker::PhantomData,
        }
    }
}

/// A [`Feedback`] rewarding increasing the execution cycles on Qemu.
#[derive(Debug)]
pub struct QemuClockIncreaseFeedback<SYS: TargetSystem> {
    name: Cow<'static, str>,
    phantom: std::marker::PhantomData<SYS>,
}

impl<S,SYS: TargetSystem> StateInitializer<S> for QemuClockIncreaseFeedback<SYS> {}

impl<EM, I, OT, S, SYS: TargetSystem> Feedback<EM, I, OT, S> for QemuClockIncreaseFeedback<SYS>
where
    S: State + UsesInput + HasNamedMetadata + MaybeHasClientPerfMonitor + Debug,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    {
        let observer = _observers
            .match_name::<QemuClockObserver<SYS>>("clock");
        let observer = if let Some(observer) = observer {
            observer
        } else {
            eprintln!("[WARN] QemuClockObserver not found, skipping clock increase feedback");
            return Ok(false);
        };
        let clock_state = state
            .named_metadata_map_mut()
            .get_mut::<MaxIcountMetadata>(&self.name)
            .unwrap();
        if observer.last_runtime() > clock_state.max_icount_seen {
            // println!("Clock improving {}",observer.last_runtime());
            clock_state.max_icount_seen = observer.last_runtime();
            return Ok(true);
        }
        Ok(false)
    }

    /// Append to the testcase the generated metadata in case of a new corpus item
    #[inline]
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        // testcase.metadata_mut().insert(QemuIcountMetadata{runtime: self.last_runtime});
        Ok(())
    }

    /// Discard the stored metadata in case that the testcase is not added to the corpus
    #[inline]
    fn discard_metadata(&mut self, _state: &mut S, _input: &I) -> Result<(), Error> {
        Ok(())
    }
}

impl<SYS: TargetSystem> Named for QemuClockIncreaseFeedback<SYS> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS: TargetSystem> QemuClockIncreaseFeedback<SYS> {
    /// Creates a new [`HitFeedback`]
    #[must_use]
    pub fn new(name: &'static str) -> Self {
        Self {
            name: Cow::from(String::from(name)),
            phantom: std::marker::PhantomData,
        }
    }
}

impl<SYS: TargetSystem> Default for QemuClockIncreaseFeedback<SYS> {
    fn default() -> Self {
        Self::new("MaxClock")
    }
}
