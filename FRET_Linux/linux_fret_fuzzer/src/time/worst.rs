use core::{fmt::Debug, marker::PhantomData};

use std::{
    borrow::Cow, ops::Sub, time::{Duration, Instant}
};

use serde::{Serialize, Deserialize};

use libafl::{
    common::HasMetadata,
    corpus::{Corpus, Testcase},
    events::EventFirer,
    executors::ExitKind,
    feedbacks::{Feedback, MapIndexesMetadata},
    observers::ObserversTuple,
    prelude::{ClientStats, Monitor, SimplePrintingMonitor, State, StateInitializer, UsesInput},
    schedulers::{MinimizerScheduler, ProbabilitySamplingScheduler, TestcaseScore},
    state::{HasCorpus, MaybeHasClientPerfMonitor, UsesState},
    Error,
};
use libafl_bolts::{ClientId, HasLen, Named};

use crate::systemstate::target_os::TargetSystem;
use crate::time::clock::QemuClockObserver;

//=========================== Scheduler

pub type TimeMaximizerCorpusScheduler<CS, O> =
    MinimizerScheduler<CS, MaxTimeFavFactor, MapIndexesMetadata, O>;

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct MaxTimeFavFactor {}

impl<S> TestcaseScore<S> for MaxTimeFavFactor
where
    S: HasCorpus,
{
    fn compute(
        _state: &S,
        entry: &mut Testcase<<S::Corpus as Corpus>::Input>,
    ) -> Result<f64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        let et = entry
            .exec_time()
            .expect("testcase.exec_time is needed for scheduler");
        let tns: i64 = et.as_nanos().try_into().expect("failed to convert time");
        Ok(-tns as f64)
    }
}

pub type LenTimeMaximizerCorpusScheduler<CS, O> =
    MinimizerScheduler<CS, MaxExecsLenFavFactor<<CS as UsesState>::State>, MapIndexesMetadata, O>;

pub type TimeStateMaximizerCorpusScheduler<CS, O, SYS> =
    MinimizerScheduler<CS, MaxTimeFavFactor, <SYS as TargetSystem>::TraceData, O>;

/// Multiply the testcase size with the execution time.
/// This favors small and quick testcases.
#[derive(Debug, Clone)]
pub struct MaxExecsLenFavFactor<S>
where
    S: HasCorpus + HasMetadata,
    <S::Corpus as Corpus>::Input: HasLen,
{
    phantom: PhantomData<S>,
}

impl<S> TestcaseScore<S> for MaxExecsLenFavFactor<S>
where
    S: HasCorpus + HasMetadata,
    <<S as HasCorpus>::Corpus as libafl::corpus::Corpus>::Input: HasLen,
{
    fn compute(
        state: &S,
        entry: &mut Testcase<<S::Corpus as Corpus>::Input>,
    ) -> Result<f64, Error> {
        let execs_per_hour = (3600.0
            / entry
                .exec_time()
                .expect("testcase.exec_time is needed for scheduler")
                .as_secs_f64());
        let execs_times_length_per_hour =
            execs_per_hour * entry.load_len(state.corpus()).unwrap() as f64;
        Ok(execs_times_length_per_hour)
    }
}

//===================================================================
/// A Feedback which rewards each increase in execution time
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ExecTimeIncFeedback<SYS: TargetSystem> {
    name: Cow<'static, str>,
    longest_time: u64,
    last_is_longest: bool,
    phantom: PhantomData<SYS>,
}

impl<S, SYS: TargetSystem> StateInitializer<S> for ExecTimeIncFeedback<SYS> {}

impl<EM, I, OT, S, SYS: TargetSystem> Feedback<EM, I, OT, S> for ExecTimeIncFeedback<SYS>
where
    S: State + UsesInput + MaybeHasClientPerfMonitor,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    {
        let observer = observers
            .match_name::<QemuClockObserver<SYS>>("clocktime")
            .expect("QemuClockObserver not found");
        if observer.last_runtime() > self.longest_time {
            self.longest_time = observer.last_runtime();
            self.last_is_longest = true;
            Ok(true)
        } else {
            self.last_is_longest = false;
            Ok(false)
        }
    }
    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        observers: &OT,
        testcase: &mut Testcase<I>,
    ) -> Result<(), Error> {
        #[cfg(feature = "feed_afl")]
        if self.last_is_longest {
            let mim: Option<&mut MapIndexesMetadata> = testcase.metadata_map_mut().get_mut();
            // pretend that the longest input alone excercises some non-existing edge, to keep it relevant
            mim.unwrap().list.push(usize::MAX);
        };
        Ok(())
    }
}

impl<SYS: TargetSystem> Named for ExecTimeIncFeedback<SYS> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS: TargetSystem> ExecTimeIncFeedback<SYS> {
    /// Creates a new [`ExecTimeReachedFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::from("ExecTimeReachedFeedback".to_string()),
            longest_time: 0,
            last_is_longest: false,
            phantom: PhantomData,
        }
    }
}

/// A Noop Feedback which records a list of all execution times
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AlwaysTrueFeedback {
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for AlwaysTrueFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for AlwaysTrueFeedback
where
    S: State + UsesInput + MaybeHasClientPerfMonitor,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    {
        Ok(true)
    }
}

impl Named for AlwaysTrueFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl AlwaysTrueFeedback {
    /// Creates a new [`ExecTimeCollectorFeedback`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            name: Cow::from("AlwaysTrueFeedback".to_string()),
        }
    }
}

//=========================== Probability Mass Scheduler

pub type TimeProbMassScheduler<S> = ProbabilitySamplingScheduler<TimeProbFactor<S>>;

#[derive(Debug, Clone)]
pub struct TimeProbFactor<S>
where
    S: HasCorpus,
{
    phantom: PhantomData<S>,
}

// impl<S> UsesState for TimeProbMassScheduler<S> {
//     type State = S;
// }

impl<S> TestcaseScore<S> for TimeProbFactor<S>
where
    S: HasCorpus,
{
    fn compute(
        _state: &S,
        entry: &mut Testcase<<S::Corpus as Corpus>::Input>,
    ) -> Result<f64, Error> {
        // TODO maybe enforce entry.exec_time().is_some()
        let et = entry
            .exec_time()
            .expect("testcase.exec_time is needed for scheduler");
        let tns: i64 = et.as_nanos().try_into().expect("failed to convert time");
        Ok(((tns as f64) / 1000.0).powf(2.0)) //microseconds
    }
}

/// Monitor that prints with a limited rate.
#[derive(Debug, Clone)]
pub struct RateLimitedMonitor {
    inner: SimplePrintingMonitor,
    last: Instant,
}

impl Monitor for RateLimitedMonitor {
    /// The client monitor, mutable
    fn client_stats_mut(&mut self) -> &mut Vec<ClientStats> {
        self.inner.client_stats_mut()
    }

    /// The client monitor
    fn client_stats(&self) -> &[ClientStats] {
        self.inner.client_stats()
    }

    /// Time this fuzzing run stated
    fn start_time(&self) -> Duration {
        self.inner.start_time()
    }

    /// Time this fuzzing run stated
    fn set_start_time(&mut self, time: Duration) {
        self.inner.set_start_time(time);
    }

    #[inline]
    fn display(&mut self, event_msg: &str, sender_id: ClientId) {
        let now = Instant::now();
        const RATE: Duration = Duration::from_secs(5);
        if (event_msg != "Testcase" && event_msg != "UserStats")
            || now.duration_since(self.last) > RATE
        {
            self.inner.display(event_msg, sender_id);
            self.last = now;
        }
    }
}

impl RateLimitedMonitor {
    /// Create new [`NopMonitor`]
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: SimplePrintingMonitor::new(),
            last: Instant::now().sub(Duration::from_secs(7200)),
        }
    }
}

impl Default for RateLimitedMonitor {
    fn default() -> Self {
        Self::new()
    }
}
