//! Stage to compute/report AFL stats

use core::{marker::PhantomData, time::Duration};

use libafl_bolts::current_time;

use itertools::Itertools;

use libafl::{
    corpus::{Corpus, HasCurrentCorpusId}, events::EventFirer, schedulers::minimizer::TopRatedsMetadata, schedulers::RemovableScheduler, schedulers::minimizer::IsFavoredMetadata, stages::Stage, state::{HasCorpus, HasImported, UsesState}, Error, HasMetadata, HasScheduler
};
use libafl::prelude::UsesInput;
use libafl::{
    events::Event,
    monitors::{AggregatorOps, UserStats, UserStatsValue},
};
use std::borrow::Cow;
use serde_json::json;

use libafl::prelude::mutational::MUTATION_STAGE_ITER;
use libafl::prelude::mutational::MUTATION_STAGE_RETRY;
use libafl::prelude::mutational::MUTATION_STAGE_SUCCESS;

use libafl::HasNamedMetadata;
use libafl::prelude::Feedback;
use libafl::prelude::HasMaxSize;
use libafl::prelude::HasSolutions;
use libafl::prelude::HasExecutions;
use std::hash::Hash;
use libafl_bolts::HasLen;
use libafl::prelude::mutational::MutatedTransform;
use libafl::prelude::FeedbackFactory;
use serde::Serialize;
use libafl::prelude::ObserversTuple;
use libafl::prelude::HasObservers;
use libafl::HasFeedback;
use libafl::ExecutesInput;
use libafl::ExecutionProcessor;

use crate::time::clock::{tick_to_time, time_to_tick, IcHist};

// the [`AflStatsStage`] is a simple stage that computes and reports some stats
#[derive(Debug, Clone)]
pub struct SchedulerStatsStage<E, EM, Z> {
    last_report_time: Duration,
    // the interval that we report all stats
    stats_report_interval: Duration,

    phantom: PhantomData<(E, EM, Z)>,
}

impl<E, EM, Z> UsesState for SchedulerStatsStage<E, EM, Z>
where
    E: UsesState,
{
    type State = E::State;
}

// impl<E, EM, Z> Stage<E, EM, Z> for SchedulerStatsStage<E, EM, Z>
// where
//     E: UsesState,
//     EM: UsesState<State = Self::State>,
//     Z: UsesState<State = Self::State>,
//     Self::State: HasNamedMetadata,
//     // E: UsesState,
//     // EM: EventFirer<State = Self::State>,
//     // Z: UsesState<State = Self::State> + HasScheduler,
//     // <Z as HasScheduler>::Scheduler: UsesState+RemovableScheduler<<<Z as HasScheduler>::Scheduler as UsesInput>::Input, Self::State>,
//     // Self::State: HasImported + HasCorpus + HasMetadata,
//     // <E as UsesState>::State: HasMetadata+HasImported+UsesState,
// {
impl<E, EM, IP, Z> Stage<E, EM, Z> for SchedulerStatsStage<E, EM, Z>
where
    Z: HasScheduler + ExecutionProcessor<EM, E::Observers> + ExecutesInput<E, EM> + HasFeedback,
    Z::Scheduler: RemovableScheduler<Self::Input, Self::State>,
    E: HasObservers + UsesState<State = Z::State>,
    E::Observers: ObserversTuple<Self::Input, Self::State> + Serialize,
    EM: EventFirer<State = Self::State>,
    // FF: FeedbackFactory<F, E::Observers>,
    // F: Feedback<EM, Self::Input, E::Observers, Self::State>,
    Self::Input: MutatedTransform<Self::Input, Self::State, Post = IP> + Clone,
    Z::State:
        HasMetadata + HasExecutions + HasSolutions + HasCorpus + HasMaxSize + HasNamedMetadata,
    Z::Feedback: Feedback<EM, Self::Input, E::Observers, Self::State>,
    // M: Mutator<Self::Input, Self::State>,
    // IP: MutatedTransformPost<Self::State> + Clone,
    <<Self as UsesState>::State as HasCorpus>::Corpus: Corpus<Input = Self::Input>, // delete me
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        _executor: &mut E,
        state: &mut <Self as UsesState>::State,
        _manager: &mut EM,
    ) -> Result<(), Error> {
        // let Some(corpus_idx) = state.current_corpus_id()? else {
        //     return Err(Error::illegal_state(
        //         "state is not currently processing a corpus index",
        //     ));
        // };


        // let corpus_size = state.corpus().count();

        let cur = current_time();

        if cur.checked_sub(self.last_report_time).unwrap_or_default() > self.stats_report_interval {
            let wort = tick_to_time(state.metadata_map().get::<IcHist>().unwrap_or(&IcHist::default()).1.0);
            if let Some(meta) = state.metadata_map().get::<TopRatedsMetadata>() {
                let kc = meta.map.keys().count();
                let mut v : Vec<_> = meta.map.values().cloned().collect();
                v.sort_unstable();
                v.dedup();
                let vc = v.len();
                #[cfg(feature = "std")]
                {
                    let json = json!({
                        "relevant":vc,
                        "objects":kc,
                    });
                    _manager.fire(
                        state,
                        Event::UpdateUserStats {
                            name: Cow::from("Minimizer"),
                            value: UserStats::new(
                                UserStatsValue::String(Cow::from(json.to_string())),
                                AggregatorOps::None,
                            ),
                            phantom: PhantomData,
                        },
                    )?;
                }
                #[cfg(not(feature = "std"))]
                log::info!(
                    "pending: {}, pend_favored: {}, own_finds: {}, imported: {}",
                    pending_size,
                    pend_favored_size,
                    self.own_finds_size,
                    self.imported_size
                );
                self.last_report_time = cur;
                // Experimental pruning
                #[cfg(any(feature = "sched_stg",feature = "sched_afl"))]
                {
                    const MULTI: usize = 10;
                    const PRUNE_THRESHOLD: usize = 20;
                    const PRUNE_MAX_KEEP: usize = 1000;
                    const PRUNE_MIN_KEEP: usize = 100;
                    let cc = state.corpus().count();
                    let to_keep = usize::max(vc*MULTI, PRUNE_MIN_KEEP);
                    let activate = cc > PRUNE_MAX_KEEP || cc > usize::max(vc*PRUNE_THRESHOLD, PRUNE_MIN_KEEP*2);
                    let mut wort_preserved = false;
                    if activate {
                        println!("Pruning corpus, keeping {} / {}", to_keep, cc);
                        let corpus = state.corpus_mut();
                        let currid = corpus.current();
                        let ids : Vec<_> = corpus.ids().filter_map(|x| {
                            let tc = corpus.get(x).unwrap().borrow();
                            let md = tc.metadata_map();
                            if !wort_preserved && tc.exec_time() == &Some(wort) && wort>Duration::ZERO { 
                                wort_preserved = true; // Keep the worst observed under all circumstances
                                Some((x, tc.exec_time().clone())) 
                            } else {
                                if vc < PRUNE_MAX_KEEP && (md.get::<IsFavoredMetadata>().is_some() || &Some(x) == currid || v.contains(&&x)) {
                                    None
                                } else {
                                    Some((x, tc.exec_time().clone()))
                                }
                            }
                        }).sorted_by_key(|x| x.1).take(usize::saturating_sub(corpus.count(),to_keep)).sorted_by_key(|x| x.0).unique().rev().collect();
                        for (cid, _) in ids {
                            let c = state.corpus_mut().remove(cid).unwrap();
                            fuzzer
                                .scheduler_mut()
                                .on_remove(state, cid, &Some(c))?;
                        }
                    }
                }
                #[cfg(feature = "std")]
                unsafe {
                    let _ = _manager.fire(
                        state,
                        Event::UpdateUserStats {
                            name: Cow::from("StdMutationalStage"),
                            value: UserStats::new(
                                UserStatsValue::String(Cow::from(format!("{} -> {}/{} {:.1}% ", MUTATION_STAGE_ITER, MUTATION_STAGE_SUCCESS, MUTATION_STAGE_RETRY, MUTATION_STAGE_SUCCESS as f32 * 100.0 / MUTATION_STAGE_RETRY as f32))),
                                AggregatorOps::None,
                            ),
                            phantom: PhantomData,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    #[inline]
    fn should_restart(&mut self, _state: &mut <Self as UsesState>::State) -> Result<bool, Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(true)
    }

    #[inline]
    fn clear_progress(&mut self, _state: &mut <Self as UsesState>::State) -> Result<(), Error> {
        // Not running the target so we wont't crash/timeout and, hence, don't need to restore anything
        Ok(())
    }
}

impl<E, EM, Z> SchedulerStatsStage<E, EM, Z> {
    // create a new instance of the [`AflStatsStage`]
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            stats_report_interval: interval,
            ..Default::default()
        }
    }
}

impl<E, EM, Z> Default for SchedulerStatsStage<E, EM, Z> {
    // the default instance of the [`AflStatsStage`]
    #[must_use]
    fn default() -> Self {
        Self {
            last_report_time: current_time(),
            stats_report_interval: Duration::from_secs(3),
            phantom: PhantomData,
        }
    }
}
