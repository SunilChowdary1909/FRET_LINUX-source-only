//! The Minimizer schedulers are a family of corpus schedulers that feed the fuzzer
//! with testcases only from a subset of the total corpus.

use core::marker::PhantomData;
use std::{cmp::{max, min}, mem::swap};

use serde::{Deserialize, Serialize};

use libafl_bolts::{rands::Rand, AsIter, HasLen};
use libafl::{
    common::HasMetadata, corpus::{Corpus, Testcase}, inputs::UsesInput, prelude::{CanTrack, CorpusId, RemovableScheduler}, schedulers::{minimizer::DEFAULT_SKIP_NON_FAVORED_PROB, Scheduler, TestcaseScore }, state::{HasCorpus, HasRand, State, UsesState}, Error, SerdeAny
    
};

use crate::time::worst::MaxTimeFavFactor;

use super::{stg::STGNodeMetadata, target_os::*};

// a state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize, SerdeAny, Default)]
pub struct LongestTracesMetadata {
    // map index -> corpus index
    pub max_trace_length: usize,
}

impl LongestTracesMetadata {
    fn new(l : usize) -> Self {
        Self {max_trace_length: l}
    }
}

// the [`MinimizerScheduler`] employs a genetic algorithm to compute a subset of the
// corpus that exercise all the requested features (e.g. all the coverage seen so far)
// prioritizing [`Testcase`]`s` using [`TestcaseScore`]
#[derive(Debug, Clone)]
pub struct LongestTraceScheduler<CS, SYS> {
    base: CS,
    skip_non_favored_prob: f64,
    phantom: PhantomData<SYS>,
}

impl<CS, SYS> UsesState for LongestTraceScheduler<CS, SYS>
where
    CS: UsesState,
{
    type State = CS::State;
}

impl<CS, SYS> Scheduler<CS::Input, CS::State> for LongestTraceScheduler<CS, SYS>
where
    CS: UsesState + Scheduler<CS::Input, CS::State>,
    CS::State: HasCorpus + HasMetadata + HasRand,
    SYS: TargetSystem,
{
    // add an entry to the corpus and return its index
    fn on_add(&mut self, state: &mut CS::State, idx: CorpusId) -> Result<(), Error> {
        let l = state.corpus()
                .get(idx)?
                .borrow()
                .metadata_map()
                .get::<SYS::TraceData>().map_or(0, |x| x.trace_length());
        self.get_update_trace_length(state,l);
        self.base.on_add(state, idx)
    }

    // replaces the testcase at the given idx
    // fn on_replace(
    //     &mut self,
    //     state: &mut CS::State,
    //     idx: CorpusId,
    //     testcase: &Testcase<<CS::State as UsesInput>::Input>,
    // ) -> Result<(), Error> {
    //     let l = state.corpus()
    //             .get(idx)?
    //             .borrow()
    //             .metadata()
    //             .get::<FreeRTOSSystemStateMetadata>().map_or(0, |x| x.trace_length);
    //     self.get_update_trace_length(state, l);
    //     self.base.on_replace(state, idx, testcase)
    // }

    // removes an entry from the corpus, returning M if M was present
    // fn on_remove(
    //     &self,
    //     state: &mut CS::State,
    //     idx: usize,
    //     testcase: &Option<Testcase<<CS::State as UsesInput>::Input>>,
    // ) -> Result<(), Error> {
    //     self.base.on_remove(state, idx, testcase)?;
    //     Ok(())
    // }

    // gets the next entry
    fn next(&mut self, state: &mut CS::State) -> Result<CorpusId, Error> {
        let mut idx = self.base.next(state)?;
        while {
            let l = state.corpus()
                    .get(idx)?
                    .borrow()
                    .metadata_map()
                    .get::<STGNodeMetadata>().map_or(0, |x| x.nodes().len());
            let m = self.get_update_trace_length(state,l);
            state.rand_mut().below(std::num::NonZero::new(m as usize+1).unwrap()) > l 
        } && state.rand_mut().coinflip(self.skip_non_favored_prob)
        {
            idx = self.base.next(state)?;
        }
        Ok(idx)
    }
    
    fn set_current_scheduled(
        &mut self,
        state: &mut <CS as UsesState>::State,
        next_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        self.base.set_current_scheduled(state, next_id)
    }
}

impl<CS, SYS> LongestTraceScheduler<CS, SYS>
where
    CS: UsesState + Scheduler<CS::Input, CS::State>,
    CS::State: HasCorpus + HasMetadata + HasRand,
    SYS: TargetSystem,
{
    pub fn get_update_trace_length(&self, state: &mut CS::State, par: usize) -> u64 {
        // Create a new top rated meta if not existing
        if let Some(td) = state.metadata_map_mut().get_mut::<LongestTracesMetadata>() {
            let m = max(td.max_trace_length, par);
            td.max_trace_length = m;
            m as u64
        } else {
            state.add_metadata(LongestTracesMetadata::new(par));
            par as u64
        }
    }
    #[allow(unused)]
    pub fn new(base: CS) -> Self {
        Self {
            base,
            skip_non_favored_prob: DEFAULT_SKIP_NON_FAVORED_PROB,
            phantom: PhantomData,
        }
    }
}

//==========================================================================================

// a state metadata holding a map of favoreds testcases for each map entry
#[derive(Debug, Serialize, Deserialize, SerdeAny, Default)]
pub struct GeneticMetadata {
    pub current_gen: Vec<(usize, f64)>,
    pub current_cursor: usize,
    pub next_gen: Vec<(usize, f64)>,
    pub gen: usize
}

impl GeneticMetadata {
    fn new(current_gen: Vec<(usize, f64)>, next_gen: Vec<(usize, f64)>) -> Self {
        Self {current_gen, current_cursor: 0, next_gen, gen: 0}
    }
}

#[derive(Debug, Clone)]
pub struct GenerationScheduler<S> {
    phantom: PhantomData<S>,
    gen_size: usize,
}

impl<S> UsesState for GenerationScheduler<S>
where
    S: State + UsesInput,
{
    type State = S;
}

impl<I, S> Scheduler<I, S> for GenerationScheduler<S>
where
    S: State + HasCorpus + HasMetadata,
    <<S as HasCorpus>::Corpus as libafl::corpus::Corpus>::Input: Clone,
{
    // get first element in current gen,
    // if current_gen is empty, swap lists, sort by FavFactor, take top k and return first
    fn next(&mut self, state: &mut S) -> Result<CorpusId, Error> {
        let mut to_remove : Vec<(usize, f64)> = vec![];
        let mut _to_return : usize = 0;
        let corpus_len = state.corpus().count();
        let mut _current_len = 0;
        let gm = state.metadata_map_mut().get_mut::<GeneticMetadata>().expect("Corpus Scheduler empty");
        // println!("index: {} curr: {:?} next: {:?} gen: {} corp: {}", gm.current_cursor, gm.current_gen.len(), gm.next_gen.len(), gm.gen,
        // c);
        match gm.current_gen.get(gm.current_cursor) {
            Some(c) => {
                _current_len = gm.current_gen.len();
                gm.current_cursor+=1;
                // println!("normal next: {}", (*c).0);
                return Ok((*c).0.into())
            },
            Option::None => {
                swap(&mut to_remove, &mut gm.current_gen);
                swap(&mut gm.next_gen, &mut gm.current_gen);
                gm.current_gen.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());
                // gm.current_gen.reverse();
                if gm.current_gen.len() == 0 {panic!("Corpus is empty");}
                let d : Vec<(usize, f64)> = gm.current_gen.drain(min(gm.current_gen.len(), self.gen_size)..).collect();
                to_remove.extend(d);
                // move all indices to the left, since all other indices will be deleted
                gm.current_gen.sort_by(|a,b| a.0.cmp(&(*b).0)); // in order of the corpus index
                // for i in 0..gm.current_gen.len() {
                //     gm.current_gen[i] = (i, gm.current_gen[i].1);
                // }
                _to_return = gm.current_gen.get(0).unwrap().0;
                // assert_eq!(to_return, 0);
                gm.current_cursor=1;
                gm.gen+=1;
                _current_len = gm.current_gen.len();
            }
        };
        // removing these elements will move all indices left by to_remove.len()
        // to_remove.sort_by(|x,y| x.0.cmp(&(*y).0));
        // to_remove.reverse();
        let cm = state.corpus_mut();
        assert_eq!(corpus_len-to_remove.len(), _current_len);
        assert_ne!(_current_len,0);
        for i in to_remove {
            cm.remove(i.0.into()).unwrap();
        }
        assert_eq!(cm.get(_to_return.into()).is_ok(),true);
        // println!("switch next: {to_return}");
        return Ok(_to_return.into());
    }

    // add the new input to the next generation
    fn on_add(
        &mut self,
        state: &mut S,
        idx: CorpusId
    ) -> Result<(), Error> {
        // println!("On Add {idx}");
        let mut tc = state.corpus_mut().get(idx).expect("Newly added testcase not found by index").borrow_mut().clone();
        let ff = MaxTimeFavFactor::compute(state, &mut tc).unwrap();
        if let Some(gm) = state.metadata_map_mut().get_mut::<GeneticMetadata>() {
            gm.next_gen.push((idx.into(),ff));
        } else {
            state.add_metadata(GeneticMetadata::new(vec![], vec![(idx.into(),ff)]));
        }
        Ok(())
    }
    
    fn set_current_scheduled(
        &mut self,
        state: &mut S,
        next_id: Option<libafl::corpus::CorpusId>,
    ) -> Result<(), Error> {
        Ok(())
    }
    // fn on_replace(
    //     &self,
    //     _state: &mut Self::State,
    //     _idx: usize,
    //     _prev: &Testcase<<Self::State as UsesInput>::Input>
    // ) -> Result<(), Error> {
    //     // println!("On Replace {_idx}");
    //     Ok(())
    // }

    // fn on_remove(
    //     &self,
    //     state: &mut Self::State,
    //     idx: usize,
    //     _testcase: &Option<Testcase<<Self::State as UsesInput>::Input>>
    // ) -> Result<(), Error> {
    //     // println!("On Remove {idx}");
    //     if let Some(gm) = state.metadata_mut().get_mut::<GeneticMetadata>() {
    //         gm.next_gen = gm.next_gen.drain(..).into_iter().filter(|x| (*x).0 != idx).collect::<Vec<(usize, f64)>>();
    //         gm.current_gen = gm.current_gen.drain(..).into_iter().filter(|x| (*x).0 != idx).collect::<Vec<(usize, f64)>>();
    //     } else {
    //         state.add_metadata(GeneticMetadata::new(vec![], vec![]));
    //     }
    //     Ok(())
    // }
}

impl<I,S> RemovableScheduler<I,S> for GenerationScheduler<S>
where
    S: State + HasCorpus + HasMetadata,
{
    // replaces the testcase at the given idx
    fn on_replace(
        &mut self,
        state: &mut <Self as UsesState>::State,
        idx: CorpusId,
        testcase: &Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }

    // removes an entry from the corpus
    fn on_remove(
        &mut self,
        state: &mut <Self as UsesState>::State,
        idx: CorpusId,
        testcase: &Option<Testcase<I>>,
    ) -> Result<(), Error> {
        Ok(())
    }
}

impl<S> GenerationScheduler<S>
{
    #[allow(unused)]
    pub fn new() -> Self {
        let gen_size = 100;
        #[cfg(feature = "gensize_1")]
        let gen_size= 1;
        #[cfg(feature = "gensize_10")]
        let gen_size= 10;
        #[cfg(feature = "gensize_100")]
        let gen_size= 100;
        #[cfg(feature = "gensize_1000")]
        let gen_size= 1000;
        Self {
            phantom: PhantomData,
            gen_size
        }
    }
}
