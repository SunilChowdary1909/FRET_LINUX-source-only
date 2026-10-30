use libafl::{events::EventFirer, inputs::UsesInput, prelude::{Feedback, ObserversTuple, StateInitializer}};
use libafl_bolts::Named;
use libafl_qemu::{modules::EmulatorModule, EmulatorModules};
use std::borrow::Cow;
use libafl::prelude::*;
use libafl_qemu::modules::*;
use libafl_qemu::*;

//============================================== Feedback

// example Feedback for type correctness
#[derive(Clone, Debug, Default)]
pub struct MinimalFeedback {
    // the name
    name: Cow<'static, str>,
}

impl<S> StateInitializer<S> for MinimalFeedback {}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for MinimalFeedback
where
    S: State + UsesInput<Input=I>,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        state: &mut S,
        manager: &mut EM,
        input: &I,
        observers: &OT,
        exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        Ok(false)
    }
}

impl Named for MinimalFeedback {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

//============================================== TestcaseScore

pub struct MinimalTestcaseScore {}

impl<S> TestcaseScore<S> for MinimalTestcaseScore
where
    S: HasMetadata + HasCorpus,
{
    fn compute(
        _state: &S,
        entry: &mut Testcase<<S::Corpus as Corpus>::Input>,
    ) -> Result<f64, Error> {
        Ok(0 as f64)
    }
}

//============================================== EmulatorModule

#[derive(Debug)]
pub struct MinimalEmulatorModule {
    af: NopAddressFilter,
    pf: NopPageFilter
}

impl<S> EmulatorModule<S> for MinimalEmulatorModule
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;
    type ModuleAddressFilter = NopAddressFilter;
    type ModulePageFilter = NopPageFilter;


    // hook run **before** QEMU is initialized
    // this is always run when Emulator gets initialized, in any case
    // install here hooks that should be alive for the whole execution of the VM, even before QEMU gets initialized
    fn pre_qemu_init<ET>(&self, _emulator_hooks: &mut EmulatorHooks<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    // hook run **after** QEMU is initialized
    // this is always run when Emulator gets initialized, in any case
    // install here hooks that should be alive for the whole execution of the VM, after QEMU gets initialized
    fn post_qemu_init<ET>(&self, _emulator_modules: &mut EmulatorModules<ET, S>)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    // run once just before fuzzing starts
    // this call can be delayed to the point at which fuzzing is supposed to start
    // it is mostly used to avoid running hooks during VM initialization, either
    // because it is useless or it would produce wrong results
    fn first_exec<ET>(&mut self, _emulator_modules: &mut EmulatorModules<ET, S>, _state: &mut S)
    where
        ET: EmulatorModuleTuple<S>,
    {
    }

    // run before a new fuzzing run starts
    // on the first run, it is executed after [`Self::first_exec`]
    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
    }

    // run after a fuzzing run ends
    fn post_exec<OT, ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
        _observers: &mut OT,
        _exit_kind: &mut ExitKind,
    ) where
        OT: ObserversTuple<S::Input, S>,
        ET: EmulatorModuleTuple<S>,
    {
    }

    // # Safety
    //
    // this is getting executed in a signal handler
    unsafe fn on_crash(&mut self) {}

    // # Safety
    //
    // this is getting executed in a signal handler
    unsafe fn on_timeout(&mut self) {}

    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        &self.af
    }
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        &mut self.af
    }
    fn update_address_filter(&mut self, qemu: Qemu, filter: Self::ModuleAddressFilter) {
    }

    fn page_filter(&self) -> &Self::ModulePageFilter {
        &self.pf
    }
    
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        &mut self.pf
    }
}