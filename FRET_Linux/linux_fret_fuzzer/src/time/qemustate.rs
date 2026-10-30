use libafl::prelude::UsesInput;
use libafl_qemu::modules::NopAddressFilter;
use libafl_qemu::modules::NopPageFilter;
use libafl_qemu::sys::CPUArchState;
use libafl_qemu::FastSnapshotPtr;
use libafl_qemu::modules::EmulatorModule;
use libafl_qemu::modules::EmulatorModuleTuple;
use libafl::executors::ExitKind;
use libafl_qemu::QemuHooks;
use libafl_qemu::EmulatorModules;
use libafl::prelude::ObserversTuple;

// TODO be thread-safe maybe with https://amanieu.github.io/thread_local-rs/thread_local/index.html
#[derive(Debug)]
pub struct QemuStateRestoreHelper {
    #[allow(unused)]
    has_snapshot: bool,
    #[allow(unused)]
    saved_cpu_states: Vec<CPUArchState>,
    fastsnap: Option<FastSnapshotPtr>
}

impl QemuStateRestoreHelper {
    #[must_use]
    pub fn new() -> Self {
        Self {
            has_snapshot: false,
            saved_cpu_states: vec![],
            fastsnap: None
        }
    }
    #[allow(unused)]
    pub fn with_fast(fastsnap: Option<FastSnapshotPtr>) -> Self {
        let mut r = Self::new();
        r.fastsnap = fastsnap;
        r
    }
}

impl Default for QemuStateRestoreHelper {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> EmulatorModule<S> for QemuStateRestoreHelper
where
    S: UsesInput,
{
    const HOOKS_DO_SIDE_EFFECTS: bool = true;
    type ModuleAddressFilter = NopAddressFilter;
    type ModulePageFilter = NopPageFilter;

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
        // unsafe { println!("snapshot post {}",emu::icount_get_raw()) };
    }

    fn pre_exec<ET>(
        &mut self,
        _emulator_modules: &mut EmulatorModules<ET, S>,
        _state: &mut S,
        _input: &S::Input,
    ) where
        ET: EmulatorModuleTuple<S>,
    {
        // only restore in pre-exec, to preserve the post-execution state for inspection
        #[cfg(feature = "snapshot_restore")]
        {
            #[cfg(feature = "snapshot_fast")]
            match self.fastsnap {
                Some(s) => unsafe { _emulator_modules.qemu().restore_fast_snapshot(s) },
                None => {self.fastsnap = Some(_emulator_modules.qemu().create_fast_snapshot(true));},
            }
            #[cfg(not(feature = "snapshot_fast"))]
            if !self.has_snapshot {
                _emulator_modules.qemu().save_snapshot("Start", true);
                self.has_snapshot = true;
            }
            else
            {
                _emulator_modules.qemu().load_snapshot("Start", true);
            }
        }
        #[cfg(not(feature = "snapshot_restore"))]
        if !self.has_snapshot {
            self.saved_cpu_states = (0.._emulator_modules.qemu().num_cpus())
                .map(|i| _emulator_modules.qemu().cpu_from_index(i).save_state())
                .collect();
            self.has_snapshot = true;
        } else {
            for (i, s) in self.saved_cpu_states.iter().enumerate() {
                _emulator_modules.qemu().cpu_from_index(i).restore_state(s);
            }
        }

        // unsafe { println!("snapshot pre {}",emu::icount_get_raw()) };
    }
    
    fn address_filter(&self) -> &Self::ModuleAddressFilter {
        todo!()
    }
    
    fn address_filter_mut(&mut self) -> &mut Self::ModuleAddressFilter {
        todo!()
    }
    
    fn page_filter(&self) -> &Self::ModulePageFilter {
        todo!()
    }
    
    fn page_filter_mut(&mut self) -> &mut Self::ModulePageFilter {
        todo!()
    }
}