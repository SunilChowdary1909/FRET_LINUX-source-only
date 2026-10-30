use libafl::{
    common::HasMetadata,
    executors::ExitKind,
    feedbacks::Feedback,
    observers::ObserversTuple,
    prelude::{State, UsesInput},
    state::{HasCorpus, MaybeHasClientPerfMonitor},
    Error,
    corpus::Corpus,
    inputs::Input,
};
use libafl::events::EventFirer;
use libafl_bolts::Named;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use super::target_os::TargetSystem;
use std::borrow::Cow;
use std::marker::PhantomData;

use crate::systemstate::target_os::*;
use libafl::prelude::StateInitializer;

//=========================== Debugging Feedback
// a [`Feedback`] meant to dump the system-traces for debugging. Depends on [`QemuSystemStateObserver`]
#[derive(Debug)]
pub struct DumpSystraceFeedback<SYS>
where
    SYS: TargetSystem,
{
    name: Cow<'static, str>,
    dumpfile: Option<PathBuf>,
    phantom: PhantomData<SYS>,
    init_time: Instant,
    last_dump: Option<Instant>,
}

impl<S, SYS> StateInitializer<S> for DumpSystraceFeedback<SYS> where SYS: TargetSystem {}

impl<EM, I, OT, S, SYS> Feedback<EM, I, OT, S> for DumpSystraceFeedback<SYS>
where
    S: State + UsesInput + MaybeHasClientPerfMonitor + HasMetadata + HasCorpus<Corpus: Corpus<Input=I>>,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
    SYS: TargetSystem,
    I: Input,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
where {
        match &self.dumpfile {
            Some(s) => {
                let time_has_come = true;
                if time_has_come {
                    self.last_dump = Some(Instant::now());
                    // Try dumping the worst case
                    let casename = s.with_file_name(&(s.file_stem().unwrap().to_str().unwrap().to_owned()+&format!("_at_{}h", (Instant::now()-self.init_time).as_secs()/3600))).with_extension("case");
                    let corpus = state.corpus();
                    let mut worst = Duration::new(0,0);
                    let mut worst_input = None;
                    for i in 0..corpus.count() {
                        let tc = corpus.get(corpus.nth(i.into())).expect("Could not get element from corpus").borrow();
                        if worst < tc.exec_time().expect("Testcase missing duration") {
                            worst_input = Some(tc.input().as_ref().unwrap().clone());
                            worst = tc.exec_time().expect("Testcase missing duration");
                        }
                    }
                    if let Some(wi) = worst_input {
                        wi.to_file(casename).expect("Could not dump testcase");
                    }

                    // Try dumping the current case
                    let tracename = s.with_extension("trace.ron");
                    match state.metadata::<SYS::TraceData>() {
                        Ok(trace) => {
                            std::fs::write(
                                tracename,
                                ron::to_string(trace)
                                    .expect("Error serializing hashmap"),
                            )
                            .expect("Can not dump to file");

                            // --- FRET Analyzer Native Export ---
                            let base_dir = s.parent().unwrap_or(std::path::Path::new("."));
                            
                            // 1. Dump Native Trace to JSON instead of RON
                            let json_path = base_dir.join("trace_amsr_fresh.json");
                            if let Ok(json_str) = serde_json::to_string_pretty(trace) {
                                let _ = std::fs::write(json_path, json_str);
                            }

                            // 2. Generate Bridging CSV
                            let csv_path = s.with_extension("trace.csv");
                            if let Ok(mut file) = std::fs::File::create(&csv_path) {
                                use std::io::Write;
                                let _ = writeln!(file, "capture_point,pid,comm,state,parent_pid,cpu,abb_type,abb_start,abb_end");
                                for interval in trace.intervals() {
                                    if let Some(sys) = trace.states_map().get(&interval.start_state) {
                                        use crate::systemstate::target_os::SystemState;
                                        use crate::systemstate::target_os::TaskControlBlock;
                                        let task = sys.current_task();
                                        let task_json = serde_json::to_value(task).ok();
                                        let pid = task_json
                                            .as_ref()
                                            .and_then(|v| v.get("pid"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let comm = task.task_name();
                                        let state_val = task_json
                                            .as_ref()
                                            .and_then(|v| v.get("state"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let parent_pid = task_json
                                            .as_ref()
                                            .and_then(|v| v.get("parent_pid"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let cpu = task_json
                                            .as_ref()
                                            .and_then(|v| v.get("cpu"))
                                            .and_then(|v| v.as_u64())
                                            .unwrap_or(0);
                                        let abb_type = interval.get_task_name_unchecked();
                                        let start = interval.start_tick;
                                        let end = interval.end_tick;
                                        let _ = writeln!(file, "FretInterval,{},\"{}\",{},{},{},{},{},{}", 
                                            pid, comm, state_val, parent_pid, cpu, abb_type, start, end);
                                    }
                                }
                            }

                            // 3. Pass to Analyzer Crate internally
                            let instance_csv = base_dir.join("timing_instance_amsr.csv");
                            let abbs_csv = base_dir.join("timing_abbs_amsr.csv");
                            
                            if let Ok(stg) = linux_fret_analyzer::stg::StateTransitionGraph::from_csv(&csv_path) {
                                let _ = stg.save_wcet(base_dir.join("wcet_multi_amsr.json"));
                                let _ = stg.save(base_dir.join("trace_amsr_fresh.dot"), "dot");
                                let _ = std::fs::write(&abbs_csv, stg.to_timing_csv());
                            }
                            let mut run_rscript = false;
                            
                            if let Ok(jobs) = linux_fret_analyzer::jobs::JobAnalyzer::from_csv(&csv_path) {
                                let _ = jobs.save(base_dir.join("jobs_multi_amsr.json"));
                                let _ = jobs.save_crpd(base_dir.join("crpd_multi_amsr.json"));
                                let jobs_csv_content = jobs.to_timing_csv();
                                let _ = std::fs::write(&instance_csv, &jobs_csv_content);
                                
                                // Only run Gantt plot if there is actually instance data (more than just the header row)
                                if jobs_csv_content.lines().count() > 1 {
                                    run_rscript = true;
                                } else {
                                    println!("[INFO] Skipping HTML Gantt generation because the trace contained no matching jobs.");
                                }
                            }
                            
                            // 4. Optionally run Gantt HTML build
                            // Note: Rscript must be installed in the host OS 
                            
                            if run_rscript {
                                // The CSV and HTML paths must be absolute because we change the command's current_dir
                                let html_path = std::fs::canonicalize(base_dir).unwrap_or_else(|_| PathBuf::from(".")).join("trace_amsr_fresh_job.html");
                                let abs_instance_csv_path = std::fs::canonicalize(&instance_csv).unwrap_or(instance_csv.clone());
                                let abs_abbs_csv_path = std::fs::canonicalize(&abbs_csv).unwrap_or(abbs_csv.clone());
                                let plot_tools = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                                    .join("../../WORK/FRET/LibAFL/fuzzers/FRET/tools/bin");
                                
                                let _ = std::process::Command::new("Rscript")
                                        .current_dir(plot_tools)
                                        .arg("plot_gantt.r") // Navigate up to parent directory
                                        .arg(&abs_instance_csv_path) // csv_file_a (requires start/end/state/state_id)
                                        .arg(&abs_abbs_csv_path)     // csv_file_b
                                        .arg("html")
                                        .arg(&html_path)
                                        .status();
                            }
                                    
                            // --- End Native Export ---
                        }
                        Err(_) => {
                            eprintln!("[WARN] TraceData not available for dump, skipping trace dump");
                        }
                    }
                }
            }
            Option::None => {
                ()
            }
        };
        Ok(false)
    }
}

impl<SYS> Named for DumpSystraceFeedback<SYS>
where
    SYS: TargetSystem,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS> DumpSystraceFeedback<SYS>
where
    SYS: TargetSystem,
{
    // creates a new [`DumpSystraceFeedback`]
    #[allow(unused)]
    pub fn new() -> Self {
        Self {
            name: Cow::from("Dumpsystemstate".to_string()),
            dumpfile: None,
            phantom: PhantomData,
            init_time: std::time::Instant::now(),
            last_dump: None,
        }
    }
    #[allow(unused)]
    pub fn with_dump(dumpfile: Option<PathBuf>) -> Self {
        Self {
            name: Cow::from("Dumpsystemstate".to_string()),
            dumpfile: dumpfile,
            phantom: PhantomData,
            init_time: std::time::Instant::now(),
            last_dump: None,
        }
    }
}

#[derive(Debug, Default)]
pub struct SystraceErrorFeedback<SYS>
where
    SYS: TargetSystem,
{
    name: Cow<'static, str>,
    dump_case: bool,
    max_reports: Option<usize>,
    phantom: std::marker::PhantomData<SYS>,
}

impl<S, SYS> StateInitializer<S> for SystraceErrorFeedback<SYS> where SYS: TargetSystem {}

impl<EM, I, OT, S, SYS> Feedback<EM, I, OT, S> for SystraceErrorFeedback<SYS>
where
    S: State + UsesInput + MaybeHasClientPerfMonitor + HasMetadata,
    EM: EventFirer<State = S>,
    OT: ObserversTuple<I, S>,
    SYS: TargetSystem,
{
    fn is_interesting(
        &mut self,
        state: &mut S,
        _manager: &mut EM,
        _input: &I,
        _observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
where {
        #[cfg(feature = "trace_stg")]
        {
            if let Some(m) = self.max_reports {
                if m <= 0 {
                    return Ok(false);
                }
                let need_to_debug = match state.metadata::<SYS::TraceData>() {
                    Ok(meta) => meta.need_to_debug(),
                    Err(_) => return Ok(false),
                };
                if need_to_debug {
                    self.max_reports = Some(m - 1);
                }
                return Ok(self.dump_case && need_to_debug);
            } else {
                return Ok(false);
            }
        }
        #[cfg(not(feature = "trace_stg"))]
        {
            return Ok(false);
        }
    }
}

impl<SYS> Named for SystraceErrorFeedback<SYS>
where
    SYS: TargetSystem,
{
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}

impl<SYS> SystraceErrorFeedback<SYS>
where
    SYS: TargetSystem,
{
    #[must_use]
    pub fn new(dump_case: bool, max_reports: Option<usize>) -> Self {
        Self {
            name: Cow::from(String::from("SystraceErrorFeedback")),
            dump_case,
            max_reports,
            phantom: std::marker::PhantomData,
        }
    }
}
