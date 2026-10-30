
use core::time::Duration;
use std::{env, path::PathBuf, process::{self, abort}, io::{Read, Write}, fs::{self, OpenOptions}, cmp::{min, max}, mem::transmute_copy, ptr::addr_of_mut, ffi::OsStr, sync::{Arc, Mutex}, sync::atomic::{AtomicBool, Ordering}};
use hashbrown::HashMap;
use libafl_bolts::{
core_affinity::Cores, ownedref::OwnedMutSlice, rands::StdRand, shmem::{ShMemProvider, StdShMemProvider}, tuples::tuple_list, AsSlice, SimpleStderrLogger
};
use libafl::{
common::{HasMetadata, HasNamedMetadata}, corpus::{Corpus, OnDiskCorpus}, events::{launcher::Launcher, EventConfig}, executors::ExitKind, feedback_or, feedback_or_fast, feedbacks::{CrashFeedback, MaxMapFeedback, TimeoutFeedback}, fuzzer::{Fuzzer, StdFuzzer}, inputs::{multi::MultipartInput, BytesInput, HasTargetBytes, Input}, monitors::MultiMonitor, observers::{CanTrack, VariableMapObserver}, prelude::{havoc_mutations, minimizer::TopRatedsMetadata, CorpusId, Generator, HitcountsMapObserver, RandBytesGenerator, SimpleEventManager, SimpleMonitor, SimplePrintingMonitor, SimpleRestartingEventManager, StdScheduledMutator}, schedulers::QueueScheduler, stages::StdMutationalStage, state::{HasCorpus, StdState}, Error, Evaluator
};
use libafl_qemu::{
elf::EasyElf, emu::Emulator, modules::{edges::{self}, EdgeCoverageModule, FilterList, StdAddressFilter, StdEdgeCoverageModule}, GuestAddr, GuestPhysAddr, QemuExecutor, QemuExitReason, QemuHooks, Regs
};
use libafl_targets::{edges_map_mut_ptr, EDGES_MAP_DEFAULT_SIZE, MAX_EDGES_FOUND};
use rand::{SeedableRng, StdRng, Rng};
use crate::{
    config::{get_target_ranges, get_target_symbols, resolve_target_symbols, resolve_snapshot_symbol}, systemstate::{self, feedbacks::{DumpSystraceFeedback, SystraceErrorFeedback}, helpers::{get_function_range, load_symbol, try_load_symbol}, mutational::{input_bytes_to_interrupt_times, DirectMemoryMutatorStage, LinuxIrqScheduleStage, STGSnippetStage}, schedulers::{GenerationScheduler, LongestTraceScheduler}, stg::{stg_map_mut_slice, GraphMaximizerCorpusScheduler, STGEdge, STGNode, StgFeedback, MAX_STG_NUM}, target_os::linux::{LinuxSystem, qemu_module::LinuxSystemStateHelper, ftrace_module::{FtraceSystemStateHelper, SharedEventBuffer, spawn_ftrace_reader}, analyzer::{symbols::SymbolTable, module::S32G3SystemStateModule}}}, time::{
        clock::{ClockTimeFeedback, IcHist, QemuClockIncreaseFeedback, QemuClockObserver, FUZZ_START_TIMESTAMP, QEMU_ICOUNT_SHIFT, QEMU_ISNS_PER_MSEC, QEMU_ISNS_PER_USEC}, qemustate::QemuStateRestoreHelper, worst::{AlwaysTrueFeedback, ExecTimeIncFeedback, RateLimitedMonitor, TimeMaximizerCorpusScheduler, TimeProbMassScheduler, TimeStateMaximizerCorpusScheduler}
    }
};
use std::time::SystemTime;
use petgraph::dot::Dot;
use crate::systemstate::stg::STGFeedbackState;
use libafl::inputs::HasMutatorBytes;
use libafl_qemu::Qemu;
use crate::cli::Cli;
use crate::cli::Commands;
use crate::cli::{set_env_from_config, set_env_from_config_with_key, get_interrupt_config};
use clap::Parser;
use log;
use rand::RngCore;
use crate::templates;
use std::ops::Range;

// Constants ================================================================================

pub static mut RNG_SEED: u64 = 1;

pub const FIRST_INT : u32 = 200000;

pub const MAX_NUM_INTERRUPT: usize = 128;
pub const NUM_INTERRUPT_SOURCES: usize = 64; // Increased for GIC SPI interrupts which start at 32. Keep in sync with qemu-libafl-bridge/include/libafl/interrupt_injection.h
pub static mut MAX_INPUT_SIZE: usize = 1024;

static INPUT_WRITE_VERIFIED: AtomicBool = AtomicBool::new(false);


static mut INTERRUPT_CONFIG: Vec<(usize, u32)> = Vec::new();

fn setup_interrupt_inputs(mut input: MultipartInput<BytesInput>, interrupt_config: &[(usize, u32)], mut random: Option<&mut rand::rngs::StdRng>) -> MultipartInput<BytesInput> {
    for &(source, _) in interrupt_config {
        let name = format!("isr_{}_times", source);
        if input.parts_by_name(&name).next().is_none() {
            if let Some(random) = random.as_mut() {
                use rand::RngCore;
                input.add_part(name, BytesInput::new(
                    (0..MAX_NUM_INTERRUPT)
                        .map(|_| (random.next_u32() % (100 * crate::time::clock::QEMU_ISNS_PER_MSEC)).to_le_bytes())
                        .flatten()
                        .collect(),
                ));
            } else {
                input.add_part(name, BytesInput::new(vec![0u8; MAX_NUM_INTERRUPT * 4]));
            }
        }
    }
    input
}

fn verify_input_write_once(qemu: &Qemu, addr: GuestAddr, expected: &[u8], label: &str) {
    let verify_enabled = env::var("FRET_VERIFY_INPUT").map(|v| v != "0").unwrap_or(false);
    if !verify_enabled || INPUT_WRITE_VERIFIED.swap(true, Ordering::SeqCst) {
        return;
    }

    let verify_len = expected.len().min(64);
    let mut observed = vec![0u8; verify_len];
    match qemu.read_mem(addr, &mut observed) {
        Ok(_) => {
            let expected_slice = &expected[..verify_len];
            if observed != expected_slice {
                eprintln!(
                    "[fuzz] Input write verification FAILED for {} at {:#x}: expected={:02x?} observed={:02x?}",
                    label,
                    addr,
                    expected_slice,
                    observed,
                );
                log::error!(
                    "Input write verification failed for {} at {:#x}: expected={:02x?} observed={:02x?}",
                    label,
                    addr,
                    expected_slice,
                    observed,
                );
            } else {
                eprintln!(
                    "[fuzz] Input write verification OK for {} at {:#x} (checked {} bytes)",
                    label,
                    addr,
                    verify_len,
                );
                log::info!(
                    "Input write verification OK for {} at {:#x} (checked {} bytes)",
                    label,
                    addr,
                    verify_len,
                );
            }
        }
        Err(e) => {
            eprintln!(
                "[fuzz] Input write verification READBACK-ERROR for {} at {:#x}: {:?}",
                label,
                addr,
                e,
            );
            log::warn!(
                "Could not read back {} at {:#x} for verification: {:?}",
                label,
                addr,
                e,
            );
        }
    }
}

pub fn get_all_fn_symbol_ranges(elf: &EasyElf, range: std::ops::Range<GuestAddr>) -> HashMap<String,std::ops::Range<GuestAddr>> {
    let mut ret : HashMap<String,std::ops::Range<GuestAddr>> = HashMap::new();

    let gob = elf.goblin();

    let mut funcs : Vec<_> = gob.syms.iter().filter(|x| x.is_function() && range.contains(&x.st_value.try_into().unwrap())).collect();
    funcs.sort_unstable_by(|x,y| x.st_value.cmp(&y.st_value));

    for sym in &funcs {
        let sym_name = gob.strtab.get_at(sym.st_name);
        if let Some(sym_name) = sym_name {
            // if ISR_SYMBOLS.contains(&sym_name) {continue;}; // skip select symbols, which correspond to ISR-safe system calls
            if let Some(r) = get_function_range(elf, sym_name) {
                ret.insert(sym_name.to_string(), r);
            }
        }
    }

    return ret;
}

#[allow(unused)]
extern "C" {
static mut libafl_interrupt_offsets : [[u32; MAX_NUM_INTERRUPT]; NUM_INTERRUPT_SOURCES];
static mut libafl_num_interrupts : [u64; NUM_INTERRUPT_SOURCES];
}


// append wort row per task to csv
macro_rules! do_dump_wort {
($state:expr, $cli:expr) => {
    if let Some(ref wort_path) = $cli.wort_output {
        eprintln!("DUMPING WORT! path={:?}", wort_path);
        use crate::systemstate::stg::STGFeedbackState;
        use crate::systemstate::target_os::linux::LinuxSystem;
        use crate::time::clock::{FUZZ_START_TIMESTAMP, _QEMU_NS_PER_ISN};
        let wall_secs = std::time::SystemTime::now()
            .duration_since(unsafe { FUZZ_START_TIMESTAMP })
            .unwrap_or_default()
            .as_secs();
        let variant = &$cli.variant;
        let seed = $cli.experiment_seed;
        if let Ok(mut wort_file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(wort_path)
        {
            use std::io::Write;
            // write header if file is empty
            let file_len = wort_file.metadata().map(|m| m.len()).unwrap_or(1);
            if file_len == 0 {
                let _ = writeln!(wort_file, "wall_seconds,variant,seed,task_name,wort_ticks,wort_us");
            }
            if let Some(stg_state) = $state.metadata_map().get::<STGFeedbackState<LinuxSystem>>() {
                for (_hash, task) in stg_state.worst_task_jobs.iter() {
                    let wort_us = (task.wort_ticks as u128
                        * _QEMU_NS_PER_ISN as u128
                        / 1_000u128) as u64;
                    let _ = writeln!(
                        wort_file,
                        "{},{},{},{},{},{}",
                        wall_secs, variant, seed, task.name, task.wort_ticks, wort_us
                    );
                }
            }
        }
    }
};
}

// dump worst case
macro_rules! do_dump_case {
( $s:expr,$cli:expr, $c:expr) => {
    if ($cli.dump_cases) {
        let dump_path = $cli.dump_name.clone().unwrap().with_extension(if $c=="" {"case"} else {$c});
        println!("Dumping worst case to {:?}", &dump_path);
        let corpus = $s.corpus();
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
            wi.to_file(dump_path);
        }
    }
}
}

// dump icount history
macro_rules! do_dump_times {
($state:expr, $cli:expr, $c:expr) => {
    if $cli.dump_times {
        let dump_path = $cli.dump_name.clone().unwrap().with_extension(if $c=="" {"time"} else {$c});
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(dump_path).expect("Could not open timedump");
        if let Ok(ichist) = $state.metadata_mut::<IcHist>() {
            for i in ichist.0.drain(..) {
                writeln!(file, "{},{}", i.0, i.1).expect("Write to dump failed");
            }
        }
    }
};
}

// dump current graph
macro_rules! do_dump_stg {
($state:expr, $cli:expr, $c:expr) => {
    #[cfg(feature = "trace_stg")]
    if $cli.dump_graph {
        let dump_path = $cli.dump_name.clone().unwrap().with_extension(if $c=="" {"dot"} else {$c});
        println!("Dumping graph to {:?}", &dump_path);
        if let Ok(md) = $state.metadata_mut::<STGFeedbackState<LinuxSystem>>() {
            let out = md.graph.map(|_i,x| x.color_print(&md.systemstate_index), |_i,x| x.color_print());
            let outs = Dot::with_config(&out, &[]).to_string();
            let outs = outs.replace("\\\"","\"");
            let outs = outs.replace(';',"\\n");
            fs::write(dump_path,outs).expect("Failed to write graph");
        }
    }
};
}

// dump top rated inputs
macro_rules! do_dump_toprated {
($state:expr, $cli:expr, $c:expr) => {
    if $cli.dump_cases {
        {
            let dump_path = $cli.dump_name.clone().unwrap().with_extension(if $c=="" {"toprated"} else {$c});
            println!("Dumping toprated to {:?}", &dump_path);
            if let Some(md) = $state.metadata_map_mut().get_mut::<TopRatedsMetadata>() {
                let mut uniq: Vec<CorpusId> = md.map.values().map(|x| x.clone()).collect();
                uniq.sort();
                uniq.dedup();
                fs::write(dump_path,ron::to_string(&md.map).expect("Failed to serialize metadata")).expect("Failed to write graph");
            }
        }
    }
};
}


// fuzzer setup

#[allow(unused)]
pub fn fuzz() {
log::set_max_level(log::LevelFilter::Info);
SimpleStderrLogger::set_logger().unwrap();
let cli = Cli::parse();
dbg!(&cli);
let symbols_kernel = cli.symbols.as_ref().unwrap_or(&cli.kernel);
set_env_from_config_with_key(symbols_kernel, &cli.config, cli.config_key.as_deref());
// load interrupt config
let interrupt_config = get_interrupt_config(symbols_kernel, &cli.config, cli.config_key.as_deref());
unsafe { INTERRUPT_CONFIG = interrupt_config.clone(); }
eprintln!("[fuzz] interrupt config: {:?}", interrupt_config);
// resolve target elf symbols
    let load_base: u64 = cli.target_load_base.unwrap_or(0);
    let direct_mem_targets = cli.target_elf.as_ref().map(|elf_path| {
        resolve_target_symbols(
            elf_path.as_path(),
            &cli.target_symbol,
            &cli.ready_flag_symbol,
            load_base,
        )
    });
unsafe {FUZZ_START_TIMESTAMP = SystemTime::now();}
if cli.dump_name.is_none() && (cli.dump_times || cli.dump_cases || cli.dump_traces || cli.dump_graph) {
    panic!("Dump name not give but dump is requested");
}
let mut starttime = std::time::Instant::now();
// Hardcoded parameters
    let timeout = Duration::from_millis(150);
let broker_port = cli.broker_port;
let cores = Cores::from_cmdline("1").unwrap();
// set up corpus and crash dirs
let corpus_dirs = [cli.dump_name.clone()
    .map(|x| x.with_extension("corpus"))
    .unwrap_or_else(|| PathBuf::from("./corpus"))];
let objective_dir = cli.dump_name.clone()
    .map(|x| x.with_extension("crashes"))
    .unwrap_or_else(|| PathBuf::from("./crashes"));
// ensure dirs exist
fs::create_dir_all(&corpus_dirs[0]).unwrap_or_else(|e| {
    eprintln!("[fuzzer] WARNING: Could not create corpus directory {:?}: {}", &corpus_dirs[0], e);
});
fs::create_dir_all(&objective_dir).unwrap_or_else(|e| {
    eprintln!("[fuzzer] WARNING: Could not create crashes directory {:?}: {}", &objective_dir, e);
});

let mut elf_buffer = Vec::new();
let elf = EasyElf::from_file(
    symbols_kernel,
    &mut elf_buffer,
)
.unwrap();

let TARGET_SYMBOLS: HashMap<&'static str, GuestAddr> = get_target_symbols(&elf);
    eprintln!("[fuzz] target symbols resolved:");
for (k, v) in &TARGET_SYMBOLS {
    eprintln!("[fuzz]   {} = {:#x}", k, v);
}
let TARGET_RANGES: HashMap<&'static str, Range<GuestAddr>> = get_target_ranges(&elf, &TARGET_SYMBOLS);


let daemon_snapshot_addr: Option<GuestAddr> = if !cli.snapshot_symbol.is_empty() {
    cli.target_elf.as_ref().and_then(|elf_path| {
        resolve_snapshot_symbol(elf_path.as_path(), &cli.snapshot_symbol, load_base)
    })
} else {
    None
};
if let Some(snap) = daemon_snapshot_addr {
    eprintln!("[fuzz] snapshot trigger: daemon symbol '{}' @ {:#x}", cli.snapshot_symbol, snap);
} else {
    eprintln!("[fuzz] snapshot trigger: kernel BREAKPOINT @ {:#x}", TARGET_SYMBOLS["BREAKPOINT"]);
}


   


if let Ok(input_len) = env::var("FUZZ_INPUT_LEN") {
    unsafe {MAX_INPUT_SIZE = str::parse::<usize>(&input_len).expect("FUZZ_INPUT_LEN was not a number");}
}
unsafe {dbg!(MAX_INPUT_SIZE);}

if let Ok(seed) = env::var("SEED_RANDOM") {
    unsafe {RNG_SEED = str::parse::<u64>(&seed).expect("SEED_RANDOM must be an integer.");}
}



// linux doesn't use isr_fn
let allowlist: Vec<Range<GuestAddr>> = vec![0x400000..0x500000];
let denylist = StdAddressFilter::allow_list(allowlist);



let mut run_client = |state: Option<_>, mut mgr, _core_id| {
    // Initialize QEMU
    let serial_log = env::var("QEMU_SERIAL_LOG").unwrap_or_else(|_| "/tmp/qemu-serial.log".to_string());
    let mut args: Vec<String> = vec![
        "target/debug/fret".to_string(),
        "-icount".to_string(),
        format!("shift={},align=off,sleep=on", QEMU_ICOUNT_SHIFT),
        "-machine".to_string(),
        "virt".to_string(),
        "-m".to_string(),
        "1024".to_string(),
        "-cpu".to_string(),
        "cortex-a53".to_string(),
        "-monitor".to_string(),
        "null".to_string(),
        "-kernel".to_string(),
        cli.kernel.as_os_str().to_str().expect("kernel path is not a string").to_string(),
        "-drive".to_string(),
        format!("if=none,format=raw,id=hd0,file={}", cli.rootfs.display()),
        "-device".to_string(),
        "virtio-blk-device,drive=hd0".to_string(),
        "-append".to_string(),
        "root=/dev/vda rw rootwait rootfstype=ext4 console=ttyAMA0 earlycon=pl011,0x09000000 loglevel=7 init=/sbin/init nokaslr norandmaps".to_string(),
        "-serial".to_string(),
        format!("file:{}", serial_log),
        "-nographic".to_string(),
        "-net".to_string(),
        "none".to_string(),
    ];
    if cli.variant == "ftrace" {
        let ftrace_chardev = env::var("FTRACE_CHR_LOG").unwrap_or_else(|_| "/tmp/qemu-ftrace.log".to_string());
        args.extend(vec![
            "-chardev".to_string(),
            format!("file,id=ftrace,path={}", ftrace_chardev),
            "-device".to_string(),
            "virtio-serial-device".to_string(),
            "-device".to_string(),
            "virtserialport,chardev=ftrace,name=org.fret.ftrace".to_string(),
        ]);
    }
    #[cfg(not(feature = "snapshot_fast"))]
    {
        args.push("-snapshot".to_string());
        args.push("-drive".to_string());
        args.push("if=none,format=qcow2,file=dummy.qcow2".to_string());
    }
    let env: Vec<(String, String)> = env::vars().collect();
    let qemu = Qemu::init(&args).expect("Emulator creation failed");

    let mut ftrace_helper: Option<FtraceSystemStateHelper> = None;
    if cli.variant == "ftrace" {
        let source_path = env::var("FTRACE_SOURCE").unwrap_or_else(|_| "/tmp/qemu-ftrace.log".to_string());
        let shared_buf: SharedEventBuffer = Arc::new(Mutex::new(Vec::new()));
        spawn_ftrace_reader(PathBuf::from(&source_path), Arc::clone(&shared_buf));
        ftrace_helper = Some(FtraceSystemStateHelper::new(shared_buf));
        eprintln!("[ftrace] enabled: source={}", source_path);
    }

    if let Some(&main_addr) = TARGET_SYMBOLS.get("FUZZ_MAIN") {
        eprintln!("[fuzz] FUZZ_MAIN resolved to {:#x}, setting breakpoint and running QEMU...", main_addr);
        eprintln!("[fuzz] waiting for FUZZ_MAIN breakpoint (kernel boot to userspace)...");
        qemu.set_breakpoint(main_addr);
        let run_start = std::time::Instant::now();
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {
                    eprintln!("[fuzz] FUZZ_MAIN breakpoint hit after {:.1}s real time", run_start.elapsed().as_secs_f64());
                }
                other => {
                    eprintln!("[fuzz] QEMU exited with {:?} after {:.1}s", other, run_start.elapsed().as_secs_f64());
                    panic!("Unexpected QEMU exit.");
                }
            }
        }
        qemu.remove_breakpoint(main_addr);
        
    } else {
        eprintln!("[fuzz] warning: FUZZ_MAIN not found in TARGET_SYMBOLS, skipping initial breakpoint wait.");
    }

    eprintln!("[fuzz] setting snapshot breakpoint...");
    
    let snapshot_bp_addr = daemon_snapshot_addr
        .unwrap_or(TARGET_SYMBOLS["BREAKPOINT"]);
    eprintln!("[fuzz] setting BREAKPOINT at {:#x} (daemon_snap={:?})",
        snapshot_bp_addr,
        daemon_snapshot_addr.map(|a| format!("{:#x}", a)));
    qemu.set_breakpoint(snapshot_bp_addr);

   
    {
        let snap_start = std::time::Instant::now();
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {
                    eprintln!("[fuzz] snapshot breakpoint hit after {:.1}s", snap_start.elapsed().as_secs_f64());
                }
                other => {
                    eprintln!("[fuzz] QEMU exited with {:?} before snapshot breakpoint after {:.1}s",
                        other, snap_start.elapsed().as_secs_f64());
                    // Don't panic — warmup or timeout may explain this.
                }
            }
        }
    }


    qemu.remove_breakpoint(snapshot_bp_addr);

    
    if daemon_snapshot_addr.is_some() && cli.warmup_seconds > 0 {
        qemu.set_breakpoint(TARGET_SYMBOLS["BREAKPOINT"]);
    }

    if cli.warmup_seconds > 0 {
        let warmup_start = std::time::Instant::now();
        let warmup_deadline = Duration::from_secs(cli.warmup_seconds);
        let mut warmup_hits: u64 = 0;
        eprintln!(
            "[fuzz] warmup enabled: running guest for {}s before snapshot...",
            cli.warmup_seconds
        );

        while warmup_start.elapsed() < warmup_deadline {
            unsafe {
                match qemu.run() {
                    Ok(QemuExitReason::Breakpoint(_)) => {
                        warmup_hits += 1;
                        if warmup_hits % 1000 == 0 {
                            eprintln!(
                                "[fuzz] warmup progress: {:.1}s elapsed, {} breakpoint returns",
                                warmup_start.elapsed().as_secs_f64(),
                                warmup_hits
                            );
                        }
                    }
                    Ok(QemuExitReason::Timeout) => {
                        // Timeout is expected — snapshot BP fires rarely during warmup.
                        // Keep looping until the wall-clock deadline is reached.
                        if warmup_hits % 100 == 0 {
                            eprintln!(
                                "[fuzz] warmup tick: {:.1}s elapsed",
                                warmup_start.elapsed().as_secs_f64()
                            );
                        }
                        warmup_hits += 1;
                    }
                    Ok(other) => {
                        eprintln!(
                            "[fuzz] warmup unexpected exit {:?} after {:.1}s, stopping warmup",
                            other,
                            warmup_start.elapsed().as_secs_f64()
                        );
                        break;
                    }
                    Err(err) => {
                        eprintln!(
                            "[fuzz] warmup qemu.run() error after {:.1}s: {:?}",
                            warmup_start.elapsed().as_secs_f64(),
                            err
                        );
                        break;
                    }
                }
            }
        }

        eprintln!(
            "[fuzz] warmup complete after {:.1}s ({} breakpoint returns)",
            warmup_start.elapsed().as_secs_f64(),
            warmup_hits
        );

        // CRITICAL: We must take the snapshot EXACTLY at snapshot_bp_addr,
        // so that input injection happens at the right place, and so that
        // PC != harness_breakpoint upon restore.
        eprintln!("[fuzz] Running to snapshot breakpoint {:#x} after warmup...", snapshot_bp_addr);
        qemu.remove_breakpoint(TARGET_SYMBOLS["BREAKPOINT"]);
        qemu.set_breakpoint(snapshot_bp_addr);
        unsafe {
            match qemu.run() {
                Ok(QemuExitReason::Breakpoint(_)) => {
                    eprintln!("[fuzz] Reached snapshot breakpoint for final snapshot capture!");
                }
                other => {
                    eprintln!("[fuzz] Unexpected exit before final snapshot: {:?}", other);
                }
            }
        }
        // Restore the harness breakpoint for fuzzing iterations
        qemu.remove_breakpoint(snapshot_bp_addr);
        qemu.set_breakpoint(TARGET_SYMBOLS["BREAKPOINT"]);
    }

    let devices = qemu.list_devices();
    println!("Devices = {devices:?}");

    // ── Pre-snapshot VMI hook installation ────────────────────────────────
    // CRITICAL: Instruction hooks must be installed BEFORE the fast snapshot
    // is taken. The fast snapshot includes the TCG translation cache state.
    // If hooks are installed after the snapshot (e.g. in first_exec), restoring
    // the snapshot reverts the TCG to its pre-hook state, so hooked kernel
    // addresses are never instrumented during fuzzing iterations.
    #[cfg(feature = "observe_systemstate")]
    {
        eprintln!("[fuzz] Pre-snapshot: installing VMI hooks into TCG before snapshot...");
        let syms_pre = crate::systemstate::target_os::linux::analyzer::symbols::SymbolTable::from_elf(
            symbols_kernel
        ).expect("Pre-snapshot: failed to load kernel symbols");
        let mut module_pre = crate::systemstate::target_os::linux::analyzer::module::S32G3SystemStateModule::new_from_symbols(
            &syms_pre,
            cli.select_task.clone(),
            false,
        ).expect("Pre-snapshot: failed to init state module");
        let (_, _, irq_addr) = direct_mem_targets.unwrap_or((0, 0, 0));
        module_pre.irq_signal_addr = irq_addr;
        module_pre.install_hooks(&qemu).expect("Pre-snapshot: failed to install VMI hooks");
        eprintln!("[fuzz] Pre-snapshot: VMI hooks installed. TCG will include hook callbacks.");
    }

    #[cfg(feature = "snapshot_fast")]
    let initial_snap = Some(qemu.create_fast_snapshot(true));
    #[cfg(not(feature = "snapshot_fast"))]
    let initial_snap = None;

    let harness_input_addr = TARGET_SYMBOLS["FUZZ_INPUT"];
    let harness_input_length_ptr = TARGET_SYMBOLS.get("FUZZ_LENGTH").copied();
    let harness_breakpoint = TARGET_SYMBOLS["BREAKPOINT"];

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |emulator: &mut Emulator<_, _, _, _, _>, state: &mut _, input: &MultipartInput<BytesInput>| {
        unsafe {
            // Interrupt injection from per-source MultipartInput parts (FreeRTOS FRET style)
            libafl_interrupt_offsets = [[0; MAX_NUM_INTERRUPT]; NUM_INTERRUPT_SOURCES];
            libafl_num_interrupts = [0; NUM_INTERRUPT_SOURCES];
            for &(source, min_us) in &INTERRUPT_CONFIG {
                let name = format!("isr_{}_times", source);
                let input_bytes = input.parts_by_name(&name).next().map(|x| x.1.bytes()).unwrap_or(&[]);
                let times = input_bytes_to_interrupt_times(input_bytes, (source, min_us));
                for j in 0..times.len() {
                    libafl_interrupt_offsets[source][j] = times[j];
                }
                libafl_num_interrupts[source] = times.len() as u64;
            }

            let fuzz_main_name = env::var("FUZZ_MAIN").unwrap_or_default();
            let input_mode = env::var("FRET_INPUT_MODE").unwrap_or_else(|_| "auto".to_string());
            let is_syscall = match input_mode.as_str() {
                "syscall" => true,
                "daemon" => false,
                _ => fuzz_main_name.contains("sys_"),
            };

            let mut bytes = input.parts_by_name("bytes").next().unwrap().1.bytes();
            let mut len = bytes.len();
            if len > MAX_INPUT_SIZE {
                bytes = &bytes[0..MAX_INPUT_SIZE];
                len = MAX_INPUT_SIZE;
            }

            if is_syscall {
                 let safe_input_addr = 0x48000000; // 128MB into RAM
                 qemu.write_mem(safe_input_addr, bytes);
                  verify_input_write_once(&qemu, safe_input_addr, bytes, "syscall_input_buffer");

                 let mut r0 = 0u64;
                 let mut r1 = 0u64;
                 let mut r2 = 0x48000000u64; // Default arg2 to point to buffer

                 if bytes.len() >= 8 {
                     r0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
                 }
                 if bytes.len() >= 16 {
                     r1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
                 }
               

                 // Register writes can race with timeout/exit when no current CPU is active.
                 // Avoid noisy WARN logs for that expected case, but keep warnings for real failures.
                 if qemu.current_cpu().is_some() {
                     if let Err(e) = qemu.write_reg(Regs::X0, r0) {
                         log::warn!("Failed to write X0: {:?}", e);
                     }
                     if let Err(e) = qemu.write_reg(Regs::X1, r1) {
                         log::warn!("Failed to write X1: {:?}", e);
                     }
                     if let Err(e) = qemu.write_reg(Regs::X2, r2) {
                         log::warn!("Failed to write X2: {:?}", e);
                     }
                 } else {
                     log::debug!("Skipping syscall register writes: no current CPU (timeout/exit boundary)");
                 }
                 
                 // PC is already at the target 
            } else {
                // For daemon campaigns, injection is handled by DirectMemoryMutatorStage.
                // For non-syscall campaigns, keep writing to FUZZ_INPUT/FUZZ_LENGTH.
                qemu.write_mem(harness_input_addr, bytes);
                verify_input_write_once(&qemu, harness_input_addr, bytes, "fuzz_input_buffer");
                if let Some(s) = harness_input_length_ptr {
                    qemu.write_mem(s, &(len as u32).to_le_bytes());
                }
            }

            qemu.run();

            // DIAGNOSTIC for Mode A vs Mode B:
            unsafe {
                let map_ptr = libafl_targets::edges_map_mut_ptr();
                let mut non_zero = 0;
                for i in 0..libafl_targets::EDGES_MAP_DEFAULT_SIZE {
                    if *map_ptr.add(i) != 0 {
                        non_zero += 1;
                    }
                }
                log::info!("[DIAGNOSTIC] After qemu.run(): raw edge map has {} non-zero bytes. MAX_EDGES_FOUND is {}", non_zero, libafl_targets::MAX_EDGES_FOUND);
            }

            if let Some(helper) = ftrace_helper.as_ref() {
                if matches!(cli.command, Commands::Showmap { .. }) {
                    let mut last_len = 0;
                    let mut stable_count = 0;
                    for _ in 0..30 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        let current_len = helper.buffer_len();
                        if current_len == last_len && current_len > 0 {
                            stable_count += 1;
                            if stable_count >= 2 {
                                break;
                            }
                        } else {
                            stable_count = 0;
                        }
                        last_len = current_len;
                    }
                }
                let trace_data: crate::systemstate::target_os::linux::LinuxTraceData =
                    helper.drain_to_trace_data();
                libafl::common::HasMetadata::add_metadata(state, trace_data);
            }

            // If the execution stops at any point other then the designated breakpoint (e.g. a breakpoint on a panic method) we consider it a crash
            // For Linux timeout-based harness: if breakpoint is never hit, that's normal (timeout = ok)
            let mut pcs = (0..qemu.num_cpus())
                .map(|i| qemu.cpu_from_index(i))
                .map(|cpu| -> Result<u64, _> { cpu.read_reg(Regs::Pc) });
            match pcs
                .find(|pc| (harness_breakpoint..harness_breakpoint + 5).contains(pc.as_ref().unwrap_or(&0)))
            {
                Some(_) => ExitKind::Ok,
                Option::None => {
                    
                    ExitKind::Ok
                },
            }
        }
    };

        // Create an observation channel to keep track of the execution time
        let clock_time_observer = QemuClockObserver::new("clocktime", &cli.select_task); // if cli.dump_times {cli.dump_name.clone().map(|x| x.with_extension("time"))} else {None}

        // Create an observation channel using the coverage map
        #[cfg(feature = "observe_edges")]
        let mut edges_observer = unsafe { VariableMapObserver::from_mut_slice(
            "edges",
            OwnedMutSlice::from_raw_parts_mut(edges_map_mut_ptr(), EDGES_MAP_DEFAULT_SIZE),
            addr_of_mut!(MAX_EDGES_FOUND),
        )};
        #[cfg(feature = "observe_hitcounts")]
        let mut edges_observer = HitcountsMapObserver::new(edges_observer);
        #[cfg(feature = "observe_edges")]
        let mut edges_observer = edges_observer.track_indices();

        #[cfg(feature = "observe_systemstate")]
        let stg_coverage_observer = unsafe { VariableMapObserver::from_mut_slice(
            "stg",
            stg_map_mut_slice(),
            addr_of_mut!(MAX_STG_NUM)
        )}.track_indices();

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // Time feedback, this one does not need a feedback state
            ClockTimeFeedback::<LinuxSystem>::new_with_observer(&clock_time_observer, &cli.select_task, if cli.dump_times {cli.dump_name.clone().map(|x| x.with_extension("time"))} else {None})
        );
        #[cfg(feature = "feed_genetic")]
        let mut feedback = feedback_or!(
            feedback,
            AlwaysTrueFeedback::new()
        );
        #[cfg(feature = "feed_afl")]
        let mut feedback = feedback_or!(
            feedback,
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new(&edges_observer)
        );
        #[cfg(feature = "feed_longest")]
        let mut feedback = feedback_or!(
            // afl feedback needs to be activated first for MapIndexesMetadata
            feedback,
            // Feedback to reward any input which increses the execution time
            ExecTimeIncFeedback::<LinuxSystem>::new()
        );
        #[cfg(all(feature = "observe_systemstate"))]
        let mut feedback = feedback_or!(
            feedback,
            DumpSystraceFeedback::<LinuxSystem>::with_dump(if cli.dump_traces {cli.dump_name.clone()} else {None})
        );
        #[cfg(feature = "trace_stg")]
        let mut feedback = feedback_or!(
            feedback,
            StgFeedback::<LinuxSystem>::new(cli.select_task.clone(), if cli.dump_graph {cli.dump_name.clone()} else {None})
        );
        #[cfg(feature = "feed_stg_edge")]
        let mut feedback = feedback_or!(
            feedback,
            MaxMapFeedback::new(&stg_coverage_observer)
        );

        // A feedback to choose if an input is producing an error
        let mut objective = feedback_or_fast!(CrashFeedback::new(), SystraceErrorFeedback::<LinuxSystem>::new(matches!(cli.command, Commands::Fuzz{..}), Some(10)));

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                unsafe {StdRand::with_seed(RNG_SEED) },
                // Corpus persisted to disk so interesting cases survive crashes.
                // OnDiskCorpus serialises each testcase to its own file under ./corpus/
                // and reloads them automatically on restart.
                OnDiskCorpus::new(corpus_dirs[0].clone()).unwrap(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(objective_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        // A minimization+queue policy to get testcasess from the corpus
        #[cfg(not(any(feature = "sched_afl", feature = "sched_stg", feature = "sched_genetic")))]
        let scheduler = QueueScheduler::new();  // fallback
        #[cfg(feature = "sched_afl",)]
        let scheduler = TimeMaximizerCorpusScheduler::new(&edges_observer,TimeProbMassScheduler::new());
        #[cfg(feature = "sched_stg")]
        let mut scheduler = GraphMaximizerCorpusScheduler::non_metadata_removing(&stg_coverage_observer,TimeProbMassScheduler::new());
        #[cfg(feature = "sched_stg")]
        {
            scheduler.skip_non_favored_prob = 0.8;
        }
        #[cfg(feature = "sched_genetic")]
        let scheduler = GenerationScheduler::new();

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        let qhelpers = tuple_list!();
                #[cfg(feature = "observe_systemstate")]
                let qhelpers = {
                     let syms = SymbolTable::from_elf(symbols_kernel).expect("Failed to load kernel symbols");
                     // Use --select-task as capture filter so trace collection aligns with feedback selection.
                     let mut module = S32G3SystemStateModule::new_from_symbols(&syms, cli.select_task.clone(), false).expect("Failed to init state module");
                     let (_, _, irq_addr) = direct_mem_targets.unwrap_or((0, 0, 0));
                     module.irq_signal_addr = irq_addr;
                     ({
                         let mut h = LinuxSystemStateHelper::with_input_mem(module, harness_input_addr, unsafe { MAX_INPUT_SIZE });
                         if cli.span_blocking {
                             h.span_task = cli.select_task.clone();
                             log::info!("[span_blocking] enabled for task {:?}", h.span_task);
                         }
                         h
                     }, qhelpers)
                };
        #[cfg(feature = "observe_edges")]
        let qhelpers = (
            StdEdgeCoverageModule::builder()
            .map_observer(edges_observer.as_mut())
            .address_filter(denylist)
            .build()
            .unwrap(), qhelpers);//StdEdgeCoverageModule::new(denylist, FilterList::None), qhelpers);
        let qhelpers = (QemuStateRestoreHelper::with_fast(initial_snap), qhelpers);

        let emulator = Emulator::empty().qemu(qemu).modules(qhelpers).build().unwrap();

        let observer_list = tuple_list!();
        #[cfg(feature = "observe_systemstate")]
        let observer_list = (stg_coverage_observer, observer_list);  // must come after clock
        #[cfg(feature = "observe_edges")]
        let observer_list = (edges_observer, observer_list);
        let observer_list = (clock_time_observer, observer_list);

        // Create a QEMU in-process executor
        let mut executor = QemuExecutor::new(
            emulator,
            &mut harness,
            observer_list,
            &mut fuzzer,
            &mut state,
            &mut mgr,
            timeout
        )
        .expect("Failed to create QemuExecutor");

        executor.break_on_timeout();

        let mutations = havoc_mutations();
        // Setup an havoc mutator with a mutational stage
        let mutator = StdScheduledMutator::new(mutations);

        let stages = (systemstate::report::SchedulerStatsStage::default(),());
        let mut stages = (StdMutationalStage::new(mutator), stages);
        // Wire in the DirectMemoryMutatorStage.
        // If --target-elf is provided, it will actively inject; otherwise the addresses
        // are zero and write_mem will be a harmless no-op (QEMU returns an error we ignore).
        #[cfg(feature = "mutate_stg")]
        let mut stages = {
            let (buf_addr, flag_addr, _) = direct_mem_targets.unwrap_or((0, 0, 0));
            let irq_stage = LinuxIrqScheduleStage::new(&interrupt_config);
            let mem_stage = DirectMemoryMutatorStage::new(
                buf_addr,
                cli.target_buffer_size,
                flag_addr,
                qemu,
            );
            let snippet_stage = STGSnippetStage::<_, _, _, LinuxSystem>::new(TARGET_SYMBOLS["FUZZ_INPUT"]);
            (irq_stage, (mem_stage, (snippet_stage, stages)))
        };

        if let Commands::Showmap { input } = cli.command.clone() {
            let s = input.as_os_str();
            // let show_input = BytesInput::new(if s=="-" {
            //         let mut buf = Vec::<u8>::new();
            //         std::io::stdin().read_to_end(&mut buf).expect("Could not read Stdin");
            //         buf
            //     } else if s=="$" {
            //         env::var("SHOWMAP_TEXTINPUT").expect("SHOWMAP_TEXTINPUT not set").as_bytes().to_owned()
            //     } else {
            //         // fs::read(s).expect("Input file for DO_SHOWMAP can not be read")
            //     });
            let show_input = match MultipartInput::from_file(input.as_os_str()) {
                Ok(x) => x,
                Err(_) => {
                    println!("Interpreting input file as raw input");
                    setup_interrupt_inputs(MultipartInput::from([("bytes", BytesInput::new(fs::read(input).expect("Can not read input file")))]), &interrupt_config, None)
                }
            };
            fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, show_input)
                .unwrap();
            do_dump_times!(state, &cli, "");
            do_dump_stg!(state, &cli, "");
            do_dump_wort!(state, &cli);

            if let Ok(trace) = state.metadata::<crate::systemstate::target_os::linux::LinuxTraceData>() {
                if let Some(name) = &cli.dump_name {
                     let trace_path = name.with_extension("trace.csv");
                     println!("Dumping trace CSV to {:?}", &trace_path);
                     if let Err(e) = trace_to_csv(trace, &trace_path) {
                         println!("Error dumping CSV trace: {:?}", e);
                     } else {
                        if let Ok(analyzer) = crate::systemstate::target_os::linux::analyzer::jobs::JobAnalyzer::from_csv(&trace_path) {
                            if cli.timing_export {
                                let _ = std::fs::write("timing_instance.csv", analyzer.to_timing_csv());
                                if let Ok(stg) = crate::systemstate::target_os::linux::analyzer::stg::StateTransitionGraph::from_csv(&trace_path) {
                                    let _ = std::fs::write("timing_abbs.csv", stg.to_timing_csv());
                                }
                            }
                        }
                     }
                }
            }
        } else if let Commands::Fuzz { random, time, seed } = cli.command {
            if let Some(se) = seed {
                unsafe {
                    let mut rng = StdRng::seed_from_u64(se);
                    let bound = 10000;
                    #[cfg(feature = "shortcut")]
                    let bound = 100;
                    let dump_step = Duration::from_secs(5);
                    let mut next_dump = std::time::Instant::now() + dump_step;
                    do_dump_wort!(state, &cli);
                    
                    for _ in 0..bound {
                        let inp2 = BytesInput::new((0..MAX_INPUT_SIZE).map(|_| rng.gen::<u8>()).collect());
                        let inp = setup_interrupt_inputs(MultipartInput::from([("bytes", inp2)]), &interrupt_config, Some(&mut rng));
                        fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, inp).unwrap();
                        
                        if std::time::Instant::now() >= next_dump {
                            do_dump_wort!(state, &cli);
                            next_dump = std::time::Instant::now() + dump_step;
                        }
                    }
                }
            }
            else if random {
                // Random mode generates its own inputs — seed the corpus with one
                // random input so that fuzz_loop_until has something to start with.
                unsafe {
                    let mut rng = StdRng::seed_from_u64(0);
                    let inp2 = BytesInput::new((0..MAX_INPUT_SIZE).map(|_| rng.gen::<u8>()).collect());
                    let inp = setup_interrupt_inputs(MultipartInput::from([("bytes", inp2)]), &interrupt_config, Some(&mut rng));
                    fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, inp).unwrap();
                }
                println!("Random mode: seeded corpus with 1 random input.");
            }
            else if let Ok(sf) = env::var("SEED_DIR") {
                state
                    .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &[PathBuf::from(&sf)])
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                        process::exit(0);
                    });
                println!("We imported {} inputs from seedfile.", state.corpus().count());
            } else if state.corpus().count() < 1 {
                state
                    .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &corpus_dirs)
                    .unwrap_or_else(|_| {
                        println!("Failed to load initial corpus at {:?}", &corpus_dirs);
                        process::exit(0);
                    });
                println!("We imported {} inputs from disk.", state.corpus().count());
            }

            match time {
                Option::None => {
                    fuzzer
                        .fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)
                        .unwrap();
                },
                Some(t) => {
                    println!("Iterations {}",t);
                    let num = t;
                    if random { unsafe {
                        println!("Random Fuzzing, ignore corpus");
                        // let mut generator = RandBytesGenerator::new(MAX_INPUT_SIZE);
                        let target_duration = Duration::from_secs(num);
                        let start_time = std::time::Instant::now();
                        let mut rng = StdRng::seed_from_u64(RNG_SEED);
                        let dump_step = Duration::from_secs(5);
                        let mut next_dump = start_time + dump_step;
                        do_dump_wort!(state, &cli);

                        while start_time.elapsed() < target_duration {
                            // let inp = generator.generate(&mut state).unwrap();
                            // libafl's generator is too slow
                            let inp2 = BytesInput::new((0..MAX_INPUT_SIZE).map(|_| rng.gen::<u8>()).collect());
                            let inp = setup_interrupt_inputs(MultipartInput::from([("bytes", inp2)]), &interrupt_config, Some(&mut rng));
                            fuzzer.evaluate_input(&mut state, &mut executor, &mut mgr, inp).unwrap();

                            if std::time::Instant::now() >= next_dump {
                                do_dump_wort!(state, &cli);
                                next_dump = std::time::Instant::now() + dump_step;
                            }
                        }
                        do_dump_times!(state, &cli, "");
                        do_dump_case!(state, &cli, "");
                        do_dump_stg!(state, &cli, "");
                        do_dump_toprated!(state, &cli, "");
                        do_dump_wort!(state, &cli);
                    }} else {
                        // fuzzer
                        //     .fuzz_loop_for_duration(&mut stages, &mut executor, &mut state, &mut mgr, Duration::from_secs(num))
                        //     .unwrap();
                        let deadline = starttime.checked_add(Duration::from_secs(num)).unwrap();
                        let dump_step = Duration::from_secs(5);

                        // Create/prime the CSV early so interruption still leaves a WORT artifact.
                        do_dump_wort!(state, &cli);
                        while starttime < deadline {
                            let remaining = deadline.saturating_duration_since(starttime);
                            let step = if remaining > dump_step { dump_step } else { remaining };
                            starttime = starttime.checked_add(step).unwrap();
                            fuzzer
                                .fuzz_loop_until(&mut stages, &mut executor, &mut state, &mut mgr, starttime)
                                .unwrap();
                            do_dump_wort!(state, &cli);
                        }
                            //     analyzer.to_json(&job_output_file);
                            //     if cli.timing_export {
                            //         let _ = stg.export_timing_csv(&PathBuf::from("timing_abbs.csv"));
                            //         }
                            //     }
                            // }
                            let mut dumper = |marker : String| {
                                let d = format!("{}.case",marker);
                                do_dump_case!(state, &cli, &d);
                                let _d = format!("{}.dot",marker);
                                do_dump_stg!(state, &cli, &_d);
                                let d = format!("{}.toprated",marker);
                                do_dump_toprated!(state, &cli, &d);
                            };

                            dumper(format!(".iter_{}",t));
                            do_dump_times!(state, &cli, "");

                            println!("Start running until saturation");
                            let ichist_init = state.metadata_map().get::<IcHist>().map(|h| h.1);
                            if ichist_init.is_none() {
                                println!("Warning: IcHist not available (0 iterations ran), skipping saturation");
                            }
                            let mut last = ichist_init.unwrap_or((0, 0));
                            while ichist_init.is_some() && SystemTime::now().duration_since(unsafe {FUZZ_START_TIMESTAMP}).unwrap_or_default().as_millis() < last.1 + Duration::from_secs(10800).as_millis() {
                                starttime=starttime.checked_add(Duration::from_secs(30)).unwrap();
                                fuzzer
                                    .fuzz_loop_until(&mut stages, &mut executor, &mut state, &mut mgr, starttime)
                                    .unwrap();
                                let after = state.metadata_map().get::<IcHist>().unwrap().1;
                                if after.0 > last.0 {
                                    last=after;
                                }
                                do_dump_case!(state, &cli, "");
                                do_dump_stg!(state, &cli, "");
                                do_dump_toprated!(state, &cli, "");
                                do_dump_wort!(state, &cli);
                            }
                        }
                        do_dump_times!(state, &cli, "");
                        do_dump_case!(state, &cli, "");
                        do_dump_stg!(state, &cli, "");
                        do_dump_toprated!(state, &cli, "");
                        do_dump_wort!(state, &cli);
                    }
                }
            }
        #[cfg(not(feature = "singlecore"))]
        return Ok(());
    };

    // Special case where no fuzzing happens, but standard input is dumped
    if let Ok(input_dump) = env::var("DUMP_SEED") {
        // Initialize QEMU
        let args: Vec<String> = env::args().collect();
        let env: Vec<(String, String)> = env::vars().collect();
        let emu = Qemu::init(&args).expect("Emu creation failed");

        if let Some(&main_addr) = TARGET_SYMBOLS.get("FUZZ_MAIN") {
            emu.set_breakpoint(main_addr); // BREAKPOINT 
        }
        unsafe {
            emu.run();

            let mut buf = [0u8].repeat(MAX_INPUT_SIZE);
            emu.read_mem(TARGET_SYMBOLS["FUZZ_INPUT"], buf.as_mut_slice());

            let dir = env::var("SEED_DIR").map_or("./corpus".to_string(), |x| x);
            let filename = if input_dump == "" {"input"} else {&input_dump};
            println!("Dumping input to: {}/{}",&dir,filename);
            fs::write(format!("{}/{}",&dir,filename), buf).expect("could not write input dump");
        }
        return;
}

    #[cfg(feature = "singlecore")]
    {
        let monitor = RateLimitedMonitor::new();
        #[cfg(not(feature = "restarting"))]
        {
            let mgr = SimpleEventManager::new(monitor);
            run_client(None, mgr, 0);
        }

        #[cfg(feature = "restarting")]
        {
            let mut shmem_provider = StdShMemProvider::new().unwrap();
            let (state, mgr) = match SimpleRestartingEventManager::launch(monitor, &mut shmem_provider)
            {
                // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
                Ok(res) => res,
                Err(err) => match err {
                    Error::ShuttingDown => {
                        return;
                    }
                    _ => {
                        panic!("Failed to setup the restarter: {}", err);
                    }
                },
            };
            run_client(state, mgr, 0);
        }
    }
    // else -> multicore
    #[cfg(not(feature = "singlecore"))]
    {
        // The shared memory allocator
        let shmem_provider = StdShMemProvider::new().expect("Failed to init shared memory");

        // The stats reporter for the broker
        let monitor = MultiMonitor::new(|s| println!("{}", s));

        // Build and run a Launcher
        match Launcher::builder()
            .shmem_provider(shmem_provider)
            .broker_port(broker_port)
            .configuration(EventConfig::from_build_id())
            .monitor(monitor)
            .run_client(&mut run_client)
            .cores(&cores)
            // .stdout_file(Some("/dev/null"))
            .build()
            .launch()
        {
            Ok(()) => (),
            Err(Error::ShuttingDown) => println!("Fuzzing stopped by user. Good bye."),
            Err(err) => panic!("Failed to run launcher: {:?}", err),
        }
    }
}

fn trace_to_csv(trace: &crate::systemstate::target_os::linux::LinuxTraceData, path: &PathBuf) -> Result<(), std::io::Error> {
    let mut w = std::fs::File::create(path)?;
    writeln!(w, "capture_point,pid,comm,state,parent_pid,cpu,abb_type,start_time,end_time")?;
    
    for interval in &trace.intervals {
        if let Some(state) = trace.states_map.get(&interval.start_state) {
            let pid = state.current_pid;
            let comm = &state.current_comm;
            let task_state_val = state.current_task.state; 
            let state_char = match task_state_val {
                0 => "R", // TASK_RUNNING
                1 => "S", // TASK_INTERRUPTIBLE
                2 => "D", // TASK_UNINTERRUPTIBLE
                _ => "S", // Others treated as sleeping/waiting
            };
            
            let capture_point = match interval.start_capture.0 {
                 crate::systemstate::CaptureEvent::APIStart => "APIStart",
                 crate::systemstate::CaptureEvent::APIEnd => "APIEnd",
                 crate::systemstate::CaptureEvent::ISRStart => "ISRStart",
                 crate::systemstate::CaptureEvent::ISREnd => "ISREnd",
                 crate::systemstate::CaptureEvent::End => "End",
                 _ => "Unknown",
            };
            
            let abb_type = match interval.level {
                0 => "UserSlice",
                1 => "Syscall",
                2 => "ISR",
                _ => "Unknown",
            };
            
            writeln!(w, "{},{},{},{},{},{},{},{},{}", 
                capture_point, pid, comm, state_char, state.current_task.parent_pid, state.current_task.cpu, abb_type, interval.start_tick, interval.end_tick)?;
        }
    }
    Ok(())
}
