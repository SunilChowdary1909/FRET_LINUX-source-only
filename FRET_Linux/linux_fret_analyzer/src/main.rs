use anyhow::{Context, Result};
use clap::Parser;
use libafl_qemu::{
    Emulator, GuestAddr, Qemu, QemuExecutor,
};
use log::{info, warn};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

mod module;
mod structures;
mod symbols;
mod stg;
mod jobs;

use module::{S32G3SystemStateModule, OutputFormat, set_output_format};
use structures::*;
use symbols::SymbolTable;


static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

const QEMU_ICOUNT_SHIFT: u32 = 5;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the vmlinux ELF with symbols
    #[clap(long, default_value = "../linux_artifacts/vmlinux")]
    vmlinux: PathBuf,

    /// Path to the compressed Kernel Image
    #[clap(long, default_value = "../linux_artifacts/Image")]
    image: PathBuf,

    /// Path to RootFS ext4
    #[clap(long, default_value = "../linux_artifacts/rootfs.ext4")]
    rootfs: PathBuf,

    /// Number of iterations to run
    #[clap(short, long, default_value = "500000")]
    iterations: u64,

    /// Output file for trace data
    #[clap(short, long, default_value = "trace.json")]
    output: PathBuf,

    /// Output format
    #[clap(long, value_enum, default_value = "json")]
    output_format: OutputFormat,

    /// Verbose output
    #[clap(short, long)]
    verbose: bool,

    #[clap(long)]
    filter_process: Option<String>,

    #[clap(long)]
    skip_idle: bool,
    
    #[clap(long)]
    stg: Option<PathBuf>,
    
    #[clap(long, default_value = "stg.dot")]
    stg_output: PathBuf,
    
    #[clap(long, default_value = "dot")]
    stg_format: String,
    
    #[clap(long)]
    wcet: bool,
    
    /// WCET analysis output file
    #[clap(long, default_value = "wcet.json")]
    wcet_output: PathBuf,

    #[clap(long)]
    jobs: bool,
    
    /// Job analysis output file
    #[clap(long, default_value = "jobs.json")]
    pub jobs_output: PathBuf,

    #[clap(long)]
    pub timing_export: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger
    if args.verbose {
        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    if let Some(trace_csv) = &args.stg {
        info!("=== STG Analysis Mode ===");
        info!("Input trace: {}", trace_csv.display());
        info!("Output: {} ({})", args.stg_output.display(), args.stg_format);
        
        let stg = stg::StateTransitionGraph::from_csv(trace_csv)
            .context("Failed to build STG from trace")?;
        
        stg.print_summary();
        stg.save(&args.stg_output, &args.stg_format)
            .context("Failed to save STG")?;
        
        info!("STG saved to: {}", args.stg_output.display());
        
        // Run WCET analysis
        if args.wcet {
            info!("\n=== WCET Analysis ===");
            stg.print_wcet_report();
            stg.save_wcet(&args.wcet_output)
                .context("Failed to save WCET analysis")?;
            info!("WCET analysis saved to: {}", args.wcet_output.display());
        }
        

        
        // Run Job analysis
        let job_analyzer = if args.jobs || args.timing_export {
            info!("\n=== Job Analysis ===");
            let analyzer = jobs::JobAnalyzer::from_csv(trace_csv)
                .context("Failed to analyze jobs from trace")?;
            analyzer.print_summary();
            Some(analyzer)
        } else {
            None
        };

        if let Some(analyzer) = &job_analyzer {
            if args.jobs {
                analyzer.save(&args.jobs_output)
                    .context("Failed to save job analysis")?;
                info!("Job analysis saved to: {}", args.jobs_output.display());
            }
        }

        if args.timing_export {
            info!("\n=== Waters Compatibility Mode ===");

            let abbs_path = trace_csv.with_file_name("linux_timing_abbs.csv");
            let stg = stg::StateTransitionGraph::from_csv(trace_csv)
                .context("Failed to build STG for Waters compatibility")?;
            std::fs::write(&abbs_path, stg.to_timing_csv())
                .context("Failed to save linux_timing_abbs.csv")?;
            info!("Waters-compatible ABBs saved to: {}", abbs_path.display());

            if let Some(analyzer) = &job_analyzer {
                let instance_path = trace_csv.with_file_name("linux_timing_instance.csv");
                std::fs::write(&instance_path, analyzer.to_timing_csv())
                    .context("Failed to save linux_timing_instance.csv")?;
                info!("Waters-compatible instances saved to: {}", instance_path.display());

                let job_csv_path = trace_csv.with_file_name("linux_timing_job.csv");
                std::fs::write(&job_csv_path, analyzer.to_timing_job_csv())
                    .context("Failed to save linux_timing_job.csv")?;
                info!("Waters-compatible job CSV saved to: {}", job_csv_path.display());

                let job_html_path = trace_csv.with_file_name("linux_timing_job.html");
                std::fs::write(&job_html_path, analyzer.to_timing_job_html())
                    .context("Failed to save linux_timing_job.html")?;
                info!("Waters-compatible job HTML saved to: {}", job_html_path.display());
            }
        }
        
        return Ok(());
    }

    info!("=== S32G3 FRET Analyzer ===");
    info!("vmlinux: {}", args.vmlinux.display());
    info!("Image: {}", args.image.display());
    info!("Iterations: {}", args.iterations);


    ctrlc::set_handler(move || {
        info!("Ctrl+C received, requesting shutdown...");
        SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
    }).expect("Error setting Ctrl+C handler");

 
    if !args.vmlinux.exists() {
        anyhow::bail!("vmlinux file not found: {}", args.vmlinux.display());
    }
    if !args.image.exists() {
        anyhow::bail!("Kernel Image not found: {}", args.image.display());
    }

    info!("Parsing ELF symbols...");
    info!("Parsing ELF symbols from vmlinux...");
    let symbols = SymbolTable::from_elf(&args.vmlinux)
        .context("Failed to parse ELF symbols from vmlinux")?;

    if args.verbose {
        info!("Symbol table contains {} symbols", symbols.list_all().len());
    }

    // Create module with filtering options
    info!("Creating system state module...");
    let mut module = S32G3SystemStateModule::new_from_symbols(
        &symbols,
        args.filter_process.clone(),
        args.skip_idle,
    )?;

    info!("Initializing QEMU with LibAFL...");

   
    let args_qemu = vec![
        "qemu-system-aarch64".to_string(),
        "-M".to_string(),
        "virt".to_string(),
        "-cpu".to_string(),
        "cortex-a53".to_string(),
        "-icount".to_string(),
        format!("shift={},align=off,sleep=on", QEMU_ICOUNT_SHIFT),
        "-smp".to_string(),
        "1".to_string(),
        "-m".to_string(),
        "128".to_string(),
        "-nodefaults".to_string(),
        "-nographic".to_string(),
        "-serial".to_string(),
        "mon:stdio".to_string(),
        // External interrupt source: virtio-rng generates IRQs 
        "-device".to_string(),
        "virtio-rng-device".to_string(),
        "-kernel".to_string(),
        args.image.to_str().unwrap().to_string(),
        "-drive".to_string(),
        format!("file={},format=raw,id=hd0", args.rootfs.to_str().unwrap()),
        "-append".to_string(),
        "root=/dev/vda rw console=ttyAMA0 earlycon".to_string(),
    ];

    let emu = Qemu::init(&args_qemu).context("Failed to initialize QEMU")?;

    info!("QEMU initialized successfully");

    // Install hooks at kernel functions
    module.install_hooks(&emu)?;

    module::set_output_path(args.output.clone());
    module::set_output_format(args.output_format);

    // Run analysis
    run_analysis(&emu, &mut module, args.iterations)?;

    // Save results
    info!("Saving results to {}", args.output.display());
    module.save_results(&args.output)?;

    info!("Analysis complete!");
    Ok(())
}

fn run_analysis(
    emu: &Qemu,
    module: &mut S32G3SystemStateModule,
    iterations: u64,
) -> Result<()> {
    info!("Starting analysis for {} iterations...", iterations);

    let mut iteration = 0;
    let mut syscall_count = 0u64;

    info!("Starting kernel execution...");

    loop {
       
        match unsafe { emu.run() } {
            Ok(exit_reason) => {
                
                module.mark_icount_ready();

                
                if module.states_captured.len() as u64 >= iterations {
                    info!(
                        "Reached {} captured events via hooks, stopping",
                        module.states_captured.len()
                    );
                    break;
                }

            
                if let Ok(count) = module.read_syscall_count(emu) {
                    if count > syscall_count {
                        syscall_count = count;
                        if syscall_count % 10 == 0 {
                            info!("Observed {} syscalls so far...", syscall_count);
                        }
                    }
                }

                iteration += 1;
                if iteration % 1000 == 0 {
                    info!("Iteration {}...", iteration);
                }
            }
            Err(e) => {
                warn!("QEMU execution error: {:?}", e);
                break;
            }
        }

        
        if iteration > 1000000 {
            warn!("Reached maximum iteration count");
            break;
        }

        if SHUTDOWN_REQUESTED.load(Ordering::Relaxed) {
            info!("Shutdown requested, stopping analysis...");
            break;
        }
    }

    info!(
        "Captured {} states (observed {} syscalls)",
        module.states_captured.len(),
        syscall_count
    );
    Ok(())
}
