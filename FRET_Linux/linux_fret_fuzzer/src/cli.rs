use clap::{Parser, Subcommand};
use std::path::PathBuf;

// Argument parsing ================================================================================

#[derive(Parser,Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    // kernel Image
    #[arg(short, long, value_name = "FILE")]
    pub kernel: PathBuf,

    // kernel ELF with symbols (vmlinux). Defaults to --kernel when omitted
    #[arg(long, value_name = "FILE")]
    pub symbols: Option<PathBuf>,

    // sets a custom config file
    #[arg(short, long, value_name = "FILE")]
    pub config: PathBuf,

    // sets the prefix of dumed files
    #[arg(short='n', long, value_name = "FILENAME")]
    pub dump_name: Option<PathBuf>,

    // do time dumps
    #[arg(short='t', long)]
    pub dump_times: bool,

    // do worst-case dumps
    #[arg(short='a', long)]
    pub dump_cases: bool,

    // do trace dumps (if supported)
    #[arg(short='r', long)]
    pub dump_traces: bool,

    // do graph dumps (if supported)
    #[arg(short='g', long)]
    pub dump_graph: bool,

    // select a task for measurments
    // select a task for measurments
    #[arg(short='s', long)]
    pub select_task: Option<String>,

    /// Let the measured task's job span blocking (sleep) intervals, so the
    /// response window covers release-to-completion rather than a single run
    /// slice. Off by default: preserves FRET's original run-slice semantics.
    #[arg(long)]
    pub span_blocking: bool,

    // generate Timing telemetry CSV reports (timing_abbs.csv, timing_instance.csv)
    #[arg(long)]
    pub timing_export: bool,

    // path to root filesystem image for QEMU
    #[arg(long, value_name = "FILE")]
    pub rootfs: PathBuf,

    // ---- Direct Memory Fuzzing Harness ----

    // path to the target daemon ELF binary (for symbol extraction)
    // example: /path/to/install/opt/amsr_em_daemon/bin/amsr_em_daemon
    #[arg(long, value_name = "FILE")]
    pub target_elf: Option<PathBuf>,

    // name of the global input-buffer symbol inside --target-elf
    // this buffer is where the fuzzer injects mutated bytes
    // example: fuzz_input_buffer
    #[arg(long, value_name = "SYMBOL", default_value = "fuzz_input_buffer")]
    pub target_symbol: String,

    // byte size of the input buffer (used to clamp injections)
    #[arg(long, value_name = "BYTES", default_value_t = 1024)]
    pub target_buffer_size: usize,

    // name of the boolean ready-flag symbol inside --target-elf
    // the fuzzer writes `1` here after injecting to wake the daemon
    // example: fuzz_data_ready
    #[arg(long, value_name = "SYMBOL", default_value = "fuzz_data_ready")]
    pub ready_flag_symbol: String,

    // name of a symbol inside --target-elf to use as the QEMU snapshot trigger
    // qEMU boots the guest and runs until this symbol executes, then snaps
    // defaults to "main" so that the daemon must have started before the snapshot
    // is taken, ensuring the daemon appears in all subsequent fuzzing traces
    // set to an empty string to fall back to the CSV BREAKPOINT symbol
    #[arg(long, value_name = "SYMBOL", default_value = "fuzz_snapshot_point")]
    pub snapshot_symbol: String,

    // Override the config lookup key used to select a row from a CSV config.
    #[arg(long, value_name = "KEY")]
    pub config_key: Option<String>,

    // runtime load base for a PIE (DYN) target ELF, in hex (e.g. 0x400000)
    // or decimal.  The fuzzer adds this offset to every symbol value read from
    // --target-elf before using it as a QEMU guest virtual address
    #[arg(long, value_name = "ADDR", value_parser = parse_u64_hex_or_dec)]
    pub target_load_base: Option<u64>,


    // libAFL broker TCP port.  Use different ports when running multiple
    // campaigns in parallel to avoid port conflicts (default: 1337)
    #[arg(long, value_name = "PORT", default_value_t = 1337)]
    pub broker_port: u16,

    // real-time warmup period before creating the campaign snapshot
    // during warmup, QEMU keeps running and can reach later userspace activity
    #[arg(long, value_name = "SECONDS", default_value_t = 0)]
    pub warmup_seconds: u64,

    // variant label written into WORT timeseries CSV (e.g. "vmi", "ftrace", "blind")
    // has no effect on fuzzer logic — purely for result tagging
    #[arg(long, value_name = "LABEL", default_value = "vmi")]
    pub variant: String,

    // numeric seed label written into WORT timeseries CSV
    // should match the seed passed to `fuzz --seed`
    #[arg(long, value_name = "N", default_value_t = 0)]
    pub experiment_seed: u64,

    // path for the WORT-over-time CSV output file
    // each row: wall_seconds,variant,seed,task_name,wort_ticks,wort_us
    // if omitted, no WORT timeseries is written
    #[arg(long, value_name = "FILE")]
    pub wort_output: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}
#[derive(Subcommand,Clone,Debug)]
pub enum Commands {
    // run a single input
    Showmap {
        // take this input
        #[arg(short, long)]
        input: PathBuf,
    },
    // start fuzzing campaign
    Fuzz {
        // disable heuristic
        #[arg(short, long)]
        random: bool,
        // seed for randomness
        #[arg(short, long)]
        seed: Option<u64>,
        // runtime in seconds
        #[arg(short, long)]
        time: Option<u64>,
    }
}

// accept both `0x1a2b3c` hex strings and plain decimal integers
pub fn parse_u64_hex_or_dec(s: &str) -> Result<u64, String> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).map_err(|e| format!("invalid hex '{}': {}", s, e))
    } else {
        s.parse::<u64>().map_err(|e| format!("invalid integer '{}': {}", s, e))
    }
}

// Set target environment variables from either KEY=VALUE text or a CSV config.
// `config_key` overrides the default kernel-stem lookup for CSV configs.
pub fn set_env_from_config_with_key(kernel: &PathBuf, path: &PathBuf, config_key: Option<&str>) {
    let is_csv = path.as_path().extension().map_or(false, |x| x == "csv");
    if !is_csv {
        // Plain KEY=VAL file — key override is not meaningful here, load as-is.
        let lines = std::fs::read_to_string(path).expect("Config file not found");
        for line in lines.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with('#')) {
            let (key, value) = line.split_once('=').expect("Expected KEY=VALUE in config");
            std::env::set_var(key.trim(), value.trim());
        }
        return;
    }
    let mut reader = csv::Reader::from_path(path).expect("CSV read from config failed");
    let lookup_key: String = config_key
        .map(|k| k.to_owned())
        .unwrap_or_else(|| {
            kernel
                .as_path()
                .file_stem()
                .expect("Kernel filename error")
                .to_str()
                .unwrap()
                .to_owned()
        });
    let mut found = false;
    for r in reader.records() {
        let rec = r.expect("CSV entry error");
        if lookup_key == rec[0].trim() {
            println!("Config from file {:?}  (key='{}')", rec, lookup_key);
            found = true;
            std::env::set_var("FUZZ_MAIN", &rec[1]);
            std::env::set_var("FUZZ_INPUT", &rec[2]);
            std::env::set_var("FUZZ_INPUT_LEN", &rec[3]);
            std::env::set_var("BREAKPOINT", &rec[4]);
            break;
        }
    }
    if !found {
        eprintln!("[config] ERROR: No row found for key '{}' in {:?}. Check --config-key or add the row.", lookup_key, path);
        std::process::exit(1);
    }
}

pub fn set_env_from_config(kernel : &PathBuf, path : &PathBuf) {
    set_env_from_config_with_key(kernel, path, None);
}

// Parse interrupt settings from the text config's INTERRUPTS value or CSV column 6.
// format: "source_idx#min_inter_arrival_us;source_idx#min_inter_arrival_us;..."
// e.g. "1#500;46#200;47#500"
// returns Vec<(source_idx, min_inter_arrival_us)>
pub fn get_interrupt_config(kernel: &std::path::PathBuf, path: &std::path::PathBuf, config_key: Option<&str>) -> Vec<(usize, u32)> {
    let is_csv = path.as_path().extension().map_or(false, |x| x == "csv");
    if !is_csv {
        let contents = std::fs::read_to_string(path).expect("Config file not found");
        let value = contents.lines().find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key.trim() == "INTERRUPTS").then_some(value.trim())
        });
        return value.map(parse_interrupt_config).unwrap_or_default();
    }
    let mut reader = csv::Reader::from_path(path).expect("CSV read from config failed");
    let lookup_key: String = config_key
        .map(|k| k.to_owned())
        .unwrap_or_else(|| {
            kernel
                .as_path()
                .file_stem()
                .expect("Kernel filename error")
                .to_str()
                .unwrap()
                .to_owned()
        });
    for r in reader.records() {
        let rec = r.expect("CSV entry error");
        if lookup_key == rec[0].trim() {
            let ret = parse_interrupt_config(&rec[6]);
            println!("Interrupt config {:?}", ret);
            return ret;
        }
    }
    Vec::new()
}

fn parse_interrupt_config(value: &str) -> Vec<(usize, u32)> {
    value
        .split(';')
        .filter(|entry| !entry.trim().is_empty())
        .map(|entry| {
            let (source, min_us) = entry
                .trim()
                .split_once('#')
                .expect("Interrupt config error: expected source#min_us");
            (
                source
                    .parse()
                    .expect("Interrupt config error: source_idx not a number"),
                min_us
                    .parse()
                    .expect("Interrupt config error: min_us not a number"),
            )
        })
        .collect()
}
// does not use interrupt timing configurations.