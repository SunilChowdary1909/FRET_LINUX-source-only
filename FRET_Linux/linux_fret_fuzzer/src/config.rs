use goblin::elf::Elf;
use goblin::elf::header::ET_DYN;
use hashbrown::HashMap;
use libafl_qemu::{elf::EasyElf, GuestAddr};
use std::{env, path::Path};

use crate::systemstate::helpers::{load_symbol, try_load_symbol};

// ============================================================================
// Target Symbol Resolution (Direct Memory Fuzzing)
// ============================================================================
pub fn resolve_target_symbols(
    elf_path: &Path,
    buffer_symbol: &str,
    flag_symbol: &str,
    load_base: u64,
) -> (GuestAddr, GuestAddr, GuestAddr) {
    let bytes = std::fs::read(elf_path)
        .unwrap_or_else(|e| panic!("Cannot read target ELF {:?}: {}", elf_path, e));

    let elf = Elf::parse(&bytes)
        .unwrap_or_else(|e| panic!("Cannot parse target ELF {:?}: {}", elf_path, e));

    let mut buffer_raw: Option<u64> = None;
    let mut flag_raw: Option<u64>   = None;
    let mut irq_raw: Option<u64>    = None;

    // Guard: PIE binary with no load base → every computed address would be wrong.
    if elf.header.e_type == ET_DYN && load_base == 0 {
        eprintln!(
            "[config] FATAL: {:?} is a PIE (ET_DYN) binary but --target-load-base was not \
             supplied (or is zero).\n\
             All symbol offsets are ELF-relative and will not match the QEMU guest VA.\n\
             \u{2022} Disable ASLR in the guest:  echo 0 > /proc/sys/kernel/randomize_va_space\n\
             \u{2022} Then find the load base once:  grep amsr_em_daemon /proc/<pid>/maps\n\
             \u{2022} Pass it as:  --target-load-base 0x<base>",
            elf_path
        );
        std::process::exit(1);
    }

    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == buffer_symbol {
                buffer_raw = Some(sym.st_value);
            } else if name == flag_symbol {
                flag_raw = Some(sym.st_value);
            } else if name == "irq_signal_seq" {
                irq_raw = Some(sym.st_value);
            }
        }
        if buffer_raw.is_some() && flag_raw.is_some() && irq_raw.is_some() {
            break;
        }
    }

    let buffer_raw = buffer_raw.unwrap_or_else(|| {
        panic!(
            "Symbol '{}' not found in {:?}. Did you compile the daemon with the fuzz buffer?",
            buffer_symbol, elf_path
        )
    });
    let flag_raw = flag_raw.unwrap_or_else(|| {
        panic!(
            "Symbol '{}' not found in {:?}. Did you compile the daemon with the fuzz ready flag?",
            flag_symbol, elf_path
        )
    });
    let irq_addr = if let Some(raw) = irq_raw { (load_base + raw) as GuestAddr } else { 0 };
    
    let buffer_addr = (load_base + buffer_raw) as GuestAddr;
    let flag_addr   = (load_base + flag_raw)   as GuestAddr;

    eprintln!(
        "[fuzz] '{}': raw=0x{:x}  base=0x{:x}  guest_va=0x{:x}",
        buffer_symbol, buffer_raw, load_base, buffer_addr
    );
    eprintln!(
        "[fuzz] '{}': raw=0x{:x}  base=0x{:x}  guest_va=0x{:x}",
        flag_symbol, flag_raw, load_base, flag_addr
    );
    eprintln!(
        "[fuzz] 'irq_signal_seq': raw=0x{:x}  base=0x{:x}  guest_va=0x{:x}",
        irq_raw.unwrap_or(0), load_base, irq_addr
    );

    (buffer_addr, flag_addr, irq_addr)
}

// resolve a single named symbol from the daemon ELF as a snapshot-trigger address
// `Some(guest_vaddr)` if the symbol is present, `None` otherwise
pub fn resolve_snapshot_symbol(elf_path: &Path, symbol: &str, load_base: u64) -> Option<GuestAddr> {
    let bytes = std::fs::read(elf_path).ok()?;
    let elf = Elf::parse(&bytes).ok()?;
    for sym in &elf.syms {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name == symbol && sym.st_value != 0 {
                let raw  = sym.st_value;
                let addr = (load_base + raw) as GuestAddr;
                eprintln!(
                    "[fuzz] snapshot-symbol '{}': raw=0x{:x}  base=0x{:x}  guest_va=0x{:x}",
                    symbol, raw, load_base, addr
                );
                return Some(addr);
            }
        }
    }
    eprintln!("[fuzz] WARNING: snapshot-symbol '{}' not found in {:?}", symbol, elf_path);
    None
}

pub fn get_target_symbols(elf: &EasyElf) -> HashMap<&'static str, GuestAddr> {
    let mut addrs = HashMap::new();

    // FreeRTOS-specific symbols (optional for Linux)
    if let Some(addr) = try_load_symbol(&elf, "__APP_CODE_START__", false) {
        addrs.insert("__APP_CODE_START__", addr);
    }
    if let Some(addr) = try_load_symbol(&elf, "__APP_CODE_END__", false) {
        addrs.insert("__APP_CODE_END__", addr);
    }
    if let Some(addr) = try_load_symbol(&elf, "__API_CODE_START__", false) {
        addrs.insert("__API_CODE_START__", addr);
    }
    if let Some(addr) = try_load_symbol(&elf, "__API_CODE_END__", false) {
        addrs.insert("__API_CODE_END__", addr);
    }
    if let Some(addr) = try_load_symbol(&elf, "trigger_job_done", false) {
        addrs.insert("trigger_job_done", addr);
    }



    // FUZZ_MAIN may be a raw hex address (e.g. 0x400bec for userspace entry)
    // or a kernel symbol name.  try_load_symbol handles both: "0x…" prefix →
    // parse as address directly, otherwise → ELF symbol lookup.
    let main_addr = try_load_symbol(
        &elf,
        &env::var("FUZZ_MAIN").unwrap_or_else(|_| "FUZZ_MAIN".to_owned()),
        false,   // no virt→phys; FUZZ_MAIN is a guest VA breakpoint address
    );
    if let Some(main_addr) = main_addr {
        addrs.insert("FUZZ_MAIN", main_addr);
    }

    let fuzz_input_name = env::var("FUZZ_INPUT").unwrap_or_else(|_| {
        eprintln!(
            "[config] WARNING: FUZZ_INPUT env var is not set.\n\
             Falling back to a literal symbol search for 'FUZZ_INPUT'.\n\
             Set it via the config file or the FUZZ_INPUT environment variable."
        );
        "FUZZ_INPUT".to_owned()
    });
    // FUZZ_INPUT for daemon campaigns is a raw userspace VA (e.g. 0x4a1a50).
    // Kernel virt→phys translation applies to kernel-space symbols in vmlinux;
    // applying it to a userspace address gives a wrong physical address.
    // Skip translation when the value is already a raw hex address.
    let do_translate = !fuzz_input_name.starts_with("0x") && !fuzz_input_name.starts_with("0X");
    let input_addr = load_symbol(&elf, &fuzz_input_name, do_translate);
    addrs.insert("FUZZ_INPUT", input_addr);

    let input_length_ptr = try_load_symbol(
        &elf,
        &env::var("FUZZ_LENGTH").unwrap_or_else(|_| "FUZZ_LENGTH".to_owned()),
        true,
    );
    if let Some(input_length_ptr) = input_length_ptr {
        addrs.insert("FUZZ_LENGTH", input_length_ptr);
    }
    let input_counter_ptr = try_load_symbol(
        &elf,
        &env::var("FUZZ_POINTER").unwrap_or_else(|_| "FUZZ_POINTER".to_owned()),
        true,
    );
    if let Some(input_counter_ptr) = input_counter_ptr {
        addrs.insert("FUZZ_POINTER", input_counter_ptr);
    }
    let breakpoint_name = env::var("BREAKPOINT").unwrap_or_else(|_| "BREAKPOINT".to_owned());
    let breakpoint_addr = elf
        .resolve_symbol(&breakpoint_name, 0)
        .unwrap_or_else(|| {
            eprintln!(
                "[config] ERROR: BREAKPOINT symbol '{}' was not found in the kernel ELF.\n\
                 \u{2022} Set the BREAKPOINT environment variable to a valid symbol name, or\n\
                 \u{2022}                  Supply a config file (--config) whose BREAKPOINT value names a reachable symbol.\n\
                 Aborting.",
                breakpoint_name
            );
            std::process::exit(1);
        });
    addrs.insert("BREAKPOINT", breakpoint_addr);

    addrs
}

pub fn get_target_ranges(
    _elf: &EasyElf,
    symbols: &HashMap<&'static str, GuestAddr>,
) -> HashMap<&'static str, std::ops::Range<GuestAddr>> {
    let mut ranges = HashMap::new();

    // Only add ranges if FreeRTOS symbols exist
    if symbols.contains_key("__APP_CODE_START__") && symbols.contains_key("__APP_CODE_END__") {
        ranges.insert(
            "APP_CODE",
            symbols["__APP_CODE_START__"]..symbols["__APP_CODE_END__"],
        );
    }
    if symbols.contains_key("__API_CODE_START__") && symbols.contains_key("__API_CODE_END__") {
        ranges.insert(
            "API_CODE",
            symbols["__API_CODE_START__"]..symbols["__API_CODE_END__"],
        );
    }

    ranges
}
