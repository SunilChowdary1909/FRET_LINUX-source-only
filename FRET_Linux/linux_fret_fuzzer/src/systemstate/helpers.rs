use hashbrown::HashMap;
use libafl_bolts::prelude::{SerdeAny, SerdeAnyMap};
use libafl_qemu::{elf::EasyElf, GuestAddr, GuestPhysAddr};
use std::{borrow::Cow, hash::{DefaultHasher, Hash, Hasher}, ops::Range};

use super::ExecInterval;

//============================= API symbols

// resolves a virtual address to a physical address using ELF program headers
//
// # Arguments
// * `vaddr` - The virtual address to resolve
// * `tab` - The ELF file containing program headers
//
// # Returns
// the corresponding physical address, or the original address if not found
fn virt2phys(vaddr: GuestPhysAddr, tab: &EasyElf) -> GuestPhysAddr {
    let ret;
    for i in &tab.goblin().program_headers {
        if i.vm_range().contains(&vaddr.try_into().unwrap()) {
            ret = vaddr - TryInto::<GuestPhysAddr>::try_into(i.p_vaddr).unwrap()
                + TryInto::<GuestPhysAddr>::try_into(i.p_paddr).unwrap();
            return ret - (ret % 2);
        }
    }
    return vaddr;
}

// looks up a symbol in the ELF file and returns its address, optionally translating to a physical address
//
// # Arguments
// * `elf` - The ELF file to search
// * `symbol` - The symbol name to look up
// * `do_translation` - Whether to translate the address to a physical address
//
// # Panics
// panics if the symbol is not found
//
// # Returns
// the address of the symbol
pub fn load_symbol(elf: &EasyElf, symbol: &str, do_translation: bool) -> GuestAddr {
    try_load_symbol(elf, symbol, do_translation).expect(&format!("Symbol {} not found", symbol))
}

// looks up a symbol in the ELF file and returns its address, optionally translating to a physical address
//
// # Arguments
// * `elf` - The ELF file to search
// * `symbol` - The symbol name to look up
// * `do_translation` - Whether to translate the address to a physical address
//
// # Returns
// some(address) if found, None otherwise
pub fn try_load_symbol(elf: &EasyElf, symbol: &str, do_translation: bool) -> Option<GuestAddr> {
    let ret = if symbol.starts_with("0x") {
        u64::from_str_radix(&symbol[2..], 16).ok()
    } else if let Ok(val) = symbol.parse::<u64>() {
        Some(val as GuestAddr)
    } else {
        elf.resolve_symbol(symbol, 0)
    };

    if do_translation {
        Option::map_or(ret, None, |x| {
            Some(virt2phys(x as GuestPhysAddr, &elf) as GuestAddr)
        })
    } else {
        ret
    }
}

// returns the address range of a function symbol in the ELF file
//
// # Arguments
// * `elf` - The ELF file to search
// * `symbol` - The function symbol name
//
// # Returns
// some(range) if found, None otherwise
pub fn get_function_range(elf: &EasyElf, symbol: &str) -> Option<std::ops::Range<GuestAddr>> {
    let gob = elf.goblin();

    let mut funcs: Vec<_> = gob.syms.iter().filter(|x| x.is_function()).collect();
    funcs.sort_unstable_by(|x, y| x.st_value.cmp(&y.st_value));

    for sym in &gob.syms {
        if let Some(sym_name) = gob.strtab.get_at(sym.st_name) {
            if sym_name == symbol {
                if sym.st_value == 0 {
                    return None;
                } else {
                    //#[cfg(cpu_target = "arm")]
                    // Required because of arm interworking addresses aka bit(0) for thumb mode
                    let addr = (sym.st_value as GuestAddr) & !(0x1 as GuestAddr);
                    //#[cfg(not(cpu_target = "arm"))]
                    //let addr = sym.st_value as GuestAddr;
                    // look for first function after addr
                    let sym_end = funcs.iter().find(|x| x.st_value > sym.st_value);
                    if let Some(sym_end) = sym_end {
                        // println!("{} {:#x}..{} {:#x}", gob.strtab.get_at(sym.st_name).unwrap_or(""),addr, gob.strtab.get_at(sym_end.st_name).unwrap_or(""),sym_end.st_value & !0x1);
                        return Some(addr..((sym_end.st_value & !0x1) as GuestAddr));
                    }
                    return None;
                };
            }
        }
    }
    return None;
}

// checks if an address is within any of the provided ranges
//
// # Arguments
// * `ranges` - A vector of (name, range) tuples
// * `addr` - The address to check
//
// # Returns
// some(range) if the address is in any range, None otherwise
pub fn in_any_range<'a>(
    ranges: &'a Vec<(Cow<'static, str>, Range<GuestAddr>)>,
    addr: GuestAddr,
) -> Option<&'a std::ops::Range<GuestAddr>> {
    for (_, r) in ranges {
        if r.contains(&addr) {
            return Some(r);
        }
    }
    return None;
}

//============================= QEMU related utility functions

// retrieves the current QEMU instruction count
//
// # Arguments
// * `emulator` - The QEMU emulator instance
//
// # Returns
// the current instruction count as a u64
pub fn get_icount(emulator: &libafl_qemu::Qemu) -> u64 {
    unsafe {
        // TODO: investigate why can_do_io is not set sometimes, as this is just a workaround
        let c = emulator.cpu_from_index(0);
        let can_do_io = (*c.raw_ptr()).neg.can_do_io;
        (*c.raw_ptr()).neg.can_do_io = true;
        let r = libafl_qemu::sys::icount_get_raw();
        (*c.raw_ptr()).neg.can_do_io = can_do_io;
        r
    }
}

// NOTE: interrupt_times_to_input_bytes, input_bytes_to_interrupt_times, and
// read_rec_return_stackframe have been removed. These were only used by the
// old interrupt-timing-based fuzzing strategy (InterruptShiftStage).
// The new DirectMemoryMutatorStage in mutational.rs does not need them.

//============================= Tracing related utility functions

// inserts or updates metadata in a map, returning a mutable reference
//
// # Arguments
// * `metadata` - The metadata map
// * `default` - Function to create a default value if not present
// * `update` - Function to update the value if present
//
// # Returns
// a mutable reference to the metadata value
pub fn metadata_insert_or_update_get<T>(
    metadata: &mut SerdeAnyMap,
    default: impl FnOnce() -> T,
    update: impl FnOnce(&mut T),
) -> &mut T
where
    T: SerdeAny,
{
    if metadata.contains::<T>() {
        let v = metadata.get_mut::<T>().unwrap();
        update(v);
        return v;
    } else {
        return metadata.get_or_insert_with(default);
    }
}

// builds an ABB (atomic basic block) profile from execution intervals
//
// # Arguments
// * `intervals` - A vector of execution intervals
//
// # Returns
// a mapping from task name to ABB address to (interval count, exec count, exec time, woet)
#[allow(unused)]
pub fn abb_profile(
    mut intervals: Vec<ExecInterval>,
) -> HashMap<Cow<'static, str>, HashMap<GuestAddr, (usize, usize, u64, u64)>> {
    let mut ret: HashMap<Cow<'static, str>, HashMap<GuestAddr, (usize, usize, u64, u64)>> = HashMap::new();
    intervals.sort_by_key(|x| x.get_task_name_unchecked());
    intervals
        .chunk_by_mut(|x, y| x.get_task_name_unchecked() == y.get_task_name_unchecked())
        // Iterate over all tasks
        .for_each(|intv_of_task| {
            // Iterate over all intervals of this task
            intv_of_task.sort_by_key(|y| y.abb.as_ref().unwrap().start);
            // Iterate over each abb of this task
            let mut inter_per_abb_of_task: Vec<&mut [ExecInterval]> = intv_of_task
                .chunk_by_mut(|y, z| y.abb.as_ref().unwrap().start == z.abb.as_ref().unwrap().start)
                .collect();
            // arrange the abbs by their start address
            inter_per_abb_of_task
                .iter_mut()
                .for_each(|ivs_of_abb_of_task| {
                    ivs_of_abb_of_task.sort_by_key(|y| y.abb.as_ref().unwrap().instance_id)
                });
            // find the woet for this abb
            let abb_woet: HashMap<GuestAddr, u64> = inter_per_abb_of_task
                .iter()
                .map(|ivs_of_abb_of_task| {
                    // group intervals by id, sum up the exec time of the abb instance
                    ivs_of_abb_of_task
                        .chunk_by(
                            |y, z| {
                                y.abb.as_ref().unwrap().instance_id
                                    == z.abb.as_ref().unwrap().instance_id
                            },
                        )
                        .map(|intv_of_abb_with_id| {
                            (
                                intv_of_abb_with_id[0].abb.as_ref().unwrap().start,
                                intv_of_abb_with_id
                                    .iter()
                                    .map(|z| z.get_exec_time())
                                    .sum::<_>(),
                            )
                        })
                        .max_by_key(|x| x.1)
                        .unwrap()
                })
                .collect();
            inter_per_abb_of_task.into_iter().for_each(|y| {
                match ret.get_mut(&y[0].get_task_name_unchecked()) {
                    Option::None => {
                        ret.insert(
                            y[0].get_task_name_unchecked(),
                            HashMap::from([(
                                y[0].abb.as_ref().unwrap().start,
                                (
                                    y.len(),
                                    y.iter().filter(|x| x.is_abb_end()).count(),
                                    y.iter().map(|z| z.get_exec_time()).sum::<_>(),
                                    abb_woet[&y[0].abb.as_ref().unwrap().start],
                                ),
                            )]),
                        );
                    }
                    Some(x) => {
                        x.insert(
                            y[0].abb.as_ref().unwrap().start,
                            (
                                y.len(),
                                y.iter().filter(|x| x.is_abb_end()).count(),
                                y.iter().map(|z| z.get_exec_time()).sum(),
                                abb_woet[&y[0].abb.as_ref().unwrap().start],
                            ),
                        );
                    }
                }
            });
        });
    ret
}

// returns an immutable reference from a mutable one
//
// # Arguments
// * `x` - A mutable reference
//
// # Returns
// an immutable reference to the same value
pub fn unmut<T>(x: &mut T) -> &T {
    &(*x)
}
