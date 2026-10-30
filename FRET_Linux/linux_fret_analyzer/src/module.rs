use crate::structures::*;
use anyhow::Result;
use clap::ValueEnum;
use libafl_qemu::{GuestAddr, Qemu};
use log::{debug, info, warn};
use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// Access to low-level QEMU hooks and CPU in callbacks
use libafl_qemu::qemu::CPU;
use libafl_qemu::QemuHooks;
// Assuming Qemu helper exposes a way to get time or icount.
// If not directly available on Qemu struct, we might need to rely on an external helper or just use the cpu.
// For now, let's look for a suitable method. libafl_qemu usually exposes `current_cpu`.
// We will try to read the ARM64 generic timer virtual count register (CNTVCT_EL0) which is a good time source.

/// QEMU virt machine GIC (Generic Interrupt Controller) constants
/// Used to read the hardware IRQ number when an interrupt fires
const GIC_CPU_BASE: u64 = 0x0801_0000;    // GIC CPU interface base for QEMU virt
const GIC_IAR_OFFSET: u64 = 0x0C;          // Interrupt Acknowledge Register offset
const GIC_IRQ_ID_MASK: u32 = 0x3FF;        // IRQ ID is bits [9:0] of IAR

/// Module for extracting S32G3 system state from QEMU
#[derive(Debug)]
pub struct S32G3SystemStateModule {
    pub __schedule_addr: GuestAddr,
    pub el0_svc_addr: GuestAddr,
    pub irq_entry_addr: GuestAddr,
    pub irq_exit_addr: GuestAddr,          // NEW: irq_exit_rcu for matched IRQ pairs
    pub syscall_exit_addr: GuestAddr,

    // Per-CPU variable for current task (ARM64 Linux shadow copy)
    pub __entry_task_offset: GuestAddr,  // Per-CPU section offset
    pub __per_cpu_offset_addr: GuestAddr, // Array of per-CPU base addresses

    // Linux Structure Offsets
    pub offsets: LinuxOffsets,

    // Captured states
    pub states_captured: Vec<RawS32G3SystemState>,
    pub icount: u64,
    pub event_count: u64,

    // Filtering options
    pub filter_process: Option<String>,
    pub skip_idle: bool,

    pub icount_ready: bool,

    // FRET-Linux Extension: ABB Tracking
    pub current_abb_start: u64,
    pub current_abb_type: ABBType,

    // IRQ number tracking: last IRQ number read from GIC IAR at entry
    pub last_irq_number: u32,

    // FRET-Linux Extension: Last task tracking for ABB attribution
    pub last_task: Option<LinuxTask>,

    // Nested context tracking
    pub abb_stack: Vec<ABBType>,
}

// Global pointer to the active module for callback access
static MODULE_PTR: AtomicU64 = AtomicU64::new(0);

// Global flag: set to true once icount subsystem is confirmed ready
static ICOUNT_READY: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy)]
pub struct LinuxOffsets {
    pub comm: u64,
    pub pid: u64,
    pub state: u64, // or __state
    pub parent: u64,
    pub cpu: u64,
}

// Global output path for periodic saving (set from main)
use std::sync::Mutex;
use once_cell::sync::Lazy;
static OUTPUT_PATH: Lazy<Mutex<Option<std::path::PathBuf>>> = Lazy::new(|| Mutex::new(None));
static OUTPUT_FORMAT: Lazy<Mutex<OutputFormat>> = Lazy::new(|| Mutex::new(OutputFormat::Json));

/// Set the output path for periodic saving
pub fn set_output_path(path: std::path::PathBuf) {
    *OUTPUT_PATH.lock().unwrap() = Some(path);
}

/// Set the output format for saving results
pub fn set_output_format(format: OutputFormat) {
    *OUTPUT_FORMAT.lock().unwrap() = format;
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Ndjson,
    Csv,
}

// Save every N captures
const SAVE_INTERVAL: u64 = 100;

impl S32G3SystemStateModule {
    /// Create module from ELF symbol table (dynamic resolution)
    pub fn new_from_symbols(
        symbols: &crate::symbols::SymbolTable,
        filter_process: Option<String>,
        skip_idle: bool,
    ) -> Result<Self> {
        info!("Resolving kernel symbols...");

        // Get function addresses
        let schedule_addr = symbols.get("__schedule")?;
        // The absolute lowest-level ARM64 exception vector entry from userspace.
        // We use the C-level handler el0t_64_sync_handler because tracing raw assembly exception
        // vectors in QEMU can sometimes fail or misbehave. At this entry point, x8 is stored
        // inside the pt_regs struct, but we can still read it from the CPU registers since 
        // The ARM64 syscall entry C-handler. Although x8 is zeroed in the CPU register, 
        // the original userspace x8 is stored in the pt_regs struct passed via x0.
        let el0_svc_addr = symbols.get("el0_svc").unwrap_or(0);

        
        // IRQ entry: Try multiple symbols in priority order.
        // do_interrupt_handler is the most reliable on ARM64 Linux 6.x — it's unique
        // and called by the el1h_64_irq exception vector for ALL hardware IRQs.
        // gic_handle_irq has duplicate symbols in vmlinux which causes resolution issues.
        let irq_entry_addr = symbols
            .get("do_interrupt_handler")  // ARM64 6.x: called by el1h_64_irq_handler for all HW IRQs
            .or_else(|_| symbols.get("gic_handle_irq"))  // GIC-based systems
            .or_else(|_| symbols.get("handle_arch_irq"))
            .or_else(|_| symbols.get("el1_irq"))
            .or_else(|_| symbols.get("el1h_irq"))
            .unwrap_or(0);
        
        // Syscall exit: ret_to_user is the return path from kernel to userspace
        // Use get_or to directly get the address if it exists
        let syscall_exit_addr = symbols.get_or("ret_to_user", 0);
        
        // Log what we found
        if syscall_exit_addr != 0 {
            info!("Found 'ret_to_user' at 0x{:x}", syscall_exit_addr);
        } else {
            warn!("'ret_to_user' NOT found - UserSpace tracking will be incomplete");
        }
        
        if irq_entry_addr != 0 {
            info!("Found IRQ entry at 0x{:x}", irq_entry_addr);
        } else {
            warn!("IRQ entry symbol NOT found - IRQ tracking disabled");
        }

        // IRQ exit: irq_exit_rcu is the counterpart to irq_enter_rcu
        // Hooking this gives us matched IRQ entry/exit pairs (like FreeRTOS ISREnd)
        let irq_exit_addr = symbols.get_or("irq_exit_rcu", 0);
        if irq_exit_addr != 0 {
            info!("Found IRQ exit (irq_exit_rcu) at 0x{:x}", irq_exit_addr);
        } else {
            warn!("'irq_exit_rcu' NOT found - IRQ exit tracking disabled");
        }


        // Get __entry_task symbol - this is the per-CPU shadow copy of current task pointer
        // NOTE: This is a per-CPU section offset, not the runtime address!
        // Runtime address = __per_cpu_offset[cpu_id] + __entry_task_offset
        let entry_task_offset = symbols.get("__entry_task")?;

        // Get __per_cpu_offset array - contains base addresses for each CPU's per-CPU data
        let per_cpu_offset_addr = symbols.get("__per_cpu_offset")?;

        info!("  __schedule:        0x{:x}", schedule_addr);
        info!("  el0_svc:           0x{:x}", el0_svc_addr);
        info!("  irq_entry:         0x{:x}", irq_entry_addr);
        info!("  syscall_exit:      0x{:x}", syscall_exit_addr);
        info!("  __entry_task:      0x{:x} (per-CPU offset)", entry_task_offset);
        info!("  __per_cpu_offset:  0x{:x}", per_cpu_offset_addr);

        if let Some(ref filter) = filter_process {
            info!("  Filtering for process: '{}'", filter);
        }
        if skip_idle {
            info!("  Skipping idle task (swapper)");
        }

        // OFFSETS retrieved via pahole for built kernel (6.6.x ARM64):
        // state: 0x18, on_cpu: 0x34, pid: 0x488, parent: 0x4a0, comm: 0x680
        let offsets = LinuxOffsets {
            comm: 0x680,
            pid: 0x488,
            state: 0x18,
            parent: 0x4a0,
            cpu: 0x34,
        };

        Ok(Self {
            __schedule_addr: schedule_addr,
            el0_svc_addr,
            irq_entry_addr,
            irq_exit_addr,
            syscall_exit_addr,
            __entry_task_offset: entry_task_offset,
            __per_cpu_offset_addr: per_cpu_offset_addr,
            offsets,
            states_captured: Vec::new(),
            icount: 0,
            event_count: 0,
            icount_ready: false,
            filter_process,
            skip_idle,
            // Default to User execution at start of trace
            current_abb_start: 0,
            current_abb_type: ABBType::UserSpace,
            last_irq_number: 0,
            last_task: None,
            abb_stack: Vec::with_capacity(32),
        })
    }

    /// Read memory safely
    pub fn read_mem(&self, qemu: &Qemu, addr: GuestAddr, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        unsafe {
            let _ = qemu.read_mem(addr, &mut buf);
        }
        Ok(buf)
    }

    /// Read a 64-bit value from memory
    pub fn read_u64(&self, qemu: &Qemu, addr: GuestAddr) -> Result<u64> {
        let mut buf = [0u8; 8];
        unsafe {
            let _ = qemu.read_mem(addr, &mut buf);
        }
        Ok(u64::from_le_bytes(buf))
    }

    /// Read the QEMU icount (deterministic instruction count).
    /// Falls back to the software block counter if icount isn't ready yet.
    pub fn read_time(&self, _cpu: &CPU) -> u64 {
        if ICOUNT_READY.load(Ordering::Relaxed) {
            unsafe { libafl_qemu::sys::icount_get_raw() }
        } else {
            self.icount
        }
    }

    /// Mark icount as ready (call after first successful emu.run() return)
    pub fn mark_icount_ready(&mut self) {
        if !self.icount_ready {
            info!("icount subsystem is now ready — switching to icount_get_raw() timestamps");
            self.icount_ready = true;
            ICOUNT_READY.store(true, Ordering::SeqCst);
        }
    }

    /// Read the syscall count (for progress tracking)
    pub fn read_syscall_count(&self, _qemu: &Qemu) -> Result<u64> {
        Ok(0) // Not implemented for Linux yet
    }

    /// Capture complete system state using a CPU handle (usable from hooks)
    pub fn capture_state_from_cpu(
        &mut self,
        cpu: &CPU,
        event: CaptureEvent,
    ) -> Result<RawS32G3SystemState> {
        // Need valid offsets to do anything useful
        let current_task = if self.offsets.pid != 0 || self.offsets.comm != 0 {
            // Read current task pointer from __entry_task per-CPU variable
            // For per-CPU variables: runtime_addr = __per_cpu_offset[cpu_id] + symbol_offset
            // We run with -smp 1, so cpu_id = 0

            // Read __per_cpu_offset[0] (first element of the array)
            let mut offset_buf = [0u8; 8];
            unsafe { let _ = cpu.read_mem(self.__per_cpu_offset_addr, &mut offset_buf); }
            let cpu0_per_cpu_base = u64::from_le_bytes(offset_buf);

            // Calculate runtime address of __entry_task for CPU 0
            let entry_task_runtime_addr = cpu0_per_cpu_base + self.__entry_task_offset;

            let mut ptr_buf = [0u8; 8];
            unsafe { let _ = cpu.read_mem(entry_task_runtime_addr, &mut ptr_buf); }
            let task_struct_addr = u64::from_le_bytes(ptr_buf);

            // Add sanity check: ignore early boot records before per-cpu current task is initialized
            if task_struct_addr == 0 {
                None
            } else {
                debug!(
                    "__per_cpu_offset[0]=0x{:x}, __entry_task=0x{:x} -> task=0x{:x}",
                    cpu0_per_cpu_base, entry_task_runtime_addr, task_struct_addr
                );

                // Read PID
                let mut pid_buf = [0u8; 4];
                unsafe { let _ = cpu.read_mem(task_struct_addr + self.offsets.pid, &mut pid_buf); }
                let pid = u32::from_le_bytes(pid_buf);

                // Read Comm (16 chars)
                let mut comm_buf = [0u8; 16];
                unsafe { let _ = cpu.read_mem(task_struct_addr + self.offsets.comm, &mut comm_buf); }
                let comm_len = comm_buf.iter().position(|&c| c == 0).unwrap_or(16);
                let comm = String::from_utf8_lossy(&comm_buf[..comm_len]).into_owned();

                // Read State (u32/unsigned int)
                let mut state_buf = [0u8; 4];
                unsafe { let _ = cpu.read_mem(task_struct_addr + self.offsets.state, &mut state_buf); }
                let state_val = u32::from_le_bytes(state_buf) as u64;

                // Read parent task_struct pointer and then parent pid
                let mut parent_ptr_buf = [0u8; 8];
                unsafe { let _ = cpu.read_mem(task_struct_addr + self.offsets.parent, &mut parent_ptr_buf); }
                let parent_task_addr = u64::from_le_bytes(parent_ptr_buf);
                let parent_pid = if parent_task_addr != 0 {
                    let mut ppid_buf = [0u8; 4];
                    unsafe { let _ = cpu.read_mem(parent_task_addr + self.offsets.pid, &mut ppid_buf); }
                    u32::from_le_bytes(ppid_buf)
                } else {
                    0
                };

                // Track specified application for demo/feedback
                if let Some(ref filter) = self.filter_process {
                    if comm.contains(filter) {
                        info!(
                            "!!! CAPTURED {} switch !!! (PID: {}, State: {}, Event: {:?})",
                            comm, pid, state_val, event
                        );
                    }
                } else if comm.starts_with("state_machine") || comm.starts_with("amsr_") || comm.starts_with("exe_") {
                    info!(
                        "!!! CAPTURED {} switch !!! (PID: {}, State: {}, Event: {:?})",
                        comm, pid, state_val, event
                    );
                }

                Some(LinuxTask {
                    pid,
                    comm,
                    state: state_val,
                    parent_pid,
                    cpu: 0, // TODO: Use on_cpu
                })
            }
        } else {
            None
        };

        // Logic to close the PREVIOUS ABB and start a NEW one
        
        // 1. Determine new ABB type based on event
        // Syscall number is now carried inside CaptureEvent::SyscallEntry(nr) — read from X8 at hook time.
        let next_abb_type = match event {
            CaptureEvent::SyscallEntry(nr) => ABBType::Syscall(nr),
            CaptureEvent::IrqEntry => {
                // PUSH: Save current context before entering IRQ
                self.abb_stack.push(self.current_abb_type);
                ABBType::IRQ(self.last_irq_number)
            },
            CaptureEvent::IrqExit => {
                // POP: Restore previous context
                self.abb_stack.pop().unwrap_or(ABBType::UserSpace)
            },
            CaptureEvent::SchedulerHook => ABBType::ContextSwitch,
            CaptureEvent::SyscallExit => ABBType::UserSpace,
            _ => self.current_abb_type, // Maintain current state for other events
        };

        let icount_now = self.read_time(cpu);
        self.icount = icount_now;

        // 2. Create the CLOSED ABB (from start -> now)
        // Attribute to the current task (or previous task context)
        let finished_abb = if let Some(task) = &current_task {
            // Option A: Attribute ContextSwitch to the previous task
            let (target_pid, target_cpu) = if matches!(self.current_abb_type, ABBType::ContextSwitch) {
                if let Some(ref prev_task) = self.last_task {
                    (prev_task.pid, prev_task.cpu)
                } else {
                    (task.pid, task.cpu)
                }
            } else {
                (task.pid, task.cpu)
            };

             Some(ABB {
                start_timestamp: self.current_abb_start,
                end_timestamp: icount_now,
                abb_type: self.current_abb_type,
                pid: target_pid,
                cpu: target_cpu,
            })
        } else {
            None
        };

        // 3. Update state tracking
        // Special Case: Context Switch duration is from Schedule -> Next Event
        // If we just finished a ContextSwitch, attribute it to the *new* task (current_task)
        // If we just finished a Syscall, attribute it to *current_task*.
        
        self.current_abb_start = icount_now;
        self.current_abb_type = next_abb_type;
        self.last_task = current_task.clone();

        // Create state regardless of filtering
        let state = RawS32G3SystemState {
            timestamp: icount_now,
            capture_point: event,
            current_task: current_task.clone(),
            current_abb: finished_abb,
        };

        // Apply filtering
        let should_capture = if let Some(ref task) = current_task {
            let mut capture = true;

            // Skip idle task if requested
            if self.skip_idle && task.comm.starts_with("swapper") {
                capture = false;
            }

            // Filter by process name if specified
            if let Some(ref filter) = self.filter_process {
                capture = capture && task.comm.contains(filter);
            }

            capture
        } else {
            false // Skip if we couldn't read task info
        };

        if should_capture {
            debug!("Captured (hook) state");
            self.states_captured.push(state.clone());
        }

        self.event_count += 1;

        // Periodic save to prevent data loss on kill
        if self.event_count % SAVE_INTERVAL == 0 {
            if let Some(path) = OUTPUT_PATH.lock().unwrap().as_ref() {
                if let Err(e) = self.save_results(path) {
                    log::warn!("Periodic save failed: {}", e);
                } else {
                    log::info!(
                        "Periodic save: {} states to {}",
                        self.states_captured.len(),
                        path.display()
                    );
                }
            }
        }

        Ok(state)
    }

    /// Capture complete system state
    pub fn capture_state(
        &mut self,
        qemu: &Qemu,
        event: CaptureEvent,
    ) -> Result<RawS32G3SystemState> {
        // Get CPU state
        let cpu = qemu
            .current_cpu()
            .ok_or_else(|| anyhow::anyhow!("Failed to get current CPU"))?;

        // Reuse the CPU logic
        self.capture_state_from_cpu(&cpu, event)
    }

    /// Reset the module state (for fuzzing loops)
    pub fn reset(&mut self) {
        self.states_captured.clear();
        self.icount = 0;
        self.event_count = 0;
        self.current_abb_start = 0;
        self.current_abb_type = ABBType::UserSpace;
        self.last_irq_number = 0;
        self.last_task = None;
        self.abb_stack.clear();
    }

    /// Save captured states to file
    pub fn save_results(&self, path: &Path) -> Result<()> {
        use chrono::Local;
        use serde_json::json;

        let mut file = File::create(path)?;
        let now = Local::now();
        let generation_timestamp = now.format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let output_format = *OUTPUT_FORMAT.lock().unwrap();

        match output_format {
            OutputFormat::Json => {
                // Create a wrapper object with metadata and data
                let output = json!({
                    "metadata": {
                        "generated_at": generation_timestamp,
                        "total_states": self.states_captured.len(),
                        "format_version": "1.0"
                    },
                    "data": self.states_captured
                });

                let json = serde_json::to_string_pretty(&output)?;
                file.write_all(json.as_bytes())?;
            }
            OutputFormat::Ndjson => {
                // One JSON object per line (no wrapper)
                for state in &self.states_captured {
                    let line = serde_json::to_string(state)?;
                    file.write_all(line.as_bytes())?;
                    file.write_all(b"\n")?;
                }
            }
            OutputFormat::Csv => {
                // Header (with timestamps for job analysis)
                file.write_all(b"capture_point,pid,comm,state,parent_pid,cpu,abb_type,abb_start,abb_end\n")?;
                for state in &self.states_captured {
                    let (pid, comm, task_state, parent_pid, cpu) =
                        if let Some(task) = &state.current_task {
                            (
                                task.pid.to_string(),
                                task.comm.replace('"', "\""),
                                task.state.to_string(),
                                task.parent_pid.to_string(),
                                task.cpu.to_string(),
                            )
                        } else {
                            ("".to_string(), "".to_string(), "0".to_string(), "0".to_string(), "0".to_string())
                        };

                    let (abb_type, abb_start, abb_end) = if let Some(abb) = &state.current_abb {
                        (
                            abb.abb_type.to_string(),
                            abb.start_timestamp.to_string(),
                            abb.end_timestamp.to_string()
                        )
                    } else {
                        ("".to_string(), "0".to_string(), "0".to_string())
                    };

                    writeln!(
                        file,
                        "{},{},\"{}\",{},{},{},{},{},{}",
                        state.capture_point,
                        pid,
                        comm,
                        task_state,
                        parent_pid,
                        cpu,
                        abb_type,
                        abb_start,
                        abb_end
                    )?;
                }
            }

        }

        Ok(())
    }

    /// Print summary of captured states
    pub fn print_summary(&self) {
        println!("\n=== Linux System State Analysis ===");
        println!("Total states captured: {}", self.states_captured.len());

        if self.states_captured.is_empty() {
            println!("No states captured!");
            return;
        }

        // Count task switches
        let mut tasks_seen = std::collections::HashMap::new();
        for state in &self.states_captured {
            if let Some(task) = &state.current_task {
                *tasks_seen.entry(task.comm.clone()).or_insert(0) += 1;
            }
        }

        println!("\nObserved Tasks:");
        for (name, count) in tasks_seen {
            println!("  Task '{}': active {} times", name, count);
        }
    }

    /// Install execution hooks at key kernel functions
    pub fn install_hooks(&mut self, _qemu: &Qemu) -> Result<()> {
        info!("Installing hooks at kernel functions...");
        // Publish this module pointer for callbacks (unsafe but effective in single-analyzer use)
        let self_ptr = self as *mut S32G3SystemStateModule as u64;
        MODULE_PTR.store(self_ptr, Ordering::SeqCst);

        // Acquire hooks interface
        let hooks = unsafe { QemuHooks::get_unchecked() };

        // Install instruction hooks at function entries
        unsafe {
            info!("  Hook at __schedule:   0x{:x}", self.__schedule_addr);
            hooks.add_instruction_hooks(0u64, self.__schedule_addr, on_func_entry, true);

            if self.el0_svc_addr != 0 {
                info!("  Hook at el0_svc:      0x{:x}", self.el0_svc_addr);
                hooks.add_instruction_hooks(0u64, self.el0_svc_addr, on_func_entry, true);
            }

            if self.irq_entry_addr != 0 {
                info!("  Hook at irq_entry:    0x{:x}", self.irq_entry_addr);
                hooks.add_instruction_hooks(0u64, self.irq_entry_addr, on_func_entry, true);
            }

            if self.irq_exit_addr != 0 {
                info!("  Hook at irq_exit:     0x{:x}", self.irq_exit_addr);
                hooks.add_instruction_hooks(0u64, self.irq_exit_addr, on_func_entry, true);
            }

            if self.syscall_exit_addr != 0 {
                info!("  Hook at syscall_exit: 0x{:x}", self.syscall_exit_addr);
                hooks.add_instruction_hooks(0u64, self.syscall_exit_addr, on_func_entry, true);
            }

            // ADDED: Block hook to count "time" (instructions/blocks)
            // We need a gen hook to pass the PC (or simple ID) to the exec hook
            hooks.add_block_hooks(
                0u64,
                Some(gen_block_hook),
                None,
                Some(exec_block_hook),
            );
        }
        
        info!("Hooks installed successfully");
        Ok(())
    }
}

// Gen hook: returns the PC as the block ID
extern "C" fn gen_block_hook(_data: u64, pc: GuestAddr) -> u64 {
    pc as u64
}

// Exec hook: increments the counter
extern "C" fn exec_block_hook(_data: u64, _id: u64) {
    if let Some(module) = unsafe { (MODULE_PTR.load(Ordering::SeqCst) as *mut S32G3SystemStateModule).as_mut() } {
        module.icount += 1;
    }
}

// Low-level hook callback executed when the instrumented instruction is hit
// Safety: called by QEMU threads. Keep it minimal and lock-free.
extern "C" fn on_func_entry(_data: u64, pc: GuestAddr) {
    unsafe {
        // Get current CPU
        let cpu_ptr = libafl_qemu::sys::libafl_qemu_current_cpu();
        if cpu_ptr.is_null() {
            return;
        }
        let cpu: CPU = std::mem::transmute(cpu_ptr);

        // Resolve module pointer
        let m = MODULE_PTR.load(Ordering::Relaxed) as *mut S32G3SystemStateModule;
        if m.is_null() {
            return;
        }
        let module = &mut *m;

        // Determine capture event by address
        let event = if pc == module.__schedule_addr {
            CaptureEvent::SchedulerHook
        } else if pc == module.el0_svc_addr {
            // ARM64 exception entry zeros out X8. By the time el0_svc executes, 
            // the original X8 is saved in pt_regs, and X0 points to pt_regs.
            // pt_regs->regs[8] is at offset 64.
            let pt_regs_ptr: u64 = cpu.read_reg(libafl_qemu::Regs::X0).unwrap_or(0);
            let mut x8_buf = [0u8; 8];
            let syscall_nr = if pt_regs_ptr != 0 && cpu.read_mem(pt_regs_ptr + 64, &mut x8_buf).is_ok() {
                u64::from_le_bytes(x8_buf)
            } else {
                0
            };
            CaptureEvent::SyscallEntry(syscall_nr)
        } else if pc == module.irq_entry_addr {
            // Read the hardware IRQ number from the GIC IAR register (MMIO)
            // GIC CPU interface IAR at 0x0801_000C contains the IRQ ID in bits [9:0]
            let mut iar_buf = [0u8; 4];
            let _ = cpu.read_mem(GIC_CPU_BASE + GIC_IAR_OFFSET, &mut iar_buf);
            let irq_nr = u32::from_le_bytes(iar_buf) & GIC_IRQ_ID_MASK;
            module.last_irq_number = irq_nr;
            CaptureEvent::IrqEntry
        } else if pc == module.irq_exit_addr {
            CaptureEvent::IrqExit
        } else if pc == module.syscall_exit_addr {
            CaptureEvent::SyscallExit
        } else {
            CaptureEvent::Unknown
        };

        // Best-effort capture; ignore errors inside hook
        let _ = module.capture_state_from_cpu(&cpu, event);
    }
}
