//! ftrace-based system-state observer for the FRET Linux fuzzer.
//!
//! # Purpose
//! Replaces the VMI observation path (`LinuxSystemStateHelper` / QEMU hooks) with
//! an ftrace-based equivalent that produces the **identical** `LinuxSystemState`
//! struct consumed by the rest of the fuzzer.
//!
//! # Architecture
//!
//! ```text
//!  ┌─────────────────────────────────────────┐
//!  │  QEMU guest kernel                       │
//!  │  ftrace events → /sys/kernel/debug/      │
//!  │  tracing/trace_pipe  (ASCII stream)      │
//!  └──────────────┬──────────────────────────┘
//!                 │  virtio-serial  OR  shared ext4 file
//!                 ▼
//!  ┌─────────────────────────────────────────┐
//!  │  Host: FtraceReader (background thread) │
//!  │  parses sched_switch / irq_handler_*    │
//!  │  → builds LinuxSystemState snapshots    │
//!  │  → stores in shared Arc<Mutex<>>        │
//!  └──────────────┬──────────────────────────┘
//!                 │
//!                 ▼
//!  FtraceSystemStateHelper::post_exec()
//!  → writes LinuxTraceData into fuzzer state metadata
//!  → rest of feedbacks/schedulers unchanged
//! ```
//!
//! # Enabling
//! Compile with `--features ftrace_obs` (add this feature to Cargo.toml when ready).
//!
//! # Guest setup (rootfs)
//! The guest init script must execute:
//! ```sh
//! mount -t debugfs none /sys/kernel/debug
//! echo sched_switch        > /sys/kernel/debug/tracing/set_event
//! echo irq_handler_entry  >> /sys/kernel/debug/tracing/set_event
//! echo irq_handler_exit   >> /sys/kernel/debug/tracing/set_event
//! echo softirq_entry      >> /sys/kernel/debug/tracing/set_event
//! echo softirq_exit       >> /sys/kernel/debug/tracing/set_event
//! echo 1 > /sys/kernel/debug/tracing/tracing_on
//! # pipe trace_pipe to a virtio-serial port or to a shared file:
//! cat /sys/kernel/debug/tracing/trace_pipe > /dev/vport0p1 &
//! ```
//! The host side reads the virtio-serial port (or a FIFO file) to get the event stream.

use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use hashbrown::{HashMap, HashSet};

use crate::systemstate::{
    AtomicBasicBlock, CaptureEvent, ExecInterval, RTOSJob,
    target_os::linux::{LinuxSystemState, LinuxTask, LinuxTraceData},
};
use crate::time::clock::_QEMU_NS_PER_ISN;

// ─── Parsed ftrace event ─────────────────────────────────────────────────────

// a single parsed ftrace event
#[derive(Debug, Clone)]
pub enum FtraceEvent {
    // `sched_switch`: prev_comm/prev_pid → next_comm/next_pid
    SchedSwitch {
        timestamp_ns: u64,
        prev_pid: u32,
        prev_comm: String,
        prev_state: u64, // raw task state flags
        next_pid: u32,
        next_comm: String,
        cpu: u32,
    },
    // `sched_wakeup`: task becomes runnable
    SchedWakeup {
        timestamp_ns: u64,
        pid: u32,
        comm: String,
        cpu: u32,
    },
    // `irq_handler_entry`: IRQ number + name
    IrqEntry {
        timestamp_ns: u64,
        irq: u32,
        name: String,
        cpu: u32,
    },
    // `irq_handler_exit`: IRQ number + return code
    IrqExit {
        timestamp_ns: u64,
        irq: u32,
        cpu: u32,
    },
    // unrecognised or unparseable line — skipped silently
    Unknown,
}

// ─── Parser ──────────────────────────────────────────────────────────────────

// parse one line of ASCII ftrace output into an `FtraceEvent`
//
// example ftrace line formats:
// ```
// <task>-<pid> [<cpu>] .... <ts_s>.<ts_us>: sched_switch: prev_comm=dummy prev_pid=123 prev_prio=99 prev_state=S ==> next_comm=swapper/0 next_pid=0 next_prio=120
// <task>-<pid> [<cpu>] .... <ts>: irq_handler_entry: irq=27 name=arch_timer
// <task>-<pid> [<cpu>] .... <ts>: irq_handler_exit: irq=27 ret=handled
// ```
pub fn parse_ftrace_line(line: &str) -> FtraceEvent {
    // Minimal tokeniser — split on whitespace and key=value pairs.
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return FtraceEvent::Unknown;
    }

    // Extract CPU field: "[NNN]"
    let cpu: u32 = {
        let cpu_start = line.find('[').and_then(|s| {
            let end = line[s..].find(']').map(|e| s + e);
            end.map(|e| (s + 1, e))
        });
        cpu_start
            .and_then(|(s, e)| line[s..e].trim().parse().ok())
            .unwrap_or(0)
    };

    // Extract timestamp: last number before ':'
    let timestamp_ns: u64 = extract_timestamp_ns(line);

    // Determine event type from the event name token after the timestamp colon.
    if let Some(event_start) = find_event_name_start(line) {
        let rest = &line[event_start..];
        if rest.starts_with("sched_switch:") {
            return parse_sched_switch(rest, timestamp_ns, cpu);
        } else if rest.starts_with("sched_wakeup:") {
            return parse_sched_wakeup(rest, timestamp_ns, cpu);
        } else if rest.starts_with("irq_handler_entry:") {
            return parse_irq_entry(rest, timestamp_ns, cpu);
        } else if rest.starts_with("irq_handler_exit:") {
            return parse_irq_exit(rest, timestamp_ns, cpu);
        }
    }
    FtraceEvent::Unknown
}

fn extract_timestamp_ns(line: &str) -> u64 {
    // Pattern: "... NNN.UUUUUU: event_name"
    // Find the last `NNN.UUU:` before the event-name colon.
    let colon_pos = line.rfind(':').unwrap_or(0);
    let before = &line[..colon_pos];
    let ts_token = before.split_whitespace().last().unwrap_or("0");
    // ts_token is like "1234.567890"
    if let Some(dot) = ts_token.find('.') {
        let secs: u64 = ts_token[..dot].parse().unwrap_or(0);
        let frac_str = &ts_token[dot + 1..];
        // Pad / trim to 9 decimal places (nanoseconds)
        let mut frac_str_padded = frac_str.to_string();
        while frac_str_padded.len() < 9 {
            frac_str_padded.push('0');
        }
        frac_str_padded.truncate(9);
        let nanos: u64 = frac_str_padded.parse().unwrap_or(0);
        return secs * 1_000_000_000 + nanos;
    }
    ts_token.parse().unwrap_or(0)
}

fn find_event_name_start(line: &str) -> Option<usize> {
    // Event name comes after the timestamp token + ": "
    // Pattern: "... ts: event_name: ..."
    // Find the second colon from the right (first is in ts, second is after event name).
    let mut colon_count = 0;
    for (i, c) in line.char_indices().rev() {
        if c == ':' {
            colon_count += 1;
            if colon_count == 2 {
                // Skip ": "
                return Some(i + 2);
            }
        }
    }
    None
}

fn kv_value<'a>(rest: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{}=", key);
    let pos = rest.find(needle.as_str())?;
    let after = &rest[pos + needle.len()..];
    // Value ends at next space
    Some(after.split_whitespace().next().unwrap_or(""))
}

fn parse_sched_switch(rest: &str, timestamp_ns: u64, cpu: u32) -> FtraceEvent {
    // prev_comm may contain spaces; use pid as the reliable field.
    let prev_pid: u32 = kv_value(rest, "prev_pid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let next_pid: u32 = kv_value(rest, "next_pid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let prev_state: u64 = kv_value(rest, "prev_state")
        .and_then(|s| {
            // State is encoded as 'S', 'R', 'D' or a hex number
            match s {
                "S" => Some(0x01),
                "D" => Some(0x02),
                "R" | "R+" => Some(0x00),
                _ => u64::from_str_radix(s.trim_start_matches("0x"), 16).ok(),
            }
        })
        .unwrap_or(0);

    // comm: use the part between "prev_comm=" and " prev_pid="
    let prev_comm = extract_comm(rest, "prev_comm", "prev_pid");
    let next_comm = extract_comm(rest, "next_comm", "next_pid");

    FtraceEvent::SchedSwitch {
        timestamp_ns,
        prev_pid,
        prev_comm,
        prev_state,
        next_pid,
        next_comm,
        cpu,
    }
}

fn extract_comm(rest: &str, comm_key: &str, next_key: &str) -> String {
    let comm_needle = format!("{}=", comm_key);
    let next_needle = format!(" {}", next_key);
    if let Some(start) = rest.find(comm_needle.as_str()) {
        let after_eq = &rest[start + comm_needle.len()..];
        if let Some(end) = after_eq.find(next_needle.as_str()) {
            return after_eq[..end].trim().to_string();
        }
        // fallback: take up to first space
        return after_eq.split_whitespace().next().unwrap_or("?").to_string();
    }
    "?".to_string()
}

fn parse_irq_entry(rest: &str, timestamp_ns: u64, cpu: u32) -> FtraceEvent {
    let irq: u32 = kv_value(rest, "irq")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let name = kv_value(rest, "name")
        .unwrap_or("?")
        .to_string();
    FtraceEvent::IrqEntry { timestamp_ns, irq, name, cpu }
}

fn parse_irq_exit(rest: &str, timestamp_ns: u64, cpu: u32) -> FtraceEvent {
    let irq: u32 = kv_value(rest, "irq")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    FtraceEvent::IrqExit { timestamp_ns, irq, cpu }
}

fn parse_sched_wakeup(rest: &str, timestamp_ns: u64, cpu: u32) -> FtraceEvent {
    let pid: u32 = kv_value(rest, "pid")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let comm = kv_value(rest, "comm").unwrap_or("?").to_string();
    FtraceEvent::SchedWakeup { timestamp_ns, pid, comm, cpu }
}

// ─── Event-stream → LinuxSystemState converter ───────────────────────────────

// accumulated per-execution snapshot built from a batch of ftrace events
#[derive(Debug, Default)]
pub struct FtraceSnapshot {
    pub states: Vec<LinuxSystemState>,
}

// convert a batch of `FtraceEvent`s (one fuzzer execution worth) into a
// `LinuxTraceData`-compatible snapshot
//
// strategy:
// - Every `sched_switch` creates a new `LinuxSystemState` for the next task
// - IRQ entry/exit are noted but do not create a new system state on their own
// (they are reflected in the ABB structure if `trace_stg` is active)
pub fn events_to_trace_data(events: &[FtraceEvent]) -> LinuxTraceData {
    let mut states: Vec<LinuxSystemState> = Vec::new();
    let mut states_map: HashMap<u64, LinuxSystemState> = HashMap::new();
    let mut tasks_seen: HashMap<u32, LinuxTask> = HashMap::new();
    let mut state_hashes: Vec<u64> = Vec::new();
    let mut state_ticks: Vec<u64> = Vec::new();
    let mut jobs: Vec<RTOSJob> = Vec::new();
    let mut intervals: Vec<ExecInterval> = Vec::new();

    let ns_per_tick = _QEMU_NS_PER_ISN.max(1) as u64;
    let to_tick = |ns: u64| -> u64 { ns / ns_per_tick };

    let mut pending_release: HashMap<u32, u64> = HashMap::new();
    let mut running_since: HashMap<u32, u64> = HashMap::new();

    // Seed with swapper/0
    tasks_seen.insert(
        0,
        LinuxTask { pid: 0, comm: "swapper/0".to_string(), state: 0, parent_pid: 0, cpu: 0 },
    );

    for event in events {
        if let FtraceEvent::SchedWakeup { timestamp_ns, pid, .. } = event {
            pending_release.insert(*pid, to_tick(*timestamp_ns));
        }

        if let FtraceEvent::SchedSwitch {
            timestamp_ns,
            next_pid,
            next_comm,
            prev_pid,
            prev_comm,
            prev_state,
            cpu,
            ..
        } = event
        {
            let ts_tick = to_tick(*timestamp_ns);

            if let Some(run_start) = running_since.remove(prev_pid) {
                if *prev_pid != 0 {
                    let release = pending_release.remove(prev_pid).unwrap_or(run_start);
                    let response = ts_tick;
                    let exec_ticks = response.saturating_sub(run_start);
                    let mut job = RTOSJob::default();
                    job.name = prev_comm.clone();
                    job.release = release;
                    job.response = response;
                    job.exec_ticks = exec_ticks;
                    job.ticks_per_abb = vec![exec_ticks];
                    job.abbs = vec![AtomicBasicBlock {
                        start: 0,
                        ends: HashSet::new(),
                        level: 0,
                        instance_id: 0,
                        instance_name: Some(prev_comm.clone().into()),
                    }];
                    jobs.push(job);
                }
            }
            running_since.insert(*next_pid, ts_tick);

            // Update or insert prev task with its new sleep state
            tasks_seen
                .entry(*prev_pid)
                .and_modify(|t| {
                    t.state = *prev_state;
                    t.comm = prev_comm.clone();
                })
                .or_insert(LinuxTask {
                    pid: *prev_pid,
                    comm: prev_comm.clone(),
                    state: *prev_state,
                    parent_pid: 0,
                    cpu: *cpu,
                });

            // Insert / refresh next task as running (state=0)
            let next_task = tasks_seen
                .entry(*next_pid)
                .and_modify(|t| {
                    t.state = 0;
                    t.comm = next_comm.clone();
                    t.cpu = *cpu;
                })
                .or_insert(LinuxTask {
                    pid: *next_pid,
                    comm: next_comm.clone(),
                    state: 0,
                    parent_pid: 0,
                    cpu: *cpu,
                })
                .clone();

            let sys_state = LinuxSystemState {
                current_pid: *next_pid,
                current_comm: next_comm.clone(),
                current_task: next_task,
                tasks: tasks_seen.clone(),
            };

            // Hash for dedup / states_map
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            let mut h = DefaultHasher::new();
            sys_state.hash(&mut h);
            let key = h.finish();

            states_map.entry(key).or_insert_with(|| sys_state.clone());
            states.push(sys_state);
            state_hashes.push(key);
            state_ticks.push(ts_tick);
        }
    }

    if state_hashes.len() >= 2 {
        for i in 0..(state_hashes.len() - 1) {
            let task_name = states
                .get(i)
                .map(|s| s.current_comm.clone())
                .unwrap_or_else(|| "unknown".to_string());
            intervals.push(ExecInterval {
                start_tick: state_ticks[i],
                end_tick: state_ticks[i + 1],
                start_state: state_hashes[i],
                end_state: state_hashes[i + 1],
                start_capture: (CaptureEvent::APIStart, task_name.clone().into()),
                end_capture: (CaptureEvent::APIEnd, task_name.clone().into()),
                level: 0,
                abb: Some(AtomicBasicBlock {
                    start: 0,
                    ends: HashSet::new(),
                    level: 0,
                    instance_id: 0,
                    instance_name: Some(task_name.into()),
                }),
            });
        }
    }

    LinuxTraceData {
        states,
        states_map,
        jobs,
        intervals,
        mem_reads: vec![Vec::new()],
        ref_cnt: 0,
    }
}

// ─── Background reader thread ─────────────────────────────────────────────────

// shared buffer between the background reader thread and the fuzzer main thread
pub type SharedEventBuffer = Arc<Mutex<Vec<FtraceEvent>>>;

// spawn a background thread that continuously reads ftrace ASCII lines from
// `source_path` (a virtio-serial device node such as `/dev/vport0p1`, or a
// host-side FIFO) and appends parsed events to `shared_buf`
//
// the thread runs until the channel is closed or EOF is reached
pub fn spawn_ftrace_reader(source_path: PathBuf, shared_buf: SharedEventBuffer) {
    thread::Builder::new()
        .name("ftrace-reader".to_string())
        .spawn(move || {
            let file = loop {
                match std::fs::File::open(&source_path) {
                    Ok(f) => break f,
                    Err(e) => {
                        eprintln!("[ftrace] waiting for source {:?}: {}", source_path, e);
                        thread::sleep(Duration::from_millis(250));
                    }
                }
            };
            // Follow file appends (like `tail -f`) so this also works with
            // chardev/file backends that append over time.
            let mut reader = BufReader::new(file);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => {
                        thread::sleep(Duration::from_millis(100));
                    }
                    Ok(_) => {
                        let ev = parse_ftrace_line(line.trim_end());
                        if !matches!(ev, FtraceEvent::Unknown) {
                            if let Ok(mut buf) = shared_buf.lock() {
                                buf.push(ev);
                            }
                        }
                    }
                    Err(_) => {
                        thread::sleep(Duration::from_millis(200));
                    }
                }
            }
        })
        .expect("Failed to spawn ftrace reader thread");
}

// ─── FtraceSystemStateHelper ──────────────────────────────────────────────────

// drop-in replacement for `LinuxSystemStateHelper` that feeds on ftrace events
// instead of QEMU VMI hooks
//
// # Usage
// ```rust
// let buf = Arc::new(Mutex::new(Vec::new()));
// spawn_ftrace_reader(PathBuf::from("/dev/vport0p1"), Arc::clone(&buf));
// let helper = FtraceSystemStateHelper::new(buf);
// // Use in place of LinuxSystemStateHelper in the emulator module list
// ```
#[derive(Debug)]
pub struct FtraceSystemStateHelper {
    // events collected since the last execution boundary
    shared_buf: SharedEventBuffer,
}

impl FtraceSystemStateHelper {
    pub fn new(shared_buf: SharedEventBuffer) -> Self {
        Self { shared_buf }
    }

    pub fn buffer_len(&self) -> usize {
        let buf = self.shared_buf.lock().expect("ftrace buf poisoned");
        buf.len()
    }

    // drain all events accumulated since the last call and convert them into
    // a `LinuxTraceData` that can be inserted into the fuzzer state metadata
    pub fn drain_to_trace_data(&self) -> LinuxTraceData {
        let events: Vec<FtraceEvent> = {
            let mut buf = self.shared_buf.lock().expect("ftrace buf poisoned");
            std::mem::take(&mut *buf)
        };
        events_to_trace_data(&events)
    }
}

// NOTE: FtraceSystemStateHelper does NOT implement `EmulatorModule` — it has no
// QEMU hooks.  Instead, call `helper.drain_to_trace_data()` inside the harness
// closure after `qemu.run()` returns and insert the result via:
//   state.metadata_map_mut().insert(helper.drain_to_trace_data());
//
// This keeps the QEMU executor interface unchanged; only the observation source
// differs.

// ─── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_sched_switch_line() {
        let line = " dummy_fuzz_tar-234   [000] d... 1234.567890: sched_switch: prev_comm=dummy_fuzz_tar prev_pid=234 prev_prio=99 prev_state=S ==> next_comm=swapper/0 next_pid=0 next_prio=120";
        let ev = parse_ftrace_line(line);
        if let FtraceEvent::SchedSwitch { prev_pid, next_pid, prev_state, cpu, .. } = ev {
            assert_eq!(prev_pid, 234);
            assert_eq!(next_pid, 0);
            assert_eq!(prev_state, 0x01); // "S"
            assert_eq!(cpu, 0);
        } else {
            panic!("Expected SchedSwitch, got {:?}", ev);
        }
    }

    #[test]
    fn parse_irq_entry_line() {
        let line = " <idle>-0   [000] d.h. 1234.000001: irq_handler_entry: irq=27 name=arch_timer";
        let ev = parse_ftrace_line(line);
        if let FtraceEvent::IrqEntry { irq, name, .. } = ev {
            assert_eq!(irq, 27);
            assert_eq!(name, "arch_timer");
        } else {
            panic!("Expected IrqEntry, got {:?}", ev);
        }
    }

    #[test]
    fn events_to_trace_populates_states() {
        let events = vec![
            FtraceEvent::SchedSwitch {
                timestamp_ns: 1_000_000,
                prev_pid: 0, prev_comm: "swapper/0".to_string(), prev_state: 0,
                next_pid: 100, next_comm: "dummy_task".to_string(),
                cpu: 0,
            },
            FtraceEvent::SchedSwitch {
                timestamp_ns: 2_000_000,
                prev_pid: 100, prev_comm: "dummy_task".to_string(), prev_state: 1,
                next_pid: 0, next_comm: "swapper/0".to_string(),
                cpu: 0,
            },
        ];
        let td = events_to_trace_data(&events);
        assert_eq!(td.states.len(), 2);
        assert_eq!(td.states[0].current_pid, 100);
        assert_eq!(td.states[1].current_pid, 0);
    }
}
