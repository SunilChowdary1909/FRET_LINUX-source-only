use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Represents a single job instance 
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Job {
    pub id: usize,
    pub pid: u32,
    pub comm: String,
    pub release_time: u64,    // Time of Wakeup
    pub completion_time: u64, // Time of Sleep
    pub response_time: u64,   // completion - release
    pub execution_time: u64,  // Sum of running intervals
    pub preemption_time: u64, // response - execution
}

pub struct JobAnalyzer {
    pub completed_jobs: Vec<Job>,
    active_jobs: HashMap<u32, JobBuilder>, // pid
    job_id_counter: usize,
}

const QEMU_ICOUNT_SHIFT: u32 = 5;
const ICNT_TO_NS_F64: f64 = (1u64 << QEMU_ICOUNT_SHIFT) as f64;
// First-order CRPD model parameters.
const CRPD_ALPHA_NUM: u64 = 1;
const CRPD_ALPHA_DEN: u64 = 4;
const CRPD_BASE_RELOAD_TICKS: u64 = 256;

fn icount_to_micros_u64(icount: u64) -> u64 {
    let ns = (icount as u128) << QEMU_ICOUNT_SHIFT;
    (ns / 1_000u128) as u64
}

fn icount_f64_to_micros_f64(icount: f64) -> f64 {
    (icount * ICNT_TO_NS_F64) / 1_000.0
}

fn estimate_crpd_ticks(preemption_time: u64, execution_time: u64) -> u64 {
    if preemption_time == 0 {
        return 0;
    }
    let proportional = preemption_time.saturating_mul(CRPD_ALPHA_NUM) / CRPD_ALPHA_DEN;
    let capacity_bound = execution_time / 3 + CRPD_BASE_RELOAD_TICKS;
    proportional
        .saturating_add(CRPD_BASE_RELOAD_TICKS)
        .min(preemption_time)
        .min(capacity_bound)
}

/// Internal builder state for an active job
struct JobBuilder {
    pid: u32,
    comm: String,
    release_time: u64,
    execution_time: u64,
}

impl JobAnalyzer {
    pub fn new() -> Self {
        Self {
            completed_jobs: Vec::new(),
            active_jobs: HashMap::new(),
            job_id_counter: 0,
        }
    }

    /// Analyze trace from CSV file
    pub fn from_csv<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .context(format!("Failed to open trace file: {:?}", path.as_ref()))?;
        let reader = BufReader::new(file);

        let mut analyzer = Self::new();
        
        // Iterate through CSV lines
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.context(format!("Failed to read line {}", line_num))?;
            
            
            if line_num == 0 {
                continue;
            }
            
            // Parse CSV: capture_point,pid,comm,state,parent_pid,cpu,abb_type,abb_start,abb_end
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 9 {
                continue;
            }
            
            let _capture_point = fields[0];
            let pid: u32 = fields[1].parse().unwrap_or(0);
            let comm = fields[2].trim_matches('"').to_string();
            let state_char = fields[3]; // "R", "S", "D", etc.
            let _abb_type = fields[6];
            let start_time: u64 = fields[7].parse().unwrap_or(0);
            let end_time: u64 = fields[8].parse().unwrap_or(0);
            
            let duration = if end_time >= start_time { end_time - start_time } else { 0 };

           
            let is_sleeping = if let Ok(state_num) = state_char.parse::<u32>() {
                // Numeric state: check if TASK_INTERRUPTIBLE (bit 0) or TASK_UNINTERRUPTIBLE (bit 1) is set
                (state_num & 0x01) != 0 || (state_num & 0x02) != 0
            } else {
                // Character state: check for "S" or "D"
                state_char == "S" || state_char == "D"
            };
            
            if is_sleeping {
                // Task is sleeping -> Complete current job if active
                 if let Some(builder) = analyzer.active_jobs.remove(&pid) {
                    let completion_time = end_time;
                    let response_time = if completion_time >= builder.release_time {
                        completion_time - builder.release_time
                    } else {
                        0
                    };
                    
                    let preemption_time = if response_time >= builder.execution_time {
                        response_time - builder.execution_time
                    } else {
                        0
                    };
                    
                    analyzer.completed_jobs.push(Job {
                        id: analyzer.job_id_counter,
                        pid: builder.pid,
                        comm: builder.comm,
                        release_time: builder.release_time,
                        completion_time,
                        response_time,
                        execution_time: builder.execution_time + duration, // Include final block
                        preemption_time,
                    });
                    analyzer.job_id_counter += 1;
                }
            } else {
                // Task is Running or Runnable
                // Check if active job exists
                analyzer.active_jobs.entry(pid)
                    .and_modify(|builder| {
                        builder.execution_time += duration;
                        // update comm just in case
                        builder.comm = comm.clone();
                    })
                    .or_insert_with(|| JobBuilder {
                        pid,
                        comm: comm.clone(),
                        release_time: start_time, // Approx release time
                        execution_time: duration,
                    });
            }
        }
        
        Ok(analyzer)
    }

    /// Calculate statistics per process
    pub fn calculate_stats(&self) -> Vec<JobStats> {
        let mut stats_map: HashMap<u32, JobStats> = HashMap::new();
        
        for job in &self.completed_jobs {
            let entry = stats_map.entry(job.pid).or_insert_with(|| JobStats {
                pid: job.pid,
                comm: job.comm.clone(),
                job_count: 0,
                min_response: u64::MAX,
                max_response: 0,
                avg_response: 0.0,
                min_execution: u64::MAX,
                max_execution: 0,
                avg_execution: 0.0,
                total_preemption: 0,
            });
            
            entry.job_count += 1;
            entry.min_response = entry.min_response.min(job.response_time);
            entry.max_response = entry.max_response.max(job.response_time);
            entry.avg_response += job.response_time as f64;
            
            entry.min_execution = entry.min_execution.min(job.execution_time);
            entry.max_execution = entry.max_execution.max(job.execution_time);
            entry.avg_execution += job.execution_time as f64;
            
            entry.total_preemption += job.preemption_time;
        }
        
        // Finalize averages
        for stats in stats_map.values_mut() {
            if stats.job_count > 0 {
                stats.avg_response /= stats.job_count as f64;
                stats.avg_execution /= stats.job_count as f64;
            }
        }
        
        let mut result: Vec<JobStats> = stats_map.into_values().collect();
        result.sort_by(|a, b| b.max_response.cmp(&a.max_response)); // Sort by max response time
        result
    }

    pub fn calculate_crpd_stats(&self) -> Vec<CrpdStats> {
        let mut stats_map: HashMap<u32, CrpdStats> = HashMap::new();

        for job in &self.completed_jobs {
            let estimated_crpd = estimate_crpd_ticks(job.preemption_time, job.execution_time);
            let entry = stats_map.entry(job.pid).or_insert_with(|| CrpdStats {
                pid: job.pid,
                comm: job.comm.clone(),
                job_count: 0,
                total_preemption: 0,
                total_estimated_crpd: 0,
                max_estimated_crpd: 0,
                avg_estimated_crpd: 0.0,
            });

            entry.job_count += 1;
            entry.total_preemption += job.preemption_time;
            entry.total_estimated_crpd += estimated_crpd;
            entry.max_estimated_crpd = entry.max_estimated_crpd.max(estimated_crpd);
            entry.avg_estimated_crpd += estimated_crpd as f64;
        }

        for stats in stats_map.values_mut() {
            if stats.job_count > 0 {
                stats.avg_estimated_crpd /= stats.job_count as f64;
            }
        }

        let mut result: Vec<CrpdStats> = stats_map.into_values().collect();
        result.sort_by(|a, b| b.max_estimated_crpd.cmp(&a.max_estimated_crpd));
        result
    }
    
    /// Export analysis as JSON
    pub fn to_json(&self) -> String {
        let stats = self.calculate_stats();
        let mut json = String::new();
        json.push_str("{\n  \"job_stats\": [\n");
        
        let entries: Vec<String> = stats.iter().map(|s| {
            format!(
                "    {{\"pid\": {}, \"comm\": \"{}\", \"jobs\": {}, \"response\": {{\"min\": {}, \"max\": {}, \"avg\": {:.2}}}, \"execution\": {{\"min\": {}, \"max\": {}, \"avg\": {:.2}}}, \"total_preemption\": {}}}",
                s.pid, s.comm, s.job_count,
                s.min_response, s.max_response, s.avg_response,
                s.min_execution, s.max_execution, s.avg_execution,
                s.total_preemption
            )
        }).collect();
        
        json.push_str(&entries.join(",\n"));
        json.push_str("\n  ]\n}\n");
        json
    }

    pub fn to_crpd_json(&self) -> String {
        let stats = self.calculate_crpd_stats();
        let mut json = String::new();
        json.push_str("{\n  \"crpd_analysis\": [\n");

        let entries: Vec<String> = stats
            .iter()
            .map(|s| {
                format!(
                    "    {{\"pid\": {}, \"comm\": \"{}\", \"jobs\": {}, \"total_preempt_us\": {}, \"total_estimated_crpd_us\": {}, \"max_estimated_crpd_us\": {}, \"avg_estimated_crpd_us\": {:.3}}}",
                    s.pid,
                    s.comm,
                    s.job_count,
                    icount_to_micros_u64(s.total_preemption),
                    icount_to_micros_u64(s.total_estimated_crpd),
                    icount_to_micros_u64(s.max_estimated_crpd),
                    icount_f64_to_micros_f64(s.avg_estimated_crpd)
                )
            })
            .collect();

        json.push_str(&entries.join(",\n"));
        json.push_str("\n  ]\n}\n");
        json
    }
    
    /// Export to Timing telemetry CSV (timing_instance.csv)
    /// Format: start,end,prio,name
    pub fn to_timing_csv(&self) -> String {
        let mut csv = String::from("start,end,prio,name\n");
        // We use a fixed priority for Linux tasks since we don't track them yet
        let default_prio = 10; 
        
        for job in &self.completed_jobs {
            let start_us = icount_to_micros_u64(job.release_time);
            let end_us = icount_to_micros_u64(job.completion_time);
            csv.push_str(&format!(
                "{},{},{},{}\n",
                start_us,
                end_us,
                default_prio,
                job.comm
            ));
        }
        csv
    }

    /// Export job stats to CSV (linux_timing_job.csv)
    pub fn to_timing_job_csv(&self) -> String {
        let stats = self.calculate_stats();
        let mut csv = String::from(
            "pid,name,jobs,min_response_us,max_response_us,avg_response_us,min_exec_us,max_exec_us,avg_exec_us,total_preempt_us\n",
        );
        for s in stats {
            csv.push_str(&format!(
                "{},{},{},{},{},{:.3},{},{},{:.3},{}\n",
                s.pid,
                s.comm,
                s.job_count,
                icount_to_micros_u64(s.min_response),
                icount_to_micros_u64(s.max_response),
                icount_f64_to_micros_f64(s.avg_response),
                icount_to_micros_u64(s.min_execution),
                icount_to_micros_u64(s.max_execution),
                icount_f64_to_micros_f64(s.avg_execution),
                icount_to_micros_u64(s.total_preemption)
            ));
        }
        csv
    }

    /// Export job stats to a simple HTML report (linux_timing_job.html)
    pub fn to_timing_job_html(&self) -> String {
        let stats = self.calculate_stats();
        let mut html = String::new();
        html.push_str("<!DOCTYPE html><html><head><meta charset=\"utf-8\">");
        html.push_str("<title>Linux Job Report</title>");
        html.push_str("<style>body{font-family:Arial,sans-serif}table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:6px;text-align:right}th{text-align:center;background:#f2f2f2}td.name{text-align:left}</style>");
        html.push_str("</head><body>");
        html.push_str("<h2>Linux Job Response Report (microseconds)</h2>");
        html.push_str("<table>");
        html.push_str("<tr><th>PID</th><th>Name</th><th>Jobs</th><th>Min Resp</th><th>Max Resp</th><th>Avg Resp</th><th>Min Exec</th><th>Max Exec</th><th>Avg Exec</th><th>Total Preempt</th></tr>");
        for s in stats {
            html.push_str(&format!(
                "<tr><td>{}</td><td class=\"name\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{}</td><td>{}</td><td>{:.3}</td><td>{}</td></tr>",
                s.pid,
                s.comm,
                s.job_count,
                icount_to_micros_u64(s.min_response),
                icount_to_micros_u64(s.max_response),
                icount_f64_to_micros_f64(s.avg_response),
                icount_to_micros_u64(s.min_execution),
                icount_to_micros_u64(s.max_execution),
                icount_f64_to_micros_f64(s.avg_execution),
                icount_to_micros_u64(s.total_preemption)
            ));
        }
        html.push_str("</table></body></html>");
        html
    }

    /// Save analysis to file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = self.to_json();
        let mut file = File::create(path.as_ref())?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    pub fn save_crpd<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = self.to_crpd_json();
        let mut file = File::create(path.as_ref())?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
    
    /// Print summary to console
    pub fn print_summary(&self) {
        let stats = self.calculate_stats();
        
        println!("\n{}", "=".repeat(80));
        println!("           JOB RESPONSE TIME ANALYSIS");
        println!("{}", "=".repeat(80));
        println!("{:>6} {:>20} {:>8} {:>15} {:>15} {:>10}", "PID", "Process", "Jobs", "Max Resp", "Avg Resp", "Exec %");
        println!("{}", "-".repeat(80));
        
        for s in stats.iter().take(15) {
            let exec_pct = if s.avg_response > 0.0 {
                (s.avg_execution / s.avg_response) * 100.0
            } else {
                0.0
            };
            
            println!("{:>6} {:>20} {:>8} {:>15} {:>15.2} {:>9.1}%", 
                s.pid, 
                truncate_str(&s.comm, 20),
                s.job_count,
                format_duration(s.max_response),
                s.avg_response,
                exec_pct
            );
        }
        println!("{}", "=".repeat(80));
    }
}

/// Statistics for a task's jobs
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct JobStats {
    pub pid: u32,
    pub comm: String,
    pub job_count: usize,
    
    pub min_response: u64,
    pub max_response: u64,
    pub avg_response: f64,
    
    pub min_execution: u64,
    pub max_execution: u64,
    pub avg_execution: f64,
    
    pub total_preemption: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CrpdStats {
    pub pid: u32,
    pub comm: String,
    pub job_count: usize,
    pub total_preemption: u64,
    pub total_estimated_crpd: u64,
    pub max_estimated_crpd: u64,
    pub avg_estimated_crpd: f64,
}

// Helper functions (reused from stg.rs)
fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}...", &s[..max_len-3])
    } else {
        s.to_string()
    }
}

fn format_duration(blocks: u64) -> String {
    if blocks >= 1_000_000 {
        format!("{:.2}M", blocks as f64 / 1_000_000.0)
    } else if blocks >= 1_000 {
        format!("{:.2}K", blocks as f64 / 1_000.0)
    } else {
        format!("{}", blocks)
    }
}
