//! State Transition Graph (STG) module for FRET analysis

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use anyhow::{Context, Result};


#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeKey {
    pub pid: u32,
    pub abb_type: String,
}


#[derive(Debug, Clone)]
pub struct STGNode {
    pub id: usize,
    pub pid: u32,
    pub comm: String,
    pub abb_type: String,
    pub visit_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EdgeKey {
    pub from_node: NodeKey,
    pub to_node: NodeKey,
    pub event: String,
}


#[derive(Debug, Clone)]
pub struct STGEdge {
    pub from_id: usize,
    pub to_id: usize,
    pub event: String,
    pub durations: Vec<u64>,
}

impl STGEdge {
    pub fn stats(&self) -> EdgeStats {
        if self.durations.is_empty() {
            return EdgeStats::default();
        }
        
        let count = self.durations.len() as u64;
        let sum: u64 = self.durations.iter().sum();
        let mean = sum / count;
        let min = *self.durations.iter().min().unwrap();
        let max = *self.durations.iter().max().unwrap();
        
        // Standard deviation
        let variance: f64 = self.durations.iter()
            .map(|&d| {
                let diff = d as f64 - mean as f64;
                diff * diff
            })
            .sum::<f64>() / count as f64;
        let std_dev = variance.sqrt();
        
        EdgeStats { count, min, max, mean, std_dev }
    }
}

/// Statistics for an edge
#[derive(Debug, Clone, Default)]
pub struct EdgeStats {
    pub count: u64,
    pub min: u64,
    pub max: u64,
    pub mean: u64,
    pub std_dev: f64,
}

/// State Transition Graph
#[derive(Debug)]
pub struct StateTransitionGraph {
    nodes: HashMap<NodeKey, STGNode>,
    edges: HashMap<EdgeKey, STGEdge>,
    node_id_counter: usize,
}

const QEMU_ICOUNT_SHIFT: u32 = 5;

fn icount_to_micros_f64(icount: u64) -> f64 {
    let ns = (icount as u128) << QEMU_ICOUNT_SHIFT;
    (ns as f64) / 1_000.0
}

impl StateTransitionGraph {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            edges: HashMap::new(),
            node_id_counter: 0,
        }
    }
    
    /// Build STG from a CSV trace file
    pub fn from_csv<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .context(format!("Failed to open trace file: {:?}", path.as_ref()))?;
        let reader = BufReader::new(file);
        
        let mut stg = Self::new();
        let mut prev_state: HashMap<u32, (NodeKey, String)> = HashMap::new(); // pid -> (prev_node, prev_event)
        
        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result.context(format!("Failed to read line {}", line_num))?;
            
        
            if line_num == 0 && line.starts_with("capture_point") {
                continue;
            }
            
            
            let fields: Vec<&str> = line.split(',').collect();
            if fields.len() < 8 {
                continue; // Skip malformed lines
            }
            
            let capture_point = fields[0].to_string();
            let pid: u32 = fields[1].parse().unwrap_or(0);
            let comm = fields[2].trim_matches('"').to_string();
            let abb_type = fields[6].to_string();
            
        
            let duration: u64 = if fields.len() >= 9 {
                let start: u64 = fields[7].parse().unwrap_or(0);
                let end: u64 = fields[8].parse().unwrap_or(0);
                if end >= start { end - start } else { 0 }
            } else {
                fields[7].parse().unwrap_or(0)
            };
            
            // Create current node key
            let curr_key = NodeKey {
                pid,
                abb_type: abb_type.clone(),
            };
            
            
            if !stg.nodes.contains_key(&curr_key) {
                let id = stg.node_id_counter;
                stg.node_id_counter += 1;
                stg.nodes.insert(curr_key.clone(), STGNode {
                    id,
                    pid,
                    comm: comm.clone(),
                    abb_type: abb_type.clone(),
                    visit_count: 0,
                });
            }
            
            // Increment visit count
            if let Some(node) = stg.nodes.get_mut(&curr_key) {
                node.visit_count += 1;
            }
            
            // Create edge from previous state
            if let Some((prev_key, _prev_event)) = prev_state.get(&pid) {
                let edge_key = EdgeKey {
                    from_node: prev_key.clone(),
                    to_node: curr_key.clone(),
                    event: capture_point.clone(),
                };
                
                let from_id = stg.nodes.get(prev_key).map(|n| n.id).unwrap_or(0);
                let to_id = stg.nodes.get(&curr_key).map(|n| n.id).unwrap_or(0);
                
                stg.edges.entry(edge_key)
                    .or_insert_with(|| STGEdge {
                        from_id,
                        to_id,
                        event: capture_point.clone(),
                        durations: Vec::new(),
                    })
                    .durations.push(duration);
            }
            
            // Update previous state for this PID
            prev_state.insert(pid, (curr_key, capture_point));
        }
        
        Ok(stg)
    }
    
    /// Get number of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    
    /// Get number of edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }
    
    /// Get all unique PIDs in the graph
    pub fn pids(&self) -> Vec<u32> {
        let mut pids: Vec<u32> = self.nodes.keys().map(|k| k.pid).collect();
        pids.sort();
        pids.dedup();
        pids
    }
    
    /// Export to DOT 
    pub fn to_dot(&self) -> String {
        let mut dot = String::new();
        dot.push_str("digraph STG {\n");
        dot.push_str("  rankdir=TB;\n");
        dot.push_str("  node [shape=box, style=filled, fillcolor=lightblue];\n\n");
        
        // Group nodes by PID
        let mut pid_nodes: HashMap<u32, Vec<&STGNode>> = HashMap::new();
        for node in self.nodes.values() {
            pid_nodes.entry(node.pid).or_default().push(node);
        }
        
        // Create subgraphs for each PID
        for (pid, nodes) in &pid_nodes {
            let comm = nodes.first().map(|n| n.comm.as_str()).unwrap_or("unknown");
            dot.push_str(&format!("  subgraph cluster_{} {{\n", pid));
            dot.push_str(&format!("    label=\"{} (PID {})\";\n", comm, pid));
            dot.push_str("    style=filled;\n");
            dot.push_str("    fillcolor=lightyellow;\n");
            
            for node in nodes {
                let color = match node.abb_type.as_str() {
                    "UserSpace" => "lightgreen",
                    t if t.starts_with("Syscall") => "lightcoral",
                    "IRQ" => "orange",
                    "ContextSwitch" => "lightgray",
                    _ => "white",
                };
                dot.push_str(&format!(
                    "    n{} [label=\"{}\\n(visits: {})\", fillcolor={}];\n",
                    node.id, node.abb_type, node.visit_count, color
                ));
            }
            dot.push_str("  }\n\n");
        }
        
        // Create edges
        for (edge_key, edge) in &self.edges {
            let stats = edge.stats();
            let label = format!(
                "{}\\ncount: {}\\nmin: {} max: {}\\nmean: {:.0}",
                edge.event, stats.count, stats.min, stats.max, stats.mean as f64
            );
            
            // Edge color based on max duration
            let color = if stats.max > 10000 { "red" }
                else if stats.max > 1000 { "orange" }
                else { "black" };
            
            let from_id = self.nodes.get(&edge_key.from_node).map(|n| n.id).unwrap_or(0);
            let to_id = self.nodes.get(&edge_key.to_node).map(|n| n.id).unwrap_or(0);
            
            dot.push_str(&format!(
                "  n{} -> n{} [label=\"{}\", color={}];\n",
                from_id, to_id, label, color
            ));
        }
        
        dot.push_str("}\n");
        dot
    }
    
    /// Export timing statistics as JSON
    pub fn to_json(&self) -> String {
        let mut json = String::new();
        json.push_str("{\n");
        json.push_str("  \"summary\": {\n");
        json.push_str(&format!("    \"nodes\": {},\n", self.node_count()));
        json.push_str(&format!("    \"edges\": {},\n", self.edge_count()));
        json.push_str(&format!("    \"pids\": {:?}\n", self.pids()));
        json.push_str("  },\n");
        
        json.push_str("  \"edges\": [\n");
        let edge_strs: Vec<String> = self.edges.iter().map(|(key, edge)| {
            let stats = edge.stats();
            format!(
                "    {{\"from\": \"{}/{}\", \"to\": \"{}/{}\", \"event\": \"{}\", \"count\": {}, \"min\": {}, \"max\": {}, \"mean\": {}}}",
                key.from_node.pid, key.from_node.abb_type,
                key.to_node.pid, key.to_node.abb_type,
                edge.event, stats.count, stats.min, stats.max, stats.mean
            )
        }).collect();
        json.push_str(&edge_strs.join(",\n"));
        json.push_str("\n  ]\n");
        json.push_str("}\n");
        json
    }
    

    pub fn to_timing_csv(&self) -> String {
        let mut csv = String::from("name,addr,active,finish,micros,woet\n");
        
        
        for (node_key, node) in &self.nodes {
            // Find all outgoing edges from this node to aggregate metrics
            let mut total_active = 0;
            let mut total_finish = 0;
            let mut total_micros = 0.0;
            let mut max_woet = 0.0;
            
            for (edge_key, edge) in &self.edges {
                if edge_key.from_node == *node_key {
                    let stats = edge.stats();
                    total_active += stats.count;
                    total_finish += stats.count; 
                    total_micros += icount_to_micros_f64(stats.mean) * stats.count as f64;
                    let max_micros = icount_to_micros_f64(stats.max);
                    if max_micros > max_woet {
                        max_woet = max_micros;
                    }
                }
            }
            
            csv.push_str(&format!(
                "{},0,{},{},{:.3},{:.3}\n",
                node.abb_type,
                total_active,
                total_finish,
                total_micros,
                max_woet
            ));
        }
        csv
    }

    /// Save to file
    pub fn save<P: AsRef<Path>>(&self, path: P, format: &str) -> Result<()> {
        let content = match format {
            "dot" => self.to_dot(),
            "json" => self.to_json(),
            _ => return Err(anyhow::anyhow!("Unknown format: {}", format)),
        };
        
        let mut file = File::create(path.as_ref())
            .context(format!("Failed to create output file: {:?}", path.as_ref()))?;
        file.write_all(content.as_bytes())?;
        
        Ok(())
    }
    
    /// Print summary to console
    pub fn print_summary(&self) {
        println!("\n=== STG Summary ===");
        println!("Nodes: {}", self.node_count());
        println!("Edges: {}", self.edge_count());
        println!("PIDs: {:?}", self.pids());
        
        // Find max edges
        let mut edges: Vec<_> = self.edges.iter().collect();
        edges.sort_by(|a, b| {
            let stats_a = a.1.stats();
            let stats_b = b.1.stats();
            stats_b.max.cmp(&stats_a.max)
        });
        
        println!("\nTop 5 Hot Edges (by max duration):");
        for (key, edge) in edges.iter().take(5) {
            let stats = edge.stats();
            println!(
                "  {} -> {} [{}]: max={}, mean={:.0}, count={}",
                key.from_node.abb_type, key.to_node.abb_type,
                edge.event, stats.max, stats.mean as f64, stats.count
            );
        }
    }
    
    
    /// Get edges for a specific PID
    fn get_edges_for_pid(&self, pid: u32) -> Vec<(&EdgeKey, &STGEdge)> {
        self.edges.iter()
            .filter(|(key, _)| key.from_node.pid == pid && key.to_node.pid == pid)
            .collect()
    }
    
    /// Get nodes for a specific PID
    fn get_nodes_for_pid(&self, pid: u32) -> Vec<(&NodeKey, &STGNode)> {
        self.nodes.iter()
            .filter(|(key, _)| key.pid == pid)
            .collect()
    }
    
    /// Compute WCET for longest path 
    pub fn compute_wcet_for_pid(&self, pid: u32) -> Option<WCETAnalysis> {
        let nodes = self.get_nodes_for_pid(pid);
        let edges = self.get_edges_for_pid(pid);
        
        if nodes.is_empty() || edges.is_empty() {
            return None;
        }
        
        let comm = nodes.first().map(|(_, n)| n.comm.clone()).unwrap_or_default();
        
        // Build adjacency list with max durations
        let mut adj: HashMap<String, Vec<(String, u64, String)>> = HashMap::new();
        for (key, edge) in &edges {
            let stats = edge.stats();
            adj.entry(key.from_node.abb_type.clone())
                .or_default()
                .push((key.to_node.abb_type.clone(), stats.max, edge.event.clone()));
        }
        
        // Find all unique node types
        let node_types: Vec<String> = nodes.iter().map(|(k, _)| k.abb_type.clone()).collect();
        
        // Compute longest path from each node 
        let mut max_dist: HashMap<String, u64> = HashMap::new();
        let mut predecessor: HashMap<String, (String, u64, String)> = HashMap::new();
        
       
        for nt in &node_types {
            max_dist.insert(nt.clone(), 0);
        }
        
        
        for _ in 0..node_types.len() {
            for (from_type, neighbors) in &adj {
                for (to_type, weight, event) in neighbors {
                    let new_dist = max_dist.get(from_type).unwrap_or(&0) + weight;
                    if new_dist > *max_dist.get(to_type).unwrap_or(&0) {
                        max_dist.insert(to_type.clone(), new_dist);
                        predecessor.insert(to_type.clone(), (from_type.clone(), *weight, event.clone()));
                    }
                }
            }
        }
        
        // Find the node with maximum distance 
        let (end_node, total_wcet) = max_dist.iter()
            .max_by_key(|(_, &d)| d)
            .map(|(k, &v)| (k.clone(), v))?;
        
        // Reconstruct critical path
        let mut critical_path = Vec::new();
        let mut current = end_node.clone();
        let mut visited = std::collections::HashSet::new();
        
        while let Some((prev, weight, event)) = predecessor.get(&current) {
            if visited.contains(&current) {
                break; // Cycle detected
            }
            visited.insert(current.clone());
            
            critical_path.push(WCETEdge {
                from: prev.clone(),
                to: current.clone(),
                max_duration: *weight,
                event: event.clone(),
            });
            current = prev.clone();
            
            // Safety break for very long paths
            if critical_path.len() > nodes.len() * 2 {
                break;
            }
        }
        critical_path.reverse();
        
        Some(WCETAnalysis {
            pid,
            comm,
            total_wcet,
            critical_path,
            node_count: nodes.len(),
            edge_count: edges.len(),
            all_edges: edges.iter().map(|(k, e)| {
                let stats = e.stats();
                WCETEdge {
                    from: k.from_node.abb_type.clone(),
                    to: k.to_node.abb_type.clone(),
                    max_duration: stats.max,
                    event: e.event.clone(),
                }
            }).collect(),
        })
    }
    
    /// Compute WCET for all processes
    pub fn compute_all_wcet(&self) -> Vec<WCETAnalysis> {
        self.pids().iter()
            .filter_map(|&pid| self.compute_wcet_for_pid(pid))
            .collect()
    }
    
    /// Print WCET analysis report
    pub fn print_wcet_report(&self) {
        println!("\n{}", "=".repeat(60));
        println!("           WCET ANALYSIS REPORT");
        println!("{}", "=".repeat(60));
        
        let mut analyses = self.compute_all_wcet();
        analyses.sort_by(|a, b| b.total_wcet.cmp(&a.total_wcet));
        
        println!("\n{:-^60}", " Top 10 Processes by WCET ");
        println!("{:>6} {:>20} {:>15} {:>10}", "PID", "Process", "Total WCET", "Edges");
        println!("{:-<60}", "");
        
        for analysis in analyses.iter().take(10) {
            println!("{:>6} {:>20} {:>15} {:>10}", 
                analysis.pid, 
                truncate_str(&analysis.comm, 20),
                format_duration(analysis.total_wcet),
                analysis.edge_count
            );
        }
        
        
        println!("\n{:-^60}", " Detailed Critical Path Analysis ");
        
        for analysis in analyses.iter().take(3) {
            println!("\n┌{}┐", "─".repeat(58));
            println!("│ {} (PID {})", analysis.comm, analysis.pid);
            println!("│ Total WCET: {} blocks", analysis.total_wcet);
            println!("├{}┤", "─".repeat(58));
            
            if analysis.critical_path.is_empty() {
                println!("│ No critical path found (single-state process)");
            } else {
                println!("│ Critical Path:");
                for (i, edge) in analysis.critical_path.iter().enumerate() {
                    let arrow = if i == analysis.critical_path.len() - 1 { "└" } else { "├" };
                    println!("│   {} {} → {} [{}: {} blocks]",
                        arrow,
                        edge.from,
                        edge.to,
                        edge.event,
                        edge.max_duration
                    );
                }
            }
            
            // Show all edges for this process
            println!("│");
            println!("│ All Transitions:");
            let mut sorted_edges = analysis.all_edges.clone();
            sorted_edges.sort_by(|a, b| b.max_duration.cmp(&a.max_duration));
            for edge in sorted_edges.iter().take(5) {
                println!("│   • {} → {}: max {} blocks",
                    edge.from, edge.to, edge.max_duration
                );
            }
            println!("└{}┘", "─".repeat(58));
        }
    }
    
    /// Export WCET analysis as JSON
    pub fn wcet_to_json(&self) -> String {
        let analyses = self.compute_all_wcet();
        let mut json = String::new();
        json.push_str("{\n  \"wcet_analysis\": [\n");
        
        let entries: Vec<String> = analyses.iter().map(|a| {
            let path_str: Vec<String> = a.critical_path.iter()
                .map(|e| format!("{{\"from\": \"{}\", \"to\": \"{}\", \"max\": {}, \"event\": \"{}\"}}", 
                    e.from, e.to, e.max_duration, e.event))
                .collect();
            
            format!(
                "    {{\"pid\": {}, \"comm\": \"{}\", \"total_wcet\": {}, \"nodes\": {}, \"edges\": {}, \"critical_path\": [{}]}}",
                a.pid, a.comm, a.total_wcet, a.node_count, a.edge_count, path_str.join(", ")
            )
        }).collect();
        
        json.push_str(&entries.join(",\n"));
        json.push_str("\n  ]\n}\n");
        json
    }
    
    /// Save WCET analysis to file
    pub fn save_wcet<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = self.wcet_to_json();
        let mut file = File::create(path.as_ref())?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }
}

/// WCET analysis result for a process
#[derive(Debug, Clone)]
pub struct WCETAnalysis {
    pub pid: u32,
    pub comm: String,
    pub total_wcet: u64,
    pub critical_path: Vec<WCETEdge>,
    pub node_count: usize,
    pub edge_count: usize,
    pub all_edges: Vec<WCETEdge>,
}

/// Edge in WCET critical path
#[derive(Debug, Clone)]
pub struct WCETEdge {
    pub from: String,
    pub to: String,
    pub max_duration: u64,
    pub event: String,
}

// Helper functions
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_edge_stats() {
        let edge = STGEdge {
            from_id: 0,
            to_id: 1,
            event: "test".to_string(),
            durations: vec![100, 200, 300],
        };
        let stats = edge.stats();
        assert_eq!(stats.count, 3);
        assert_eq!(stats.min, 100);
        assert_eq!(stats.max, 300);
        assert_eq!(stats.mean, 200);
    }
}
