# FRET Fuzzer Software Architecture

FRET (FreeRTOS Real-Time) is a sophisticated greybox fuzzer designed for testing real-time operating systems, specifically FreeRTOS kernels. It leverages QEMU system-mode emulation to provide binary-only coverage-guided fuzzing with advanced system state tracking and real-time analysis capabilities.

## High-Level Architecture

The FRET fuzzer follows a multi-layered architecture with the following key components:

```
┌─────────────────────────────────────────────────────────────────┐
│                        FRET Fuzzer                             │
├─────────────────────────────────────────────────────────────────┤
│ CLI Interface (cli.rs) & Configuration (config.rs)             │
├─────────────────────────────────────────────────────────────────┤
│ Main Fuzzer Loop (fuzzer.rs)                                   │
│ ├── LibAFL Framework Integration                               │
│ ├── QEMU System-Mode Emulation                                 │
│ └── Target Binary Loading & Symbol Resolution                  │
├─────────────────────────────────────────────────────────────────┤
│ System State Tracking (systemstate/)                           │
│ ├── Target OS Abstraction (target_os/)                        │
│ │   └── FreeRTOS Implementation (freertos/)                   │
│ ├── State Transition Graph (stg.rs)                           │
│ ├── System State Feedbacks (feedbacks.rs)                     │
│ ├── Custom Mutation Strategies (mutational.rs)                │
│ └── Specialized Schedulers (schedulers.rs)                    │
├─────────────────────────────────────────────────────────────────┤
│ Timing Analysis (time/)                                         │
│ ├── Clock Management (clock.rs)                               │
│ ├── QEMU State Management (qemustate.rs)                      │
│ └── Basic Worst-Case Heuristics (worst.rs)             │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Main Fuzzer Engine (`fuzzer.rs`)

The main fuzzer engine coordinates all components and implements the core fuzzing loop:

- **QEMU Integration**: Uses LibAFL's QEMU integration for system-mode emulation
- **Symbol Resolution**: Resolves kernel symbols and sets up memory mappings
- **Input Generation**: Manages interrupt timing and system inputs
- **Corpus Management**: Maintains test cases with execution time metadata
- **Feedback Orchestration**: Coordinates multiple feedback mechanisms

### 2. System State Tracking (`systemstate/`)

This is the heart of FRET's innovation - tracking and analyzing real-time system states:

#### 2.1 Target OS Abstraction (`target_os/`)

Provides a generic interface for different RTOS implementations:

```rust
trait TargetSystem {
    type State: SystemState;
    type TCB: TaskControlBlock;  
    type TraceData: SystemTraceData;
}
```

#### 2.2 FreeRTOS Implementation (`target_os/freertos/`)

- **QEMU Module** (`qemu_module.rs`): Hooks into QEMU execution to capture system states
- **State Capture**: Records task control blocks, ready queues, delay lists
- **Symbol Resolution** (`config.rs`): Maps kernel symbols to addresses
- **Post-processing**: Converts raw states into refined system representations

#### 2.3 System State Representation

**Hierarchical Data Structures:**
- `RawFreeRTOSSystemState`: Raw data captured from QEMU at specific instants
- `FreeRTOSSystemState`: Refined system state without execution context
- `ExecInterval`: Execution intervals between system state changes
- `AtomicBasicBlock`: Single-entry multiple-exit code regions
- `RTOSJob`: Complete task execution with timing information
- `RTOSTask`: Generalized task representation

### 3. State Transition Graph (STG) (`stg.rs`)

The STG is a key innovation that models system execution as a directed graph:

- **Nodes**: Represent system states with associated atomic basic blocks
- **Edges**: Represent state transitions with execution timing
- **Path Analysis**: Tracks execution paths and identifies worst-case scenarios
- **Scheduling Analysis**: Models task scheduling decisions and preemption

**STG Features:**
- State deduplication using hash-based node identification
- Edge weight tracking for timing analysis
- Path-based coverage feedback
- Integration with corpus scheduling

### 4. Feedback Mechanisms (`feedbacks.rs`)

FRET implements multiple specialized feedback mechanisms:

- **STG-based Feedback**: Uses state transition graph coverage
- **Timing Feedback**: Focuses on worst-case execution time
- **System State Feedback**: Tracks unique system configurations
- **Traditional Coverage**: Standard edge coverage for comparison

### 5. Custom Mutation Strategies (`mutational.rs`)

Specialized mutation operators for real-time systems:

- **Interrupt Timing Mutation**: Modifies interrupt arrival times
- **STG-guided Mutation**: Uses state transition graph to guide mutations
- **System State Mutation**: Targets specific system configurations

### 6. Timing Analysis (`time/`)

Comprehensive timing analysis for real-time systems:

- **Clock Management**: Tracks QEMU instruction counts and timing
- **WCET Analysis**: Identifies worst-case execution times
- **Response Time Analysis**: Measures task response times
- **Temporal Schedulers**: Prioritize inputs based on timing properties

## Information Flow

### System State Capture Flow

1. **Symbol Resolution** (`target_os::freertos::config.rs`):
   - Resolves kernel symbols (task control blocks, queues, etc.)
   - Creates address ranges for API functions and ISR handlers

2. **Runtime Capture** (`target_os::freertos::qemu_module::FreeRTOSSystemStateHelper`):
   - Hooks QEMU execution at critical points (syscalls, interrupts)
   - Captures `RawFreeRTOSSystemState` snapshots
   - Records memory reads and execution intervals

3. **State Processing**:
   - Converts raw states to `FreeRTOSSystemState` (refined representation)
   - Generates `ExecInterval` objects for execution flow
   - Identifies `AtomicBasicBlock` regions

4. **STG Construction** (`stg::StgFeedback`):
   - **Core Classes**:
     - `STGFeedbackState<SYS>`: Maintains the state transition graph and metadata
     - `STGNode<SYS>`: Represents graph nodes containing system state hash and atomic basic block
     - `STGEdge`: Represents graph edges with execution timing and transition information
     - `StgFeedback<SYS>`: Main feedback mechanism that builds and updates the STG
   - **Process**:
     - Analyzes `ExecInterval` sequences from trace data
     - Creates `STGNode` instances for unique system state + ABB combinations
     - Adds `STGEdge` instances for state transitions with timing weights
     - Uses `HashMap<u64, NodeIndex>` for efficient node deduplication
     - Integrates with `DiGraph<STGNode<SYS>, STGEdge>` from petgraph library

5. **Feedback Integration**:
   - **Timing-Based Feedbacks**:
     - `ClockTimeFeedback<SYS>`: Tracks QEMU instruction count increases
     - `QemuClockIncreaseFeedback<SYS>`: Monitors clock progression patterns
     - `ExecTimeIncFeedback<SYS>`: Focuses on execution time improvements
   - **Corpus Schedulers**:
     - `TimeMaximizerCorpusScheduler<CS, O>`: Prioritizes inputs with longer execution times
     - `TimeStateMaximizerCorpusScheduler<CS, O, SYS>`: Combines timing and system state coverage
     - `LongestTraceScheduler<CS, SYS>`: Schedules based on trace length metrics
     - `GenerationScheduler<S>`: Implements generation-based scheduling strategies
   - **Mutation Strategies**:
     - `InterruptShiftStage<E, EM, Z, SYS>`: Mutates interrupt timing sequences
     - `STGSnippetStage<E, EM, Z, SYS>`: Uses STG paths to guide mutation decisions
   - **Integration Process**:
     - Multiple feedback mechanisms run in parallel during corpus evaluation
     - `StgFeedback` updates the state transition graph with new paths
     - Timing feedbacks identify inputs that trigger longer execution paths
     - Schedulers use combined metrics to prioritize corpus entries for mutation

### Execution Flow

1. **Initialization**:
   - Load target kernel binary
   - Resolve symbols and setup memory mappings
   - Initialize QEMU system-mode emulation
   - Setup hooks for system state capture

2. **Fuzzing Loop**:
   - Generate/mutate input (interrupt timing sequence)
   - Execute target in QEMU with system state tracking
   - Capture execution trace and timing information
   - Build/update state transition graph
   - Evaluate feedback mechanisms
   - Update corpus and select next input

3. **Runtime Monitoring and Analysis**:
   - Display fuzzing progress, coverage metrics, and timing statistics
   - Maintain and prioritize test cases based on coverage and timing feedback

4. **Output Generation**
   - **Time Dumps** (`--dump-times`, `-t`): Export execution timing data for offline analysis
   - **Worst-Case Dumps** (`--dump-cases`, `-a`): Save inputs that trigger worst-case execution scenarios
   - **Trace Dumps** (`--dump-traces`, `-r`): Export detailed execution traces including system state transitions
   - **Graph Dumps** (`--dump-graph`, `-g`): Output state transition graphs in DOT format for visualization
   - **Task-Specific Analysis** (`--select-task`, `-s`): Focus measurements on specific RTOS tasks
   - **Configurable Output Prefix** (`--dump-name`, `-n`): Set custom prefixes for all output files
