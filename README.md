# FRET_LINUX

This repository contains my Linux extension of FRET for exploring worst-case
response times (WORT) of real-time workloads in an AArch64 Linux guest. The
fuzzer runs the guest in QEMU system emulation and uses LibAFL for input
generation and feedback.

## Repository structure

- **FRET_LINUX-source-only** (this repository) contains the Linux fuzzer,
  analyzer, sample workloads, and their configuration.
- **[FRET-source-only](https://github.com/SunilChowdary1909/FRET-source-only)**
  is the supporting FRET framework, checked out at `WORK/FRET`.
- **[FRET-LibAFL](https://github.com/SunilChowdary1909/FRET-LibAFL)** and
  **[FRET-qemu](https://github.com/SunilChowdary1909/FRET-qemu)** are pinned
  submodules of FRET. The required LibAFL and QEMU changes are already in
  those commits; no patches need to be copied manually.
- FRET retains its upstream FreeRTOS submodule for the original framework.
  FreeRTOS is not the target OS for this Linux extension.

The Linux fuzzer observes kernel scheduling and task state through VMI hooks
in QEMU/TCG; an ftrace-based observation module is also present. The hooks are
installed before the fast snapshot so they remain active after restoration.
The fuzzer builds a state-transition graph (STG) from observed execution and
uses STG feedback and mutations to explore scheduling paths. Timing feedback
tracks costly executions, and the optional WORT output records the current
worst response time during a campaign.

Sample workloads are in `FRET_Linux/linux_apps/`: `avfusion.c` is a
multi-stage input-dependent workload, while `chain_mtx.c` and
`periodic_mtx.c` exercise mutex and periodic-task behavior. The analyzer in
`FRET_Linux/linux_fret_analyzer/` reads fuzzer traces and can produce STG,
WCET-related, job, and timing-export reports.

## Prerequisites

- Linux x86_64 host and Git
- Nix with flakes enabled for the fuzzer and analyzer builds; the FRET flake
  provides the Rust toolchain and QEMU build dependencies
- `aarch64-linux-gnu-gcc` for building `avfusion` directly
- Podman if using the provided periodic/mutex workload build scripts
- An AArch64 Linux kernel image (`Image`), matching symbol-bearing `vmlinux`,
  and bootable ext4 root filesystem for execution

## Setup

Clone the public source branch and initialize the dependencies in layers:

```sh
git clone --branch publication-source-only \
  https://github.com/SunilChowdary1909/FRET_LINUX-source-only.git FRET_LINUX

cd FRET_LINUX

git submodule update --init -- WORK/FRET
git -C WORK/FRET submodule update --init
git -C WORK/FRET/qemu-libafl-bridge submodule update --init
```

These commands initialize the required FRET and QEMU submodules. Full
recursive cloning also attempts EDK2's optional nested UnitTestFramework
Subhook dependency, whose upstream URL currently returns HTTP 404. The
LibAFL QEMU build disables tests and does not require that dependency.

## Build

The full build has not yet been verified: Nix was unavailable in the
environment where it was attempted.

Build the fuzzer from the repository root:

```sh
bash FRET_Linux/linux_fret_fuzzer/build_fuzzer.sh
```

This script enters the `WORK/FRET` Nix development environment and builds
`FRET_Linux/linux_fret_fuzzer/Cargo.toml`. The expected debug executable is
`FRET_Linux/linux_fret_fuzzer/target/debug/fret`.

Build the `avfusion` sample workload with the AArch64 cross-compiler:

```sh
mkdir -p FRET_Linux/linux_apps/bin
aarch64-linux-gnu-gcc -static -O2 -pthread \
  -o FRET_Linux/linux_apps/bin/avfusion \
  FRET_Linux/linux_apps/avfusion.c -lrt
```

The `build_apps.sh`, `build_chain.sh`, and `build_v2.sh` scripts build the
periodic/mutex examples using Podman. Their binaries are written to
`FRET_Linux/linux_apps/bin/` and are not included in this repository.

## Configuration and runtime files

`FRET_Linux/linux_fret_fuzzer/fuzz_config.txt` is the default `KEY=VALUE`
configuration. It sets `FUZZ_MAIN`, `FUZZ_INPUT`, `FUZZ_INPUT_LEN`,
`BREAKPOINT`, and `INTERRUPTS`.

`FRET_Linux/linux_fret_fuzzer/fuzz_config.csv` is an optional alternative with
rows for `periodic_mtx`, `chain_mtx`, `avfusion`, and `avfusion_oracle`.
Select a row with `--config-key`, for example:

```sh
--config FRET_Linux/linux_fret_fuzzer/fuzz_config.csv --config-key avfusion
```

The CSV and text config contain example target addresses. Check or update
them for the target ELF and guest kernel you use; these addresses have not
been verified against newly built binaries here.

The repository does not include the guest kernel, `vmlinux`, root filesystem,
compiled workload binaries, or campaign inputs and outputs. Prepare the
kernel and rootfs separately, and ensure the guest starts the workload and
that the configured addresses match your build.

## Run

After building the fuzzer and workload, set paths to your guest artifacts.
The example keeps generated files outside the source tree:

```sh
ARTIFACTS=/path/to/linux-artifacts
OUT=/tmp/fret-linux-run
mkdir -p "$OUT"

FRET_Linux/linux_fret_fuzzer/target/debug/fret \
  --kernel "$ARTIFACTS/Image" \
  --symbols "$ARTIFACTS/vmlinux" \
  --rootfs "$ARTIFACTS/rootfs.ext4" \
  --config FRET_Linux/linux_fret_fuzzer/fuzz_config.txt \
  --target-elf FRET_Linux/linux_apps/bin/avfusion \
  --span-blocking \
  --dump-name "$OUT/avfusion" \
  --dump-traces \
  --dump-graph \
  --wort-output "$OUT/wort.csv" \
  --variant vmi \
  --experiment-seed 123 \
  fuzz --seed 123 --time 60
```

`--span-blocking` measures the `avfusion` response window from release through
completion, including blocking intervals. Trace, graph, corpus, and timing
outputs are generated data; keep them out of the repository.

## Analyze

Build the analyzer from the repository root in the FRET Nix environment:

```sh
PROJECT_ROOT="$PWD"
OUT=${OUT:-/tmp/fret-linux-run}
mkdir -p "$OUT"
cd WORK/FRET
nix develop . --command cargo build --release \
  --manifest-path "$PROJECT_ROOT/FRET_Linux/linux_fret_analyzer/Cargo.toml"
cd "$PROJECT_ROOT"
```

Use the CSV trace produced by `--dump-traces` as analyzer input:

```sh
FRET_Linux/linux_fret_analyzer/target/release/fret_linux_analyzer \
  --stg "$OUT/avfusion.trace.csv" \
  --wcet \
  --jobs \
  --stg-output "$OUT/avfusion.stg.dot" \
  --wcet-output "$OUT/wcet.json" \
  --jobs-output "$OUT/jobs.json"
```

Add `--timing-export` to write timing-compatible CSV and HTML reports. These
reports and the input trace are local runtime data, not source files.
