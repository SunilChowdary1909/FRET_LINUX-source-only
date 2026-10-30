# FRET_LINUX

FRET_LINUX is the Linux thesis implementation: a grey-box fuzzer for studying
worst-case response times (WORT) of real-time workloads running in an AArch64
Linux guest under QEMU system emulation.

## Public repositories

- [FRET_LINUX-source-only](https://github.com/SunilChowdary1909/FRET_LINUX-source-only)
  is this repository and contains the Linux fuzzer, analyzer, benchmark source,
  configuration, and build documentation.
- [FRET-source-only](https://github.com/SunilChowdary1909/FRET-source-only) is
  the supporting FRET framework, included here at `WORK/FRET`.
- [FRET-LibAFL](https://github.com/SunilChowdary1909/FRET-LibAFL) and
  [FRET-qemu](https://github.com/SunilChowdary1909/FRET-qemu) are pinned as
  submodules of `WORK/FRET`. Their required source modifications are already
  included at the pinned commits; no local patch-copying step is needed.
- FreeRTOS remains an upstream submodule of FRET for the original framework.
  It is not the target operating system for this Linux project.

## What it does

The Linux fuzzer combines LibAFL with a patched QEMU system emulator. It
injects workload data and configured interrupts into a Linux guest and uses
execution timing and observed system state to guide exploration.

The VMI observation path installs QEMU/TCG hooks at Linux kernel symbols to
observe scheduling and task state during guest execution. Hooks are installed
before the fast snapshot so they remain active after snapshot restoration. The
source also contains an ftrace-oriented state-observation module.

The state-transition graph (STG) represents observed system states and
execution intervals as nodes and transitions. STG feedback and mutations can
guide exploration toward new scheduling paths. Timing feedback tracks costly
executions; WORT output records the observed worst response-time value over a
campaign when enabled.

The sample workloads are in [`FRET_Linux/linux_apps/`](FRET_Linux/linux_apps/):

- `avfusion.c` is a multi-stage, input-dependent workload; use
  `--span-blocking` for its release-to-completion response window.
- `chain_mtx.c` and `periodic_mtx.c` provide mutex/periodic task workloads.
- The app README describes their harness symbols and available build scripts.

The offline analyzer in `FRET_Linux/linux_fret_analyzer/` can build an STG
from the fuzzer's CSV trace, report WCET-related information, analyze jobs,
and optionally export timing data.

## Clone

```sh
git clone --branch publication-source-only \
  https://github.com/SunilChowdary1909/FRET_LINUX-source-only.git FRET_LINUX

cd FRET_LINUX

git submodule update --init -- WORK/FRET
git -C WORK/FRET submodule update --init
git -C WORK/FRET/qemu-libafl-bridge submodule update --init
```

These are the verified layered clone commands. They initialize FRET, its
LibAFL/QEMU/FreeRTOS references, and QEMU's direct submodules. Full recursive
cloning additionally attempts EDK2's optional nested UnitTestFramework
Subhook dependency, whose upstream URL currently returns HTTP 404; the
documented Linux fuzzer build disables QEMU tests and does not need it.

## Prerequisites and build

Use a Linux x86_64 host with Git and Nix flakes enabled. The FRET flake
provides the pinned Rust toolchain and QEMU build dependencies. The full
fuzzer build has **not yet been verified**: the prior build attempt could not
run because Nix was unavailable in the build environment.

Build the fuzzer from the repository root:

```sh
bash FRET_Linux/linux_fret_fuzzer/build_fuzzer.sh
```

The script enters the `WORK/FRET` Nix development environment and builds the
manifest at `FRET_Linux/linux_fret_fuzzer/Cargo.toml`. The expected debug
binary path is `FRET_Linux/linux_fret_fuzzer/target/debug/fret`.

Build the `avfusion` sample workload with an AArch64 Linux cross-compiler:

```sh
mkdir -p FRET_Linux/linux_apps/bin
aarch64-linux-gnu-gcc -static -O2 -pthread \
  -o FRET_Linux/linux_apps/bin/avfusion \
  FRET_Linux/linux_apps/avfusion.c -lrt
```

The `build_apps.sh`, `build_chain.sh`, and `build_v2.sh` scripts are also
present for the periodic/mutex examples; they use Podman and an Ubuntu
container to install the cross-compiler. Build outputs go under
`FRET_Linux/linux_apps/bin/`, which is not part of the source snapshot.

## Configuration and runtime artifacts

The published runtime configuration is
[`fuzz_config.txt`](FRET_Linux/linux_fret_fuzzer/fuzz_config.txt), a
`KEY=VALUE` text file containing `FUZZ_MAIN`, `FUZZ_INPUT`, `FUZZ_INPUT_LEN`,
`BREAKPOINT`, and `INTERRUPTS`. The repository also includes an optional
[`fuzz_config.csv`](FRET_Linux/linux_fret_fuzzer/fuzz_config.csv) with entries
only for the published `periodic_mtx`, `chain_mtx`, `avfusion`, and
`avfusion_oracle` sample workloads; unrelated target configurations are not
included. To select a CSV row, pass `--config-key avfusion` (or another listed
key) along with `--config .../fuzz_config.csv`. The text configuration remains
the default example used below.

The CSV and text files contain example target addresses. Verify or update
them for the exact target ELF and guest kernel you build; these addresses have
not been validated against newly built binaries in this environment.

The source publication does not include:

- an AArch64 Linux kernel `Image` and matching symbol-bearing `vmlinux`;
- a bootable ext4 root filesystem containing and launching the workload;
- compiled target binaries, guest applications, fuzzing inputs, campaigns,
  traces, logs, or generated analysis outputs.

Provide those runtime artifacts separately. In particular, make sure the
guest starts the workload and that the symbols/addresses in the text
configuration match the kernel and target ELF. The fuzzer's `--target-elf`
option supplies target symbol information; it does not provide the guest
kernel or root filesystem.

## Run a short campaign

After building the fuzzer and workload and preparing the guest artifacts,
set paths to your own kernel, `vmlinux`, and root filesystem. Keep outputs
outside the source tree:

```sh
ARTIFACTS=/path/to/linux-artifacts
OUT=/tmp/fret-linux-run
mkdir -p "$OUT"

FRET_LINUX/linux_fret_fuzzer/target/debug/fret \
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

The output prefix may produce corpus, case, trace, graph, and timing files.
They are experiment outputs: keep them outside the repository and do not
commit them.

## Analyze a trace

The fuzzer's `--dump-traces` output includes a CSV trace suitable for the
offline analyzer. Build the analyzer in the FRET Nix environment:

```sh
PROJECT_ROOT="$PWD"
OUT=${OUT:-/tmp/fret-linux-run}
mkdir -p "$OUT"
cd WORK/FRET
nix develop . --command cargo build --release \
  --manifest-path "$PROJECT_ROOT/FRET_Linux/linux_fret_analyzer/Cargo.toml"
cd "$PROJECT_ROOT"
```

Then analyze a trace and write generated reports outside the source tree:

```sh
FRET_Linux/linux_fret_analyzer/target/release/fret_linux_analyzer \
  --stg "$OUT/avfusion.trace.csv" \
  --wcet \
  --jobs \
  --stg-output "$OUT/avfusion.stg.dot" \
  --wcet-output "$OUT/wcet.json" \
  --jobs-output "$OUT/jobs.json"
```

Add `--timing-export` to the analyzer to export its timing-compatible CSV/HTML
reports. Analyzer inputs and all generated reports are local runtime data,
not part of this source-only repository.

## Reproducibility status

The source, scripts, submodule pins, and text configuration are published.
The layered clone procedure was verified. The full fuzzer/analyzer build and
end-to-end run remain unverified because Nix, Cargo, and Rust were unavailable
in the verification environment. A matching kernel/rootfs, running guest
workload, and verified target addresses are also required before a campaign
can be reproduced.
