# FRET_LINUX

FRET_LINUX is the Linux port of FRET, a grey-box fuzzer for worst-case
response-time analysis of real-time software. It runs an AArch64 Linux guest
under a patched QEMU system emulator and uses Linux scheduling state as
feedback.

This publication contains source code, build configuration, and submodule
references only. Guest kernels, root filesystems, application binaries,
fuzzing inputs, campaigns, and generated results are not included.

## Clone

```sh
git clone --branch publication-source-only \
  https://github.com/SunilChowdary1909/FRET_LINUX-source-only.git FRET_LINUX
cd FRET_LINUX
git submodule update --init -- WORK/FRET
git -C WORK/FRET submodule update --init
git -C WORK/FRET/qemu-libafl-bridge submodule update --init
```

The FRET submodule pins the corresponding source-only LibAFL and QEMU
publication commits. FreeRTOS remains referenced from its existing upstream
repository; it is not required as the Linux target. These commands initialize
the required submodule layers without recursively fetching EDK2's optional
UnitTestFramework Subhook dependency, whose upstream repository is unavailable.
The LibAFL QEMU build disables tests.

## Prerequisites

- Linux x86_64 host
- Git with recursive submodule support
- Nix with flakes enabled (used by the fuzzer build)
- `aarch64-linux-gnu-gcc` to build the sample benchmark application
- A matching AArch64 Linux kernel image (`Image`), symbol-bearing kernel ELF
  (`vmlinux`), and root filesystem image

## Build

Build the fuzzer from any working directory:

```sh
bash FRET_Linux/linux_fret_fuzzer/build_fuzzer.sh
```

Build the `avfusion` sample workload:

```sh
mkdir -p FRET_Linux/linux_apps/bin
cd FRET_Linux/linux_apps
aarch64-linux-gnu-gcc -static -O2 -pthread \
  -o bin/avfusion avfusion.c -lrt
cd ../..
```

The kernel, `vmlinux`, root filesystem, and target executable are local runtime
artifacts and must be prepared separately. See
[`FRET_Linux/linux_apps/README.md`](FRET_Linux/linux_apps/README.md) for
workload details.

## Run

Set the artifact paths for your guest and target, then run a short campaign:

```sh
ARTIFACTS=/path/to/linux-artifacts
APP="$PWD/FRET_Linux/linux_apps/bin/avfusion"
FUZZER="$PWD/FRET_Linux/linux_fret_fuzzer"

"$FUZZER/target/debug/fret" \
  --kernel "$ARTIFACTS/Image" \
  --symbols "$ARTIFACTS/vmlinux" \
  --rootfs "$ARTIFACTS/rootfs.ext4" \
  --config "$FUZZER/fuzz_config.txt" \
  --target-elf "$APP" \
  --span-blocking \
  --dump-name "$PWD/out/avfusion" \
  fuzz --seed 123 --time 60
```

`fuzz_config.txt` is a plain `KEY=VALUE` configuration for the sample
workload. Update its target addresses if rebuilding the application changes
its layout. Campaign output is written outside the source tree in `out/`.

The offline analyzer is in `FRET_Linux/linux_fret_analyzer`; build it with
`cargo build --release --manifest-path FRET_Linux/linux_fret_analyzer/Cargo.toml`.

## Source layout

- `FRET_Linux/linux_fret_fuzzer/` — Linux fuzzer
- `FRET_Linux/linux_fret_analyzer/` — trace and scheduling-state analyzer
- `FRET_Linux/linux_apps/` — sample workload source
- `WORK/FRET/` — FRET build environment and pinned LibAFL/QEMU submodules
