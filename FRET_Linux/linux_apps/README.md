# Linux benchmark targets for FRET

Userspace `aarch64` programs that the Linux FRET fuzzer drives to study
worst-case response time (WORT). Every benchmark follows the same harness
contract so the fuzzer can treat them interchangeably:

| Symbol | Role |
|--------|------|
| `fuzz_input_buffer[1024]` | mutated bytes are written here each iteration (`--target-symbol`, default `fuzz_input_buffer`) |
| `fuzz_data_ready` | fuzzer sets it to `1` after injecting; the target clears it when consumed (`--ready-flag-symbol`) |
| `fuzz_snapshot_point()` | executed once per job release; QEMU takes / restores the campaign snapshot here (`--snapshot-symbol`) |
| `SYS_getpid` (`__arm64_sys_getpid`) | job / cycle-end checkpoint selected by `BREAKPOINT` in `fuzz_config.txt` |

Each run performs `N_JOBS = 3` periodic job releases with a `10 us` nominal
period; per-stage work lengths are scaled by the fuzzer input.

## Benchmarks

### `avfusion.c`  (config keys `avfusion`, `avfusion_oracle`)

Input-gated dependency-depth pipeline. Five SCHED_FIFO threads:

```
ctrl  (prio 90)  main thread - measured; blocks on mq_receive for radar's result
ota   (prio 75)  pure preemptor, fires into the measured window
radar (prio 70)  stage 3 - waits on cam if input gate bit1 is set
cam   (prio 60)  stage 2 - waits on diag if input gate bit0 is set
diag  (prio 50)  stage 1 tail
```

The per-job input (16-byte stride) carries gate bits + an `order` byte. The
deep path (`ctrl` waiting through radar -> cam -> diag) assembles only under
the full conjunction of both gate bits and `order == 0`, so blind mutation
rarely hits it while an STG-guided search can extend a depth-2 input to
depth-3. `ctrl` then does its own heavy work scaled by the depth that
actually assembled - that magnitude is what FRET measures.

Because `ctrl`'s response window is release-to-completion (it spans the
`mq_receive` block), run the fuzzer with **`--span-blocking`** for this target.

Build:

```bash
aarch64-linux-gnu-gcc -static -O2 -pthread -o bin/avfusion avfusion.c -lrt
# oracle - forces full depth-3 every job:
aarch64-linux-gnu-gcc -static -O2 -pthread -DAVFUSION_ORACLE -o bin/avfusion_oracle avfusion.c -lrt
```

### `chain_mtx.c`  (config key `chain_mtx`)

Priority-ordered stage chain using mutex hold times and message queues.
The worst case tracks a scalar work size, so guided and blind search converge
on it - it is the baseline `avfusion` is designed to beat. Build with
`build_chain.sh` (`-> bin/chain_mtx`).

### `periodic_mtx.c`  (config key `periodic_mtx`)

Periodic multi-priority task set with a shared mutex and a fuzzer-scaled
high-priority span. Used for the coverage / periodic campaigns. Build with
`build_apps.sh` or `build_v2.sh` (`-> bin/periodic_mtx_v2`).

## Building

Prereq: `gcc-aarch64-linux-gnu` (the wrapper scripts pull it inside a
throwaway `ubuntu:24.04` podman container, so only podman is needed locally).

```bash
bash build_chain.sh     # chain_mtx
bash build_apps.sh      # periodic_mtx_v2
bash build_v2.sh        # periodic_mtx_v2 (no -lpthread variant)
# avfusion: see its build lines above
```

Binaries land in `bin/`.

## Getting a binary into the rootfs

```bash
./install_to_rootfs.sh <binary-name>
```

or mount the image manually:

```bash
sudo mount -o loop ../linux_artifacts/rootfs_no_amsr_v6.ext4 /mnt/rootfs
sudo cp bin/avfusion /mnt/rootfs/root/
sudo umount /mnt/rootfs
```

## Running under the fuzzer

From the repo root - see the top-level `README.md` section 7. Example:

```bash
FRET_Linux/linux_fret_fuzzer/target/release/fret \
  --kernel FRET_Linux/linux_artifacts/Image \
  --symbols FRET_Linux/linux_artifacts/vmlinux \
  --rootfs FRET_Linux/linux_artifacts/rootfs_no_amsr_v6.ext4 \
  --config FRET_Linux/linux_fret_fuzzer/fuzz_config.txt \
  --target-elf FRET_Linux/linux_apps/bin/avfusion \
  --span-blocking --timing-export \
  -t -a -r -g -n out/avfusion \
  fuzz --seed 123 --time 3600
```

## Inspecting a trace

```bash
# context switches involving the measured task (comm is truncated to 15 chars)
jq '.[] | select(.current_task.comm | startswith("avfusion"))' out/avfusion.trace.json
```

Offline STG / WCET / job analysis is done by
`FRET_Linux/linux_fret_analyzer` (top-level `README.md` section 8).
