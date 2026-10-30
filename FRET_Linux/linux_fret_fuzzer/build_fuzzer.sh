#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
fret_root="$project_root/WORK/FRET"

cd "$fret_root"
nix develop "$fret_root" --command cargo build \
    --manifest-path "$project_root/FRET_Linux/linux_fret_fuzzer/Cargo.toml" \
    --no-default-features \
    --features std,snapshot_fast,restarting,do_hash_notify_state,do_hash_notify_value,config_stg,shortcut,trace_job_response_times
