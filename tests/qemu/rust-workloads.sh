#!/usr/bin/env bash
# Boots Ginux, starts the official rust:alpine image in a domain, and has
# its rustc compile and run the stress programs in tests/linux-workloads
# (allocator, thread churn, mmap, file I/O, malloc metadata and every kind
# of descriptor above 1024), then has
# cargo fetch serde from crates.io and build a derive project through a
# pipe. Each of these found kernel bugs that ordinary shell tests did not.
# The guest downloads the sources from a host HTTP server at 10.0.2.2.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
output_file=$(mktemp "${TMPDIR:-/tmp}/ginux-rust-workloads.XXXXXX")
volume_image=$(mktemp "${TMPDIR:-/tmp}/ginux-rust-workloads-volume.XXXXXX")
qemu_pid_file=$(mktemp "${TMPDIR:-/tmp}/ginux-rust-workloads-pid.XXXXXX")
# A free port the host picks, unless one is given: runs in parallel (other
# worktrees, other suites) would otherwise collide on a fixed one.
http_port="${GINUX_WORKLOAD_HTTP_PORT:-$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}"
qemu_pid=""
http_pid=""

stop_qemu() {
    local pid=""
    if [[ -s "$qemu_pid_file" ]]; then
        read -r pid <"$qemu_pid_file" || true
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_qemu
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ -n "$http_pid" ]]; then
        kill "$http_pid" 2>/dev/null || true
    fi
    cp "$output_file" "$repo_root/target/rust-workloads-serial.log" 2>/dev/null || true
    rm -f "$output_file" "$volume_image" "$qemu_pid_file"
}
trap cleanup EXIT

# Waits up to `seconds` for a line beginning with `marker`.
wait_for() {
    local marker=$1
    local seconds=${2:-120}
    for _ in $(seq 1 "$seconds"); do
        grep -Eq "^${marker}" "$output_file" && return 0
        if grep -Eq '^GINUX_(BOOT|KERNEL)_PANIC|domain marked failed' "$output_file"; then
            break
        fi
        sleep 1
    done
    tail -n 80 "$output_file" >&2
    echo "Rust workload test failed while waiting for '$marker'." >&2
    stop_qemu
    return 1
}

python3 -I -m http.server "$http_port" --bind 127.0.0.1 \
    --directory "$repo_root/tests/linux-workloads" >/dev/null 2>&1 &
http_pid=$!

toolchain=/usr/local/rustup/toolchains/1.99.1-x86_64-unknown-linux-musl/bin
fetch="wget -q http://10.0.2.2:${http_port}"
dd if=/dev/zero of="$volume_image" bs=1048576 count=1 2>/dev/null
{
    wait_for 'ginux> ' 300
    printf '%s\n' \
        'domain new rust' \
        'domain set rust image=rust:alpine init=/bin/sh' \
        'domain start rust --attach'
    wait_for 'ginux: OCI image ready' 900
    sleep 5
    printf '%s\n' \
        "export PATH=$toolchain:\$PATH CARGO_HOME=/tmp/cargo; cd /tmp" \
        "for p in memstress threadstress mmapstress iostress metastress preempt highfd; do $fetch/\$p.rs -O \$p.rs && rustc --edition 2021 -O \$p.rs -o \$p || echo BUILD_FAILED \$p; done; echo SOURCES\"_BUILT\""
    wait_for 'SOURCES_BUILT' 900
    printf '%s\n' \
        "./memstress 8 20000 && echo MEMSTRESS\"_OK\"" \
        "./threadstress 200 && echo THREADSTRESS\"_OK\"" \
        "./mmapstress 20000 && echo MMAPSTRESS\"_OK\"" \
        "./iostress 4 300 /tmp/io && echo IOSTRESS\"_OK\"" \
        "./metastress 300000 && echo METASTRESS\"_OK\"" \
        "./preempt && echo PREEMPT\"_OK\"" \
        "./highfd && echo HIGHFD\"_OK\""
    wait_for 'MEMSTRESS_OK' 600
    wait_for 'THREADSTRESS_OK' 600
    wait_for 'MMAPSTRESS_OK' 600
    wait_for 'IOSTRESS_OK' 900
    wait_for 'METASTRESS_OK' 600
    wait_for 'PREEMPT_OK' 120
    wait_for 'HIGHFD_OK' 120
    printf '%s\n' \
        "cargo new --vcs none --offline sd >/dev/null 2>&1; cd sd" \
        "printf 'serde = { version = \"1\", features = [\"derive\"] }\\n' >> Cargo.toml" \
        "printf '#[derive(serde::Serialize, Debug)]\\nstruct Point { x: i32 }\\nfn main() { println!(\"{:?}\", Point { x: 7 }); }\\n' > src/main.rs" \
        "cargo build -j1 2>&1 | grep -E 'Finished|error'; ./target/debug/sd | grep -q 'Point { x: 7 }' && echo SERDE_DERIVE\"_OK\"" \
        'exit 0'
    wait_for 'SERDE_DERIVE_OK' 1200
    wait_for 'ginux: Linux init exited cleanly' 120
    sleep 2
    printf '%s\n' 'shutdown'
} | GINUX_MEMORY=8G GINUX_VOLUME_IMAGE="$volume_image" GINUX_QEMU_PID_FILE="$qemu_pid_file" \
    "$repo_root/tools/qemu/run.sh" >"$output_file" 2>&1 &
qemu_pid=$!

for _ in $(seq 1 7200); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    tail -n 80 "$output_file"
    echo "Rust workload test failed: QEMU did not shut down." >&2
    exit 1
fi
wait "$qemu_pid" || true
qemu_pid=""

for marker in MEMSTRESS_OK THREADSTRESS_OK MMAPSTRESS_OK IOSTRESS_OK METASTRESS_OK PREEMPT_OK HIGHFD_OK SERDE_DERIVE_OK; do
    if ! grep -Eq "^${marker}" "$output_file"; then
        tail -n 80 "$output_file"
        echo "Rust workload test failed: missing ${marker}." >&2
        exit 1
    fi
done
echo "Rust toolchain workload test passed."
