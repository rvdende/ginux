#!/usr/bin/env bash
# Turns code addresses from a Ginux crash report into function names and
# source lines.
#
# Usage: tools/debug/symbolize.sh IMAGE_BASE ADDRESS...
#
# IMAGE_BASE is the "kernel image base" from the report and each ADDRESS is
# a rip or stack address from it (hex, with or without 0x). The script builds
# the current sources once more with line tables and symbols kept, in
# target/symbolized, so the report must come from a build of the same
# sources. Addresses are moved from the loaded base to the PE image base.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
if [[ $# -lt 2 ]]; then
    sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
fi
symbolizer=$(command -v llvm-symbolizer || command -v llvm-symbolizer-21 || true)
[[ -n "$symbolizer" ]] || { echo "llvm-symbolizer is required" >&2; exit 1; }

target_dir="$repo_root/target/symbolized"
(
    cd "$repo_root"
    GINUX_LINUX_PROBE_EXPORT="$repo_root/build/linux-probe.elf" \
        GINUX_LINUX_DYNAMIC_EXPORT_DIR="$repo_root/build/linux-dynamic" \
        CARGO_TARGET_DIR="$target_dir" CARGO_PROFILE_RELEASE_DEBUG=line-tables-only \
        CARGO_PROFILE_RELEASE_STRIP=none \
        cargo build --quiet --release --package ginux-boot --target x86_64-unknown-uefi
)
# llvm-symbolizer finds the PDB by the relative name recorded in the image,
# so it runs from the deps directory against ../ginux-boot.efi.
deps="$target_dir/x86_64-unknown-uefi/release/deps"

# The PE header's preferred base; addresses are rebased onto it.
pe_base=0x140000000
loaded_base=$((16#${1#0x}))
shift
for address in "$@"; do
    value=$((16#${address#0x}))
    printf '0x%x ' "$((value - loaded_base + pe_base))"
done | (cd "$deps" && xargs "$symbolizer" --obj=../ginux-boot.efi --pretty-print --functions=linkage)
