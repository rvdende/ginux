#!/usr/bin/env bash
# Boot the removable media from tools/images/build-boot-media.sh the way a PC
# would see it: the hybrid ISO as a CD-ROM and as a USB stick, and the raw image
# as a USB stick. Each boot must reach the embedded controller prompt.

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../../tools/qemu/common.sh"

qemu="$(find_qemu)"
ovmf_code="$(find_ovmf_code)"
ovmf_vars_template="$(find_ovmf_vars)"
accelerator="${QEMU_ACCEL:-$(default_accelerator)}"
if [[ "$accelerator" == "tcg" ]]; then
    cpu_model="${QEMU_CPU:-max,+smep,+smap,+umip}"
else
    cpu_model="${QEMU_CPU:-host,+smep,+smap,+umip}"
fi
media_dir="${GINUX_MEDIA_DIR:-$repo_root/build/media}"
timeout_seconds="${GINUX_MEDIA_TIMEOUT:-120}"
work_dir="$(mktemp -d)"
qemu_pid=""

cleanup() {
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    rm -rf "$work_dir"
}
trap cleanup EXIT

boot_case() {
    local label=$1
    shift
    local log="$work_dir/$label.log"
    cp "$ovmf_vars_template" "$work_dir/vars.fd"
    dd if=/dev/zero of="$work_dir/volume.raw" bs=1048576 count=1 status=none
    "$qemu" \
        -machine "q35,accel=$accelerator" \
        -cpu "$cpu_model" \
        -smp 1 \
        -m 1G \
        -display none \
        -monitor none \
        -serial "file:$log" \
        -no-reboot \
        -net none \
        -device "intel-iommu,intremap=off" \
        -device "virtio-blk-pci,drive=ginux-volume,disable-legacy=on,iommu_platform=on,serial=ginux-volume" \
        -netdev "user,id=ginux-net,restrict=on" \
        -device "virtio-net-pci,netdev=ginux-net,disable-legacy=on,iommu_platform=on,mac=52:54:00:12:34:56,addr=0x3" \
        -drive "if=none,id=ginux-volume,format=raw,file=$work_dir/volume.raw" \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$work_dir/vars.fd" \
        "$@" &
    qemu_pid=$!
    local elapsed=0
    while ((elapsed < timeout_seconds)); do
        if grep -aq "Type 'help' for commands." "$log" 2>/dev/null; then
            kill "$qemu_pid" 2>/dev/null || true
            wait "$qemu_pid" 2>/dev/null || true
            qemu_pid=""
            echo "ok   $label"
            return 0
        fi
        if grep -aEq '^GINUX_(BOOT|KERNEL)_PANIC' "$log" 2>/dev/null || ! kill -0 "$qemu_pid" 2>/dev/null; then
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
    echo "FAIL $label; last serial output:" >&2
    tr -d '\r' <"$log" | tail -15 >&2
    return 1
}

iso="$media_dir/ginux.iso"
usb="$media_dir/ginux-usb.img"
for image in "$iso" "$usb"; do
    if [[ ! -s "$image" ]]; then
        echo "Missing $image; run 'make boot-media' first." >&2
        exit 1
    fi
done

echo "Booting removable media with QEMU/$accelerator using CPU $cpu_model"
boot_case iso-cdrom \
    -drive "if=none,id=media,format=raw,media=cdrom,readonly=on,file=$iso" \
    -device "ide-cd,drive=media,bootindex=1"
boot_case iso-usb-stick \
    -device qemu-xhci,id=xhci \
    -drive "if=none,id=media,format=raw,readonly=on,file=$iso" \
    -device "usb-storage,bus=xhci.0,drive=media,removable=on,bootindex=1"
boot_case raw-usb-stick \
    -device qemu-xhci,id=xhci \
    -drive "if=none,id=media,format=raw,readonly=on,file=$usb" \
    -device "usb-storage,bus=xhci.0,drive=media,removable=on,bootindex=1"
echo "Removable boot media test passed."
