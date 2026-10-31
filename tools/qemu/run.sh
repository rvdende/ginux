#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

qemu="$(find_qemu)"
ovmf_code="$(find_ovmf_code)"
ovmf_vars_template="$(find_ovmf_vars)"
accelerator="${QEMU_ACCEL:-$(default_accelerator)}"
if [[ "$accelerator" == "tcg" ]]; then
    default_cpu_model="max,+smep,+smap,+umip"
else
    default_cpu_model="host,+smep,+smap,+umip"
fi
cpu_model="${QEMU_CPU:-$default_cpu_model}"
esp_dir="${GINUX_ESP_DIR:-$repo_root/build/esp}"
runtime_dir="$repo_root/build/qemu"
ovmf_vars="$runtime_dir/ovmf-vars.fd"
volume_image="${GINUX_VOLUME_IMAGE:-$runtime_dir/volume.raw}"
volume_size="${GINUX_VOLUME_SIZE:-64G}"
default_volume_bytes=68719476736

if [[ ! -f "$esp_dir/EFI/BOOT/BOOTX64.EFI" ]]; then
    echo "Missing $esp_dir/EFI/BOOT/BOOTX64.EFI; run 'make build' first." >&2
    exit 1
fi

mkdir -p "$runtime_dir"
cp "$ovmf_vars_template" "$ovmf_vars"
if [[ ! -f "$volume_image" ]]; then
    truncate -s "$volume_size" "$volume_image"
elif [[ -z "${GINUX_VOLUME_IMAGE:-}" && -z "${GINUX_VOLUME_SIZE:-}" ]]; then
    if current_volume_bytes=$(stat -f '%z' "$volume_image" 2>/dev/null) ||
        current_volume_bytes=$(stat -c '%s' "$volume_image" 2>/dev/null); then
        if [[ "$current_volume_bytes" =~ ^[0-9]+$ ]] &&
            ((current_volume_bytes < default_volume_bytes)); then
            truncate -s "$default_volume_bytes" "$volume_image"
        fi
    fi
fi

echo "Booting x86-64 Ginux with QEMU/$accelerator using CPU $cpu_model"

if [[ -n "${GINUX_QEMU_PID_FILE:-}" ]]; then
    printf '%s\n' "$$" >"$GINUX_QEMU_PID_FILE"
fi

memory="${GINUX_MEMORY:-1G}"
network_capture=()
if [[ -n "${GINUX_PCAP:-}" ]]; then
    network_capture=(-object "filter-dump,id=ginux-capture,netdev=ginux-net,file=$GINUX_PCAP")
fi
# GINUX_QEMU_USB_INPUT=1 adds a USB keyboard and tablet on an xHCI
# controller, which Ginux offers to domains as /dev/input/eventN.
usb_input=()
if [[ "${GINUX_QEMU_USB_INPUT:-}" == "1" ]]; then
    usb_input=(
        -device "qemu-xhci,id=xhci"
        -device "usb-kbd,bus=xhci.0"
        -device "usb-tablet,bus=xhci.0"
    )
fi
qemu_netdev="user,id=ginux-net,restrict=off"
# GINUX_QEMU_LOG names a file for QEMU's CPU reset and guest error log.
# It also keeps QEMU paused, instead of exiting, when the guest resets or
# triple-faults, so the monitor can still read the CPU state.
qemu_log=()
if [[ -n "${GINUX_QEMU_LOG:-}" ]]; then
    # GINUX_QEMU_LOG_INTERRUPTS=1 also logs every exception and interrupt
    # (QEMU_ACCEL=tcg only), which shows the faults that led to a reset.
    events=cpu_reset,guest_errors
    if [[ "${GINUX_QEMU_LOG_INTERRUPTS:-}" == "1" ]]; then
        events+=",int"
    fi
    qemu_log=(-d "$events" -D "$GINUX_QEMU_LOG" -no-shutdown)
fi
# GINUX_QEMU_DISPLAY selects a QEMU display such as gtk or sdl, to see the
# framebuffer (and a Wayland desktop on /dev/fb0) in a window.
display="${GINUX_QEMU_DISPLAY:-none}"
# GINUX_QEMU_MONITOR names a Unix socket for the QEMU monitor, which tests
# use to take screenshots (screendump) and inject input.
monitor="none"
if [[ -n "${GINUX_QEMU_MONITOR:-}" ]]; then
    monitor="unix:${GINUX_QEMU_MONITOR},server=on,wait=off"
fi
if [[ -n "${GINUX_QEMU_DNS:-}" ]]; then
    qemu_netdev+=",dns=${GINUX_QEMU_DNS}"
fi
if [[ -n "${GINUX_QEMU_HOSTFWD:-}" ]]; then
    qemu_netdev+=",hostfwd=${GINUX_QEMU_HOSTFWD}"
fi

exec "$qemu" \
    -machine "q35,accel=$accelerator" \
    -cpu "$cpu_model" \
    -smp 1 \
    -m "$memory" \
    -display "$display" \
    -monitor "$monitor" \
    -serial stdio \
    -no-reboot \
    ${qemu_log[@]+"${qemu_log[@]}"} \
    -net none \
    -device "intel-iommu,intremap=off" \
    -device "virtio-blk-pci,drive=ginux-volume,disable-legacy=on,iommu_platform=on,serial=ginux-volume" \
    -netdev "$qemu_netdev" \
    ${network_capture[@]+"${network_capture[@]}"} \
    -device "virtio-net-pci,netdev=ginux-net,disable-legacy=on,iommu_platform=on,mac=52:54:00:12:34:56,addr=0x3" \
    ${usb_input[@]+"${usb_input[@]}"} \
    -drive "if=none,id=ginux-volume,format=raw,file=$volume_image" \
    -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
    -drive "if=pflash,format=raw,file=$ovmf_vars" \
    -drive "if=none,id=ginux-esp,format=raw,file=fat:rw:$esp_dir" \
    -device "ide-hd,drive=ginux-esp,bootindex=1"
