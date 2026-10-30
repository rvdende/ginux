#!/usr/bin/env bash
# Boot Ginux on a QEMU machine shaped like a physical AMD desktop instead of the
# virtio reference profile: AMD IOMMU, an NVMe SSD with a GPT disk, AHCI,
# xHCI with a USB keyboard, a VGA framebuffer, and no virtio devices.
#
# The first boot keeps a serial port, checks the bring-up report, and types a
# command on the USB keyboard through the QEMU monitor. The second removes the
# serial port, as on most PCs, and checks that the framebuffer console shows
# text. Screenshots are kept in build/qemu/hardware-profile/.

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
esp_dir="${GINUX_ESP_DIR:-$repo_root/build/esp}"
output_dir="$repo_root/build/qemu/hardware-profile"
timeout_seconds="${GINUX_PROFILE_TIMEOUT:-90}"
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

if [[ ! -f "$esp_dir/EFI/BOOT/BOOTX64.EFI" ]]; then
    echo "Missing $esp_dir/EFI/BOOT/BOOTX64.EFI; run 'make build' first." >&2
    exit 1
fi
mkdir -p "$output_dir"

# A small GPT disk like a dual-boot SSD, including a Ginux volume partition.
disk="$work_dir/nvme.raw"
truncate -s 256M "$disk"
sgdisk --clear \
    --new=1:2048:+32M --typecode=1:ef00 --change-name=1:"EFI System Partition" \
    --new=2:0:+128M --typecode=2:8300 --change-name=2:"ubuntu-root" \
    --new=3:0:+16M --typecode=3:8200 --change-name=3:"swap" \
    --new=4:0:0 --typecode=4:80769f29-5413-45a3-abab-5b44b6125922 --change-name=4:"ginux-volume" \
    "$disk" >/dev/null

boot_profile() {
    local label=$1 serial=$2
    local log="$work_dir/$label.log"
    local monitor="$work_dir/$label.monitor"
    cp "$ovmf_vars_template" "$work_dir/vars.fd"
    : >"$log"
    "$qemu" \
        -machine "q35,accel=$accelerator" \
        -cpu "$cpu_model" \
        -smp 1 \
        -m 1G \
        -display none \
        -vga std \
        -monitor "unix:$monitor,server=on,wait=off" \
        -serial "$serial" \
        -no-reboot \
        -net none \
        -device amd-iommu \
        -device qemu-xhci,id=xhci \
        -device usb-kbd,bus=xhci.0 \
        -drive "if=none,id=nvm,format=raw,file=$disk" \
        -device "nvme,drive=nvm,serial=GINUXNVME01" \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$work_dir/vars.fd" \
        -drive "if=none,id=esp,format=raw,file=fat:rw:$esp_dir" \
        -device "ide-hd,drive=esp,bootindex=1" &
    qemu_pid=$!
}

screenshot() {
    local label=$1
    printf 'screendump "%s"\n' "$work_dir/$label.ppm" |
        socat - "UNIX-CONNECT:$work_dir/$label.monitor" >/dev/null
    sleep 1
    python3 -I - "$work_dir/$label.ppm" "$output_dir/$label.png" <<'EOF'
import sys
from PIL import Image
image = Image.open(sys.argv[1]).convert("RGB")
image.save(sys.argv[2])
# Count non-black pixels from the luminance histogram.
histogram = image.convert("L").histogram()
print(sum(histogram) - histogram[0])
EOF
}

stop_qemu() {
    kill "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    qemu_pid=""
}

echo "Booting the physical-hardware profile with QEMU/$accelerator using CPU $cpu_model"

monitor_command() {
    printf '%s\n' "$1" | socat - "UNIX-CONNECT:$work_dir/serial.monitor" >/dev/null
}

boot_profile serial "file:$work_dir/serial.log"
for _ in $(seq 1 "$timeout_seconds"); do
    grep -aq 'bring-up> ' "$work_dir/serial.log" && break
    grep -aq 'ginux: halted' "$work_dir/serial.log" && break
    grep -aEq '^GINUX_(BOOT|KERNEL)_PANIC' "$work_dir/serial.log" && break
    sleep 1
done
# Type a command on the emulated USB keyboard.
for key in e c h o spc u s b o k ret; do
    monitor_command "sendkey $key"
    sleep 0.2
done
for _ in $(seq 1 10); do
    grep -aq '^usbok' <(tr -d '\r' <"$work_dir/serial.log") && break
    sleep 1
done
screenshot serial >/dev/null
stop_qemu
tr -d '\r' <"$work_dir/serial.log" | sed -n '/hardware bring-up mode/,$p' >"$output_dir/serial.log"
failed=0
for expected in \
    'entering hardware bring-up mode' \
    'serial console present' \
    'framebuffer 1280x800' \
    'AMD-Vi' \
    'NVMe controller' \
    'USB controller (xHCI)' \
    'SATA controller (AHCI)' \
    'QEMU NVMe Ctrl (serial GINUXNVME01' \
    'namespace 1: 524288 blocks of 512 bytes' \
    'partition 1: 32 MiB EFI system "EFI System Partition"' \
    'partition 2: 128 MiB Linux filesystem "ubuntu-root"' \
    'partition 3: 16 MiB Linux swap "swap"' \
    'MiB Ginux volume "ginux-volume"' \
    'keyboard 0627:0001 on port' \
    'Ginux bring-up shell' \
    'bring-up> echo usbok' \
    'usbok'; do
    if ! grep -Fq "$expected" "$output_dir/serial.log"; then
        echo "missing: $expected" >&2
        failed=1
    fi
done
if ((failed)); then
    cat "$output_dir/serial.log" >&2
    exit 1
fi
echo "ok   bring-up report over serial and USB keyboard input"

boot_profile no-serial none
sleep "${GINUX_PROFILE_SCREEN_DELAY:-20}"
lit=$(screenshot no-serial)
stop_qemu
if ((lit < 20000)); then
    echo "framebuffer console shows too little text without a serial port ($lit lit pixels)" >&2
    exit 1
fi
echo "ok   framebuffer console without a serial port ($lit lit pixels)"
echo "Hardware profile test passed; screenshots in ${output_dir#"$repo_root"/}"
