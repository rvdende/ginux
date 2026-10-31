#!/usr/bin/env bash
# Boot Ginux on a QEMU machine shaped like a physical AMD desktop instead of the
# virtio reference profile: AMD IOMMU with DMA remapping, an e1000e NIC on a
# network with a DHCP server, an NVMe SSD with a GPT disk, AHCI,
# xHCI with USB keyboards (one behind a hub), a VGA framebuffer, and no virtio
# devices.
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
# A second data disk on the SATA controller.
sata="$work_dir/sata.raw"
truncate -s 64M "$sata"
sgdisk --clear --new=1:2048:0 --typecode=1:8300 --change-name=1:"sata-data" "$sata" >/dev/null

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
        -netdev user,id=net0,restrict=on \
        -device e1000e,netdev=net0 \
        -device amd-iommu,dma-remap=on \
        -audiodev "wav,id=sound,path=$work_dir/$label.wav" \
        -device intel-hda \
        -device hda-duplex,audiodev=sound \
        -device qemu-xhci,id=xhci \
        -device usb-tablet,bus=xhci.0 \
        -device usb-kbd,bus=xhci.0 \
        -device qemu-xhci,id=xhci2 \
        -device usb-hub,bus=xhci2.0,port=1 \
        -device usb-kbd,bus=xhci2.0,port=1.2 \
        -drive "if=none,id=nvm,format=raw,file=$disk" \
        -device "nvme,drive=nvm,serial=GINUXNVME01" \
        -drive "if=pflash,format=raw,readonly=on,file=$ovmf_code" \
        -drive "if=pflash,format=raw,file=$work_dir/vars.fd" \
        -drive "if=none,id=esp,format=raw,file=fat:rw:$esp_dir" \
        -device "ide-hd,drive=esp,bootindex=1" \
        -drive "if=none,id=sata,format=raw,file=$sata" \
        -device "ide-hd,drive=sata,bus=ide.2,serial=GINUXSATA01" &
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
# Play the HD Audio test tone into QEMU's WAV recorder.
for key in b e e p ret; do
    monitor_command "sendkey $key"
    sleep 0.2
done
for _ in $(seq 1 15); do
    grep -aq 'played a 440 Hz tone' "$work_dir/serial.log" && break
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
    'QEMU HARDDISK (serial GINUXSATA01), 131072 sectors of 512 bytes (64 MiB)' \
    'MiB Linux filesystem "sata-data"' \
    'NotBootKeyboard(' \
    'by firmware, status' \
    'Intel 82574, MAC 52:54:00:12:34:56, link up' \
    'DHCP offer 10.0.2.15 from 10.0.2.2' \
    '8086:2668 HD Audio' \
    'codec 0: 1af4:0022, 1 output converters, outputs: line out' \
    'devices confined to their' \
    'AMD-Vi blocked a stray DMA from this controller' \
    'keyboard 0627:0001 on port' \
    'hub with 8 ports' \
    'keyboard 0627:0001 on port 5.2' \
    'Ginux bring-up shell' \
    'bring-up> echo usbok' \
    'usbok' \
    'bring-up> beep' \
    'codec 0 played a 440 Hz tone'; do
    if ! grep -Fq "$expected" "$output_dir/serial.log"; then
        echo "missing: $expected" >&2
        failed=1
    fi
done
# The recorded tone must contain samples well above silence.
# QEMU fills in the WAV header's length only on a clean exit, so read the
# 16-bit samples after the 44-byte header directly.
loud=$(python3 -I - "$work_dir/serial.wav" <<'EOF'
import struct, sys
with open(sys.argv[1], "rb") as recording:
    data = recording.read()[44:]
samples = struct.unpack("<%dh" % (len(data) // 2), data[: len(data) // 2 * 2])
print(sum(1 for sample in samples if abs(sample) > 1000))
EOF
)
if ((loud < 10000)); then
    echo "the HD Audio tone was not recorded ($loud loud samples)" >&2
    failed=1
fi
keyboards=$(grep -c 'keyboard 0627:0001 on port' "$output_dir/serial.log" || true)
if ((keyboards != 2)); then
    echo "expected keyboards on both xHCI controllers, found $keyboards" >&2
    failed=1
fi
if ((failed)); then
    cat "$output_dir/serial.log" >&2
    exit 1
fi
echo "ok   bring-up report over serial and USB keyboard input (two controllers)"

boot_profile no-serial none
# Firmware enumeration time varies with the device set, so poll the screen
# until the console has drawn the bring-up report.
lit=0
for _ in $(seq 1 "$timeout_seconds"); do
    sleep 1
    lit=$(screenshot no-serial)
    ((lit >= 20000)) && break
done
stop_qemu
if ((lit < 20000)); then
    echo "framebuffer console shows too little text without a serial port ($lit lit pixels)" >&2
    exit 1
fi
echo "ok   framebuffer console without a serial port ($lit lit pixels)"
echo "Hardware profile test passed; screenshots in ${output_dir#"$repo_root"/}"
