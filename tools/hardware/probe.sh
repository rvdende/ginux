#!/usr/bin/env bash
# Collect the hardware facts needed to bring Ginux up on a physical machine.
#
# Run on the target computer under a Linux distribution (e.g. Ubuntu) as root:
#   sudo tools/hardware/probe.sh
# The script only reads system state. It writes ginux-probe-<host>-<date>.tar.gz
# in the current directory; copy that archive back to the development machine.

set -uo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "Run as root (sudo) so firmware tables and device registers are readable." >&2
    exit 1
fi

stamp="$(date +%Y%m%d-%H%M%S)"
name="ginux-probe-$(hostname -s)-$stamp"
work="$(mktemp -d)"
out="$work/$name"
mkdir -p "$out/acpi"

capture() {
    local file=$1
    shift
    if command -v "$1" >/dev/null 2>&1; then
        "$@" >"$out/$file" 2>&1
    else
        echo "missing command: $1" >"$out/$file"
    fi
}

# Platform, firmware, and boot path.
capture uname.txt uname -a
capture os-release.txt cat /etc/os-release
capture cmdline.txt cat /proc/cmdline
capture cpuinfo.txt cat /proc/cpuinfo
capture meminfo.txt cat /proc/meminfo
capture iomem.txt cat /proc/iomem
capture dmidecode.txt dmidecode
capture efibootmgr.txt efibootmgr -v
capture secure-boot.txt mokutil --sb-state
ls -la /sys/firmware/efi >"$out/efi-sysfs.txt" 2>&1
cat /sys/firmware/efi/fw_platform_size >>"$out/efi-sysfs.txt" 2>&1

# ACPI tables: MADT (APIC/x2APIC), MCFG (PCIe ECAM), DMAR or IVRS (IOMMU),
# HPET, FADT, and the DSDT/SSDTs for power and device enumeration.
for table in /sys/firmware/acpi/tables/*; do
    [[ -f "$table" ]] && cp "$table" "$out/acpi/" 2>/dev/null
done
capture acpidump.txt acpidump

# Interrupts, timers, and IOMMU as Linux brought them up.
capture interrupts.txt cat /proc/interrupts
capture clocksource.txt cat /sys/devices/system/clocksource/clocksource0/available_clocksource
dmesg >"$out/dmesg.txt" 2>&1
grep -iE 'iommu|AMD-Vi|DMAR|x2apic|ioapic|hpet|tsc|efifb|simpledrm|nvme|ahci|xhci|serial|ttyS' \
    "$out/dmesg.txt" >"$out/dmesg-highlights.txt" 2>&1
ls -la /sys/class/iommu >"$out/iommu-sysfs.txt" 2>&1

# PCI and USB devices with bound drivers, IDs, BARs, and capabilities (MSI-X).
capture lspci-nnk.txt lspci -nnk
capture lspci-vvv.txt lspci -vvv -nn
capture lspci-tree.txt lspci -tv
capture lsusb.txt lsusb
capture lsusb-tree.txt lsusb -t

# Storage controllers and disks.
capture lsblk.txt lsblk -o NAME,MODEL,SERIAL,SIZE,TYPE,TRAN,FSTYPE,PTTYPE,MOUNTPOINTS
capture nvme-list.txt nvme list
capture fdisk.txt fdisk -l

# Network interfaces and drivers.
capture ip-link.txt ip -details link
for iface in /sys/class/net/*; do
    iface="${iface##*/}"
    [[ "$iface" == lo ]] && continue
    capture "ethtool-$iface.txt" ethtool -i "$iface"
done

# Display: firmware framebuffer (GOP) geometry and the GPU.
ls -la /sys/class/graphics >"$out/graphics-sysfs.txt" 2>&1
for fb in /sys/class/graphics/fb*; do
    [[ -d "$fb" ]] || continue
    for attribute in name virtual_size bits_per_pixel stride; do
        printf '%s/%s: %s\n' "$fb" "$attribute" "$(cat "$fb/$attribute" 2>/dev/null)"
    done
done >>"$out/graphics-sysfs.txt"
ls -la /sys/class/drm >"$out/drm-sysfs.txt" 2>&1

# Serial ports, useful as an early console if the board has one.
capture serial.txt sh -c 'ls -la /dev/ttyS* 2>&1; cat /proc/tty/driver/serial 2>&1'

tar -C "$work" -czf "$name.tar.gz" "$name"
rm -rf "$work"
echo "Wrote $PWD/$name.tar.gz"
