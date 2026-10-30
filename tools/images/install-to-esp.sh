#!/usr/bin/env bash
# Install Ginux next to an existing Linux installation on this computer.
#
# Copies the unified EFI image to <ESP>/EFI/ginux/ginux.efi and registers a
# firmware boot entry for it. The entry is not added to the default boot order,
# so the computer keeps booting the existing system unless Ginux is chosen in
# the firmware boot menu or --boot-next is given (a one-time boot). The
# removable-media fallback loader EFI/BOOT/BOOTX64.EFI is never touched.
#
# Usage: sudo tools/images/install-to-esp.sh [--esp DIR] [--efi FILE]
#                                            [--no-boot-entry] [--boot-next]

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
efi_image="$repo_root/build/esp/EFI/BOOT/BOOTX64.EFI"
esp=""
boot_entry=true
boot_next=false
label="Ginux"
loader='\EFI\ginux\ginux.efi'

while (($#)); do
    case "$1" in
        --esp) esp=$2; shift 2 ;;
        --efi) efi_image=$2; shift 2 ;;
        --no-boot-entry) boot_entry=false; shift ;;
        --boot-next) boot_next=true; shift ;;
        -h | --help) sed -n '2,13p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -s "$efi_image" ]]; then
    echo "Missing $efi_image; run 'make build' first." >&2
    exit 1
fi
if [[ -z "$esp" ]]; then
    esp="$(findmnt -n -o TARGET /boot/efi 2>/dev/null || findmnt -n -o TARGET /efi 2>/dev/null || true)"
fi
if [[ -z "$esp" || ! -d "$esp/EFI" ]]; then
    echo "No EFI system partition found; mount it or pass --esp DIR." >&2
    exit 1
fi

install -D -m 0644 "$efi_image" "$esp/EFI/ginux/ginux.efi"
sync
echo "Installed $esp/EFI/ginux/ginux.efi"

if ! $boot_entry; then
    exit 0
fi
if [[ "$(id -u)" -ne 0 ]] || ! command -v efibootmgr >/dev/null 2>&1; then
    echo "Registering a boot entry needs root and efibootmgr; rerun with sudo or pass --no-boot-entry." >&2
    exit 1
fi

partition="$(findmnt -n -o SOURCE --target "$esp")"
disk="/dev/$(lsblk -n -o PKNAME "$partition" | head -n 1)"
number="$(cat "/sys/class/block/${partition##*/}/partition")"

existing="$(efibootmgr | sed -n "s/^Boot\([0-9A-Fa-f]\{4\}\)[* ] $label\b.*/\1/p" | head -n 1)"
if [[ -z "$existing" ]]; then
    # --create-only leaves BootOrder unchanged.
    efibootmgr --create-only --disk "$disk" --part "$number" --label "$label" --loader "$loader" >/dev/null
    existing="$(efibootmgr | sed -n "s/^Boot\([0-9A-Fa-f]\{4\}\)[* ] $label\b.*/\1/p" | head -n 1)"
fi
echo "Firmware boot entry Boot$existing ($label) points at $disk partition $number"

if $boot_next; then
    efibootmgr --bootnext "$existing" >/dev/null
    echo "The next reboot starts Ginux once; the following one returns to the default entry."
else
    echo "Choose '$label' in the firmware boot menu, or run: sudo efibootmgr --bootnext $existing"
fi
