#!/usr/bin/env bash
# Package the unified Ginux EFI image as removable boot media.
#
# Produces, under build/media/:
#   ginux.iso      UEFI-bootable hybrid ISO. Its El Torito EFI image is also
#                  exposed as a GPT EFI system partition, so the same file can
#                  be burned to optical media or written to a USB stick.
#   ginux-usb.img  Raw GPT disk image with a single EFI system partition, for
#                  firmware that does not boot hybrid ISOs from USB.
#
# Neither image needs root to build: the FAT filesystem is written with mtools
# and the partition table with sgdisk.

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
efi_image="${GINUX_EFI_IMAGE:-$repo_root/build/esp/EFI/BOOT/BOOTX64.EFI}"
output_dir="${GINUX_MEDIA_DIR:-$repo_root/build/media}"
mebibyte=$((1024 * 1024))

for command in mkfs.vfat mmd mcopy sgdisk xorriso; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Missing $command; install dosfstools, mtools, gdisk, and xorriso." >&2
        exit 1
    fi
done
if [[ ! -s "$efi_image" ]]; then
    echo "Missing $efi_image; run 'make build' first." >&2
    exit 1
fi

work_dir="$(mktemp -d)"
trap 'rm -rf "$work_dir"' EXIT
mkdir -p "$output_dir"

# Size the EFI system partition to the image plus 4 MiB of FAT overhead.
efi_bytes=$(stat -c '%s' "$efi_image")
fat_mib=$(((efi_bytes + mebibyte - 1) / mebibyte + 4))
fat_image="$work_dir/efiboot.img"
truncate -s "${fat_mib}M" "$fat_image"
mkfs.vfat -n GINUX "$fat_image" >/dev/null
mmd -i "$fat_image" ::/EFI ::/EFI/BOOT
mcopy -i "$fat_image" "$efi_image" ::/EFI/BOOT/BOOTX64.EFI

# Hybrid ISO: append the FAT image as GPT partition 2 (type EF00) and point
# the El Torito EFI boot entry at the same bytes.
iso_root="$work_dir/iso"
mkdir -p "$iso_root"
printf 'Ginux UEFI boot media\n' >"$iso_root/README.TXT"
iso="$output_dir/ginux.iso"
rm -f "$iso"
xorriso -as mkisofs \
    -quiet \
    -o "$iso" \
    -V GINUX \
    -R -J \
    -append_partition 2 0xef "$fat_image" \
    -appended_part_as_gpt \
    -e --interval:appended_partition_2:all:: \
    -no-emul-boot \
    "$iso_root"

# Raw USB image: 1 MiB for the protective MBR and primary GPT, the EFI
# system partition, and 1 MiB for the backup GPT.
usb="$output_dir/ginux-usb.img"
rm -f "$usb"
truncate -s "$((fat_mib + 2))M" "$usb"
sgdisk --clear \
    --new=1:2048:+"${fat_mib}M" \
    --typecode=1:ef00 \
    --change-name=1:"Ginux EFI" \
    "$usb" >/dev/null
dd if="$fat_image" of="$usb" bs=1M seek=1 conv=notrunc status=none

for image in "$iso" "$usb"; do
    printf '%s  %s (%s MiB)\n' \
        "$(sha256sum "$image" | cut -d' ' -f1)" \
        "${image#"$repo_root"/}" \
        "$(($(stat -c '%s' "$image") / mebibyte))"
done
cat <<EOF

Write either image to a USB stick (this erases the stick):
  sudo dd if=${usb#"$repo_root"/} of=/dev/sdX bs=4M conv=fsync status=progress
Then boot the target computer from it in UEFI mode with Secure Boot disabled.
EOF
