#!/usr/bin/env bash
# Fetches e2fsprogs for the LTP domain (alpine:3.22): LTP formats its test
# devices with mkfs.ext2 (the default filesystem of every test that needs a
# device), and Alpine's busybox has no mke2fs. The packages are pinned by
# SHA-256 and their files repacked into one tarball that the LTP harness
# serves and tests/ltp/setup.sh unpacks into the domain's root:
#
#   build/e2fsprogs/e2fsprogs.tar.gz
#
# A rerun with the tarball in place does nothing. Without network access
# the run goes on without it, and the tests that need a device report
# mkfs.ext2 missing (TCONF).
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
out_dir="$repo_root/build/e2fsprogs"
tarball="$out_dir/e2fsprogs.tar.gz"
mirror="${GINUX_ALPINE_MIRROR:-https://dl-cdn.alpinelinux.org/alpine}/v3.22/main/x86_64"

# Package file, SHA-256: e2fsprogs and the libraries mke2fs links.
packages=(
    "e2fsprogs-1.47.2-r2.apk 4e59067f388ba8338dca3babd5784799d2d434eb6c19076d17ff96e50fbb1a49"
    "e2fsprogs-libs-1.47.2-r2.apk 4aeee327c9d8465ca403e4283e07055c353a2e3446f69113e624c91eab2e7e9e"
    "libcom_err-1.47.2-r2.apk bb138d264fbf92ae95b355b43b0cf2ab59ce4abcb0594024bb687e3eecc490a4"
    "libblkid-2.41.6-r1.apk ab85cd837c906979c24e5a006a81789ae9715e6e913c421c71950bdf1450164c"
    "libuuid-2.41.6-r1.apk eb8fa9e042b51443a6ac8c9fa4d1dca5a1a458c5f3980bffa5167f005f47a504"
    "libeconf-0.6.3-r0.apk fe4fbf324f84f7c8b475cfc708c5505aa630bced7b5f6289bf5ca36d9b587829"
)

if [[ -f "$tarball" ]]; then
    exit 0
fi
mkdir -p "$out_dir/apk"
for entry in "${packages[@]}"; do
    read -r file sha256 <<<"$entry"
    apk="$out_dir/apk/$file"
    if [[ ! -f "$apk" ]] || ! echo "$sha256  $apk" | sha256sum --check --status; then
        if ! curl -sSfL -o "$apk.part" "$mirror/$file"; then
            echo "fetch-e2fsprogs.sh: cannot fetch $file; LTP runs without mkfs.ext2" >&2
            exit 0
        fi
        mv "$apk.part" "$apk"
    fi
    if ! echo "$sha256  $apk" | sha256sum --check --status; then
        echo "fetch-e2fsprogs.sh: $file does not match its pinned SHA-256" >&2
        rm -f "$apk"
        exit 1
    fi
done
# An .apk is gzipped tar segments: the signature, the package metadata
# (dotfiles at the top) and the files. Keep the files.
root="$out_dir/root"
rm -rf "$root"
mkdir -p "$root"
for entry in "${packages[@]}"; do
    read -r file _ <<<"$entry"
    tar -xzf "$out_dir/apk/$file" -C "$root" --exclude='.*' 2>/dev/null
done
# Files and links only: the domain's own directories keep their modes.
(cd "$root" && find . ! -type d | sort) |
    tar --owner=0 --group=0 --numeric-owner --mtime=@0 --no-recursion -C "$root" \
        -T - -czf "$tarball.part"
mv "$tarball.part" "$tarball"
rm -rf "$root"
