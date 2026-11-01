#!/usr/bin/env bash
# Builds the Linux Test Project (LTP) syscall tests as static musl binaries
# for running inside a Ginux domain (tests/qemu/ltp.sh, docs/LTP.md).
#
#   tools/ltp/build.sh [--clean | --force | --runner-only | --variant NAME]
#
# The build runs in a pinned Alpine container, so the host needs only
# Docker. LTP is a pinned release tarball whose SHA-256 is checked; it is
# cached in build/ltp-cache. The build tree stays in target/ltp-build, so a
# rerun only rebuilds what changed (--clean starts over). --runner-only
# rebuilds just the guest-side runner (tools/ltp/ltp-runner.c).
#
# A build that is already up to date does nothing: build/ltp[-NAME] keeps a
# stamp of everything the build depends on (the LTP release, the builder
# image, the variant and the scripts in tools/ltp), so a rerun starts Docker
# only when one of those changed, and only for the runner when that is all
# that changed. --force rebuilds anyway.
#
# --variant no-oom-protection builds a diagnostic copy in build/ltp-NAME
# (tree in target/ltp-build-NAME) whose library skips the oom_score_adj
# check that stops every new-API test on Ginux today; see
# tools/ltp/no-oom-protection.c. Run it with tests/qemu/ltp.sh --variant NAME.
#
# Outputs, in build/ltp:
#   ltp/                stripped install tree (LTPROOT in the guest)
#   ltp.tar.gz          the tree as a reproducible gzip tarball
#   ltp.tar.xz          the same tree as xz, a tenth of the size; the QEMU
#                       test downloads this one into the domain
#   ltp-runner          the static guest-side test runner
#   binaries.txt        test binaries that built
#   test-dirs.txt       binary TAB source directory (under testcases/kernel)
#   build-failures.txt  test binaries that did not build under musl
#
# Tests that do not build under musl are skipped, not patched: each test
# directory is built with make -k and whatever built is installed.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)

ltp_version=20260930
ltp_sha256=b9837481134fa6eabce91c2fba57d96695f81360468f83e11e6982584ad4d29d
ltp_url="https://github.com/linux-test-project/ltp/releases/download/${ltp_version}/ltp-full-${ltp_version}.tar.xz"
# alpine:3.22, pinned by digest so the toolchain and musl do not drift.
builder_image="${GINUX_LTP_BUILDER_IMAGE:-alpine@sha256:2e0b81d60597f449baa56dc25d355367869d2dca4cd57e866f1e2b52af3eb55f}"

cache_dir="$repo_root/build/ltp-cache"
tarball="$cache_dir/ltp-full-${ltp_version}.tar.xz"

runner_only=0
clean=0
force=0
variant=
while (($#)); do
    case "$1" in
        --clean) clean=1 ;;
        --force) force=1 ;;
        --runner-only) runner_only=1 ;;
        --variant) variant=${2:?--variant needs a name}; shift ;;
        *) echo "usage: $0 [--clean | --force | --runner-only | --variant NAME]" >&2; exit 2 ;;
    esac
    shift
done
work_dir="$repo_root/target/ltp-build${variant:+-$variant}"
out_dir="$repo_root/build/ltp${variant:+-$variant}"
if ((clean)); then
    rm -rf "$work_dir" "$out_dir"
fi

mkdir -p "$cache_dir" "$work_dir" "$out_dir"

# What each output depends on: the runner on the builder image and its
# source, the test tree on the release, the image, the variant and the
# build scripts.
runner_inputs=$(
    {
        echo "$builder_image"
        sha256sum "$repo_root/tools/ltp/ltp-runner.c" "$repo_root/tools/ltp/container-build.sh"
    } | sha256sum | cut -d' ' -f1
)
tree_inputs=$(
    {
        echo "$ltp_version $ltp_sha256 $builder_image ${variant:-default}"
        sha256sum "$repo_root/tools/ltp/container-build.sh" "$repo_root/tools/ltp/no-oom-protection.c"
    } | sha256sum | cut -d' ' -f1
)
runner_stamp="$out_dir/.runner-inputs"
tree_stamp="$out_dir/.tree-inputs"
stamp_matches() { [[ -f "$1" && "$(cat "$1")" == "$2" ]]; }
if ((!force)); then
    runner_current=0
    if [[ -x "$out_dir/ltp-runner" ]] && stamp_matches "$runner_stamp" "$runner_inputs"; then
        runner_current=1
    fi
    if ((!runner_only)) && [[ -s "$out_dir/ltp.tar.xz" && -s "$out_dir/binaries.txt" ]] &&
        stamp_matches "$tree_stamp" "$tree_inputs"; then
        # The test tree is current: at most the runner needs building.
        if ((runner_current)); then
            echo "LTP is up to date in $out_dir (--force rebuilds)"
            exit 0
        fi
        runner_only=1
    elif ((runner_only && runner_current)); then
        echo "LTP runner is up to date: $out_dir/ltp-runner (--force rebuilds)"
        exit 0
    fi
fi

if ((!runner_only)) &&
    { [[ ! -f "$tarball" ]] || ! echo "$ltp_sha256  $tarball" | sha256sum -c --quiet - 2>/dev/null; }; then
    echo "Downloading LTP $ltp_version"
    curl -fsSL -o "$tarball.part" "$ltp_url"
    echo "$ltp_sha256  $tarball.part" | sha256sum -c --quiet -
    mv "$tarball.part" "$tarball"
fi

if ((runner_only)); then
    echo "Building the LTP guest runner in $builder_image"
else
    echo "Building LTP $ltp_version syscall tests (static, musl) in $builder_image"
fi
docker run --rm \
    -e LTP_VERSION="$ltp_version" \
    -e RUNNER_ONLY="$runner_only" \
    -e VARIANT="$variant" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -e JOBS="${GINUX_LTP_JOBS:-$(nproc)}" \
    -v "$cache_dir:/cache:ro" \
    -v "$repo_root/tools/ltp:/scripts:ro" \
    -v "$work_dir:/work" \
    -v "$out_dir:/out" \
    "$builder_image" /bin/sh /scripts/container-build.sh

printf '%s\n' "$runner_inputs" >"$runner_stamp"
echo "Runner:   $out_dir/ltp-runner"
if ((runner_only)); then
    exit 0
fi
printf '%s\n' "$tree_inputs" >"$tree_stamp"
echo "LTP tree: $out_dir/ltp ($(wc -l <"$out_dir/binaries.txt") test binaries)"
echo "Tarballs: $out_dir/ltp.tar.gz ($(du -h "$out_dir/ltp.tar.gz" | cut -f1))," \
    "$out_dir/ltp.tar.xz ($(du -h "$out_dir/ltp.tar.xz" | cut -f1))"
if [[ -s "$out_dir/build-failures.txt" ]]; then
    echo "Did not build under musl: $(tr '\n' ' ' <"$out_dir/build-failures.txt")"
fi
