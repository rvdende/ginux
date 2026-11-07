#!/usr/bin/env bash
# Runs the Linux Test Project syscall tests (tests/ltp/syscalls.list) in an
# Alpine domain on Ginux under QEMU with the Rust harness in tests/ltp, which
# makes each LTP test a libtest trial (docs/LTP.md):
#
#   test accept01 ... ok
#   test abort01  ... ignored (known failure: TFAIL)
#   test bind06   ... ignored (TCONF: ...)
#   test fork14   ... FAILED
#
# A failure of a test that tests/ltp/baseline.txt does not list is a
# regression and fails the run; --strict fails on every failure. Results go
# to target/ltp-results.txt (NAME RESULT SECONDS DETAIL per test), a
# failure-cluster report to target/ltp-report.txt, each test's console
# output to target/ltp/logs/NAME.log and the serial console to
# target/ltp-serial.log.
#
# Needs `make ltp` (the static LTP build) and `make build`. For example:
#
#   tests/qemu/ltp.sh --tests "abort01 accept01"   # named tests
#   tests/qemu/ltp.sh --filter '^(open|read)'      # tests matching a regex
#   tests/qemu/ltp.sh -- --exact accept01 -q       # libtest arguments
#
# LTP_TESTS and LTP_FILTER do the same from make: LTP_FILTER=^mmap make test-ltp
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$repo_root/target/tmp"
export TMPDIR="${TMPDIR:-$repo_root/target/tmp}"

usage() {
    cat <<'EOF'
usage: tests/qemu/ltp.sh [OPTION...] [LIBTEST-ARGUMENT...] [-- LIBTEST-ARGUMENT...]

Options (and the environment variables they set):
  --list FILE            run list (tests/ltp/syscalls.list)         LTP_LIST
  --tests "A B"          only these tests                           LTP_TESTS
  --filter REGEX         only tests whose name matches              LTP_FILTER
  --variant NAME         use build/ltp-NAME, suffix the outputs     LTP_VARIANT
  --esp-dir DIR          the ESP to boot (build/esp)                GINUX_ESP_DIR
  --default-budget N     seconds for a test without a budget (60)   LTP_BUDGET
  --grace N              seconds past a budget before a reboot (30) LTP_GRACE
  --between-tests N      seconds between tests (60)                 LTP_BETWEEN_TESTS
  --setup-timeout N      seconds to start the runner (600)          LTP_SETUP_TIMEOUT
  --max-boots N          stop after N boots (400)                   LTP_MAX_BOOTS
  --memory SIZE          QEMU memory (6G)                           GINUX_MEMORY
  --domain-memory-mib N  the domain's memory (4096)                 LTP_DOMAIN_MEMORY_MIB
  --domain-cpus N        CPUs of the guest and domain, 1, 2 or 4 (4) LTP_DOMAIN_CPUS
  --image IMAGE          the domain's image (alpine:3.22)           LTP_IMAGE
  --baseline FILE        known failures (tests/ltp/baseline.txt)    LTP_BASELINE
  --strict               fail on every failure, baseline or not     LTP_STRICT=1
  --update-baseline      rewrite the baseline from this run         LTP_UPDATE_BASELINE=1

Other arguments go to libtest, which selects among those tests: a name
filter, --exact, --skip NAME, --ignored (run the tests the list skips), -q.
libtest's own --list (list the tests, run nothing) goes after `--`.
EOF
}

libtest_args=()
while (($# > 0)); do
    case $1 in
        --?*=*) set -- "${1%%=*}" "${1#*=}" "${@:2}" ;;
    esac
    case $1 in
        --list | --tests | --filter | --variant | --esp-dir | --default-budget | --grace | \
            --between-tests | --setup-timeout | --max-boots | --memory | --domain-memory-mib | \
            --domain-cpus | --image | --baseline)
            if (($# < 2)); then
                echo "ltp.sh: $1 needs a value" >&2
                exit 2
            fi
            case $1 in
                --list) export LTP_LIST=$2 ;;
                --tests) export LTP_TESTS=$2 ;;
                --filter) export LTP_FILTER=$2 ;;
                --variant) export LTP_VARIANT=$2 ;;
                --esp-dir) export GINUX_ESP_DIR=$2 ;;
                --default-budget) export LTP_BUDGET=$2 ;;
                --grace) export LTP_GRACE=$2 ;;
                --between-tests) export LTP_BETWEEN_TESTS=$2 ;;
                --setup-timeout) export LTP_SETUP_TIMEOUT=$2 ;;
                --max-boots) export LTP_MAX_BOOTS=$2 ;;
                --memory) export GINUX_MEMORY=$2 ;;
                --domain-memory-mib) export LTP_DOMAIN_MEMORY_MIB=$2 ;;
                --domain-cpus) export LTP_DOMAIN_CPUS=$2 ;;
                --image) export LTP_IMAGE=$2 ;;
                --baseline) export LTP_BASELINE=$2 ;;
            esac
            shift 2
            ;;
        --strict)
            export LTP_STRICT=1
            shift
            ;;
        --update-baseline)
            export LTP_UPDATE_BASELINE=1
            shift
            ;;
        -h | --help)
            usage
            exit 0
            ;;
        --)
            shift
            libtest_args+=("$@")
            break
            ;;
        *)
            libtest_args+=("$1")
            shift
            ;;
    esac
done

# Relative paths are relative to where this script was started; the harness
# would take them from the repository root.
for name in LTP_LIST GINUX_ESP_DIR LTP_BASELINE; do
    value=${!name:-}
    if [[ -n "$value" && "$value" != /* ]]; then
        export "$name=$PWD/$value"
    fi
done

cd "$repo_root"
# Build the harness, then run it directly rather than through `cargo test`,
# so that SIGTERM to this script's PID or a Ctrl-C reaches it (it stops QEMU
# and writes the final results).
harness=$(cargo test --quiet --manifest-path tests/ltp/Cargo.toml --test ltp --no-run \
    --message-format=json-render-diagnostics |
    sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1)
if [[ -z "$harness" ]]; then
    echo "ltp.sh: building the LTP harness (tests/ltp) produced no test executable" >&2
    exit 1
fi
exec "$harness" ${libtest_args[@]+"${libtest_args[@]}"}
