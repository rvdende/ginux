#!/usr/bin/env bash
# Runs the Linux Test Project syscall tests (tests/ltp/syscalls.list) in an
# Alpine domain on Ginux under QEMU, one machine-parseable line per test:
#
#   LTP NAME RESULT SECONDS DETAIL
#
# RESULT is TPASS, TFAIL, TBROK, TCONF, TWARN, CRASH (the domain, kernel or
# QEMU went down), HANG (over the test's time budget) or SKIP (marked in the
# list). The summary goes to target/ltp-results.txt, a failure-cluster
# report to target/ltp-report.txt, each test's console output to
# target/ltp/logs/NAME.log and the serial console to target/ltp-serial.log.
#
# Needs `make ltp` (the static LTP build) and `make build`. Options are
# passed to tests/ltp/driver.py; for example:
#
#   tests/qemu/ltp.sh --tests "abort01 accept01"   # named tests
#   tests/qemu/ltp.sh --filter '^(open|read)'      # tests matching a regex
#
# LTP_TESTS and LTP_FILTER do the same from make: LTP_FILTER=^mmap make test-ltp
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$repo_root/target/tmp"
export TMPDIR="${TMPDIR:-$repo_root/target/tmp}"

exec python3 -I "$repo_root/tests/ltp/driver.py" "$@"
