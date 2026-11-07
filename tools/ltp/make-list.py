#!/usr/bin/env python3
"""Generates tests/ltp/syscalls.list from LTP's runtest/syscalls.

    tools/ltp/make-list.py [LIST]

Run after tools/ltp/build.sh (it reads build/ltp and the LTP sources in
target/ltp-build). Every runtest/syscalls entry becomes one line, in LTP's
order. Generated notes start with "auto:": tests whose binary did not build
or that need kernel modules (SKIP_RULES) are marked skipped,
and tests whose LTP timeout or runtime exceed the harness's default budget
get a larger budget. Lines with any other note are
curated by hand and are kept unchanged when the list is regenerated.
"""

import math
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LTP = REPO / "build/ltp"

# Keep in step with tests/ltp/src/config.rs and tests/ltp/setup.sh.
DEFAULT_BUDGET = 60
LTP_DEFAULT_TIMEOUT = 30
RUNTIME_MUL = 0.1
SLACK = 15

# Tests skipped from their LTP metadata, with the reason recorded: Ginux
# loads no kernel modules (LTP's test modules are not built). Delete a rule
# to run those tests again.
SKIP_RULES = (
    (
        re.compile(r"\.needs_drivers\s*=|\btst_module_(load|exists)\s*\("),
        "needs loadable kernel modules",
    ),
)

HEADER = """\
# LTP syscall tests run by tests/qemu/ltp.sh (see docs/LTP.md).
#
# One test per line, as in LTP's runtest/syscalls:
#
#   TAG COMMAND [ARG...]            run, with the default budget (60 s)
#   TAG COMMAND [ARG...]  # budget=N   run, allowing N seconds
#   !TAG COMMAND [ARG...] # REASON  skipped, recorded as SKIP with REASON
#
# Regenerate with tools/ltp/make-list.py after changing the LTP version.
# Notes starting with "auto:" are generated (budgets from LTP's timeout and
# runtime, skips for tests that did not build or need kernel modules);
# lines with any other note are curated by hand and survive regeneration.
"""


EXTRA_HEADER = "Tests from outside runtest/syscalls, curated by hand."


def read_metadata(source):
    """Returns (timeout, runtime, skip reason) from a test's source."""
    try:
        text = source.read_text(errors="replace")
    except OSError:
        return 0, 0, None
    timeout = re.search(r"\.timeout\s*=\s*(\d+)", text)
    runtime = re.search(r"\.runtime\s*=\s*(\d+)", text)
    reason = next((reason for rule, reason in SKIP_RULES if rule.search(text)), None)
    return (
        int(timeout.group(1)) if timeout else 0,
        int(runtime.group(1)) if runtime else 0,
        reason,
    )


def main():
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "tests/ltp/syscalls.list"
    runtest = (LTP / "ltp/runtest/syscalls").read_text().splitlines()
    binaries = set((LTP / "binaries.txt").read_text().split())
    failures = set((LTP / "build-failures.txt").read_text().split())
    installed = {path.name for path in (LTP / "ltp/testcases/bin").iterdir()}
    dirs = dict(
        line.split("\t", 1) for line in (LTP / "test-dirs.txt").read_text().splitlines() if line
    )
    version = (LTP / "ltp/VERSION").read_text().strip()
    sources = REPO / f"target/ltp-build/ltp-full-{version}/testcases/kernel"

    curated = {}
    if out.exists():
        for line in out.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "#" not in stripped:
                continue
            note = stripped.split("#", 1)[1].strip()
            if not note.startswith("auto:"):
                curated[stripped.lstrip("!").split()[0]] = line

    lines = [HEADER, f"# Generated from LTP {version} runtest/syscalls.", ""]
    budgets = skipped = 0
    listed = set()
    for raw in runtest:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        tag, command = entry.split(None, 1)
        command = " ".join(command.split())
        listed.add(tag)
        if tag in curated:
            lines.append(curated[tag])
            continue
        binary = command.split()[0]
        if binary not in installed:
            reason = "not built under musl" if binary in failures else "not built"
            lines.append(f"!{tag} {command}  # auto: {reason}")
            skipped += 1
            continue
        budget = DEFAULT_BUDGET
        reason = None
        if binary in binaries and binary in dirs:
            directory = sources / dirs[binary]
            for stem in (binary, re.sub(r"_(64|16)$", "", binary)):
                if (directory / f"{stem}.c").exists():
                    timeout, runtime, reason = read_metadata(directory / f"{stem}.c")
                    needed = LTP_DEFAULT_TIMEOUT + timeout + math.ceil(runtime * RUNTIME_MUL) + SLACK
                    budget = max(budget, 30 * math.ceil(needed / 30))
                    break
        if reason:
            lines.append(f"!{tag} {command}  # auto: {reason}")
            skipped += 1
        elif budget > DEFAULT_BUDGET:
            lines.append(f"{tag} {command}  # auto: budget={budget}")
            budgets += 1
        else:
            lines.append(f"{tag} {command}")
    # Curated tests from outside runtest/syscalls (Ginux's own tests in
    # tools/ltp/tests, the memory controller's) stay, at the end.
    extra = [line for tag, line in curated.items() if tag not in listed]
    if extra:
        lines += ["", f"# {EXTRA_HEADER}", *extra]
    out.write_text("\n".join(lines) + "\n")
    print(
        f"Wrote {out}: {sum(1 for l in lines if l and not l.startswith('#'))} tests, "
        f"{skipped} skipped, {budgets} with larger budgets, {len(curated)} curated lines kept"
    )


if __name__ == "__main__":
    main()
