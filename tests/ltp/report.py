#!/usr/bin/env python3
"""Clusters LTP failures from a tests/qemu/ltp.sh run.

    tests/ltp/report.py [--variant NAME]

Reads target/ltp-results.txt and the per-test logs in target/ltp/logs and
writes target/ltp-report.txt: results by syscall area (the LTP source
directory), by normalized first failure message, by errno, by Ginux kernel
diagnostic, and the crashes and hangs. With --variant, the files of that
run (target/ltp-results-NAME.txt, ...) are used instead.
"""

import argparse
import collections
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
NOT_PASSING = ("TFAIL", "TBROK", "TWARN", "CRASH", "HANG")
COLUMNS = ("TPASS", "TFAIL", "TBROK", "TCONF", "TWARN", "CRASH", "HANG", "SKIP", "NOTRUN")

FAILURE_LINE = re.compile(r"\b(TFAIL|TBROK|TWARN)\b")
ERRNO = re.compile(r"\b(E[A-Z0-9]{2,}) \(\d+\)")


def load_results(path):
    results = []
    for line in path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, result, seconds, *detail = line.split(" ", 3)
        results.append((name, result, float(seconds), detail[0] if detail else ""))
    return results


def normalize(line):
    line = re.sub(r"^.*?\b(TFAIL|TBROK|TWARN)\b[\s:]*", r"\1: ", line)
    # Old-API lines repeat the source position after the type.
    line = re.sub(r"^(\w+): [\w.-]+\.c:\d+:\s*", r"\1: ", line)
    line = re.sub(r"\b(\w+)\(.*\)(\s+(?:failed|succeeded|returned|expected))", r"\1(...)\2", line)
    line = re.sub(r"0x[0-9a-fA-F]+", "X", line)
    line = re.sub(r"(?<![A-Za-z_])-?\d+(?![A-Za-z_])", "N", line)
    line = re.sub(r"/[\w./-]+", "PATH", line)
    return line.strip()[:150]


def kernel_message(line):
    """The label of a kernel diagnostic, without its values."""
    line = re.split(r":\s*-?\d", line.strip(), maxsplit=1)[0]
    line = re.sub(r"=\S+", "=N", line)
    return re.sub(r"\d+", "N", line)[:120]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--variant", default="")
    args = parser.parse_args()
    suffix = f"-{args.variant}" if args.variant else ""
    results_path = REPO / f"target/ltp-results{suffix}.txt"
    report_path = REPO / f"target/ltp-report{suffix}.txt"
    logs = REPO / f"target/ltp{suffix}/logs"
    dirs_file = REPO / f"build/ltp{suffix}/test-dirs.txt"
    dirs = {}
    if dirs_file.exists():
        for line in dirs_file.read_text().splitlines():
            binary, directory = line.split("\t", 1)
            dirs[binary] = directory.removeprefix("syscalls/")

    results = load_results(results_path)
    commands = {}
    list_file = REPO / "tests/ltp/syscalls.list"
    for line in list_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            fields = line.lstrip("!").split()
            commands[fields[0]] = fields[1]

    totals = collections.Counter(result for _, result, _, _ in results)
    areas = collections.defaultdict(collections.Counter)
    errnos = collections.defaultdict(list)
    symptoms = collections.defaultdict(list)
    kernel = collections.defaultdict(set)
    crashes, hangs = [], []

    for name, result, seconds, detail in results:
        area = dirs.get(commands.get(name, name), "?")
        areas[area][result] += 1
        if result not in NOT_PASSING:
            continue
        log_path = logs / f"{name}.log"
        text = log_path.read_text(errors="replace") if log_path.exists() else ""
        lines = text.splitlines()
        failures = [line for line in lines if FAILURE_LINE.search(line)]
        for line in lines:
            if line.startswith("ginux: "):
                kernel[kernel_message(line)].add(name)
        if result == "CRASH":
            crashes.append((name, area, detail))
            symptoms[f"CRASH: {re.sub(r'[0-9]+', 'N', detail)}"].append(name)
            continue
        if result == "HANG":
            hangs.append((name, area, seconds, detail))
            symptoms[f"HANG: {detail.split()[0]}"].append(name)
            continue
        seen = set()
        for line in failures:
            for errno in ERRNO.findall(line):
                if errno not in seen:
                    seen.add(errno)
                    errnos[errno].append(name)
        brok = [line for line in failures if "TBROK" in line]
        first = (brok or failures or [f"{result}: {detail} (no failure message)"])[0]
        symptoms[normalize(first)].append(name)

    out = []
    out.append(f"LTP report for {results_path}")
    out.append("total=" + str(len(results)) + " " + " ".join(f"{c}={totals[c]}" for c in COLUMNS))
    out.append("")
    out.append("== By area (LTP source directory), most non-passing first ==")
    out.append(f"{'area':28} {'tests':>5} " + " ".join(f"{c:>6}" for c in COLUMNS[:-2]))
    for area, counts in sorted(
        areas.items(), key=lambda item: (-sum(item[1][c] for c in NOT_PASSING), item[0])
    ):
        if not sum(counts[c] for c in NOT_PASSING):
            continue
        out.append(
            f"{area:28} {sum(counts.values()):>5} "
            + " ".join(f"{counts[c]:>6}" for c in COLUMNS[:-2])
        )
    passing = sorted(a for a, c in areas.items() if not sum(c[x] for x in NOT_PASSING))
    out.append(f"(areas with no failures: {len(passing)})")
    out.append("")
    out.append("== Failure symptoms (first TBROK, else first TFAIL line, normalized) ==")
    for symptom, names in sorted(symptoms.items(), key=lambda item: (-len(item[1]), item[0])):
        out.append(f"{len(names):5}  {symptom}")
        out.append(f"       e.g. {' '.join(names[:8])}")
    out.append("")
    out.append("== errno reported in TFAIL/TBROK/TWARN lines (tests per errno) ==")
    for errno, names in sorted(errnos.items(), key=lambda item: (-len(item[1]), item[0])):
        out.append(f"{len(names):5}  {errno:12} e.g. {' '.join(names[:10])}")
    out.append("")
    out.append("== Ginux kernel diagnostics in non-passing tests (tests per message) ==")
    for message, names in sorted(kernel.items(), key=lambda item: (-len(item[1]), item[0]))[:60]:
        out.append(f"{len(names):5}  {message}")
        out.append(f"       e.g. {' '.join(sorted(names)[:8])}")
    out.append("")
    out.append("== Crashes ==")
    for name, area, detail in crashes:
        out.append(f"{name:24} {area:20} {detail}")
    out.append("")
    out.append("== Hangs ==")
    for name, area, seconds, detail in hangs:
        out.append(f"{name:24} {area:20} {seconds:8.1f}s {detail}")
    report_path.write_text("\n".join(out) + "\n")
    print(f"ltp: report in {report_path}")


if __name__ == "__main__":
    main()
