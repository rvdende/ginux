#!/usr/bin/env python3
"""Runs the LTP syscall tests inside a Ginux domain under QEMU.

tests/qemu/ltp.sh is the entry point; docs/LTP.md describes the harness.

The driver boots Ginux with tools/qemu/run.sh, starts an Alpine domain,
serves the LTP tree, the guest runner and the run list over HTTP (the guest
reaches the host at 10.0.2.2) and starts the runner (tools/ltp/ltp-runner.c)
from the domain's shell through tests/ltp/setup.sh. The runner enforces each
test's time budget inside the guest and brackets each test's console output
with @@LTP BEGIN/END markers.

If the kernel panics, the domain goes down, QEMU exits, or a test runs
past its budget plus a grace period without the runner reporting (the guest
is wedged), the test is recorded as CRASH or HANG, QEMU is killed (by PID)
and rebooted, and the run continues with the next test. A crash leaves the
kernel unable to start the domain again (the process registry is not
recovered), so the driver always reboots rather than restarting the domain.
"""

import argparse
import collections
import dataclasses
import datetime
import functools
import http.server
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]

MARKER = re.compile(rb"@@LTP (BEGIN|END|READY|DONE|SETUP_FAILED|RUNNER_EXITED)(?: ([^\r\n]*))?")
PANIC = re.compile(rb"GINUX_(?:BOOT|KERNEL)_PANIC")
DOMAIN_DOWN = re.compile(
    rb"ginux: Linux init (?:exited|execution failed)|domain marked failed"
)
RESULTS = ("TPASS", "TFAIL", "TBROK", "TCONF", "TWARN", "CRASH", "HANG", "SKIP", "NOTRUN")


@dataclasses.dataclass
class Test:
    tag: str
    command: str
    budget: int
    skip: str | None  # the reason, for a test marked skipped in the list


@dataclasses.dataclass
class Result:
    result: str
    seconds: float
    detail: str


class BootError(Exception):
    pass


def parse_list(path, default_budget):
    """Parses a run list: `[!]TAG COMMAND [ARG...] [# NOTE]`.

    `!` marks a test skipped, with NOTE as the reason; `budget=N` in NOTE
    sets the test's time budget in seconds.
    """
    line_re = re.compile(r"^(!?)(\S+)\s+([^#]*?)\s*(?:#\s*(.*))?$")
    tests = []
    seen = set()
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = line_re.match(line)
        if not match or not match.group(3):
            raise SystemExit(f"{path}:{lineno}: cannot parse: {raw}")
        skipped, tag, command, note = match.groups()
        note = note or ""
        if tag in seen:
            raise SystemExit(f"{path}:{lineno}: duplicate test {tag}")
        seen.add(tag)
        budget = default_budget
        budget_match = re.search(r"\bbudget=(\d+)\b", note)
        if budget_match:
            budget = int(budget_match.group(1))
            note = (note[: budget_match.start()] + note[budget_match.end():]).strip()
        tests.append(Test(tag, command, budget, (note or "skipped") if skipped else None))
    return tests


def printed_result(output, kind):
    """Whether the test printed a `kind` result line: from the new LTP API
    ("file.c:12: TFAIL: ...") or the old one ("name    1  TFAIL  :  ...")."""
    return re.search(rb"(?m)(?:\.c:\d+: |^\S+\s+\d+\s+)" + kind + rb"\b", output) is not None


def classify(status, output, budget):
    """Maps the runner's END status and the test's output to a result."""
    if status == "timeout":
        return "HANG", f"guest-timeout {budget}s"
    if status.startswith("lost"):
        return "TBROK", f"runner lost the test's exit status ({status})"
    if status.startswith("signal="):
        return "TBROK", f"killed by signal {status[7:]}"
    if not status.startswith("exit="):
        return "TBROK", status
    code = int(status[5:])
    # LTP's library also kills the test when a child reports TBROK; it then
    # prints the same "Test killed!" line, but that is a break, not a hang.
    if b"reported TBROK killing the test" in output:
        return "TBROK", f"{status} (a child reported TBROK)"
    if b"Test killed! (timeout?)" in output:
        return "HANG", f"ltp-timeout {status}"
    if code == 0:
        # The LTP library counts results in a page it shares with the test
        # process and derives the exit status from it. Under Ginux that page
        # does not yet reach the library's process from the test, so the
        # exit status can claim success after the test reported a failure:
        # the results it printed decide.
        # LTP's rule: any break, failure or warning marks the test; skips
        # (TCONF) only when nothing passed.
        for kind in (b"TBROK", b"TFAIL", b"TWARN"):
            if printed_result(output, kind):
                return kind.decode(), f"{status} ({kind.decode()} printed)"
        if printed_result(output, b"TCONF") and not printed_result(output, b"TPASS"):
            return "TCONF", f"{status} (TCONF printed)"
        return "TPASS", status
    if code in (126, 127):
        return "TBROK", f"{status} (could not execute)"
    if code >= 128:
        # An exit status of 128+N from a test usually means a signal killed
        # something it waited for.
        return "TBROK", f"{status} (signal {code - 128} reported as an exit status?)"
    if code > 63:
        return "TBROK", f"{status} (not an LTP result)"
    if code & 2:
        return "TBROK", status
    if code & 1:
        return "TFAIL", status
    if code & 4:
        return "TWARN", status
    if code & 32:
        return "TCONF", status
    return "TBROK", f"{status} (no LTP result bits)"


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args):
        pass


class Qemu:
    """One QEMU boot: the serial console, its event stream and its log."""

    def __init__(self, args, boot, log):
        self.args = args
        self.boot = boot
        self.log = log
        self.data = bytearray()
        self.lock = threading.Lock()
        self.events = queue.Queue()
        self.proc = None

    def start(self):
        env = dict(os.environ)
        env.update(
            GINUX_ESP_DIR=str(self.args.esp_dir),
            GINUX_MEMORY=self.args.memory,
            GINUX_VOLUME_IMAGE=str(self.args.volume),
            GINUX_QEMU_PID_FILE=str(self.args.work / "qemu.pid"),
        )
        self.log.write(f"\n===== ltp driver: boot {self.boot} at {time.strftime('%H:%M:%S')} =====\n".encode())
        self.log.flush()
        self.proc = subprocess.Popen(
            [str(REPO / "tools/qemu/run.sh")],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
        )
        threading.Thread(target=self._reader, daemon=True).start()

    def _reader(self):
        fd = self.proc.stdout.fileno()
        pending = b""
        pending_offset = 0
        while True:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            now = time.monotonic()
            if not chunk:
                break
            with self.lock:
                self.data += chunk
            self.log.write(chunk)
            self.log.flush()
            pending += chunk
            while True:
                newline = pending.find(b"\n")
                if newline < 0:
                    break
                line = pending[:newline]
                end = pending_offset + newline + 1
                self._scan(line.rstrip(b"\r"), pending_offset, end, now)
                pending = pending[newline + 1:]
                pending_offset = end
        self.events.put(("eof", "", time.monotonic(), len(self.data), len(self.data)))

    def _scan(self, line, start, end, now):
        match = MARKER.search(line)
        if match:
            args = (match.group(2) or b"").decode(errors="replace")
            self.events.put((match.group(1).decode(), args, now, start, end))
        elif PANIC.search(line):
            self.events.put(("panic", line.decode(errors="replace"), now, start, end))
        elif DOMAIN_DOWN.search(line):
            self.events.put(("domain-down", line.decode(errors="replace"), now, start, end))

    def send(self, line):
        try:
            self.proc.stdin.write(line.encode() + b"\n")
            self.proc.stdin.flush()
        except OSError:
            pass

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def wait_for(self, needle, seconds, start=0):
        """Polls the console until `needle` appears after offset `start`;
        returns the offset just past it. Stops early if the kernel panics or
        QEMU exits."""
        deadline = time.monotonic() + seconds
        while True:
            with self.lock:
                position = self.data.find(needle, start)
                panicked = PANIC.search(self.data, start)
            if position >= 0:
                return position + len(needle)
            if panicked:
                raise BootError("kernel panic")
            if not self.alive():
                raise BootError("QEMU exited")
            if time.monotonic() > deadline:
                raise BootError(f"no {needle.decode()!r} within {seconds}s")
            time.sleep(0.1)

    def settle(self, seconds=5.0):
        """Waits until the console has been quiet for half a second (so a
        crash report is complete), or `seconds` pass."""
        deadline = time.monotonic() + seconds
        size = -1
        while time.monotonic() < deadline:
            with self.lock:
                current = len(self.data)
            if current == size:
                return
            size = current
            time.sleep(0.5)

    def output(self, start, end=None):
        with self.lock:
            return bytes(self.data[start:end])

    def stop(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        try:
            self.proc.stdin.close()
        except OSError:
            pass


class Run:
    def __init__(self, args, tests):
        self.args = args
        self.tests = tests
        self.runnable = [test for test in tests if test.skip is None]
        self.results = {}
        for test in tests:
            if test.skip is not None:
                self.results[test.tag] = Result("SKIP", 0.0, test.skip)
        self.logs = args.work / "logs"
        shutil.rmtree(self.logs, ignore_errors=True)
        self.logs.mkdir(parents=True)
        self.boots = 0
        self.started = time.time()

    # Results ---------------------------------------------------------

    def record(self, test, result, seconds, detail, output):
        self.results[test.tag] = Result(result, seconds, detail)
        (self.logs / f"{test.tag}.log").write_bytes(output.replace(b"\r\n", b"\n"))
        print(f"LTP {test.tag} {result} {seconds:.2f} {detail}", flush=True)
        self.write_results()

    def counts(self):
        counts = collections.Counter(r.result for r in self.results.values())
        counts["NOTRUN"] = len(self.tests) - len(self.results)
        return counts

    def write_results(self, final=False):
        counts = self.counts()
        lines = [
            f"# Ginux LTP results ({'complete' if final else 'in progress'}), "
            f"{datetime.datetime.now().isoformat(timespec='seconds')}",
            f"# list={self.args.list_name} ltp={self.args.ltp_version} "
            f"kernel={self.args.kernel_rev} boots={self.boots} "
            f"elapsed={int(time.time() - self.started)}s",
            f"# total={len(self.tests)} "
            + " ".join(f"{name}={counts[name]}" for name in RESULTS),
            "# name result seconds detail",
        ]
        for test in self.tests:
            result = self.results.get(test.tag, Result("NOTRUN", 0.0, "not reached"))
            lines.append(f"{test.tag} {result.result} {result.seconds:.2f} {result.detail}")
        target = self.args.results
        temporary = target.with_suffix(".tmp")
        temporary.write_text("\n".join(lines) + "\n")
        temporary.replace(target)

    # Sessions --------------------------------------------------------

    def run(self, base_url):
        position = 0
        failed_boots = 0
        while position < len(self.runnable):
            if self.boots >= self.args.max_boots:
                print(f"ltp: stopping after {self.boots} boots", file=sys.stderr)
                break
            self.boots += 1
            qemu = Qemu(self.args, self.boots, self.args.serial_log)
            try:
                qemu.start()
                phase_start = self.start_domain(qemu, base_url, position)
                outcome, position, progressed = self.run_session(qemu, phase_start, position)
            except BootError as error:
                outcome, progressed = f"boot failed: {error}", False
                tail = qemu.output(max(0, len(qemu.data) - 600)).decode(errors="replace")
                tail = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", tail)
                print(f"ltp: boot {self.boots}: {error}; console ends:\n{tail}", file=sys.stderr)
                # Start the next boot from a fresh volume in case this one
                # was left unusable.
                self.shutdown(qemu)
                new_volume(self.args.volume)
            finally:
                self.shutdown(qemu)
            if outcome == "done":
                break
            failed_boots = 0 if progressed else failed_boots + 1
            if failed_boots >= 3:
                print("ltp: three boots in a row made no progress; stopping", file=sys.stderr)
                break
        self.write_results(final=True)

    def start_domain(self, qemu, base_url, position):
        args = self.args
        offset = qemu.wait_for(b"ginux> ", 120)
        # The volume keeps domain configurations across reboots, so after the
        # first boot the domain already exists and creating it is rejected.
        qemu.send("domain new ltp")
        offset = qemu.wait_for(b"ginux> ", 30, offset)
        # LTP's credential tests switch between root and other users (nobody,
        # bin), which a domain allows only with user-switching=true.
        qemu.send(
            f"domain set ltp image={args.image} init=/bin/sh memory-mib={args.domain_memory_mib}"
            " user-switching=true"
        )
        offset = qemu.wait_for(b"settings accepted", 30, offset)
        qemu.send("domain start ltp --attach")
        offset = qemu.wait_for(b"ginux: entering configured Linux init", 900, offset)
        offset = qemu.wait_for(b"/ # ", 60, offset)
        # The runner cannot replace the init shell: Ginux fails execve in a
        # domain's init process (ENOENT). The quotes keep the shell's echo of
        # this line from looking like a marker.
        qemu.send(
            f"wget -q -O /tmp/ltp-setup.sh {base_url}/setup.sh && "
            f"/bin/sh /tmp/ltp-setup.sh {base_url} {position}; "
            'echo "@@LTP" RUNNER"_"EXITED $?'
        )
        return offset

    def run_session(self, qemu, phase_start, position):
        """Consumes runner events until the list is done or the guest fails.
        Returns (outcome, next position, whether any test finished)."""
        args = self.args
        progressed = False
        current = None  # (test, begin time, output offset)
        deadline = time.monotonic() + args.setup_timeout
        while True:
            try:
                kind, text, when, start, end = qemu.events.get(timeout=0.25)
            except queue.Empty:
                kind = None
            now = time.monotonic()
            if kind is not None and start < phase_start:
                continue
            if kind == "READY":
                deadline = now + args.between_tests
            elif kind == "BEGIN":
                index = int(text.split()[0])
                test = self.runnable[index]
                current = (test, when, end)
                deadline = now + test.budget + args.grace
            elif kind == "END":
                fields = text.split()
                index, status, millis = int(fields[0]), fields[2], int(fields[3])
                leftover = int(fields[4]) if len(fields) > 4 else 0
                test = self.runnable[index]
                output = qemu.output(current[2] if current else start, start)
                result, detail = classify(status, output, test.budget)
                if leftover > 0:
                    detail += f" leftover={leftover}"
                self.record(test, result, millis / 1000, detail, output)
                current = None
                position = index + 1
                progressed = True
                deadline = now + args.between_tests
            elif kind == "DONE":
                return "done", len(self.runnable), progressed
            elif kind in ("SETUP_FAILED", "RUNNER_EXITED", "panic", "domain-down", "eof") or (
                kind is None and not qemu.alive()
            ):
                qemu.settle()
                what = {
                    "SETUP_FAILED": f"setup failed: {text}",
                    "RUNNER_EXITED": f"runner exited: status {text.strip()}",
                    "panic": "kernel panic",
                    "domain-down": f"domain down: {text.strip()}",
                    "eof": "QEMU exited",
                    None: "QEMU exited",
                }[kind]
                if current is not None:
                    test, began, offset = current
                    self.record(test, "CRASH", now - began, what, qemu.output(offset))
                    return what, self.runnable.index(test) + 1, True
                print(f"ltp: boot {self.boots}: {what} between tests", file=sys.stderr)
                return what, position, progressed
            if now > deadline:
                if current is not None:
                    test, began, offset = current
                    self.record(
                        test, "HANG", now - began,
                        f"host-watchdog {test.budget}+{args.grace}s (guest wedged)",
                        qemu.output(offset),
                    )
                    return "wedged", self.runnable.index(test) + 1, True
                print(f"ltp: boot {self.boots}: no runner progress", file=sys.stderr)
                return "stalled", position, progressed

    def shutdown(self, qemu):
        # Nothing in the guest needs saving: the console is attached to the
        # domain (or the guest is wedged), so QEMU is simply stopped. The
        # volume's metadata is transactional and survives this like a crash.
        qemu.stop()


def new_volume(path):
    """A fresh sparse volume; reboots within a run reuse it, so the domain
    image comes from the OCI cache after the first boot."""
    path.unlink(missing_ok=True)
    with open(path, "wb") as volume:
        volume.truncate(8 << 30)


def git_rev():
    try:
        rev = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        return rev + ("-dirty" if dirty else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", type=Path, default=REPO / "tests/ltp/syscalls.list")
    parser.add_argument("--filter", default=os.environ.get("LTP_FILTER", ""),
                        help="regular expression selecting test names")
    parser.add_argument("--tests", default=os.environ.get("LTP_TESTS", ""),
                        help="space-separated test names to run")
    parser.add_argument("--default-budget", type=int,
                        default=int(os.environ.get("LTP_BUDGET", "60")))
    parser.add_argument("--grace", type=int, default=30,
                        help="seconds past a budget before the host declares the guest wedged")
    parser.add_argument("--between-tests", type=int, default=60)
    parser.add_argument("--setup-timeout", type=int, default=600)
    parser.add_argument("--max-boots", type=int, default=int(os.environ.get("LTP_MAX_BOOTS", "400")))
    parser.add_argument("--memory", default=os.environ.get("GINUX_MEMORY", "6G"))
    parser.add_argument("--domain-memory-mib", type=int, default=4096)
    parser.add_argument("--image", default=os.environ.get("LTP_IMAGE", "alpine:3.22"))
    parser.add_argument("--variant", default=os.environ.get("LTP_VARIANT", ""),
                        help="use the diagnostic LTP build in build/ltp-VARIANT "
                        "(tools/ltp/build.sh --variant) and suffix the outputs")
    parser.add_argument("--esp-dir", type=Path,
                        default=Path(os.environ.get("GINUX_ESP_DIR", REPO / "build/esp")))
    args = parser.parse_args()

    suffix = f"-{args.variant}" if args.variant else ""
    ltp_dir = REPO / f"build/ltp{suffix}"
    for required in ("ltp.tar.xz", "ltp-runner"):
        if not (ltp_dir / required).is_file():
            raise SystemExit(
                f"Missing {ltp_dir / required}; run 'make ltp'"
                + (f" (tools/ltp/build.sh --variant {args.variant})" if args.variant else "")
                + " first."
            )
    if not (args.esp_dir / "EFI/BOOT/BOOTX64.EFI").is_file():
        raise SystemExit(f"Missing {args.esp_dir}/EFI/BOOT/BOOTX64.EFI; run 'make build' first.")

    tests = parse_list(args.list, args.default_budget)
    if args.tests:
        wanted = set(args.tests.split())
        unknown = wanted - {test.tag for test in tests}
        if unknown:
            raise SystemExit(f"Not in {args.list}: {' '.join(sorted(unknown))}")
        tests = [test for test in tests if test.tag in wanted]
    if args.filter:
        pattern = re.compile(args.filter)
        tests = [test for test in tests if pattern.search(test.tag)]
    if not tests:
        raise SystemExit("No tests selected.")

    target = REPO / "target"
    args.work = target / f"ltp{suffix}"
    args.work.mkdir(parents=True, exist_ok=True)
    args.results = target / f"ltp-results{suffix}.txt"
    args.serial_log_path = target / f"ltp-serial{suffix}.log"
    args.volume = args.work / "volume.raw"
    args.list_name = os.path.relpath(args.list, REPO)
    args.ltp_version = (ltp_dir / "ltp/VERSION").read_text().strip()
    args.kernel_rev = git_rev()

    new_volume(args.volume)

    serve = args.work / "serve"
    shutil.rmtree(serve, ignore_errors=True)
    serve.mkdir()
    (serve / "ltp.tar.xz").symlink_to(ltp_dir / "ltp.tar.xz")
    (serve / "ltp-runner").symlink_to(ltp_dir / "ltp-runner")
    (serve / "setup.sh").symlink_to(REPO / "tests/ltp/setup.sh")
    run = Run(args, tests)
    (serve / "runlist.txt").write_text(
        "".join(
            f"{index}\t{test.tag}\t{test.budget}\t{test.command}\n"
            for index, test in enumerate(run.runnable)
        )
    )

    handler = functools.partial(QuietHandler, directory=str(serve))
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base_url = f"http://10.0.2.2:{server.server_address[1]}"

    def on_signal(signum, frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, on_signal)
    print(
        f"ltp: {len(run.runnable)} tests to run, {len(tests) - len(run.runnable)} skipped; "
        f"results in {args.results}, serial log in {args.serial_log_path}",
        flush=True,
    )
    with open(args.serial_log_path, "wb") as serial_log:
        args.serial_log = serial_log
        try:
            run.run(base_url)
        except KeyboardInterrupt:
            print("ltp: interrupted", file=sys.stderr)
            run.write_results(final=True)
        finally:
            server.shutdown()

    counts = run.counts()
    print("ltp: " + " ".join(f"{name}={counts[name]}" for name in RESULTS) + f" boots={run.boots}", flush=True)
    report = [sys.executable, "-I", str(REPO / "tests/ltp/report.py")]
    subprocess.run(report + (["--variant", args.variant] if args.variant else []), check=False)
    # Test failures are the baseline, not an error; an incomplete run is.
    return 1 if counts["NOTRUN"] else 0


if __name__ == "__main__":
    sys.exit(main())
