# Linux Test Project (LTP) Compatibility Harness

Ginux's Linux compatibility is driven by the syscall tests of the
[Linux Test Project](https://github.com/linux-test-project/ltp) rather than by
chasing bugs one program at a time. This harness builds LTP statically for
musl, runs each test of `runtest/syscalls` in an Alpine domain on Ginux under
QEMU, and reports one machine-parseable line per test plus failure clusters.

## Progress

| Ginux | Change | Tests run | TPASS | TFAIL | TBROK | TCONF | CRASH | HANG |
|---|---|---|---|---|---|---|---|---|
| `d1f41667` | baseline (below) | 1362 | 41 | 39 | 1181 | 75 | 11 | 9 |
| `62dce194` | `/proc/PID/oom_score_adj` kept per process | 1362 | 1043 | 38 | 130 | 76 | 52 | 17 |
| `de94acb9` | fork EAGAIN, orphan reparenting, EINTR waits, edge-triggered epoll, timer preemption, killed-by-signal status | 1362 | 1045 | 39 | 169 | 76 | 15 | 12 |
| `76719aee` | a fault kills only its process, frame map counts, IPv4 loopback, `/proc/sys` node clash | 1362 | 1072 | 37 | 162 | 75 | 4 | 6 |
| `778dd3d0` | blocking semop/msgsnd/msgrcv, cross-process futexes, sleeping state, pipe capacity, SA_RESTART, CPU time, signals on the timer tick | 1362 | 1146 | 36 | 88 | 76 | 0 | 14 |

A crash takes the whole domain down, so the run reboots for the next test:
the `de94acb9` run needed 23 boots against 68 before, the `76719aee` run 6,
and the `778dd3d0` run went through in one. Its 14 hangs are LTP's own
30-second timeouts (no guest wedges): epoll_wait01/08/11/12/16,
pselect01/_64, select02 and select04 (select and epoll_pwait still return
no events rather than waiting for a signal), poll02 and ppoll01 (fixed
since), futex_wait03, futex_wake03 and rt_tgsigqueueinfo01. Its remaining crashes
are access04, fchownat03, madvise10, madvise11, mq_open01, move_mount03,
munmap01, readv01, sendmmsg01, shmat01, statmount03 and waitid05 to
waitid08; its hangs are bind04 (flaky), epoll_wait01, epoll_wait12,
io_setup02, pipeio_1/2/5/7, prot_hsymlinks, recvmmsg01, select04 and
semctl01. Most hangs are a test looping on a value Ginux reports wrongly,
not a scheduling stall. Results of a full run are kept in
`target/ltp-baseline/` (not committed).

## Baseline (2026-10-31)

Ginux at `d1f41667` (no kernel change since), LTP 20260930,
`tests/ltp/syscalls.list`, QEMU/KVM with one vCPU and 6 GiB, domain
`alpine:3.22`:

| Run | Tests run | TPASS | TFAIL | TBROK | TCONF | TWARN | CRASH | HANG | SKIP | Boots | Time |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Baseline | 1362 | 41 | 39 | 1181 | 75 | 6 | 11 | 9 | 190 | 17 | 16 min |
| Diagnostic variant (`no-oom-protection`) | 1362 | 1047 | 39 | 127 | 76 | 6 | 53 | 14 | 190 | 64 | 53 min |

The 190 skips: 181 tests need a loop block device, 6 need kernel modules,
and 3 did not build under musl. Two baseline runs gave the same result for
every test. The variant is not fully repeatable: in an interrupted earlier
variant run `bind04` wedged the guest, here it passed, so state left by
earlier tests in the same boot matters.

One bug dominates the baseline: **1136 of the 1181 TBROKs are LTP's library
failing its own setup** because `/proc/PID/oom_score_adj` does not keep the
value written to it. Every new-API LTP test stops there. The diagnostic
variant (see below) skips that one check: then **1047 tests pass (77% of
those run)**, and the remaining failures are the real work list.

### Failure clusters

Counts are tests, from the baseline (B) and the variant (V); the logs are
`target/ltp/logs/NAME.log` (and `target/ltp-no-oom-protection/logs`).

1. **`oom_score_adj` does not stick** (B 1136). LTP writes -1000 to
   `/proc/<lib pid>/oom_score_adj`, reads 0 back and gives up. Ginux must
   keep the value (-1000..1000, per process) or refuse the write (`EACCES`),
   which LTP tolerates. `getpid01`:
   ```text
   tst_tmpdir.c:308: TINFO: Using /tmp/ltp/LTP_getNAgHIC as tmpdir (ramfs filesystem)
   tst_memutils.c:176: TBROK: oom_score_adj = 0, but expect -1000.
   ```
2. **A fault or failed fork in one process takes the whole domain down**
   (all CRASH results: B 11, V 53). *Status:* a fault now kills only the
   faulting process (`643d714b`), and pages have a map count, so munmap,
   copy-on-write, exec and exit no longer free a page another process still
   maps (the cause of the "snapshot failed at stage 8" and "completion failed
   at stage 162" crashes). The memory/fork/wait slice runs without a crash. The kernel cannot complete or
   unwind the child ("runtime fork preparation failed at stage 13/11",
   "runtime child completion failed at stage 14/17/162", "live registry
   refresh snapshot failed at stage 8"), resumes the parent in the wrong
   context ("Linux resume FS mismatch", "scheduled process return failed"),
   the domain's init faults and the domain is marked failed. In four tests
   the runner (the test program's parent) exits with status 255 instead
   (`fork04`, `ptrace07`, `recvfrom01`, `rt_tgsigqueueinfo01`). Triggers:
   `abort()` in old-API tests (`getres[gu]id02/03*`: `SIGABRT` does not
   terminate, musl's `a_crash` executes `hlt` and takes #GP), tests that
   fork several children (`waitpid06`..`13`, `kill06/08/10`, `execve05`,
   `fork07`, `futex_wake03`, `semctl01`), and user page faults in tests
   (`chmod01`, `epoll_wait01`, `select04`, `sendfile07`, `shmat01`,
   `waitid05/06`, `madvise10/11`, `munmap01`). After such a crash the domain
   cannot be started again until reboot ("Linux process registry setup
   failed"). `waitpid06` (V):
   ```text
   ginux: runtime fork preparation failed at stage 13
   ginux: runtime child completion failed at stage 13
   ginux: scheduled process return failed child/parent/resumed/dispatch: 3 1 0 0
   ginux: Linux user fault vector/error/address/rip:14 6 18446744071616660459 4406038
   ginux: Linux init execution failed; domain marked failed
   ```
3. **Root cannot change credentials** (B 15, V 38): `setuid`, `seteuid`,
   `setgid`, `setreuid`, `setregid`, `setgroups`, `setfsgid` return `EPERM`
   for uid 0. The compatibility ledger lists these as Policy-denied, but
   tests (and daemons) that drop to `nobody` cannot run: `access01..03`,
   `creat04`, `execve02`, `msgget02`, `ptrace02`, `readlink01`, `semget02`,
   `kill05`, `mlockall02/03`, `getgroups03`, `fcntl18`, `dirtyc0w`. `access01`
   (V): `access01.c:256: TBROK: setuid(65534) failed: EPERM (1)`.
4. **A signal-killed child is reported as a normal exit with status 128+N**,
   and **a parent's `alarm` reaches its child** (V 27 at exactly 30 s; B
   `kill12`). `waitpid` gives `WIFEXITED` with 137 for `SIGKILL`, 139 for
   `SIGSEGV`; LTP prints "Child returned with 137/142". LTP's 30 s overall
   timeout is an `alarm` in the library's parent, yet the test child dies of
   `SIGALRM` (142): `alarm` is inherited across `fork` or delivered to the
   wrong process. `kill12` (B): `signal error: unexpected exit number
   returned when signal sent was 9, the status of the process is 35072`.
5. **Blocking calls are not interrupted by signals** (V 5, then the 30 s
   timeout of cluster 4): `msgrcv05/06`, `msgsnd05/06`, `semop03` get
   `EAGAIN` where `EINTR` is expected. `msgsnd05`: `TFAIL: msgsnd(24,
   0x44c040, 1024, 0) expected EINTR: EAGAIN/EWOULDBLOCK (11)`.
6. **`TST_CHECKPOINT` wake-ups between processes time out** (V 17):
   `tst_checkpoint_wake(0, 1, 10000) failed: ETIMEDOUT (110)` in `pause01/02`,
   `epoll_wait05/15`, `execve04`, `fcntl15`, `mincore04`, `pipe13`,
   `process_vm_readv02/03`, `tgkill01`. LTP's checkpoints are futexes in a
   `MAP_SHARED` file page; the waking parent never finds the waiting child
   (cross-process futex keys, or the child never reached the wait).
7. **Missing `/proc` files** (B 29, more in V): `/proc/sys/kernel/tainted`
   (19 tests with `.taint_check` stop before running), `/proc/mounts` and
   `/proc/self/mounts` (7-9), `/proc/sys/user/max_user_namespaces` (7), and
   single ones (`kernel/pid_max`, `shmmax`, `sem`, `msgmni`, `printk`,
   `core_pattern`, `io_uring_disabled`, `fs/pipe-max-size`, `/proc/modules`).
   Without the harness's `KCONFIG_SKIP_CHECK=1` another 95 tests stop at
   "Cannot parse kernel .config"; Ginux could publish `/proc/config.gz`.
   `bpf_prog04`:
   `tst_taint.c:43: TBROK: Failed to open FILE '/proc/sys/kernel/tainted'
   for reading: ENOENT (2)`.
8. **POSIX record locks are per process; no leases** (V 20, B 10 of them):
   `F_GETLK` does not see another process's lock and `F_SETLK` takes an
   already locked region (`fcntl11/15/17/19/20/21/22` and `_64`);
   `F_SETLEASE` and `F_GETOWN_EX` return `EINVAL` (`fcntl23/27/31/32`).
   `fcntl11`: `TFAIL: fcntl11.c:156: lock type is wrong should be F_RDLCK is
   F_UNLCK`.
9. **Hangs: a spinning process is never preempted for signals or timers**
   (B 9, V 14). Five to ten tests wedge the guest until the host watchdog
   reboots it (`sigrelse01`: 153 million `read` calls returning `EAGAIN`;
   `setsid01`, `rename14`, `sendmsg02`, `setitimer01`, `setrlimit06`,
   `times03`, `epoll_wait08`, `perf_event_open02`, `prot_hsymlinks`); the
   kernel only logs "Linux runtime exceeded sixty seconds". `pipeio_1/2/5/7`
   hit the runner's 60 s budget and `pipeio_3/4/6/8` warn "Timed out waiting
   for child processes to exit". Related: `sleep 2` in the domain returns at
   once.
10. **Socket errno mapping** (6): operations on a non-socket descriptor
    return `EBADF` instead of `ENOTSOCK` (`recv01`, `send01`, `sendto01`,
    `recvfrom01`, `listen01`); `MSG_ERRQUEUE` gives `EINVAL` instead of
    `EAGAIN`; `SIOCGIFCONF` gives `ENOTTY` (`sockioctl01`). `recv01`:
    `TFAIL: recv01.c:124: invalid socket ; returned -1 (expected -1), errno 9
    (expected 88)`.

Smaller ones: setting the clock is Policy-denied (`clock_settime01..04`,
`clock_adjtime01/02`, `settimeofday01`, `stime01`: `EPERM`), `mprotect` and
`mmap` `EINVAL` cases (`mprotect02/04`, `signal06`, `mmap03/18`),
`tst_get_bad_addr` failing (`clock_adjtime02`, `symlink03`), `msync02`
reading stale data, guarded-buffer corruption in `chmod01`, `renameat2`
flags (`EINVAL`), `removexattr` returning `ENODATA` for `ENOENT`,
`open(O_DIRECTORY)` succeeding on a FIFO (`fcntl07`: LTP's cleanup then
fails with `ENOTDIR`), and `clone` with `CLONE_PARENT` (`EINVAL`). TCONF is
mostly expected: no libnuma in the static build (20), `ramfs` lacks leases,
no hugetlbfs, 32-bit-only syscalls.

`target/ltp-report.txt` lists every cluster with its tests;
`tests/ltp/report.py --variant no-oom-protection` does the same for the
variant.

## Running it

Requirements: Docker (the build runs in a pinned Alpine container), QEMU with
KVM, and OVMF.

```sh
make ltp            # tools/ltp/build.sh: build LTP into build/ltp (once, ~5 min)
make test-ltp OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd \
    OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
```

`make test-ltp` builds Ginux (`make build`) and runs `tests/qemu/ltp.sh`. To
keep a running VM's `build/esp` untouched, build and boot a separate image:
`make test-ltp ESP_DIR=build/esp-ltp`. `TMPDIR` defaults to `target/tmp`.
The full list takes about 16 minutes on KVM today (most tests stop at
once; the diagnostic variant below takes 53). Select tests with

```sh
tests/qemu/ltp.sh --tests "abort01 accept01"     # by name
tests/qemu/ltp.sh --filter '^(open|read)'        # by regular expression
LTP_FILTER='^mmap' make test-ltp                 # the same from make
```

`tests/qemu/ltp.sh --help` lists the other options (default budget, memory,
domain image, `--variant`).

Outputs:

| File | Contents |
|---|---|
| `target/ltp-results.txt` | summary counts, then `NAME RESULT SECONDS DETAIL` per test, in list order; rewritten after every test |
| `target/ltp-report.txt` | results by LTP source directory, failure symptoms, errnos, Ginux kernel diagnostics, crashes and hangs |
| `target/ltp/logs/NAME.log` | the console output of each test, kernel diagnostics included |
| `target/ltp-serial.log` | the whole serial console of every boot |

While running, the harness prints the same line per test to stdout:

```text
LTP abort01 TBROK 0.02 exit=2
LTP pipeio_1 HANG 60.04 guest-timeout 60s
LTP getdents01 CRASH 0.42 domain down: ginux: Linux init execution failed; domain marked failed
```

| Result | Meaning |
|---|---|
| `TPASS` | exit status 0 |
| `TFAIL`, `TBROK`, `TWARN`, `TCONF` | LTP's exit status bits (2 TBROK, 1 TFAIL, 4 TWARN, 32 TCONF, in that precedence); also `TBROK` if the test was killed by a signal (`killed by signal N`, or an exit status of 128 or more, which is how Ginux reports a signal death today), could not be executed (126, 127), or the runner lost its status |
| `HANG` | over its time budget: `guest-timeout` (the runner killed it), `ltp-timeout` (LTP's own timeout fired: "Test killed! (timeout?)"), or `host-watchdog` (the guest stopped reporting; QEMU was rebooted) |
| `CRASH` | the domain, the kernel or QEMU went down during the test; QEMU was rebooted |
| `SKIP` | marked skipped in the list, with the reason as detail |
| `NOTRUN` | not reached (the run was interrupted or gave up) |

The driver exits non-zero only when the run is incomplete; test failures are
the baseline, not an error.

## How it works

- `tools/ltp/build.sh` downloads a pinned LTP release (SHA-256 checked, cached
  in `build/ltp-cache`), and in an `alpine:3.22` container pinned by digest
  builds `lib`, `libs`, `testcases/lib` and every directory of
  `testcases/kernel/syscalls` (plus the few `runtest/syscalls` entries that
  live elsewhere: `dirtyc0w*`, `dirtypipe`, `msgstress01`, `pipeio`,
  `prot_hsymlinks`). Each directory builds on its own with `make -k`, so a
  test that does not build under musl is skipped, not patched
  (`build/ltp/build-failures.txt`: today `fmtmsg01`, `timer_create01`,
  `timer_create03`). The build tree stays in `target/ltp-build`, so reruns are
  incremental. Outputs: the stripped tree `build/ltp/ltp`, `ltp.tar.gz`, and
  `ltp.tar.xz` (21 MB instead of 226 MB: the static binaries share most of
  their code, which only xz's large window sees), which is what the domain
  downloads.
- Binaries are **static-pie** (`-static-pie -fPIE`), not fixed-address
  `-static`: Ginux runs a file written at runtime only if it is position
  independent; its fixed-address (ET_EXEC) loader accepts only tiny programs
  (5 code pages, 8 pages in all).
- `tests/qemu/ltp.sh` runs `tests/ltp/driver.py`, which boots Ginux with
  `tools/qemu/run.sh` (6 GiB, KVM, a fresh sparse volume in `target/ltp`),
  creates domain `ltp` from `alpine:3.22`, and serves the tree, the runner and
  the run list over HTTP on a free port (the guest reaches it at 10.0.2.2).
  In the domain's shell it fetches `tests/ltp/setup.sh`, which downloads and
  unpacks the tree into `/opt/ltp` (about 4 s) and execs the runner.
- The runner, `tools/ltp/ltp-runner.c` (a static-pie C program built with
  LTP), runs each test as `sh -c "exec COMMAND"` in its own process group with
  stdin on `/dev/null`, `TMPDIR=/tmp/ltp`, `LTPROOT=/opt/ltp`, and
  `LTP_RUNTIME_MUL=0.1` (race and stress tests loop for a tenth of their
  runtime). It brackets each test's output with `@@LTP BEGIN` and
  `@@LTP END INDEX TAG STATUS MILLISECONDS LEFTOVER` and enforces the test's
  budget **in the guest** with `alarm`: at the budget it kills the test's
  process group. Afterwards it kills whatever the test left running (found
  through `/proc`, reported as `leftover=N`) and empties `TMPDIR`.
- The driver watches the console. If the kernel panics, the domain goes down
  (`domain marked failed`, `Linux init exited`), the runner exits, QEMU
  exits, or a test runs past its budget plus 30 s without an `END` (the guest
  is wedged), it records `CRASH` or `HANG` for the running test, kills QEMU
  by PID, boots again (about 10 s: the volume keeps the domain and the OCI
  cache), and continues with the next test. It always reboots rather than
  restarting the domain: after a crash the kernel cannot start the domain
  again ("Linux process registry setup failed"). It gives up after three
  boots in a row that run no test, or after 400 boots.

### Ginux limitations the harness works around

These are findings in their own right:

- `execve` in a domain's init process fails with `ENOENT`, so the runner
  cannot replace the init shell (`exec`); it runs as its child.
- busybox `timeout` takes the whole domain down (its vfork-and-daemonize
  watcher; "Linux runtime cleanup failed"), and the next domain start then
  fails until reboot. The runner enforces budgets itself.
- `alarm` does not interrupt the runner while a test spins on the CPU (the
  kernel only logs "Linux runtime exceeded sixty seconds"), and a few tests
  wedge the guest entirely; the host watchdog covers both.
- Fixed-address static executables written at runtime are rejected
  (`ENOEXEC`, "Linux exec of runtime file rejected"), hence static-pie.

## The run list

`tests/ltp/syscalls.list` has one line per `runtest/syscalls` entry, in LTP's
order:

```text
# comment
TAG COMMAND [ARG...]                  run, default budget (60 s)
TAG COMMAND [ARG...]  # budget=N      run, allowing N seconds
!TAG COMMAND [ARG...] # REASON        skipped: recorded as SKIP with REASON
```

`tools/ltp/make-list.py` regenerates it from the build. Notes starting with
`auto:` are generated: a budget of LTP's timeout (30 s plus the test's
`.timeout`) plus a tenth of its `.runtime` plus 15 s, rounded up to 30 s,
when that exceeds 60 s; and skips for tests that did not build, that need a
loop block device (`.needs_device`, `.mount_device`, `.format_device`,
`.all_filesystems`, or `tst_acquire_device()` in old-API tests: LTP makes and
mounts a filesystem image), or that need loadable kernel modules. Lines with
any other note are curated by hand and survive regeneration, so to skip a
test permanently write `!TAG COMMAND  # reason`. To run the device tests
again (once Ginux has loop devices), delete the rule from `SKIP_RULES` in
`tools/ltp/make-list.py`.

Tests of Policy-denied operations (changing credentials, setting the clock;
see [LINUX-COMPATIBILITY.md](LINUX-COMPATIBILITY.md)) are deliberately not
skipped yet: whether a domain's root may drop to `nobody` is a decision, and
many programs need it. Once decided, mark them with a curated reason, e.g.
`!clock_settime01 clock_settime01  # setting the clock is denied in domains`.

To investigate one test, run it alone (`--tests NAME`) and read
`target/ltp/logs/NAME.log`; the kernel's diagnostics are interleaved with
the test's output.

To add tests from another LTP runtest file, build its directories in
`tools/ltp/container-build.sh` and append its entries to a new list file;
`--list FILE` runs it.

To move to a new LTP release, change `ltp_version` and `ltp_sha256` in
`tools/ltp/build.sh`, run `make ltp`, then `tools/ltp/make-list.py`.

## Diagnostic variant: past the oom_score_adj blocker

`tools/ltp/build.sh --variant no-oom-protection` builds a second copy in
`build/ltp-no-oom-protection` whose LTP library skips the `oom_score_adj`
self-check that stops every new-API test today (two no-op functions linked
first; `tools/ltp/no-oom-protection.c`; LTP's sources are untouched). Run it
with `tests/qemu/ltp.sh --variant no-oom-protection`; its outputs carry the
suffix (`target/ltp-results-no-oom-protection.txt`, ...). It shows what fails
once that one bug is fixed; it is not the baseline.
