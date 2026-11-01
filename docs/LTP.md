# Linux Test Project (LTP) Compatibility Harness

Ginux's Linux compatibility is driven by the syscall tests of the
[Linux Test Project](https://github.com/linux-test-project/ltp) rather than by
chasing bugs one program at a time. This harness builds LTP statically for
musl, runs each test of `runtest/syscalls` in an Alpine domain on Ginux under
QEMU, and reports one machine-parseable line per test plus failure clusters.

## Progress

| Ginux | Change | Tests run | TPASS | TFAIL | TBROK | TCONF | TWARN | CRASH | HANG |
|---|---|---|---|---|---|---|---|---|---|
| `d1f41667` | baseline (below) | 1362 | 41* | 39 | 1181 | 75 | 6 | 11 | 9 |
| `62dce194` | `/proc/PID/oom_score_adj` kept per process | 1362 | 1043* | 38 | 130 | 76 | 6 | 52 | 17 |
| `de94acb9` | fork EAGAIN, orphan reparenting, EINTR waits, edge-triggered epoll, timer preemption, killed-by-signal status | 1362 | 394 | 233 | 554 | 126 | 28 | 15 | 12 |
| `76719aee` | a fault kills only its process, frame map counts, IPv4 loopback, `/proc/sys` node clash | 1362 | 397 | 231 | 542 | 139 | 43 | 4 | 6 |
| `778dd3d0` | blocking semop/msgsnd/msgrcv, cross-process futexes, sleeping state, pipe capacity, SA_RESTART, CPU time, signals on the timer tick | 1362 | 420 | 240 | 504 | 141 | 43 | 0 | 14 |
| `18f44c93` | POSIX record locks, epoll_wait waits outside init, MAP_SHARED file pages shared | 1362 | 388 | 256 | 441 | 170 | 92 | 0 | 15 |
| `7c6e1149` | `/proc/PID/maps`, clock_gettime into any writable page | 1362 | 471 | 261 | 431 | 173 | 10 | 0 | 16 |
| `68bb7d48` | compat batch (`/dev/null`, pipe sizes, stream writes, status fields, connect errors) | 1362 | 492 | 264 | 405 | 174 | 10 | 1 | 16 |
| `bdeb9c12` | growing socket table, FUTEX_REQUEUE, nanosleep restarts, /proc lists every process, shared anonymous memory, killed sleepers run first, right-sized process lists | 1362 | 503 | 265 | 380 | 181 | 10 | 0 | 23 |
| `e35668d6` | /proc/PID directories and names, PageEntry, pause() sleeping, killed processes run first, restart deadlines in a pruned list | 1362 | 507 | 272 | 376 | 181 | 10 | 0 | 16 |
| `62aaf7da` | credentials and file owners (`user-switching=true` for the LTP domain), permission checks, hard links, overlay symlinks in path walks, Linux path errors, unshare of user/mount namespaces | 1362 | 627 | 263 | 228 | 214 | 13 | 0 | 17 |
| `250c427b` | domain mounts (read-only, nodev, umount2), device files, PATH_MAX paths and namei-style symlink walks, renameat2 exchange; every process parks in its blocking calls (`chdir04` fixed after this run) | 1362 | 644 | 257 | 212 | 222 | 14 | 0 | 13 |
| `22941a5a` | the FUTEX_WAKE fast path wakes other processes' waits (most "tst_checkpoint_wait failed" breaks), SIGKILL ends a parked process | 1362 | 659 | 261 | 193 | 222 | 13 | 0 | 14 |
| `114ced1f` | O_TMPFILE, openat2, fchmodat2, shared eventfd/timerfd files, waits without full snapshots; first run of the Rust harness (`tests/ltp`, baseline 430 known failures) | 1362 | 711 | 244 | 170 | 221 | 13 | 0 | 3 |
| `27ccc587` | descriptor tables banked as whole arrays, open-file ids assigned at fork, lock-free kernel frame checks | 1362 | 720 | 235 | 170 | 222 | 13 | 0 | 2 |

\* Counted with the exit status alone, which overstated passes (below).
The later rows are rescored from each run's saved console logs with LTP's
own rule (`classify` in `tests/ltp/src/classify.rs`): a test that printed any
TBROK, TFAIL or TWARN counts as that, and TCONF only when nothing passed.
Each row ran with that commit's changes on top of its parent. The drop at
`18f44c93` is the shared result page starting to work: tests whose
failures were lost before now report them.

**Pass counts before 2026-11-01 were overstated by about 600.** The LTP
library counts results in a MAP_SHARED page of a /dev/shm file and derives
the test's exit status from it. Ginux gave each process its own copy of
such a page, so results from the test process never reached the library's
process, which then exited 0: in the `778dd3d0` run 204 tests that
printed TFAIL and 416 that printed TBROK (60 of them an anonymous mmap
with fd 0 refused, about 60 "Test haven't reported results" or "bad magic"
from the lost page) were counted as passes. The harness now classifies by the printed results when
the exit status claims success, and shared mappings of a file now map the
file's own pages.

The `bdeb9c12` run no longer runs out of memory near its end (futex
and fork-heavy tests used to leave processes and ~380 MB behind, so every
exec after futex_cmp_requeue01 failed). Its extra hangs are tests that now
get further (futex_wait02/03, futex_wake03), and wait401 and waitpid10,
which pass alone but hung after killed processes outlived their tests;
killed processes now run first and die, and pause() sleeps properly
(after the run: signal01 passes, kill11 fails instead of breaking).

In the `e35668d6` run rename14 wedged the guest: with pause() sleeping
properly, its parent pauses for SIGALRM while two children rename in busy
loops, and nothing else got the CPU (not even LTP's own timeout). pause()
went back to returning EINTR after one yield (signal01 hangs again), and
init's killed-first pick is limited to sleeping processes and orphans init
adopted, since a running process with a live parent may be one a fork
transaction runs nested on the kernel stack. Both wait for the scheduler
loop.

A crash takes the whole domain down, so the run reboots for the next test:
the `de94acb9` run needed 23 boots against 68 before, the `76719aee` run 6,
and the `778dd3d0` run went through in one. The `7c6e1149` run's 16 hangs:
connect01 and fork14 stopped the guest reporting (the host watchdog
rebooted it); the rest are LTP's own 30-second timeouts with the guest
still alive: epoll_wait01/08/11/12/16, pselect01/_64, select02 and
select04 (select and epoll_pwait still return no events rather than
waiting for a signal), poll02, ppoll01, pause01, tgkill01 and
rt_tgsigqueueinfo01. Results of a
full run are kept in `target/ltp-baseline/` (not committed).

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
3. ~~**Root cannot change credentials**~~ (B 15, V 38; fixed 2026-11-01):
   each process now has real, effective, saved and filesystem ids and
   supplementary groups (`crates/credentials`), files have owners, and opens,
   creates, removals, chmod, chown, utimes, access(2) and exec check them.
   Root may switch ids only in a domain set `user-switching=true`, the one
   flag that grants it (`linux_user::user_switching_allowed`); the LTP
   harness sets it. `setgroups03` still fails: LTP built for musl expects
   `setgroups(33, ...)` to fail because musl's `NGROUPS` is 32, while
   Linux (and Ginux) allow 65536.
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
make ltp            # tools/ltp/build.sh: build LTP into build/ltp (~5 min once; then a no-op)
make test-ltp OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd \
    OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd
```

`make test-ltp` builds Ginux (`make build`) and runs `tests/qemu/ltp.sh`,
which builds and runs the Rust harness in `tests/ltp` (below). To keep a
running VM's `build/esp` untouched, build and boot a separate image:
`make test-ltp ESP_DIR=build/esp-ltp`. `TMPDIR` defaults to `target/tmp`.
The full list takes about 25 minutes on KVM today. Select tests with

```sh
tests/qemu/ltp.sh --tests "abort01 accept01"     # by name
tests/qemu/ltp.sh --filter '^(open|read)'        # by regular expression
tests/qemu/ltp.sh accept                         # libtest's filter: names containing "accept"
tests/qemu/ltp.sh -- --exact accept01 -q         # libtest's arguments, after --
LTP_FILTER='^mmap' make test-ltp                 # the same from make (LTP_ARGS for the rest)
```

`tests/qemu/ltp.sh --help` lists the other options (`--list FILE`,
`--variant`, `--esp-dir`, budgets, memory, the domain image, `--strict`,
`--update-baseline`); each sets one of the environment variables the
harness reads.

### The harness

`tests/ltp` is a standalone crate (its own workspace, like `userland/`).
Its test target `ltp` uses [libtest-mimic](https://crates.io/crates/libtest-mimic)
to make each entry of the run list one trial, named by its tag, so cargo
runs it and libtest's arguments select tests:

```sh
cargo test --manifest-path tests/ltp/Cargo.toml --test ltp -- accept          # names containing accept
cargo test --manifest-path tests/ltp/Cargo.toml --test ltp -- --exact accept01
cargo test --manifest-path tests/ltp/Cargo.toml --test ltp -- --list          # list; boots nothing
cargo test --manifest-path tests/ltp/Cargo.toml --test ltp -- --ignored       # the tests the list skips
LTP_VARIANT=probe GINUX_ESP_DIR=build/esp-probe LTP_LIST=/path/probe.list \
    cargo test --manifest-path tests/ltp/Cargo.toml --test ltp -- -q
make ltp-check                                   # the harness's fmt, clippy and unit tests
```

The settings come from the environment (`tests/ltp/src/config.rs`):
`LTP_LIST`, `LTP_TESTS`, `LTP_FILTER`, `LTP_VARIANT`, `GINUX_ESP_DIR`,
`LTP_BUDGET`, `LTP_GRACE`, `LTP_BETWEEN_TESTS`, `LTP_SETUP_TIMEOUT`,
`LTP_MAX_BOOTS`, `GINUX_MEMORY`, `LTP_DOMAIN_MEMORY_MIB`, `LTP_IMAGE`,
`LTP_BASELINE`, `LTP_STRICT=1` and `LTP_UPDATE_BASELINE=1` (relative paths
are taken from the repository root; `ltp.sh` resolves them from where it
runs). `--strict` and `--update-baseline` also work as arguments of the
test binary. The harness applies libtest's selection before it boots, so
the guest runs only the selected tests. They all share one QEMU session,
which runs on a background thread in list order; the trials run one at a
time (`--test-threads` is forced to 1), each waiting for its result.
`ltp.sh` builds the test binary and runs it directly rather than through
`cargo test`, so a SIGTERM to its PID or a Ctrl-C reaches it: it stops
QEMU, writes the final results, prints the summary and exits 1.

Each test is one libtest line:

```text
test abort01      ... ignored (known failure: TFAIL)
test access01     ... ok
test add_key05    ... ignored (TCONF: ...)
test cachestat01  ... ignored (SKIP: auto: needs a loop block device (mkfs and mount))
test fork14       ... FAILED
```

| Result | Trial |
|---|---|
| `TPASS` | ok |
| `TCONF`, `SKIP` | ignored, with the first TCONF message or the list's reason |
| `TFAIL`, `TBROK`, `TWARN`, `HANG`, `CRASH` | ignored as `known failure: RESULT` if the baseline lists the test; otherwise failed, with the result, its detail and the last 40 lines of the test's log |
| `NOTRUN` | failed (not reached) |

On a terminal a status line shows what runs now and for how long (the boot
step, such as the first domain start pulling Alpine, or the current test),
the results so far and the elapsed time, e.g.
`[412/1362] running fork14 12s | pass 380 fail 20 broken 9 conf 3 | 6m41s`.
It follows libtest's open `test NAME ... ` line (or is a line of its own
when stdout is not the terminal), and messages such as a reboot print above
it. Without a terminal the boot steps print as `ltp:` lines instead.

### The baseline

`tests/ltp/baseline.txt` lists the tests known not to pass, one
`NAME RESULT` per line (TFAIL, TBROK, TWARN, HANG or CRASH; tests the list
skips and TCONFs are not in it). A listed test that fails again is ignored
as a known failure, whatever its result now; a failure of any other test is
a regression and fails the run, so a full run with no regressions exits 0
(failing trials or an incomplete run exit 101). A listed test that passes is
a pass, and the run ends by printing `newly passing: NAME...` (and
`no longer failing (now TCONF): NAME...`) so the baseline can be updated:
`tests/qemu/ltp.sh --update-baseline` (`LTP_UPDATE_BASELINE=1`) rewrites it
from the run (failing tests that ran get their new result, tests that
passed or were TCONF are dropped, tests that did not run keep their
entries). `--strict` (`LTP_STRICT=1`) ignores the baseline: every failure
fails the run. `LTP_BASELINE=FILE` uses another file, e.g. for a variant.

Outputs:

| File | Contents |
|---|---|
| `target/ltp-results.txt` | summary counts, then `NAME RESULT SECONDS DETAIL` per test, in list order; rewritten after every test |
| `target/ltp-report.txt` | results by LTP source directory, failure symptoms, errnos, Ginux kernel diagnostics, crashes and hangs |
| `target/ltp/logs/NAME.log` | the console output of each test, kernel diagnostics included |
| `target/ltp-serial.log` | the whole serial console of every boot |

The results file's detail says why, e.g.

```text
abort01 TBROK 0.02 exit=2
pipeio_1 HANG 60.04 guest-timeout 60s
getdents01 CRASH 0.42 domain down: ginux: Linux init execution failed; domain marked failed
```

| Result | Meaning |
|---|---|
| `TPASS` | exit status 0 |
| `TFAIL`, `TBROK`, `TWARN`, `TCONF` | LTP's exit status bits (2 TBROK, 1 TFAIL, 4 TWARN, 32 TCONF, in that precedence); also `TBROK` if the test was killed by a signal (`killed by signal N`, or an exit status of 128 or more, which is how Ginux reports a signal death today), could not be executed (126, 127), or the runner lost its status |
| `HANG` | over its time budget: `guest-timeout` (the runner killed it), `ltp-timeout` (LTP's own timeout fired: "Test killed! (timeout?)"), or `host-watchdog` (the guest stopped reporting; QEMU was rebooted) |
| `CRASH` | the domain, the kernel or QEMU went down during the test; QEMU was rebooted |
| `SKIP` | marked skipped in the list, with the reason as detail |
| `NOTRUN` | not reached (the run was interrupted or gave up) |

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
  incremental, and a rerun with nothing changed returns at once: stamps in
  `build/ltp` (`.tree-inputs`, `.runner-inputs`) hash the release, builder
  image, variant and `tools/ltp` scripts, and Docker starts only when one of
  them changed (only for the runner when just `ltp-runner.c` did; `--force`
  rebuilds anyway). Outputs: the stripped tree `build/ltp/ltp`, `ltp.tar.gz`, and
  `ltp.tar.xz` (21 MB instead of 226 MB: the static binaries share most of
  their code, which only xz's large window sees), which is what the domain
  downloads.
- Binaries are **static-pie** (`-static-pie -fPIE`), not fixed-address
  `-static`: Ginux runs a file written at runtime only if it is position
  independent; its fixed-address (ET_EXEC) loader accepts only tiny programs
  (5 code pages, 8 pages in all).
- The harness's session (`tests/ltp/src/session.rs`) boots Ginux with
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
- The session watches the console. If the kernel panics, the domain goes down
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

Tests of Policy-denied operations (setting the clock, loading modules; see
[LINUX-COMPATIBILITY.md](LINUX-COMPATIBILITY.md)) are deliberately not
skipped yet. Changing credentials is decided: a domain's root may switch
users only with `user-switching=true`, which the LTP domain sets. Mark a
denied operation's tests with a curated reason, e.g.
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
