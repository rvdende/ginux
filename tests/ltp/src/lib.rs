//! The Ginux LTP harness: runs the Linux Test Project syscall tests in an
//! Alpine domain on Ginux under QEMU (docs/LTP.md).
//!
//! The test target `tests/ltp.rs` turns each entry of the run list into one
//! libtest trial. One QEMU session runs the selected tests in list order on
//! a background thread ([`session`]) and hands each trial its result over a
//! channel.
//!
//! The session boots Ginux with `tools/qemu/run.sh`, starts an Alpine
//! domain, serves the LTP tree, the guest runner and the run list over HTTP
//! ([`http`]; the guest reaches the host at 10.0.2.2) and starts the runner
//! (`tools/ltp/ltp-runner.c`) from the domain's shell through
//! `tests/ltp/setup.sh`. The runner enforces each test's time budget inside
//! the guest and brackets each test's console output with `@@LTP BEGIN/END`
//! markers ([`console`]).
//!
//! If the kernel panics, the domain goes down, QEMU exits, or a test runs
//! past its budget plus a grace period without the runner reporting (the
//! guest is wedged), the test is recorded as CRASH or HANG, QEMU is killed
//! and rebooted, and the run continues with the next test. A crash leaves
//! the kernel unable to start the domain again (the process registry is not
//! recovered), so the session always reboots rather than restarting the
//! domain.

pub mod baseline;
pub mod classify;
pub mod config;
pub mod console;
pub mod http;
pub mod list;
pub mod progress;
pub mod session;
pub mod verdict;

pub use verdict::Verdict;
