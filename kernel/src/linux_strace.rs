//! Ginux's strace: a process whose environment at exec holds
//! `GINUX_STRACE=1`, and every process it starts after that, logs each system
//! call to the kernel log (pid/tid, number, arguments, the path argument if
//! any, and the result). Domains have no ptrace, and images seldom ship
//! strace; this answers "which call fails" without either.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

const SLOTS: usize = 64;

/// One traced process per slot: `(execution instance << 32 | pid) + 1`, so
/// 0 is a free slot. When all are used the oldest is replaced.
static TRACED: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static NEXT: AtomicUsize = AtomicUsize::new(0);
/// Whether any process was ever traced: the one check untraced system calls
/// pay.
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// The environment entry that starts a trace.
pub(crate) const ENVIRONMENT: &[u8] = b"GINUX_STRACE=1\0";

fn key(instance: usize, pid: u32) -> u64 {
    ((instance as u64) << 32 | u64::from(pid)) + 1
}

pub(crate) fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

pub(crate) fn traced(instance: usize, pid: u32) -> bool {
    let key = key(instance, pid);
    TRACED
        .iter()
        .any(|slot| slot.load(Ordering::Relaxed) == key)
}

pub(crate) fn trace(instance: usize, pid: u32) {
    if traced(instance, pid) {
        return;
    }
    let slot = NEXT.fetch_add(1, Ordering::Relaxed) % SLOTS;
    TRACED[slot].store(key(instance, pid), Ordering::Relaxed);
    ACTIVE.store(true, Ordering::Relaxed);
}

/// The argument (0 = rdi) of system call `number` that names a path.
pub(crate) fn path_argument(number: u64) -> Option<usize> {
    match number {
        // open, stat, lstat, access, execve, chdir, rename, mkdir, rmdir,
        // creat, link, unlink, symlink, readlink, chmod, chown, lchown,
        // mknod, statfs, chroot, the path xattr calls.
        2
        | 4
        | 6
        | 21
        | 59
        | 80
        | 82..=90
        | 92
        | 94
        | 133
        | 137
        | 161
        | 188
        | 189
        | 191
        | 192
        | 194
        | 195
        | 197
        | 198 => Some(0),
        // The *at calls: openat, mkdirat, mknodat, fchownat, newfstatat,
        // unlinkat, renameat, linkat, readlinkat, fchmodat, faccessat,
        // utimensat, execveat, statx, openat2, faccessat2, fchmodat2.
        257..=260 | 262..=265 | 267..=269 | 280 | 322 | 332 | 437 | 439 | 452 => Some(1),
        // symlinkat: the new name.
        266 => Some(2),
        _ => None,
    }
}

/// Whether system call `number` may not return to its caller (exec
/// replaces the program, exit ends it): its trace line is written first.
pub(crate) fn logged_before(number: u64) -> bool {
    matches!(number, 59 | 60 | 231 | 322)
}

/// One system call's trace line.
pub(crate) struct Call {
    pub(crate) pid: u32,
    pub(crate) tid: u32,
    pub(crate) number: u64,
    pub(crate) arguments: [u64; 4],
    pub(crate) path: [u8; 128],
    pub(crate) path_length: usize,
}

impl Call {
    pub(crate) fn log(&self, result: Option<u64>) {
        crate::serial_write("ginux: strace ");
        crate::serial_write_u64(u64::from(self.pid));
        crate::serial_write("/");
        crate::serial_write_u64(u64::from(self.tid));
        crate::serial_write(" ");
        crate::serial_write_u64(self.number);
        crate::serial_write("(");
        for (index, argument) in self.arguments.iter().enumerate() {
            if index != 0 {
                crate::serial_write(", ");
            }
            crate::serial_write_hex(*argument);
        }
        if self.path_length != 0 {
            crate::serial_write(", \"");
            crate::serial_write_bytes(&self.path[..self.path_length]);
            crate::serial_write("\"");
        }
        crate::serial_write(")");
        match result {
            // Errors as Linux numbers them (-2 is ENOENT).
            Some(result) if result > u64::MAX - 4096 => {
                crate::serial_write(" = -");
                crate::serial_write_u64(result.wrapping_neg());
            }
            Some(result) => {
                crate::serial_write(" = ");
                crate::serial_write_hex(result);
            }
            None => crate::serial_write(" ..."),
        }
        crate::serial_write("\r\n");
    }
}
