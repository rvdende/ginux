// Every kind of descriptor above 1024, as Linux lets RLIMIT_NOFILE reach
// past it: with the low part of the table full, each kind is made (and so
// lands above 1024), moved to 2000 and up with dup2, and used there: epoll
// watching a high descriptor, select past FD_SETSIZE, poll with more than
// 64 pollfds, a fork child sharing a high eventfd, SCM_RIGHTS, flock,
// F_SETFL, /proc/self/fdinfo and close_range. Prints one line per check;
// exits 1 if any failed.
use std::ffi::c_void;

const O_RDONLY: i32 = 0;
const O_WRONLY: i32 = 1;
const O_RDWR: i32 = 2;
const O_CREAT: i32 = 0o100;
const O_TRUNC: i32 = 0o1000;
const O_NONBLOCK: i32 = 0o4000;
const O_CLOEXEC: i32 = 0o2000000;
const O_TMPFILE: i32 = 0o20200000;
const F_DUPFD: i32 = 0;
const F_GETFD: i32 = 1;
const F_GETFL: i32 = 3;
const F_SETFL: i32 = 4;
const POLLIN: i16 = 1;
const EPOLLIN: u32 = 1;
const EPOLL_CTL_ADD: i32 = 1;
const SIGUSR1: i32 = 10;
const RLIMIT_NOFILE: i32 = 7;
const IN_CREATE: u32 = 0x100;
const FAN_MARK_ADD: u32 = 1;
const FAN_OPEN: u64 = 0x20;
const AT_FDCWD: i32 = -100;
const LOCK_EX: i32 = 2;
const LOCK_UN: i32 = 8;
const AF_UNIX: i32 = 1;
const AF_INET: i32 = 2;
const SOCK_STREAM: i32 = 1;
const SOCK_DGRAM: i32 = 2;
const SOL_SOCKET: i32 = 1;
const SCM_RIGHTS: i32 = 1;
const MSG_DONTWAIT: i32 = 0x40;
const SYS_RT_SIGPROCMASK: i64 = 14;
const SYS_SIGNALFD4: i64 = 289;
const SYS_USERFAULTFD: i64 = 323;
const SYS_IO_URING_SETUP: i64 = 425;
const SYS_PIDFD_OPEN: i64 = 434;
const SYS_CLOSE_RANGE: i64 = 436;
const UFFDIO_API: u64 = 0xc018_aa3f;
const EBADF: i32 = 9;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(C, packed)]
struct EpollEvent {
    events: u32,
    data: u64,
}

#[repr(C)]
struct IoVec {
    base: *mut u8,
    length: usize,
}

#[repr(C)]
struct MessageHeader {
    name: *mut u8,
    name_length: u32,
    iov: *mut IoVec,
    iov_length: usize,
    control: *mut u8,
    control_length: usize,
    flags: i32,
}

extern "C" {
    fn open(path: *const std::ffi::c_char, flags: i32, ...) -> i32;
    fn close(fd: i32) -> i32;
    fn dup2(fd: i32, target: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn read(fd: i32, buffer: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, buffer: *const c_void, count: usize) -> isize;
    fn pread(fd: i32, buffer: *mut c_void, count: usize, offset: i64) -> isize;
    fn poll(fds: *mut PollFd, count: u64, timeout: i32) -> i32;
    fn select(count: i32, read: *mut u64, write: *mut u64, except: *mut u64, timeout: *mut i64) -> i32;
    fn setrlimit(resource: i32, limit: *const [u64; 2]) -> i32;
    fn eventfd(initial: u32, flags: i32) -> i32;
    fn timerfd_create(clock: i32, flags: i32) -> i32;
    fn timerfd_settime(fd: i32, flags: i32, new: *const [i64; 4], old: *mut [i64; 4]) -> i32;
    fn epoll_create1(flags: i32) -> i32;
    fn epoll_ctl(epoll: i32, operation: i32, fd: i32, event: *mut EpollEvent) -> i32;
    fn epoll_wait(epoll: i32, events: *mut EpollEvent, count: i32, timeout: i32) -> i32;
    fn inotify_init1(flags: i32) -> i32;
    fn inotify_add_watch(fd: i32, path: *const u8, mask: u32) -> i32;
    fn fanotify_init(flags: u32, event_flags: u32) -> i32;
    fn fanotify_mark(fd: i32, flags: u32, mask: u64, directory: i32, path: *const u8) -> i32;
    fn memfd_create(name: *const u8, flags: u32) -> i32;
    fn mkdir(path: *const u8, mode: u32) -> i32;
    fn mkfifo(path: *const u8, mode: u32) -> i32;
    fn unlink(path: *const u8) -> i32;
    fn readlink(path: *const u8, buffer: *mut u8, size: usize) -> isize;
    fn socket(domain: i32, kind: i32, protocol: i32) -> i32;
    fn socketpair(domain: i32, kind: i32, protocol: i32, fds: *mut i32) -> i32;
    fn sendmsg(fd: i32, message: *const MessageHeader, flags: i32) -> isize;
    fn recvmsg(fd: i32, message: *mut MessageHeader, flags: i32) -> isize;
    fn pipe(fds: *mut i32) -> i32;
    fn flock(fd: i32, operation: i32) -> i32;
    fn ioctl(fd: i32, request: u64, ...) -> i32;
    fn syscall(number: i64, ...) -> i64;
    fn getpid() -> i32;
    fn kill(pid: i32, signal: i32) -> i32;
    fn fork() -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
    fn __errno_location() -> *mut i32;
}

fn errno() -> i32 {
    unsafe { *__errno_location() }
}

struct Checks {
    failures: u32,
}

impl Checks {
    fn check(&mut self, name: &str, ok: bool) {
        if ok {
            println!("highfd: ok {name}");
        } else {
            println!("highfd: FAIL {name} (errno {})", errno());
            self.failures += 1;
        }
    }
}

fn readable(fd: i32, timeout: i32) -> bool {
    let mut pollfd = PollFd { fd, events: POLLIN, revents: 0 };
    unsafe { poll(&mut pollfd, 1, timeout) == 1 && pollfd.revents & POLLIN != 0 }
}

/// `directory/name` as a C string.
fn path(directory: &str, name: &str) -> Vec<u8> {
    let mut path = format!("{directory}{name}").into_bytes();
    path.push(0);
    path
}

fn main() {
    // The directory to work in (made if absent): /tmp/highfd-files by
    // default (the workload test builds this program as /tmp/highfd).
    let directory = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/highfd-files".to_string());
    let base = path(&directory, "");
    let fifo_path = path(&directory, "/fifo");
    let file_path = path(&directory, "/file");
    let created_path = path(&directory, "/created");
    let mut checks = Checks { failures: 0 };
    let limit = [4096_u64, 4096];
    checks.check("setrlimit 4096", unsafe { setrlimit(RLIMIT_NOFILE, &limit) } == 0);
    // Fill the table below 1024, so new descriptors land above it.
    let mut first_filler = -1;
    let mut last_filler = -1;
    while last_filler < 1023 {
        let fd = unsafe { open(b"/dev/null\0".as_ptr().cast(), O_RDONLY) };
        if fd < 0 {
            break;
        }
        if first_filler < 0 {
            first_filler = fd;
        }
        last_filler = fd;
    }
    checks.check("fill the table below 1024", last_filler == 1023);

    let usr1 = 1_u64 << (SIGUSR1 - 1);
    unsafe {
        syscall(SYS_RT_SIGPROCMASK, 0_i64, &usr1 as *const u64, 0_i64, 8_i64);
        mkdir(base.as_ptr(), 0o700);
        unlink(fifo_path.as_ptr());
        unlink(created_path.as_ptr());
        mkfifo(fifo_path.as_ptr(), 0o600);
    }
    let mut ring = [0_u32; 30];
    let mut pipe_ends = [-1_i32; 2];
    let kinds: Vec<(&str, i32)> = unsafe {
        vec![
            ("eventfd", eventfd(0, 0)),
            ("timerfd", timerfd_create(1, 0)),
            ("epoll", epoll_create1(0)),
            ("signalfd", syscall(SYS_SIGNALFD4, -1_i64, &usr1 as *const u64, 8_i64, 0_i64) as i32),
            ("inotify", inotify_init1(0)),
            ("fanotify", fanotify_init(0, O_RDONLY as u32)),
            ("pidfd", syscall(SYS_PIDFD_OPEN, getpid() as i64, 0_i64) as i32),
            ("memfd", memfd_create(b"highfd\0".as_ptr(), 0)),
            ("O_TMPFILE", open(base.as_ptr().cast(), O_TMPFILE | O_RDWR, 0o600)),
            ("fifo", open(fifo_path.as_ptr().cast(), O_RDWR)),
            ("userfaultfd", syscall(SYS_USERFAULTFD, O_CLOEXEC as i64) as i32),
            ("io_uring", syscall(SYS_IO_URING_SETUP, 4_i64, ring.as_mut_ptr()) as i32),
            (
                "regular file",
                open(file_path.as_ptr().cast(), O_RDWR | O_CREAT | O_TRUNC, 0o600),
            ),
            ("pipe", if pipe(pipe_ends.as_mut_ptr()) == 0 { pipe_ends[0] } else { -1 }),
            ("socket", socket(AF_INET, SOCK_DGRAM, 0)),
        ]
    };
    let mut fds = Vec::new();
    for (index, (name, fd)) in kinds.iter().enumerate() {
        checks.check(&format!("{name} made above 1024 (fd {fd})"), *fd >= 1024);
        let target = 2000 + index as i32;
        let moved = unsafe { dup2(*fd, target) } == target;
        unsafe { close(*fd) };
        checks.check(&format!("dup2 {name} to {target}"), moved);
        checks.check(&format!("F_GETFD {name} at {target}"), unsafe { fcntl(target, F_GETFD) } == 0);
        fds.push(target);
    }
    let [efd, tfd, epfd, sfd, ifd, nfd, pfd, mfd, xfd, ffd, ufd, _rfd, file, _pipe, _socket] =
        fds[..]
    else {
        unreachable!()
    };

    let mut value = 1_u64;
    let value_ptr = &mut value as *mut u64 as *mut c_void;
    checks.check("eventfd write", unsafe { write(efd, value_ptr, 8) } == 8);
    checks.check("eventfd readable", readable(efd, 0));
    let spec = [0_i64, 0, 0, 1_000_000];
    checks.check("timerfd settime", unsafe { timerfd_settime(tfd, 0, &spec, std::ptr::null_mut()) } == 0);
    checks.check(
        "timerfd expires",
        readable(tfd, 1000) && unsafe { read(tfd, value_ptr, 8) } == 8 && value >= 1,
    );
    let mut event = EpollEvent { events: EPOLLIN, data: 0xfeed };
    checks.check("epoll_ctl watches fd 2000", unsafe { epoll_ctl(epfd, EPOLL_CTL_ADD, efd, &mut event) } == 0);
    let mut got = EpollEvent { events: 0, data: 0 };
    let waited = unsafe { epoll_wait(epfd, &mut got, 1, 1000) };
    let data = got.data;
    checks.check("epoll_wait reports fd 2000", waited == 1 && data == 0xfeed);
    let copy = unsafe { fcntl(epfd, F_DUPFD, 2500) };
    checks.check("F_DUPFD epoll to 2500", copy == 2500);
    checks.check("epoll_wait through 2500", unsafe { epoll_wait(copy, &mut got, 1, 1000) } == 1);

    let mut set = vec![0_u64; 4096 / 64];
    set[efd as usize / 64] |= 1 << (efd % 64);
    let mut timeout = [1_i64, 0];
    let ready = unsafe {
        select(efd + 1, set.as_mut_ptr(), std::ptr::null_mut(), std::ptr::null_mut(), timeout.as_mut_ptr())
    };
    checks.check(
        "select with nfds past 1024",
        ready == 1 && set[efd as usize / 64] >> (efd % 64) & 1 == 1,
    );
    let mut pollfds: Vec<PollFd> = (0..1500).map(|_| PollFd { fd: -1, events: 0, revents: 0 }).collect();
    pollfds[0] = PollFd { fd: efd, events: POLLIN, revents: 0 };
    pollfds[700] = PollFd { fd: first_filler, events: POLLIN, revents: 0 };
    pollfds[1499] = PollFd { fd: tfd, events: POLLIN, revents: 0 };
    let ready = unsafe { poll(pollfds.as_mut_ptr(), 1500, 1000) };
    checks.check(
        "poll with 1500 pollfds",
        ready == 2 && pollfds[0].revents == POLLIN && pollfds[700].revents == POLLIN,
    );
    checks.check("eventfd read", unsafe { read(efd, value_ptr, 8) } == 8 && value == 1);

    let mut information = [0_u8; 128];
    checks.check(
        "signalfd reads SIGUSR1",
        unsafe { kill(getpid(), SIGUSR1) } == 0
            && readable(sfd, 1000)
            && unsafe { read(sfd, information.as_mut_ptr() as *mut c_void, 128) } == 128
            && information[0] as i32 == SIGUSR1,
    );
    checks.check(
        "inotify watch",
        unsafe { inotify_add_watch(ifd, base.as_ptr(), IN_CREATE) } >= 0,
    );
    unsafe { close(open(created_path.as_ptr().cast(), O_CREAT | O_WRONLY, 0o600)) };
    checks.check("inotify event", readable(ifd, 1000));
    checks.check(
        "fanotify mark",
        unsafe { fanotify_mark(nfd, FAN_MARK_ADD, FAN_OPEN, AT_FDCWD, base.as_ptr()) } == 0,
    );
    checks.check("pidfd of a running process", !readable(pfd, 0));
    let child = unsafe { fork() };
    if child == 0 {
        // The child's eventfd at 2000 is the parent's open file.
        let one = 1_u64;
        let written = unsafe { write(efd, &one as *const u64 as *const c_void, 8) };
        unsafe { _exit(if written == 8 { 0 } else { 1 }) };
    }
    let mut status = -1;
    unsafe { waitpid(child, &mut status, 0) };
    checks.check("fork child writes fd 2000", status == 0 && readable(efd, 0));

    let mut buffer = [0_u8; 16];
    let buffer_ptr = buffer.as_mut_ptr() as *mut c_void;
    checks.check(
        "memfd",
        unsafe { write(mfd, b"memfd".as_ptr() as *const c_void, 5) } == 5
            && unsafe { pread(mfd, buffer_ptr, 5, 0) } == 5
            && &buffer[..5] == b"memfd",
    );
    checks.check(
        "O_TMPFILE",
        unsafe { write(xfd, b"tmp".as_ptr() as *const c_void, 3) } == 3
            && unsafe { pread(xfd, buffer_ptr, 3, 0) } == 3,
    );
    checks.check(
        "fifo",
        unsafe { write(ffd, b"x".as_ptr() as *const c_void, 1) } == 1
            && unsafe { read(ffd, buffer_ptr, 1) } == 1
            && buffer[0] == b'x',
    );
    let mut api = [0xaa_u64, 0, 0];
    checks.check("userfaultfd UFFDIO_API", unsafe { ioctl(ufd, UFFDIO_API, api.as_mut_ptr()) } == 0);
    checks.check(
        "regular file write and flock",
        unsafe { write(file, b"regular".as_ptr() as *const c_void, 7) } == 7
            && unsafe { flock(file, LOCK_EX) } == 0
            && unsafe { flock(file, LOCK_UN) } == 0,
    );
    checks.check(
        "F_SETFL O_NONBLOCK at 2000",
        unsafe { fcntl(efd, F_SETFL, O_NONBLOCK) } == 0
            && unsafe { fcntl(efd, F_GETFL) } & O_NONBLOCK != 0,
    );
    let info_path = format!("/proc/self/fdinfo/{efd}\0");
    let info = unsafe { open(info_path.as_ptr().cast(), O_RDONLY) };
    checks.check("/proc/self/fdinfo/2000", info >= 0 && unsafe { read(info, buffer_ptr, 16) } > 0);
    unsafe { close(info) };
    let link_path = format!("/proc/self/fd/{file}\0");
    let mut link = [0_u8; 64];
    checks.check(
        "/proc/self/fd link",
        unsafe { readlink(link_path.as_ptr(), link.as_mut_ptr(), 63) } > 0,
    );

    // SCM_RIGHTS: a high descriptor sent, received above 1024.
    let mut pair = [-1_i32; 2];
    checks.check("socketpair", unsafe { socketpair(AF_UNIX, SOCK_STREAM, 0, pair.as_mut_ptr()) } == 0);
    let mut byte = [b'r'];
    let mut iov = IoVec { base: byte.as_mut_ptr(), length: 1 };
    let mut control = [0_u8; 24];
    control[..8].copy_from_slice(&20_u64.to_ne_bytes());
    control[8..12].copy_from_slice(&SOL_SOCKET.to_ne_bytes());
    control[12..16].copy_from_slice(&SCM_RIGHTS.to_ne_bytes());
    control[16..20].copy_from_slice(&file.to_ne_bytes());
    let mut message = MessageHeader {
        name: std::ptr::null_mut(),
        name_length: 0,
        iov: &mut iov,
        iov_length: 1,
        control: control.as_mut_ptr(),
        control_length: control.len(),
        flags: 0,
    };
    checks.check("SCM_RIGHTS sends 2012", unsafe { sendmsg(pair[0], &message, 0) } == 1);
    control = [0; 24];
    message.control_length = control.len();
    let received = if unsafe { recvmsg(pair[1], &mut message, MSG_DONTWAIT) } == 1 {
        i32::from_ne_bytes(control[16..20].try_into().unwrap())
    } else {
        -1
    };
    checks.check(
        "SCM_RIGHTS receives above 1024",
        received >= 1024 && unsafe { pread(received, buffer_ptr, 7, 0) } == 7,
    );

    let last = 2000 + kinds.len() as i32 - 1;
    checks.check(
        "close_range 2000..",
        unsafe { syscall(SYS_CLOSE_RANGE, 2000_i64, u32::MAX as i64, 0_i64) } == 0,
    );
    checks.check(
        "closed",
        unsafe { fcntl(2000, F_GETFD) } == -1 && errno() == EBADF && unsafe { fcntl(last, F_GETFD) } == -1,
    );
    checks.check("dup2 at the soft limit is EBADF", unsafe { dup2(0, 4096) } == -1 && errno() == EBADF);
    println!("highfd failures={}", checks.failures);
    std::process::exit(if checks.failures == 0 { 0 } else { 1 });
}
