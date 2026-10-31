// Checks the shared-memory path Wayland clients use for wl_shm pools: a
// memfd is mapped MAP_SHARED in two processes, its descriptor travels over
// an AF_UNIX socket as SCM_RIGHTS, writes through either mapping are seen
// by the other and by pread without msync, and the pool can grow with
// ftruncate and be mapped again with its old contents intact.
use std::ffi::c_void;
use std::ptr;

const PAGE: usize = 4096;
const POOL: usize = 3 * PAGE;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
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
    fn memfd_create(name: *const u8, flags: u32) -> i32;
    fn ftruncate(fd: i32, length: i64) -> i32;
    fn mmap(address: *mut u8, length: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(address: *mut u8, length: usize) -> i32;
    fn pread(fd: i32, buffer: *mut u8, count: usize, offset: i64) -> isize;
    fn socketpair(domain: i32, kind: i32, protocol: i32, fds: *mut i32) -> i32;
    fn sendmsg(fd: i32, message: *const MessageHeader, flags: i32) -> isize;
    fn recvmsg(fd: i32, message: *mut MessageHeader, flags: i32) -> isize;
    fn read(fd: i32, buffer: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, buffer: *const c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
    fn fork() -> i32;
    fn recv(fd: i32, buffer: *mut c_void, length: usize, flags: i32) -> isize;
    fn poll(fds: *mut PollFd, count: u64, timeout: i32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
    fn _exit(code: i32) -> !;
}

fn map(fd: i32, length: usize) -> *mut u8 {
    let address = unsafe { mmap(ptr::null_mut(), length, 3, 1, fd, 0) };
    assert!(address as isize != -1, "mmap MAP_SHARED failed");
    address
}

fn fill(base: *mut u8, length: usize, seed: u8) {
    for index in 0..length {
        unsafe { base.add(index).write((index as u8).wrapping_mul(7) ^ seed) };
    }
}

fn first_mismatch(base: *const u8, length: usize, seed: u8) -> Option<usize> {
    (0..length).find(|index| unsafe { base.add(*index).read() } != (*index as u8).wrapping_mul(7) ^ seed)
}

fn send_fd(socket: i32, fd: i32) {
    let mut byte = [b'F'];
    let mut iov = IoVec { base: byte.as_mut_ptr(), length: 1 };
    // cmsghdr { len: u64, level: i32, type: i32 } followed by the descriptor.
    let mut control = [0_u8; 24];
    control[..8].copy_from_slice(&20_u64.to_ne_bytes());
    control[8..12].copy_from_slice(&1_i32.to_ne_bytes());
    control[12..16].copy_from_slice(&1_i32.to_ne_bytes());
    control[16..20].copy_from_slice(&fd.to_ne_bytes());
    let message = MessageHeader {
        name: ptr::null_mut(),
        name_length: 0,
        iov: &mut iov,
        iov_length: 1,
        control: control.as_mut_ptr(),
        control_length: control.len(),
        flags: 0,
    };
    assert_eq!(unsafe { sendmsg(socket, &message, 0) }, 1, "sendmsg SCM_RIGHTS failed");
}

fn receive_fd(socket: i32) -> i32 {
    let mut byte = [0_u8];
    let mut iov = IoVec { base: byte.as_mut_ptr(), length: 1 };
    let mut control = [0_u8; 24];
    let mut message = MessageHeader {
        name: ptr::null_mut(),
        name_length: 0,
        iov: &mut iov,
        iov_length: 1,
        control: control.as_mut_ptr(),
        control_length: control.len(),
        flags: 0,
    };
    assert_eq!(unsafe { recvmsg(socket, &mut message, 0) }, 1, "recvmsg failed");
    assert!(message.control_length >= 20, "no SCM_RIGHTS control message");
    i32::from_ne_bytes(control[16..20].try_into().unwrap())
}

// Passes the memfd to this same process and checks both descriptors map
// the same pages, before any second process is involved.
fn same_process(fd: i32) -> u64 {
    let mut sockets = [0_i32; 2];
    assert_eq!(unsafe { socketpair(1, 1, 0, sockets.as_mut_ptr()) }, 0, "socketpair failed");
    send_fd(sockets[0], fd);
    let received = receive_fd(sockets[1]);
    eprintln!("memfdshare: received descriptor {received} for {fd}");
    let first = map(fd, POOL);
    let second = map(received, POOL);
    fill(first, POOL, 0x11);
    let errors = match first_mismatch(second, POOL, 0x11) {
        Some(index) => {
            eprintln!("memfdshare: second mapping differs at byte {index}");
            1
        }
        None => 0,
    };
    unsafe { munmap(first, POOL) };
    unsafe { munmap(second, POOL) };
    unsafe { close(received) };
    unsafe { close(sockets[0]) };
    unsafe { close(sockets[1]) };
    errors
}

fn child(socket: i32) -> i32 {
    let fd = receive_fd(socket);
    eprintln!("memfdshare: child received descriptor {fd}");
    let pool = map(fd, POOL);
    if let Some(index) = first_mismatch(pool, POOL, 0x5a) {
        eprintln!("child: parent pattern differs at byte {index}");
        return 1;
    }
    fill(pool, POOL, 0xa5);
    let mut ack = [b'A'];
    if unsafe { write(socket, ack.as_ptr().cast(), 1) } != 1 {
        eprintln!("memfdshare: child could not acknowledge");
        return 1;
    }
    eprintln!("memfdshare: child acknowledged");
    // Wait for the parent to grow the pool, then map the larger size.
    unsafe { read(socket, ack.as_mut_ptr().cast(), 1) };
    let grown = map(fd, 2 * POOL);
    if let Some(index) = first_mismatch(grown, POOL, 0xa5) {
        eprintln!("child: grown pool lost old contents at byte {index}");
        return 1;
    }
    if let Some(index) = first_mismatch(unsafe { grown.add(POOL) }, POOL, 0x3c) {
        eprintln!("child: grown tail written by parent differs at byte {index}");
        return 1;
    }
    unsafe { munmap(pool, POOL) };
    unsafe { munmap(grown, 2 * POOL) };
    0
}

fn main() {
    let fd = unsafe { memfd_create(b"wl_shm\0".as_ptr(), 1) };
    assert!(fd >= 0, "memfd_create failed");
    assert_eq!(unsafe { ftruncate(fd, POOL as i64) }, 0, "ftruncate failed");
    let mut errors = same_process(fd);
    let mut sockets = [0_i32; 2];
    assert_eq!(unsafe { socketpair(1, 1, 0, sockets.as_mut_ptr()) }, 0, "socketpair failed");
    let pool = map(fd, POOL);
    fill(pool, POOL, 0x5a);
    let pid = unsafe { fork() };
    if pid == 0 {
        unsafe { close(sockets[0]) };
        unsafe { close(fd) };
        let code = child(sockets[1]);
        unsafe { _exit(code) };
    }
    unsafe { close(sockets[1]) };
    send_fd(sockets[0], fd);
    eprintln!("memfdshare: parent sent descriptor");
    let mut ack = [0_u8];
    let mut received = -1;
    // Wait the way Wayland programs do: poll, then a non-blocking read.
    for _ in 0..20 {
        let mut fds = [PollFd { fd: sockets[0], events: 1, revents: 0 }];
        let ready = unsafe { poll(fds.as_mut_ptr(), 1, 1000) };
        received = unsafe { recv(sockets[0], ack.as_mut_ptr().cast(), 1, 0x40) };
        if received == 1 {
            break;
        }
        eprintln!(
            "memfdshare: parent poll {ready}/{:#x}, recv {received} ({})",
            fds[0].revents,
            std::io::Error::last_os_error()
        );
    }
    assert_eq!(received, 1, "no ack from child");
    if let Some(index) = first_mismatch(pool, POOL, 0xa5) {
        eprintln!("parent: child's writes not visible in parent mapping at byte {index}");
        errors += 1;
    }
    let mut copy = vec![0_u8; POOL];
    let read_back = unsafe { pread(fd, copy.as_mut_ptr(), POOL, 0) };
    if read_back != POOL as isize || first_mismatch(copy.as_ptr(), POOL, 0xa5).is_some() {
        eprintln!("parent: pread does not see the shared pages ({read_back})");
        errors += 1;
    }
    assert_eq!(unsafe { ftruncate(fd, 2 * POOL as i64) }, 0, "ftruncate grow failed");
    let grown = map(fd, 2 * POOL);
    fill(unsafe { grown.add(POOL) }, POOL, 0x3c);
    unsafe { write(sockets[0], ack.as_ptr().cast(), 1) };
    let mut status = 0;
    unsafe { waitpid(pid, &mut status, 0) };
    if status != 0 {
        eprintln!("child failed with status {status:#x}");
        errors += 1;
    }
    println!("memfdshare errors={errors}");
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
