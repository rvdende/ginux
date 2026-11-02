use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{control_abi, linux_process, memory};

const PAGE_SIZE: usize = 4096;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;
const FRAME_CAPACITY: usize = 320;
const SEMAPHORE_CAPACITY: usize = 250;
const MESSAGE_CAPACITY: usize = 4048;
const WALK_LIMIT: usize = 262_144;
pub(crate) const SEM_VALUE_MAX: u16 = 32_767;

struct SysvIpcRuntimeOwner {
    locks: [AtomicBool; INSTANCE_LIMIT],
    root_addresses: [AtomicU64; INSTANCE_LIMIT],
    root_generations: [AtomicU32; INSTANCE_LIMIT],
    attachment_root_addresses: [AtomicU64; INSTANCE_LIMIT],
    attachment_root_generations: [AtomicU32; INSTANCE_LIMIT],
    next_ids: [AtomicU32; INSTANCE_LIMIT],
    semaphore_root_addresses: [AtomicU64; INSTANCE_LIMIT],
    semaphore_root_generations: [AtomicU32; INSTANCE_LIMIT],
    next_semaphore_ids: [AtomicU32; INSTANCE_LIMIT],
    message_root_addresses: [AtomicU64; INSTANCE_LIMIT],
    message_root_generations: [AtomicU32; INSTANCE_LIMIT],
    next_message_ids: [AtomicU32; INSTANCE_LIMIT],
    semaphore_processes: [UnsafeCell<SemaphoreProcesses>; INSTANCE_LIMIT],
}

// SAFETY: an instance's `semaphore_processes` is only reached through a
// `Guard` holding that instance's lock.
unsafe impl Sync for SysvIpcRuntimeOwner {}

/// Which semaphore value a blocked `semop` waits on: to rise far enough for
/// a decrement, or (`zero`) to reach zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SemaphoreBlock {
    pub(crate) number: u16,
    pub(crate) zero: bool,
}

/// A process waiting in `semop`. The record outlives the call's restarts and
/// goes when the call completes, fails, times out or is interrupted, or the
/// process exits.
#[derive(Clone, Copy)]
pub(crate) struct SemaphoreWait {
    pub(crate) pid: u32,
    pub(crate) id: u32,
    pub(crate) block: SemaphoreBlock,
    /// Elapsed nanoseconds after which `semtimedop` gives up.
    pub(crate) deadline: Option<u64>,
}

/// A process's `SEM_UNDO` adjustment of one value, applied when it exits.
#[derive(Clone, Copy)]
struct SemaphoreUndo {
    pid: u32,
    id: u32,
    number: u16,
    adjustment: i32,
}

struct SemaphoreProcesses {
    waits: Vec<SemaphoreWait>,
    undo: Vec<SemaphoreUndo>,
    /// Processes waiting in msgsnd or msgrcv, with the queue they wait on.
    message_waits: Vec<(u32, u32)>,
}

impl SemaphoreProcesses {
    const EMPTY: Self = Self {
        waits: Vec::new(),
        undo: Vec::new(),
        message_waits: Vec::new(),
    };
}

static SYSV_IPC_RUNTIME: SysvIpcRuntimeOwner = SysvIpcRuntimeOwner {
    locks: [const { AtomicBool::new(false) }; INSTANCE_LIMIT],
    root_addresses: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    root_generations: [const { AtomicU32::new(0) }; INSTANCE_LIMIT],
    attachment_root_addresses: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    attachment_root_generations: [const { AtomicU32::new(0) }; INSTANCE_LIMIT],
    next_ids: [const { AtomicU32::new(1) }; INSTANCE_LIMIT],
    semaphore_root_addresses: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    semaphore_root_generations: [const { AtomicU32::new(0) }; INSTANCE_LIMIT],
    next_semaphore_ids: [const { AtomicU32::new(1) }; INSTANCE_LIMIT],
    message_root_addresses: [const { AtomicU64::new(0) }; INSTANCE_LIMIT],
    message_root_generations: [const { AtomicU32::new(0) }; INSTANCE_LIMIT],
    next_message_ids: [const { AtomicU32::new(1) }; INSTANCE_LIMIT],
    semaphore_processes: [const { UnsafeCell::new(SemaphoreProcesses::EMPTY) }; INSTANCE_LIMIT],
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error {
    Exists,
    Invalid,
    NoEntry,
    NoMemory,
    /// The domain's segment limit (shmmni) is reached.
    NoSpace,
    Range,
    WouldBlock,
    TooBig,
    Fault,
}

#[derive(Clone, Copy)]
pub(crate) struct SegmentInfo {
    pub(crate) key: i32,
    pub(crate) size: u64,
    pub(crate) mode: u16,
    pub(crate) creator_pid: u32,
    pub(crate) last_pid: u32,
    pub(crate) attachments: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct SemaphoreSetInfo {
    pub(crate) key: i32,
    pub(crate) count: u64,
    pub(crate) mode: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct SemaphoreOperation {
    pub(crate) number: u16,
    pub(crate) operation: i16,
    pub(crate) flags: u16,
}

#[derive(Clone, Copy)]
pub(crate) struct MessageQueueInfo {
    pub(crate) key: i32,
    pub(crate) mode: u16,
    pub(crate) bytes: u64,
    pub(crate) messages: u64,
    pub(crate) byte_limit: u64,
    pub(crate) last_sender: u32,
    pub(crate) last_receiver: u32,
}

#[derive(Clone, Copy)]
pub(crate) struct PosixQueueInfo {
    pub(crate) id: u32,
    pub(crate) max_messages: u64,
    pub(crate) max_message_size: u64,
    pub(crate) messages: u64,
    pub(crate) created: bool,
}

#[repr(C)]
struct MessageQueue {
    next_queue: memory::FrameLease,
    id: u32,
    key: i32,
    mode: u16,
    _reserved: u16,
    byte_limit: u64,
    bytes: u64,
    messages: u64,
    head: memory::FrameLease,
    tail: memory::FrameLease,
    last_sender: u32,
    last_receiver: u32,
    posix: u8,
    linked: u8,
    name_length: u16,
    max_messages: u32,
    max_message_size: u32,
    open_references: u64,
    name: [u8; 256],
}

#[repr(C)]
struct MessagePage {
    next_message: memory::FrameLease,
    next_page: memory::FrameLease,
    message_type: i64,
    size: u64,
    used: u16,
    _padding: [u8; 6],
    bytes: [u8; MESSAGE_CAPACITY],
}

#[derive(Clone, Copy)]
#[repr(C)]
struct Semaphore {
    value: u16,
    _reserved: u16,
    last_pid: u32,
    waiting_increase: u32,
    waiting_zero: u32,
}

#[repr(C)]
struct SemaphorePage {
    next_set: memory::FrameLease,
    next_page: memory::FrameLease,
    id: u32,
    key: i32,
    count: u64,
    mode: u16,
    values_used: u16,
    creator_pid: u32,
    last_pid: u32,
    _padding: [u8; 4],
    values: [Semaphore; SEMAPHORE_CAPACITY],
}

#[repr(C)]
struct SegmentPage {
    next_segment: memory::FrameLease,
    next_page: memory::FrameLease,
    id: u32,
    key: i32,
    size: u64,
    mode: u16,
    marked_for_removal: u8,
    _reserved: u8,
    creator_pid: u32,
    last_pid: u32,
    attachments: u64,
    frames_used: u16,
    _padding: [u8; 6],
    frames: [memory::FrameLease; FRAME_CAPACITY],
}

#[repr(C)]
struct Attachment {
    next: memory::FrameLease,
    segment: memory::FrameLease,
    address: u64,
    length: u64,
    pid: u32,
}

const _: () = assert!(core::mem::size_of::<SegmentPage>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<Attachment>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<SemaphorePage>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<MessageQueue>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<MessagePage>() == PAGE_SIZE);

struct Guard {
    instance: usize,
}

impl Guard {
    fn acquire() -> Option<Self> {
        let instance = linux_process::current_ipc_instance();
        let lock = SYSV_IPC_RUNTIME.locks.get(instance)?;
        while lock
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Some(Self { instance })
    }
}

impl Guard {
    fn semaphore_processes(&mut self) -> &mut SemaphoreProcesses {
        // SAFETY: the guard holds this instance's lock, which serializes all
        // access to its semaphore process state.
        unsafe { &mut *SYSV_IPC_RUNTIME.semaphore_processes[self.instance].get() }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        SYSV_IPC_RUNTIME.locks[self.instance].store(false, Ordering::Release);
    }
}

fn root(
    addresses: &[AtomicU64; INSTANCE_LIMIT],
    generations: &[AtomicU32; INSTANCE_LIMIT],
    instance: usize,
) -> Option<memory::FrameLease> {
    memory::FrameLease::from_parts(
        addresses[instance].load(Ordering::Acquire),
        generations[instance].load(Ordering::Acquire),
    )
}

fn publish_root(
    addresses: &[AtomicU64; INSTANCE_LIMIT],
    generations: &[AtomicU32; INSTANCE_LIMIT],
    instance: usize,
    value: Option<memory::FrameLease>,
) {
    let value = value.unwrap_or(memory::FrameLease::EMPTY);
    generations[instance].store(value.generation(), Ordering::Release);
    addresses[instance].store(value.address(), Ordering::Release);
}

fn segment_page(frame: memory::FrameLease) -> Option<&'static SegmentPage> {
    Some(unsafe { &*(frame.direct_map_address()? as *const SegmentPage) })
}

fn segment_page_mut(frame: memory::FrameLease) -> Option<&'static mut SegmentPage> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut SegmentPage) })
}

fn attachment(frame: memory::FrameLease) -> Option<&'static Attachment> {
    Some(unsafe { &*(frame.direct_map_address()? as *const Attachment) })
}

fn attachment_mut(frame: memory::FrameLease) -> Option<&'static mut Attachment> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut Attachment) })
}

fn semaphore_page(frame: memory::FrameLease) -> Option<&'static SemaphorePage> {
    Some(unsafe { &*(frame.direct_map_address()? as *const SemaphorePage) })
}

fn semaphore_page_mut(frame: memory::FrameLease) -> Option<&'static mut SemaphorePage> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut SemaphorePage) })
}

fn message_queue(frame: memory::FrameLease) -> Option<&'static MessageQueue> {
    Some(unsafe { &*(frame.direct_map_address()? as *const MessageQueue) })
}

fn message_queue_mut(frame: memory::FrameLease) -> Option<&'static mut MessageQueue> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut MessageQueue) })
}

fn message_page(frame: memory::FrameLease) -> Option<&'static MessagePage> {
    Some(unsafe { &*(frame.direct_map_address()? as *const MessagePage) })
}

fn message_page_mut(frame: memory::FrameLease) -> Option<&'static mut MessagePage> {
    Some(unsafe { &mut *(frame.direct_map_address()? as *mut MessagePage) })
}

fn allocate_zeroed() -> Option<memory::FrameLease> {
    let [frame] = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL)?;
    let Some(address) = frame.direct_map_address() else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return None;
    };
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE) };
    Some(frame)
}

fn find_segment(
    instance: usize,
    id: u32,
) -> Option<(memory::FrameLease, Option<memory::FrameLease>)> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        instance,
    );
    let mut previous = None;
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let page = segment_page(frame)?;
        if page.id == id {
            return Some((frame, previous));
        }
        previous = current;
        current = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
    }
    None
}

fn find_key(instance: usize, key: i32) -> Option<memory::FrameLease> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        instance,
    );
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let page = segment_page(frame)?;
        if page.key == key && page.marked_for_removal == 0 {
            return Some(frame);
        }
        current = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
    }
    None
}

fn info(page: &SegmentPage) -> SegmentInfo {
    SegmentInfo {
        key: page.key,
        size: page.size,
        mode: page.mode,
        creator_pid: page.creator_pid,
        last_pid: page.last_pid,
        attachments: page.attachments,
    }
}

fn release_segment_chain(first: memory::FrameLease) -> bool {
    let mut current = Some(first);
    for _ in 0..WALK_LIMIT {
        let Some(frame) = current else { return true };
        let Some(page) = segment_page(frame) else {
            return false;
        };
        let next = (page.next_page != memory::FrameLease::EMPTY).then_some(page.next_page);
        for data in page.frames[..usize::from(page.frames_used)].iter().copied() {
            if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[data]) {
                return false;
            }
        }
        if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]) {
            return false;
        }
        current = next;
    }
    false
}

fn unlink_and_release(
    instance: usize,
    frame: memory::FrameLease,
    previous: Option<memory::FrameLease>,
) -> bool {
    let Some(page) = segment_page(frame) else {
        return false;
    };
    let next = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
    if let Some(previous) = previous {
        let Some(previous) = segment_page_mut(previous) else {
            return false;
        };
        previous.next_segment = next.unwrap_or(memory::FrameLease::EMPTY);
    } else {
        publish_root(
            &SYSV_IPC_RUNTIME.root_addresses,
            &SYSV_IPC_RUNTIME.root_generations,
            instance,
            next,
        );
    }
    release_segment_chain(frame)
}

pub(crate) fn get_or_create(
    key: i32,
    size: u64,
    mode: u16,
    create: bool,
    exclusive: bool,
    pid: u32,
    ids: SegmentIds,
) -> Result<u32, Error> {
    let SegmentIds { requested, limit } = ids;
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    if key != 0 {
        if let Some(frame) = find_key(guard.instance, key) {
            let page = segment_page(frame).ok_or(Error::Invalid)?;
            if create && exclusive {
                return Err(Error::Exists);
            }
            if size > page.size {
                return Err(Error::Invalid);
            }
            return Ok(page.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    if size == 0 {
        return Err(Error::Invalid);
    }
    let pages = usize::try_from(size.div_ceil(PAGE_SIZE as u64)).map_err(|_| Error::Invalid)?;
    // No more segments than /proc/sys/kernel/shmmni allows (ENOSPC).
    let mut existing = 0;
    let mut current = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
    );
    while let Some(page) = current.and_then(segment_page) {
        existing += 1;
        if existing >= limit {
            return Err(Error::NoSpace);
        }
        current = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
    }
    let first = allocate_zeroed().ok_or(Error::NoMemory)?;
    // A requested id (/proc/sys/kernel/shm_next_id) that is free is used, and
    // the counter moves past it; otherwise the next free id.
    let next = &SYSV_IPC_RUNTIME.next_ids[guard.instance];
    let id = match requested.filter(|id| {
        *id != 0 && *id <= i32::MAX as u32 && find_segment(guard.instance, *id).is_none()
    }) {
        Some(id) => {
            if next.load(Ordering::Acquire) <= id {
                next.store(id + 1, Ordering::Release);
            }
            id
        }
        None => next.fetch_add(1, Ordering::AcqRel),
    };
    if id == 0 {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[first]);
        return Err(Error::NoMemory);
    }
    {
        let page = segment_page_mut(first).ok_or(Error::NoMemory)?;
        page.id = id;
        page.key = key;
        page.size = size;
        page.mode = mode & 0o777;
        page.creator_pid = pid;
        page.last_pid = pid;
    }
    let mut metadata = first;
    for index in 0..pages {
        if index != 0 && index.is_multiple_of(FRAME_CAPACITY) {
            let Some(next) = allocate_zeroed() else {
                let _ = release_segment_chain(first);
                return Err(Error::NoMemory);
            };
            let Some(page) = segment_page_mut(metadata) else {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[next]);
                let _ = release_segment_chain(first);
                return Err(Error::NoMemory);
            };
            page.next_page = next;
            metadata = next;
        }
        let Some(data) = allocate_zeroed() else {
            let _ = release_segment_chain(first);
            return Err(Error::NoMemory);
        };
        let Some(page) = segment_page_mut(metadata) else {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[data]);
            let _ = release_segment_chain(first);
            return Err(Error::NoMemory);
        };
        let slot = usize::from(page.frames_used);
        page.frames[slot] = data;
        page.frames_used += 1;
    }
    let old_root = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
    );
    segment_page_mut(first).ok_or(Error::NoMemory)?.next_segment =
        old_root.unwrap_or(memory::FrameLease::EMPTY);
    publish_root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
        Some(first),
    );
    Ok(id)
}

/// How a new segment gets its id: the id `/proc/sys/kernel/shm_next_id`
/// asks for, if any, and how many segments `shmmni` allows in all.
#[derive(Clone, Copy)]
pub(crate) struct SegmentIds {
    pub(crate) requested: Option<u32>,
    pub(crate) limit: usize,
}

/// Every segment of the current instance with its id, in creation order,
/// for `/proc/sysvipc/shm`.
pub(crate) fn segments() -> Vec<(u32, SegmentInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    let mut current = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(page) = current.and_then(segment_page) else {
            break;
        };
        if found.try_reserve(1).is_err() {
            break;
        }
        found.push((page.id, info(page)));
        current = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
    }
    found
}

/// Every System V message queue of the current instance with its id, in
/// creation order, for `/proc/sysvipc/msg` (POSIX queues share the list and
/// are left out).
pub(crate) fn message_queues() -> Vec<(u32, MessageQueueInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    let mut current = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(queue) = current.and_then(message_queue) else {
            break;
        };
        if queue.posix == 0 {
            if found.try_reserve(1).is_err() {
                break;
            }
            found.push((
                queue.id,
                MessageQueueInfo {
                    key: queue.key,
                    mode: queue.mode,
                    bytes: queue.bytes,
                    messages: queue.messages,
                    byte_limit: queue.byte_limit,
                    last_sender: queue.last_sender,
                    last_receiver: queue.last_receiver,
                },
            ));
        }
        current = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    }
    found
}

/// Every semaphore set of the current instance with its id, in creation
/// order, for `/proc/sysvipc/sem`.
pub(crate) fn semaphore_sets() -> Vec<(u32, SemaphoreSetInfo)> {
    let mut found = Vec::new();
    let Some(guard) = Guard::acquire() else {
        return found;
    };
    let mut current = root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(page) = current.and_then(semaphore_page) else {
            break;
        };
        if found.try_reserve(1).is_err() {
            break;
        }
        found.push((
            page.id,
            SemaphoreSetInfo {
                key: page.key,
                count: page.count,
                mode: page.mode,
            },
        ));
        current = (page.next_set != memory::FrameLease::EMPTY).then_some(page.next_set);
    }
    found
}

pub(crate) fn segment(id: u32) -> Result<SegmentInfo, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_segment(guard.instance, id).ok_or(Error::Invalid)?;
    segment_page(frame).map(info).ok_or(Error::Invalid)
}

pub(crate) fn frame(id: u32, index: usize) -> Result<memory::FrameLease, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (mut metadata, _) = find_segment(guard.instance, id).ok_or(Error::Invalid)?;
    let mut remaining = index;
    for _ in 0..WALK_LIMIT {
        let page = segment_page(metadata).ok_or(Error::Invalid)?;
        if remaining < usize::from(page.frames_used) {
            return Ok(page.frames[remaining]);
        }
        remaining -= usize::from(page.frames_used);
        if page.next_page == memory::FrameLease::EMPTY {
            return Err(Error::Invalid);
        }
        metadata = page.next_page;
    }
    Err(Error::Invalid)
}

pub(crate) fn attach(id: u32, address: u64, pid: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (segment, _) = find_segment(guard.instance, id).ok_or(Error::Invalid)?;
    if segment_page(segment).ok_or(Error::Invalid)?.attachments == u64::MAX {
        return Err(Error::NoMemory);
    }
    let record = allocate_zeroed().ok_or(Error::NoMemory)?;
    let length = segment_page(segment).ok_or(Error::Invalid)?.size;
    let old_root = root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
    );
    let entry = attachment_mut(record).ok_or(Error::NoMemory)?;
    entry.next = old_root.unwrap_or(memory::FrameLease::EMPTY);
    entry.segment = segment;
    entry.address = address;
    entry.length = length;
    entry.pid = pid;
    let page = segment_page_mut(segment).ok_or(Error::Invalid)?;
    page.attachments = page.attachments.checked_add(1).ok_or(Error::NoMemory)?;
    page.last_pid = pid;
    publish_root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
        Some(record),
    );
    Ok(())
}

pub(crate) fn attachment_at(address: u64, pid: u32) -> Result<(u32, u64), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let mut current = root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let frame = current.ok_or(Error::Invalid)?;
        let entry = attachment(frame).ok_or(Error::Invalid)?;
        if entry.address == address && entry.pid == pid {
            let page = segment_page(entry.segment).ok_or(Error::Invalid)?;
            return Ok((page.id, entry.length));
        }
        current = (entry.next != memory::FrameLease::EMPTY).then_some(entry.next);
    }
    Err(Error::Invalid)
}

fn detach_matching(instance: usize, pid: u32, address: Option<u64>) -> Result<usize, Error> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        instance,
    );
    let mut previous = None;
    let mut removed = 0;
    for _ in 0..WALK_LIMIT {
        let Some(record) = current else {
            return Ok(removed);
        };
        let entry = attachment(record).ok_or(Error::Invalid)?;
        if entry.pid == pid && address.is_none_or(|address| entry.address == address) {
            let next = (entry.next != memory::FrameLease::EMPTY).then_some(entry.next);
            let segment = entry.segment;
            if let Some(previous) = previous {
                attachment_mut(previous).ok_or(Error::Invalid)?.next =
                    next.unwrap_or(memory::FrameLease::EMPTY);
            } else {
                publish_root(
                    &SYSV_IPC_RUNTIME.attachment_root_addresses,
                    &SYSV_IPC_RUNTIME.attachment_root_generations,
                    instance,
                    next,
                );
            }
            let page = segment_page_mut(segment).ok_or(Error::Invalid)?;
            page.attachments = page.attachments.checked_sub(1).ok_or(Error::Invalid)?;
            page.last_pid = pid;
            let remove = page.marked_for_removal != 0 && page.attachments == 0;
            let segment_id = page.id;
            if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[record]) {
                return Err(Error::Invalid);
            }
            if remove {
                let (_, segment_previous) =
                    find_segment(instance, segment_id).ok_or(Error::Invalid)?;
                if !unlink_and_release(instance, segment, segment_previous) {
                    return Err(Error::Invalid);
                }
            }
            removed += 1;
            current = next;
            if address.is_some() {
                return Ok(removed);
            }
            continue;
        }
        previous = current;
        current = (entry.next != memory::FrameLease::EMPTY).then_some(entry.next);
    }
    Err(Error::Invalid)
}

pub(crate) fn detach(address: u64, pid: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    (detach_matching(guard.instance, pid, Some(address))? == 1)
        .then_some(())
        .ok_or(Error::Invalid)
}

pub(crate) fn inherit_process_attachments(parent: u32, child: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    if parent == child {
        return Err(Error::Invalid);
    }
    let mut current = root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(record) = current else { return Ok(()) };
        let source = attachment(record).ok_or(Error::Invalid)?;
        let next = (source.next != memory::FrameLease::EMPTY).then_some(source.next);
        if source.pid == child {
            let _ = detach_matching(guard.instance, child, None);
            return Err(Error::Invalid);
        }
        if source.pid == parent {
            let Some(clone) = allocate_zeroed() else {
                let _ = detach_matching(guard.instance, child, None);
                return Err(Error::NoMemory);
            };
            let root = root(
                &SYSV_IPC_RUNTIME.attachment_root_addresses,
                &SYSV_IPC_RUNTIME.attachment_root_generations,
                guard.instance,
            );
            let Some(entry) = attachment_mut(clone) else {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[clone]);
                let _ = detach_matching(guard.instance, child, None);
                return Err(Error::NoMemory);
            };
            entry.next = root.unwrap_or(memory::FrameLease::EMPTY);
            entry.segment = source.segment;
            entry.address = source.address;
            entry.length = source.length;
            entry.pid = child;
            let Some(segment) = segment_page_mut(source.segment) else {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[clone]);
                let _ = detach_matching(guard.instance, child, None);
                return Err(Error::Invalid);
            };
            let Some(attachments) = segment.attachments.checked_add(1) else {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[clone]);
                let _ = detach_matching(guard.instance, child, None);
                return Err(Error::NoMemory);
            };
            segment.attachments = attachments;
            segment.last_pid = child;
            publish_root(
                &SYSV_IPC_RUNTIME.attachment_root_addresses,
                &SYSV_IPC_RUNTIME.attachment_root_generations,
                guard.instance,
                Some(clone),
            );
        }
        current = next;
    }
    let _ = detach_matching(guard.instance, child, None);
    Err(Error::Invalid)
}

pub(crate) fn drop_process_attachments(pid: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    undo_process_semaphores(&mut guard, pid);
    detach_matching(guard.instance, pid, None).map(|_| ())
}

/// Ends an exiting process's semaphore wait and applies its `SEM_UNDO`
/// adjustments, clamped to the value's range as Linux does.
fn undo_process_semaphores(guard: &mut Guard, pid: u32) {
    let instance = guard.instance;
    let processes = guard.semaphore_processes();
    processes.waits.retain(|wait| wait.pid != pid);
    processes.message_waits.retain(|(waiter, _)| *waiter != pid);
    processes.undo.retain(|undo| {
        if undo.pid != pid {
            return true;
        }
        let value = find_semaphore_set(instance, undo.id)
            .and_then(|(first, _)| semaphore_value_frame(first, usize::from(undo.number)))
            .and_then(|(frame, slot)| Some(&mut semaphore_page_mut(frame)?.values[slot]));
        if let Some(value) = value {
            value.value = (i32::from(value.value) + undo.adjustment)
                .clamp(0, i32::from(SEM_VALUE_MAX)) as u16;
            value.last_pid = pid;
        }
        false
    });
}

/// The wait `pid` recorded in an earlier, restarted `semop`.
pub(crate) fn semaphore_wait(pid: u32) -> Option<SemaphoreWait> {
    let mut guard = Guard::acquire()?;
    guard
        .semaphore_processes()
        .waits
        .iter()
        .find(|wait| wait.pid == pid)
        .copied()
}

/// Records that a process waits in `semop`, replacing its earlier record.
pub(crate) fn begin_semaphore_wait(wait: SemaphoreWait) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let waits = &mut guard.semaphore_processes().waits;
    if let Some(existing) = waits.iter_mut().find(|existing| existing.pid == wait.pid) {
        *existing = wait;
        return Ok(());
    }
    waits.try_reserve(1).map_err(|_| Error::NoMemory)?;
    waits.push(wait);
    Ok(())
}

/// The queue `pid` waited on in an earlier, restarted msgsnd or msgrcv.
pub(crate) fn message_wait(pid: u32) -> Option<u32> {
    let mut guard = Guard::acquire()?;
    guard
        .semaphore_processes()
        .message_waits
        .iter()
        .find(|(waiter, _)| *waiter == pid)
        .map(|(_, id)| *id)
}

/// Records that `pid` waits on queue `id` in msgsnd or msgrcv.
pub(crate) fn begin_message_wait(pid: u32, id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let waits = &mut guard.semaphore_processes().message_waits;
    if let Some(existing) = waits.iter_mut().find(|(waiter, _)| *waiter == pid) {
        existing.1 = id;
        return Ok(());
    }
    waits.try_reserve(1).map_err(|_| Error::NoMemory)?;
    waits.push((pid, id));
    Ok(())
}

pub(crate) fn end_message_wait(pid: u32) {
    if let Some(mut guard) = Guard::acquire() {
        guard
            .semaphore_processes()
            .message_waits
            .retain(|(waiter, _)| *waiter != pid);
    }
}

pub(crate) fn end_semaphore_wait(pid: u32) {
    if let Some(mut guard) = Guard::acquire() {
        guard
            .semaphore_processes()
            .waits
            .retain(|wait| wait.pid != pid);
    }
}

pub(crate) fn teardown() -> bool {
    let Some(mut guard) = Guard::acquire() else {
        return false;
    };
    *guard.semaphore_processes() = SemaphoreProcesses::EMPTY;
    let mut attachments = root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(record) = attachments else { break };
        let Some(entry) = attachment(record) else {
            return false;
        };
        attachments = (entry.next != memory::FrameLease::EMPTY).then_some(entry.next);
        if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[record]) {
            return false;
        }
    }
    if attachments.is_some() {
        return false;
    }
    publish_root(
        &SYSV_IPC_RUNTIME.attachment_root_addresses,
        &SYSV_IPC_RUNTIME.attachment_root_generations,
        guard.instance,
        None,
    );
    let mut segments = root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
    );
    publish_root(
        &SYSV_IPC_RUNTIME.root_addresses,
        &SYSV_IPC_RUNTIME.root_generations,
        guard.instance,
        None,
    );
    for _ in 0..WALK_LIMIT {
        let Some(segment) = segments else { break };
        let Some(page) = segment_page(segment) else {
            return false;
        };
        segments = (page.next_segment != memory::FrameLease::EMPTY).then_some(page.next_segment);
        if !release_segment_chain(segment) {
            return false;
        }
    }
    if segments.is_some() {
        return false;
    }
    let mut sets = root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        guard.instance,
    );
    publish_root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        guard.instance,
        None,
    );
    for _ in 0..WALK_LIMIT {
        let Some(set) = sets else { break };
        let Some(page) = semaphore_page(set) else {
            return false;
        };
        sets = (page.next_set != memory::FrameLease::EMPTY).then_some(page.next_set);
        if !release_semaphore_chain(set) {
            return false;
        }
    }
    if sets.is_some() {
        return false;
    }
    let mut queues = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    publish_root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
        None,
    );
    for _ in 0..WALK_LIMIT {
        let Some(queue_frame) = queues else {
            return true;
        };
        let Some(queue) = message_queue(queue_frame) else {
            return false;
        };
        queues = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
        let messages = (queue.head != memory::FrameLease::EMPTY).then_some(queue.head);
        if !release_messages(messages)
            || !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[queue_frame])
        {
            return false;
        }
    }
    false
}

pub(crate) fn mark_for_removal(id: u32, pid: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, previous) = find_segment(guard.instance, id).ok_or(Error::Invalid)?;
    let page = segment_page_mut(frame).ok_or(Error::Invalid)?;
    page.marked_for_removal = 1;
    page.last_pid = pid;
    if page.attachments == 0 && !unlink_and_release(guard.instance, frame, previous) {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(crate) fn set_mode(id: u32, mode: u16, pid: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_segment(guard.instance, id).ok_or(Error::Invalid)?;
    let page = segment_page_mut(frame).ok_or(Error::Invalid)?;
    page.mode = mode & 0o777;
    page.last_pid = pid;
    Ok(())
}

fn find_semaphore_set(
    instance: usize,
    id: u32,
) -> Option<(memory::FrameLease, Option<memory::FrameLease>)> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        instance,
    );
    let mut previous = None;
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let page = semaphore_page(frame)?;
        if page.id == id {
            return Some((frame, previous));
        }
        previous = current;
        current = (page.next_set != memory::FrameLease::EMPTY).then_some(page.next_set);
    }
    None
}

fn find_semaphore_key(instance: usize, key: i32) -> Option<memory::FrameLease> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        instance,
    );
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let page = semaphore_page(frame)?;
        if page.key == key {
            return Some(frame);
        }
        current = (page.next_set != memory::FrameLease::EMPTY).then_some(page.next_set);
    }
    None
}

fn semaphore_value_frame(
    mut frame: memory::FrameLease,
    mut number: usize,
) -> Option<(memory::FrameLease, usize)> {
    for _ in 0..WALK_LIMIT {
        let page = semaphore_page(frame)?;
        if number < usize::from(page.values_used) {
            return Some((frame, number));
        }
        number = number.checked_sub(usize::from(page.values_used))?;
        if page.next_page == memory::FrameLease::EMPTY {
            return None;
        }
        frame = page.next_page;
    }
    None
}

fn release_semaphore_chain(first: memory::FrameLease) -> bool {
    let mut current = Some(first);
    for _ in 0..WALK_LIMIT {
        let Some(frame) = current else { return true };
        let Some(page) = semaphore_page(frame) else {
            return false;
        };
        current = (page.next_page != memory::FrameLease::EMPTY).then_some(page.next_page);
        if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]) {
            return false;
        }
    }
    false
}

pub(crate) fn semaphore_get_or_create(
    key: i32,
    count: u64,
    mode: u16,
    create: bool,
    exclusive: bool,
    pid: u32,
) -> Result<u32, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    if key != 0 {
        if let Some(frame) = find_semaphore_key(guard.instance, key) {
            let page = semaphore_page(frame).ok_or(Error::Invalid)?;
            if create && exclusive {
                return Err(Error::Exists);
            }
            if count > page.count {
                return Err(Error::Invalid);
            }
            return Ok(page.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    let count = usize::try_from(count).map_err(|_| Error::Invalid)?;
    if count == 0 {
        return Err(Error::Invalid);
    }
    let first = allocate_zeroed().ok_or(Error::NoMemory)?;
    let id = SYSV_IPC_RUNTIME.next_semaphore_ids[guard.instance].fetch_add(1, Ordering::AcqRel);
    if id == 0 || id > i32::MAX as u32 {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[first]);
        return Err(Error::NoMemory);
    }
    {
        let Some(page) = semaphore_page_mut(first) else {
            let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[first]);
            return Err(Error::NoMemory);
        };
        page.id = id;
        page.key = key;
        page.count = count as u64;
        page.mode = mode & 0o777;
        page.creator_pid = pid;
        page.last_pid = pid;
    }
    let mut metadata = first;
    let mut remaining = count;
    while remaining != 0 {
        let used = remaining.min(SEMAPHORE_CAPACITY);
        semaphore_page_mut(metadata)
            .ok_or(Error::NoMemory)?
            .values_used = used as u16;
        remaining -= used;
        if remaining != 0 {
            let Some(next) = allocate_zeroed() else {
                let _ = release_semaphore_chain(first);
                return Err(Error::NoMemory);
            };
            let Some(page) = semaphore_page_mut(metadata) else {
                let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[next]);
                let _ = release_semaphore_chain(first);
                return Err(Error::NoMemory);
            };
            page.next_page = next;
            metadata = next;
        }
    }
    let old_root = root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        guard.instance,
    );
    semaphore_page_mut(first).ok_or(Error::NoMemory)?.next_set =
        old_root.unwrap_or(memory::FrameLease::EMPTY);
    publish_root(
        &SYSV_IPC_RUNTIME.semaphore_root_addresses,
        &SYSV_IPC_RUNTIME.semaphore_root_generations,
        guard.instance,
        Some(first),
    );
    Ok(id)
}

pub(crate) fn semaphore_set(id: u32) -> Result<SemaphoreSetInfo, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let page = semaphore_page(frame).ok_or(Error::Invalid)?;
    Ok(SemaphoreSetInfo {
        key: page.key,
        count: page.count,
        mode: page.mode,
    })
}

pub(crate) fn semaphore_get(id: u32, number: usize) -> Result<(u16, u32, u32, u32), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (first, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let (frame, slot) = semaphore_value_frame(first, number).ok_or(Error::Range)?;
    let value = semaphore_page(frame).ok_or(Error::Invalid)?.values[slot];
    let (waiting_increase, waiting_zero) = guard
        .semaphore_processes()
        .waits
        .iter()
        .filter(|wait| wait.id == id && usize::from(wait.block.number) == number)
        .fold((0, 0), |(increase, zero), wait| {
            if wait.block.zero {
                (increase, zero + 1)
            } else {
                (increase + 1, zero)
            }
        });
    Ok((value.value, value.last_pid, waiting_increase, waiting_zero))
}

pub(crate) fn semaphore_set_value(
    id: u32,
    number: usize,
    value: u16,
    pid: u32,
) -> Result<(), Error> {
    if value > SEM_VALUE_MAX {
        return Err(Error::Range);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (first, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let (frame, slot) = semaphore_value_frame(first, number).ok_or(Error::Range)?;
    guard
        .semaphore_processes()
        .undo
        .retain(|undo| undo.id != id || usize::from(undo.number) != number);
    let semaphore = &mut semaphore_page_mut(frame).ok_or(Error::Invalid)?.values[slot];
    semaphore.value = value;
    semaphore.last_pid = pid;
    semaphore_page_mut(first).ok_or(Error::Invalid)?.last_pid = pid;
    Ok(())
}

pub(crate) fn semaphore_apply<F>(
    id: u32,
    operation_count: usize,
    pid: u32,
    mut operation: F,
) -> Result<Option<SemaphoreBlock>, Error>
where
    F: FnMut(usize) -> Option<SemaphoreOperation>,
{
    const IPC_NOWAIT: u16 = 0o4000;
    const SEM_UNDO: u16 = 0x1000;
    if operation_count == 0 {
        return Err(Error::Invalid);
    }
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (first, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let set_count = semaphore_page(first).ok_or(Error::Invalid)?.count as usize;
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & !(IPC_NOWAIT | SEM_UNDO) != 0 || usize::from(current.number) >= set_count
        {
            return Err(Error::Invalid);
        }
        let (frame, slot) =
            semaphore_value_frame(first, usize::from(current.number)).ok_or(Error::Invalid)?;
        let mut simulated =
            i32::from(semaphore_page(frame).ok_or(Error::Invalid)?.values[slot].value);
        for prior_index in 0..index {
            let prior = operation(prior_index).ok_or(Error::Invalid)?;
            if prior.number == current.number {
                simulated = simulated
                    .checked_add(i32::from(prior.operation))
                    .ok_or(Error::Range)?;
            }
        }
        let blocks = match current.operation.cmp(&0) {
            core::cmp::Ordering::Greater => {
                if simulated
                    .checked_add(i32::from(current.operation))
                    .is_none_or(|value| value > i32::from(SEM_VALUE_MAX))
                {
                    return Err(Error::Range);
                }
                false
            }
            core::cmp::Ordering::Less => simulated < -i32::from(current.operation),
            core::cmp::Ordering::Equal => simulated != 0,
        };
        if !blocks {
            continue;
        }
        if current.flags & IPC_NOWAIT != 0 {
            return Err(Error::WouldBlock);
        }
        return Ok(Some(SemaphoreBlock {
            number: current.number,
            zero: current.operation == 0,
        }));
    }
    // SEM_UNDO keeps the opposite of each change, to apply at exit; an
    // adjustment out of the value's range fails the call (ERANGE).
    let undo = &mut guard.semaphore_processes().undo;
    let mut new_entries = 0;
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & SEM_UNDO == 0 || current.operation == 0 {
            continue;
        }
        let existing = undo
            .iter()
            .find(|entry| entry.pid == pid && entry.id == id && entry.number == current.number)
            .map(|entry| entry.adjustment);
        let earlier: i32 = (0..index)
            .filter_map(&mut operation)
            .filter(|prior| prior.flags & SEM_UNDO != 0 && prior.number == current.number)
            .map(|prior| -i32::from(prior.operation))
            .sum();
        let adjustment = existing.unwrap_or(0) + earlier - i32::from(current.operation);
        if adjustment.abs() > i32::from(SEM_VALUE_MAX) {
            return Err(Error::Range);
        }
        new_entries += usize::from(existing.is_none());
    }
    undo.try_reserve(new_entries).map_err(|_| Error::NoMemory)?;
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        if current.flags & SEM_UNDO == 0 || current.operation == 0 {
            continue;
        }
        match undo
            .iter_mut()
            .find(|entry| entry.pid == pid && entry.id == id && entry.number == current.number)
        {
            Some(entry) => entry.adjustment -= i32::from(current.operation),
            None => undo.push(SemaphoreUndo {
                pid,
                id,
                number: current.number,
                adjustment: -i32::from(current.operation),
            }),
        }
    }
    undo.retain(|entry| entry.adjustment != 0);
    for index in 0..operation_count {
        let current = operation(index).ok_or(Error::Invalid)?;
        let (frame, slot) =
            semaphore_value_frame(first, usize::from(current.number)).ok_or(Error::Invalid)?;
        let semaphore = &mut semaphore_page_mut(frame).ok_or(Error::Invalid)?.values[slot];
        if current.operation != 0 {
            semaphore.value =
                u16::try_from(i32::from(semaphore.value) + i32::from(current.operation))
                    .map_err(|_| Error::Range)?;
        }
        semaphore.last_pid = pid;
    }
    semaphore_page_mut(first).ok_or(Error::Invalid)?.last_pid = pid;
    Ok(None)
}

pub(crate) fn semaphore_set_all<F>(id: u32, pid: u32, mut value: F) -> Result<(), Error>
where
    F: FnMut(usize) -> Option<u16>,
{
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (first, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let count = semaphore_page(first).ok_or(Error::Invalid)?.count as usize;
    // Setting values clears every process's adjustments to them.
    guard
        .semaphore_processes()
        .undo
        .retain(|undo| undo.id != id);
    for index in 0..count {
        if value(index)
            .filter(|value| *value <= SEM_VALUE_MAX)
            .is_none()
        {
            return Err(Error::Range);
        }
    }
    for index in 0..count {
        let (frame, slot) = semaphore_value_frame(first, index).ok_or(Error::Invalid)?;
        let semaphore = &mut semaphore_page_mut(frame).ok_or(Error::Invalid)?.values[slot];
        semaphore.value = value(index).ok_or(Error::Invalid)?;
        semaphore.last_pid = pid;
    }
    semaphore_page_mut(first).ok_or(Error::Invalid)?.last_pid = pid;
    Ok(())
}

pub(crate) fn semaphore_set_mode(id: u32, mode: u16, pid: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    let page = semaphore_page_mut(frame).ok_or(Error::Invalid)?;
    page.mode = mode & 0o777;
    page.last_pid = pid;
    Ok(())
}

pub(crate) fn semaphore_remove(id: u32) -> Result<(), Error> {
    let mut guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, previous) = find_semaphore_set(guard.instance, id).ok_or(Error::Invalid)?;
    guard
        .semaphore_processes()
        .undo
        .retain(|undo| undo.id != id);
    let next = {
        let page = semaphore_page(frame).ok_or(Error::Invalid)?;
        (page.next_set != memory::FrameLease::EMPTY).then_some(page.next_set)
    };
    if let Some(previous) = previous {
        semaphore_page_mut(previous).ok_or(Error::Invalid)?.next_set =
            next.unwrap_or(memory::FrameLease::EMPTY);
    } else {
        publish_root(
            &SYSV_IPC_RUNTIME.semaphore_root_addresses,
            &SYSV_IPC_RUNTIME.semaphore_root_generations,
            guard.instance,
            next,
        );
    }
    release_semaphore_chain(frame)
        .then_some(())
        .ok_or(Error::Invalid)
}

fn find_message_queue(
    instance: usize,
    id: u32,
) -> Option<(memory::FrameLease, Option<memory::FrameLease>)> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        instance,
    );
    let mut previous = None;
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let queue = message_queue(frame)?;
        if queue.id == id {
            return Some((frame, previous));
        }
        previous = current;
        current = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    }
    None
}

fn find_message_key(instance: usize, key: i32) -> Option<memory::FrameLease> {
    let mut current = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        instance,
    );
    for _ in 0..WALK_LIMIT {
        let frame = current?;
        let queue = message_queue(frame)?;
        if queue.key == key {
            return Some(frame);
        }
        current = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    }
    None
}

fn release_message(first: memory::FrameLease) -> bool {
    let mut current = Some(first);
    for _ in 0..WALK_LIMIT {
        let Some(frame) = current else { return true };
        let Some(page) = message_page(frame) else {
            return false;
        };
        current = (page.next_page != memory::FrameLease::EMPTY).then_some(page.next_page);
        if !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]) {
            return false;
        }
    }
    false
}

fn release_messages(mut message: Option<memory::FrameLease>) -> bool {
    for _ in 0..WALK_LIMIT {
        let Some(frame) = message else { return true };
        let Some(page) = message_page(frame) else {
            return false;
        };
        message = (page.next_message != memory::FrameLease::EMPTY).then_some(page.next_message);
        if !release_message(frame) {
            return false;
        }
    }
    false
}

pub(crate) fn message_get_or_create(
    key: i32,
    mode: u16,
    create: bool,
    exclusive: bool,
    requested: Option<u32>,
) -> Result<u32, Error> {
    const DEFAULT_BYTE_LIMIT: u64 = 16_384;
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    if key != 0 {
        if let Some(frame) = find_message_key(guard.instance, key) {
            let queue = message_queue(frame).ok_or(Error::Invalid)?;
            if create && exclusive {
                return Err(Error::Exists);
            }
            return Ok(queue.id);
        }
        if !create {
            return Err(Error::NoEntry);
        }
    }
    let frame = allocate_zeroed().ok_or(Error::NoMemory)?;
    // A requested id (/proc/sys/kernel/msg_next_id) that is free is used, and
    // the counter moves past it; otherwise the next free id.
    let next = &SYSV_IPC_RUNTIME.next_message_ids[guard.instance];
    let id = match requested.filter(|id| {
        *id != 0 && *id <= i32::MAX as u32 && find_message_queue(guard.instance, *id).is_none()
    }) {
        Some(id) => {
            if next.load(Ordering::Acquire) <= id {
                next.store(id + 1, Ordering::Release);
            }
            id
        }
        None => next.fetch_add(1, Ordering::AcqRel),
    };
    if id == 0 || id > i32::MAX as u32 {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return Err(Error::NoMemory);
    }
    let old_root = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    let Some(queue) = message_queue_mut(frame) else {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return Err(Error::NoMemory);
    };
    queue.next_queue = old_root.unwrap_or(memory::FrameLease::EMPTY);
    queue.id = id;
    queue.key = key;
    queue.mode = mode & 0o777;
    queue.byte_limit = DEFAULT_BYTE_LIMIT;
    publish_root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
        Some(frame),
    );
    Ok(id)
}

fn posix_info(queue: &MessageQueue, created: bool) -> PosixQueueInfo {
    PosixQueueInfo {
        id: queue.id,
        max_messages: u64::from(queue.max_messages),
        max_message_size: u64::from(queue.max_message_size),
        messages: queue.messages,
        created,
    }
}

pub(crate) fn posix_queue_open(
    name: &[u8],
    create: bool,
    exclusive: bool,
    mode: u16,
    max_messages: u32,
    max_message_size: u32,
) -> Result<PosixQueueInfo, Error> {
    if name.is_empty() || name.len() > 255 || max_messages == 0 || max_message_size == 0 {
        return Err(Error::Invalid);
    }
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let mut current = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    for _ in 0..WALK_LIMIT {
        let Some(frame) = current else { break };
        let queue = message_queue_mut(frame).ok_or(Error::Invalid)?;
        if queue.posix != 0
            && queue.linked != 0
            && usize::from(queue.name_length) == name.len()
            && queue.name[..name.len()] == *name
        {
            if create && exclusive {
                return Err(Error::Exists);
            }
            queue.open_references = queue
                .open_references
                .checked_add(1)
                .ok_or(Error::NoMemory)?;
            return Ok(posix_info(queue, false));
        }
        current = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    }
    if !create {
        return Err(Error::NoEntry);
    }
    let frame = allocate_zeroed().ok_or(Error::NoMemory)?;
    let id = SYSV_IPC_RUNTIME.next_message_ids[guard.instance].fetch_add(1, Ordering::AcqRel);
    if id == 0 || id > i32::MAX as u32 {
        let _ = memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame]);
        return Err(Error::NoMemory);
    }
    let old_root = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    let queue = message_queue_mut(frame).ok_or(Error::NoMemory)?;
    queue.next_queue = old_root.unwrap_or(memory::FrameLease::EMPTY);
    queue.id = id;
    queue.mode = mode & 0o777;
    queue.byte_limit = u64::from(max_messages) * u64::from(max_message_size);
    queue.posix = 1;
    queue.linked = 1;
    queue.name_length = name.len() as u16;
    queue.max_messages = max_messages;
    queue.max_message_size = max_message_size;
    queue.open_references = 1;
    queue.name[..name.len()].copy_from_slice(name);
    let info = posix_info(queue, true);
    publish_root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
        Some(frame),
    );
    Ok(info)
}

pub(crate) fn posix_queue_info(id: u32) -> Result<PosixQueueInfo, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue(frame).ok_or(Error::Invalid)?;
    (queue.posix != 0)
        .then(|| posix_info(queue, false))
        .ok_or(Error::Invalid)
}

pub(crate) fn posix_queue_duplicate(id: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue_mut(frame).ok_or(Error::Invalid)?;
    if queue.posix == 0 {
        return Err(Error::Invalid);
    }
    queue.open_references = queue
        .open_references
        .checked_add(1)
        .ok_or(Error::NoMemory)?;
    Ok(())
}

pub(crate) fn posix_queue_close(id: u32) -> Result<Option<PosixQueueInfo>, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, previous) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue_mut(frame).ok_or(Error::Invalid)?;
    if queue.posix == 0 || queue.open_references == 0 {
        return Err(Error::Invalid);
    }
    queue.open_references -= 1;
    if queue.open_references == 0 && queue.linked == 0 {
        let info = posix_info(queue, false);
        remove_message_queue_locked(guard.instance, frame, previous).map(|()| Some(info))
    } else {
        Ok(None)
    }
}

pub(crate) fn posix_queue_unlink(name: &[u8]) -> Result<Option<PosixQueueInfo>, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let mut current = root(
        &SYSV_IPC_RUNTIME.message_root_addresses,
        &SYSV_IPC_RUNTIME.message_root_generations,
        guard.instance,
    );
    let mut previous = None;
    for _ in 0..WALK_LIMIT {
        let Some(frame) = current else { break };
        let queue = message_queue_mut(frame).ok_or(Error::Invalid)?;
        if queue.posix != 0
            && queue.linked != 0
            && usize::from(queue.name_length) == name.len()
            && queue.name[..name.len()] == *name
        {
            queue.linked = 0;
            queue.name_length = 0;
            queue.name.fill(0);
            return if queue.open_references == 0 {
                let info = posix_info(queue, false);
                remove_message_queue_locked(guard.instance, frame, previous).map(|()| Some(info))
            } else {
                Ok(None)
            };
        }
        previous = Some(frame);
        current = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    }
    Err(Error::NoEntry)
}

fn remove_message_queue_locked(
    instance: usize,
    frame: memory::FrameLease,
    previous: Option<memory::FrameLease>,
) -> Result<(), Error> {
    let queue = message_queue(frame).ok_or(Error::Invalid)?;
    let next = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    let messages = (queue.head != memory::FrameLease::EMPTY).then_some(queue.head);
    if let Some(previous) = previous {
        message_queue_mut(previous)
            .ok_or(Error::Invalid)?
            .next_queue = next.unwrap_or(memory::FrameLease::EMPTY);
    } else {
        publish_root(
            &SYSV_IPC_RUNTIME.message_root_addresses,
            &SYSV_IPC_RUNTIME.message_root_generations,
            instance,
            next,
        );
    }
    if release_messages(messages)
        && memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame])
    {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}

pub(crate) fn message_queue_info(id: u32) -> Result<MessageQueueInfo, Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue(frame).ok_or(Error::Invalid)?;
    Ok(MessageQueueInfo {
        key: queue.key,
        mode: queue.mode,
        bytes: queue.bytes,
        messages: queue.messages,
        byte_limit: queue.byte_limit,
        last_sender: queue.last_sender,
        last_receiver: queue.last_receiver,
    })
}

pub(crate) fn message_send<F>(
    id: u32,
    message_type: i64,
    size: usize,
    pid: u32,
    mut read: F,
) -> Result<(), Error>
where
    F: FnMut(usize, &mut [u8]) -> bool,
{
    if message_type <= 0 {
        return Err(Error::Invalid);
    }
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (queue_frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue(queue_frame).ok_or(Error::Invalid)?;
    if queue
        .bytes
        .checked_add(size as u64)
        .is_none_or(|bytes| bytes > queue.byte_limit)
    {
        return Err(Error::WouldBlock);
    }
    let first = allocate_zeroed().ok_or(Error::NoMemory)?;
    {
        let page = message_page_mut(first).ok_or(Error::NoMemory)?;
        page.message_type = message_type;
        page.size = size as u64;
    }
    let mut page_frame = first;
    let mut offset = 0;
    loop {
        let length = (size - offset).min(MESSAGE_CAPACITY);
        let page = message_page_mut(page_frame).ok_or(Error::Invalid)?;
        if !read(offset, &mut page.bytes[..length]) {
            let _ = release_message(first);
            return Err(Error::Fault);
        }
        page.used = length as u16;
        offset += length;
        if offset == size {
            break;
        }
        let Some(next) = allocate_zeroed() else {
            let _ = release_message(first);
            return Err(Error::NoMemory);
        };
        page.next_page = next;
        page_frame = next;
    }
    let queue = message_queue_mut(queue_frame).ok_or(Error::Invalid)?;
    if queue.tail != memory::FrameLease::EMPTY {
        message_page_mut(queue.tail)
            .ok_or(Error::Invalid)?
            .next_message = first;
    } else {
        queue.head = first;
    }
    queue.tail = first;
    queue.bytes += size as u64;
    queue.messages += 1;
    queue.last_sender = pid;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn message_receive<F>(
    id: u32,
    size: usize,
    selector: i64,
    no_error: bool,
    except: bool,
    copy: bool,
    pid: u32,
    mut write: F,
) -> Result<usize, Error>
where
    F: FnMut(i64, usize, &[u8]) -> bool,
{
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (queue_frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue(queue_frame).ok_or(Error::Invalid)?;
    let mut current = (queue.head != memory::FrameLease::EMPTY).then_some(queue.head);
    let mut previous = None;
    let mut selected = None;
    let mut selected_previous = None;
    for (ordinal, _) in (0..WALK_LIMIT).enumerate() {
        let Some(frame) = current else { break };
        let page = message_page(frame).ok_or(Error::Invalid)?;
        let matches = if copy {
            i64::try_from(ordinal).is_ok_and(|ordinal| ordinal == selector)
        } else if selector == 0 {
            true
        } else if selector > 0 && except {
            page.message_type != selector
        } else if selector > 0 {
            page.message_type == selector
        } else {
            page.message_type <= selector.checked_abs().ok_or(Error::Invalid)?
        };
        if matches
            && (selected.is_none()
                || selector < 0
                    && message_page(selected.unwrap())
                        .is_none_or(|prior| page.message_type < prior.message_type))
        {
            selected = Some(frame);
            selected_previous = previous;
            if selector >= 0 {
                break;
            }
        }
        previous = current;
        current = (page.next_message != memory::FrameLease::EMPTY).then_some(page.next_message);
    }
    let selected = selected.ok_or(Error::WouldBlock)?;
    let first = message_page(selected).ok_or(Error::Invalid)?;
    let message_size = usize::try_from(first.size).map_err(|_| Error::Invalid)?;
    if message_size > size && !no_error {
        return Err(Error::TooBig);
    }
    let copied = message_size.min(size);
    if copied == 0 && !write(first.message_type, 0, &[]) {
        return Err(Error::Fault);
    }
    let mut page_frame = selected;
    let mut offset = 0;
    while offset < copied {
        let page = message_page(page_frame).ok_or(Error::Invalid)?;
        let length = usize::from(page.used).min(copied - offset);
        if length == 0 || !write(first.message_type, offset, &page.bytes[..length]) {
            return Err(Error::Fault);
        }
        offset += length;
        if offset < copied {
            if page.next_page == memory::FrameLease::EMPTY {
                return Err(Error::Invalid);
            }
            page_frame = page.next_page;
        }
    }
    if copy {
        return Ok(copied);
    }
    let next = (first.next_message != memory::FrameLease::EMPTY).then_some(first.next_message);
    let queue = message_queue_mut(queue_frame).ok_or(Error::Invalid)?;
    if let Some(previous) = selected_previous {
        message_page_mut(previous)
            .ok_or(Error::Invalid)?
            .next_message = next.unwrap_or(memory::FrameLease::EMPTY);
    } else {
        queue.head = next.unwrap_or(memory::FrameLease::EMPTY);
    }
    if queue.tail == selected {
        queue.tail = selected_previous.unwrap_or(memory::FrameLease::EMPTY);
    }
    queue.bytes = queue
        .bytes
        .checked_sub(message_size as u64)
        .ok_or(Error::Invalid)?;
    queue.messages = queue.messages.checked_sub(1).ok_or(Error::Invalid)?;
    queue.last_receiver = pid;
    release_message(selected)
        .then_some(copied)
        .ok_or(Error::Invalid)
}

pub(crate) fn message_queue_set(id: u32, mode: u16, byte_limit: u64) -> Result<(), Error> {
    if byte_limit == 0 {
        return Err(Error::Invalid);
    }
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, _) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue_mut(frame).ok_or(Error::Invalid)?;
    if byte_limit < queue.bytes {
        return Err(Error::Invalid);
    }
    queue.mode = mode & 0o777;
    queue.byte_limit = byte_limit;
    Ok(())
}

pub(crate) fn message_queue_remove(id: u32) -> Result<(), Error> {
    let guard = Guard::acquire().ok_or(Error::Invalid)?;
    let (frame, previous) = find_message_queue(guard.instance, id).ok_or(Error::Invalid)?;
    let queue = message_queue(frame).ok_or(Error::Invalid)?;
    let next = (queue.next_queue != memory::FrameLease::EMPTY).then_some(queue.next_queue);
    let messages = (queue.head != memory::FrameLease::EMPTY).then_some(queue.head);
    if let Some(previous) = previous {
        message_queue_mut(previous)
            .ok_or(Error::Invalid)?
            .next_queue = next.unwrap_or(memory::FrameLease::EMPTY);
    } else {
        publish_root(
            &SYSV_IPC_RUNTIME.message_root_addresses,
            &SYSV_IPC_RUNTIME.message_root_generations,
            guard.instance,
            next,
        );
    }
    if !release_messages(messages)
        || !memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[frame])
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(crate) fn verify_message_queue_lifecycle() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Ok(id) = message_get_or_create(0x4d53_4751, 0o620, true, true, None) else {
        return false;
    };
    let large_size = MESSAGE_CAPACITY + 37;
    let large_sent = message_send(id, 3, large_size, 1, |offset, bytes| {
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = ((offset + index) % 251) as u8;
        }
        true
    });
    let small = b"second";
    let small_sent = message_send(id, 1, small.len(), 1, |offset, bytes| {
        let Some(source) = small.get(offset..offset + bytes.len()) else {
            return false;
        };
        bytes.copy_from_slice(source);
        true
    });
    let initial_info = message_queue_info(id)
        .is_ok_and(|queue| queue.messages == 2 && queue.bytes == (large_size + small.len()) as u64);
    let selected_small = message_receive(
        id,
        small.len(),
        -2,
        false,
        false,
        false,
        2,
        |message_type, offset, bytes| {
            message_type == 1 && small.get(offset..offset + bytes.len()) == Some(bytes)
        },
    );
    let mut copied = 0;
    let after_small = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let copied_large = message_receive(
        id,
        large_size,
        0,
        false,
        false,
        true,
        2,
        |message_type, offset, bytes| {
            let valid = message_type == 3
                && bytes
                    .iter()
                    .enumerate()
                    .all(|(index, byte)| *byte == ((offset + index) % 251) as u8);
            copied += bytes.len();
            valid
        },
    );
    let after_copy = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let too_big = message_receive(id, 8, 3, false, false, false, 2, |_, _, _| true);
    let after_too_big = message_queue_info(id).is_ok_and(|queue| queue.messages == 1);
    let mut truncated = [0_u8; 8];
    let truncated_large = message_receive(
        id,
        truncated.len(),
        3,
        true,
        false,
        false,
        2,
        |message_type, offset, bytes| {
            if message_type != 3 || offset + bytes.len() > truncated.len() {
                return false;
            }
            truncated[offset..offset + bytes.len()].copy_from_slice(bytes);
            true
        },
    );
    let after_truncated = message_queue_info(id).is_ok_and(|queue| queue.messages == 0);
    let verified = large_sent.is_ok()
        && small_sent.is_ok()
        && initial_info
        && selected_small == Ok(small.len())
        && after_small
        && copied_large == Ok(large_size)
        && copied == large_size
        && after_copy
        && too_big == Err(Error::TooBig)
        && after_too_big
        && truncated_large == Ok(truncated.len())
        && after_truncated
        && truncated
            .iter()
            .enumerate()
            .all(|(index, byte)| *byte == (index % 251) as u8)
        && message_queue_set(id, 0o600, 32_768).is_ok()
        && message_queue_info(id).is_ok_and(|queue| {
            queue.mode == 0o600 && queue.byte_limit == 32_768 && queue.messages == 0
        })
        && message_queue_remove(id).is_ok()
        && matches!(message_queue_info(id), Err(Error::Invalid));
    verified && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
}

pub(crate) fn verify_semaphore_lifecycle() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Ok(id) = semaphore_get_or_create(
        0x5345_4d41,
        (SEMAPHORE_CAPACITY + 7) as u64,
        0o640,
        true,
        true,
        1,
    ) else {
        return false;
    };
    let operations = [
        SemaphoreOperation {
            number: 0,
            operation: -2,
            flags: 0,
        },
        SemaphoreOperation {
            number: 1,
            operation: 3,
            flags: 0,
        },
    ];
    let blocked = [
        SemaphoreOperation {
            number: 0,
            operation: -1,
            flags: 0,
        },
        SemaphoreOperation {
            number: 1,
            operation: 4,
            flags: 0,
        },
    ];
    let verified = semaphore_set_value(id, 0, 2, 1).is_ok()
        && semaphore_apply(id, operations.len(), 1, |index| {
            operations.get(index).copied()
        }) == Ok(None)
        && semaphore_get(id, 0).is_ok_and(|value| value.0 == 0 && value.1 == 1)
        && semaphore_get(id, 1).is_ok_and(|value| value.0 == 3 && value.1 == 1)
        && semaphore_apply(id, blocked.len(), 2, |index| blocked.get(index).copied())
            == Ok(Some(SemaphoreBlock {
                number: 0,
                zero: false,
            }))
        && semaphore_get(id, 1).is_ok_and(|value| value.0 == 3)
        && semaphore_set_all(id, 3, |index| Some((index % 101) as u16)).is_ok()
        && semaphore_get(id, SEMAPHORE_CAPACITY + 6)
            .is_ok_and(|value| value.0 == ((SEMAPHORE_CAPACITY + 6) % 101) as u16)
        && semaphore_set_mode(id, 0o600, 3).is_ok()
        && semaphore_set(id)
            .is_ok_and(|set| set.count == (SEMAPHORE_CAPACITY + 7) as u64 && set.mode == 0o600)
        && semaphore_remove(id).is_ok()
        && matches!(semaphore_set(id), Err(Error::Invalid));
    verified && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
}

pub(crate) fn verify_shared_memory_lifecycle() -> bool {
    let Some(before) = memory::owner_live_frame_count(memory::FrameOwner::KERNEL) else {
        return false;
    };
    let Ok(id) = get_or_create(
        0x4749_4e55,
        2 * PAGE_SIZE as u64,
        0o600,
        true,
        true,
        1,
        SegmentIds {
            requested: None,
            limit: 4096,
        },
    ) else {
        return false;
    };
    let verified = (|| {
        let first = frame(id, 0).ok()?;
        let second = frame(id, 1).ok()?;
        let first_address = first.direct_map_address()?;
        let second_address = second.direct_map_address()?;
        unsafe {
            (first_address as *mut u8).write(0x47);
            (second_address as *mut u8).write(0x58);
        }
        attach(id, 0x4000_0000, 1).ok()?;
        inherit_process_attachments(1, 2).ok()?;
        let state = segment(id).ok()?;
        if state.size != 2 * PAGE_SIZE as u64
            || state.mode != 0o600
            || state.attachments != 2
            || attachment_at(0x4000_0000, 1).ok()? != (id, 2 * PAGE_SIZE as u64)
            || attachment_at(0x4000_0000, 2).ok()? != (id, 2 * PAGE_SIZE as u64)
            || unsafe { (first_address as *const u8).read() } != 0x47
            || unsafe { (second_address as *const u8).read() } != 0x58
        {
            return None;
        }
        mark_for_removal(id, 1).ok()?;
        if segment(id).ok()?.attachments != 2 {
            return None;
        }
        detach(0x4000_0000, 1).ok()?;
        if segment(id).ok()?.attachments != 1 {
            return None;
        }
        drop_process_attachments(2).ok()?;
        matches!(segment(id), Err(Error::Invalid)).then_some(())
    })()
    .is_some();
    verified
        && memory::owner_live_frame_count(memory::FrameOwner::KERNEL) == Some(before)
        && get_or_create(
            0x4749_4e55,
            0,
            0,
            false,
            false,
            1,
            SegmentIds {
                requested: None,
                limit: 4096,
            },
        ) == Err(Error::NoEntry)
}
