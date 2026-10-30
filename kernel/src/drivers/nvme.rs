//! Read-only polling NVMe driver.
//!
//! This driver issues only Identify and Read commands. It never writes to the
//! medium, so it is safe to run against a disk that holds another operating
//! system. It uses one admin queue pair and one I/O queue pair without
//! interrupts.

use core::ptr::{addr_of, addr_of_mut};

use super::pci::Function;
use super::{wait_until, BlockDevice, DmaPage};

const REGISTER_CAPABILITIES: usize = 0x00;
const REGISTER_VERSION: usize = 0x08;
const REGISTER_CONFIGURATION: usize = 0x14;
const REGISTER_STATUS: usize = 0x1c;
const REGISTER_ADMIN_QUEUE_ATTRIBUTES: usize = 0x24;
const REGISTER_ADMIN_SUBMISSION_QUEUE: usize = 0x28;
const REGISTER_ADMIN_COMPLETION_QUEUE: usize = 0x30;
const DOORBELL_BASE: usize = 0x1000;
const CONFIGURATION_ENABLE: u32 = 1;
// 64-byte submission and 16-byte completion entries, NVM command set, 4 KiB pages.
const CONFIGURATION_QUEUE_ENTRY_SIZES: u32 = (6 << 16) | (4 << 20);
const STATUS_READY: u32 = 1;
const STATUS_FATAL: u32 = 1 << 1;
const QUEUE_ENTRIES: u16 = 16;
const OPCODE_CREATE_IO_SUBMISSION_QUEUE: u8 = 0x01;
const OPCODE_CREATE_IO_COMPLETION_QUEUE: u8 = 0x05;
const OPCODE_IDENTIFY: u8 = 0x06;
const OPCODE_READ: u8 = 0x02;
const IDENTIFY_NAMESPACE: u32 = 0x00;
const IDENTIFY_CONTROLLER: u32 = 0x01;
const IDENTIFY_ACTIVE_NAMESPACES: u32 = 0x02;
const COMMAND_TIMEOUT_SECONDS: u64 = 5;

static mut ADMIN_SUBMISSION: DmaPage = DmaPage::ZERO;
static mut ADMIN_COMPLETION: DmaPage = DmaPage::ZERO;
static mut IO_SUBMISSION: DmaPage = DmaPage::ZERO;
static mut IO_COMPLETION: DmaPage = DmaPage::ZERO;
static mut DATA: DmaPage = DmaPage::ZERO;

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    UnsupportedPageSize,
    DisableTimedOut,
    EnableTimedOut,
    ControllerFatal,
    CommandTimedOut(u8),
    CommandFailed(u8, u16),
    NoNamespace,
    UnsupportedBlockSize(u32),
    OutOfRange,
}

struct Queue {
    entries: *mut u8,
    completions: *mut u8,
    tail: u16,
    head: u16,
    phase: bool,
    submission_doorbell: usize,
    completion_doorbell: usize,
}

/// An enabled controller with one active namespace.
pub(crate) struct Controller {
    registers: usize,
    admin: Queue,
    io: Queue,
    next_command: u16,
    pub(crate) namespace: u32,
    pub(crate) block_size: u32,
    pub(crate) block_count: u64,
}

/// What Identify Controller reports.
pub(crate) struct ControllerIdentity {
    pub(crate) serial: [u8; 20],
    pub(crate) model: [u8; 40],
    pub(crate) firmware: [u8; 8],
    pub(crate) version: u32,
}

impl Controller {
    /// Resets and enables the controller, identifies it, and opens the first
    /// active namespace for reading.
    ///
    /// # Safety
    ///
    /// `function` must be an NVMe controller that no other code drives, and
    /// its registers and the static DMA pages must be identity mapped.
    pub(crate) unsafe fn open(function: Function) -> Result<(Self, ControllerIdentity), Error> {
        let registers = function.memory_bar(0).ok_or(Error::NoMemoryBar)? as usize;
        function.enable_memory_and_bus_master();
        let capabilities = read64(registers, REGISTER_CAPABILITIES);
        let doorbell_stride = 4_usize << ((capabilities >> 32) & 0xf);
        let minimum_page_shift = 12 + ((capabilities >> 48) & 0xf);
        if minimum_page_shift != 12 {
            return Err(Error::UnsupportedPageSize);
        }
        let ready_timeout = (((capabilities >> 24) & 0xff) / 2).max(1) + 1;

        write32(registers, REGISTER_CONFIGURATION, 0);
        if !wait_until(ready_timeout, || {
            read32(registers, REGISTER_STATUS) & STATUS_READY == 0
        }) {
            return Err(Error::DisableTimedOut);
        }

        let admin = Queue::new(
            addr_of_mut!(ADMIN_SUBMISSION.0).cast(),
            addr_of_mut!(ADMIN_COMPLETION.0).cast(),
            registers + DOORBELL_BASE,
            registers + DOORBELL_BASE + doorbell_stride,
        );
        let io = Queue::new(
            addr_of_mut!(IO_SUBMISSION.0).cast(),
            addr_of_mut!(IO_COMPLETION.0).cast(),
            registers + DOORBELL_BASE + 2 * doorbell_stride,
            registers + DOORBELL_BASE + 3 * doorbell_stride,
        );
        let entries = u32::from(QUEUE_ENTRIES - 1);
        write32(
            registers,
            REGISTER_ADMIN_QUEUE_ATTRIBUTES,
            (entries << 16) | entries,
        );
        write64(
            registers,
            REGISTER_ADMIN_SUBMISSION_QUEUE,
            admin.entries as u64,
        );
        write64(
            registers,
            REGISTER_ADMIN_COMPLETION_QUEUE,
            admin.completions as u64,
        );
        write32(
            registers,
            REGISTER_CONFIGURATION,
            CONFIGURATION_QUEUE_ENTRY_SIZES | CONFIGURATION_ENABLE,
        );
        if !wait_until(ready_timeout, || {
            read32(registers, REGISTER_STATUS) & (STATUS_READY | STATUS_FATAL) != 0
        }) {
            return Err(Error::EnableTimedOut);
        }
        if read32(registers, REGISTER_STATUS) & STATUS_FATAL != 0 {
            return Err(Error::ControllerFatal);
        }

        let mut controller = Self {
            registers,
            admin,
            io,
            next_command: 0,
            namespace: 0,
            block_size: 0,
            block_count: 0,
        };
        let identity = controller.identify_controller()?;
        controller.open_namespace()?;
        controller.create_io_queues()?;
        Ok((controller, identity))
    }

    /// Reads `count` blocks starting at `block` into the shared data page and
    /// returns it. At most one page is transferred.
    pub(crate) fn read(&mut self, block: u64, count: u32) -> Result<&[u8], Error> {
        let bytes = u64::from(count) * u64::from(self.block_size);
        if count == 0
            || bytes > 4096
            || block
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.block_count)
        {
            return Err(Error::OutOfRange);
        }
        let mut command = [0_u32; 16];
        command[1] = self.namespace;
        command[6] = data_address() as u32;
        command[7] = (data_address() >> 32) as u32;
        command[10] = block as u32;
        command[11] = (block >> 32) as u32;
        command[12] = count - 1;
        self.submit(false, OPCODE_READ, command)?;
        // SAFETY: the controller finished writing the page before completing.
        let page = unsafe { &*addr_of!(DATA) };
        Ok(&page.0[..bytes as usize])
    }

    fn identify_controller(&mut self) -> Result<ControllerIdentity, Error> {
        let mut command = [0_u32; 16];
        command[6] = data_address() as u32;
        command[7] = (data_address() >> 32) as u32;
        command[10] = IDENTIFY_CONTROLLER;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        // SAFETY: Identify completed into the data page.
        let data = unsafe { &(*addr_of!(DATA)).0 };
        let mut identity = ControllerIdentity {
            serial: [0; 20],
            model: [0; 40],
            firmware: [0; 8],
            version: read32(self.registers, REGISTER_VERSION),
        };
        identity.serial.copy_from_slice(&data[4..24]);
        identity.model.copy_from_slice(&data[24..64]);
        identity.firmware.copy_from_slice(&data[64..72]);
        Ok(identity)
    }

    fn open_namespace(&mut self) -> Result<(), Error> {
        let mut command = [0_u32; 16];
        command[6] = data_address() as u32;
        command[7] = (data_address() >> 32) as u32;
        command[10] = IDENTIFY_ACTIVE_NAMESPACES;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        // SAFETY: Identify completed into the data page.
        let data = unsafe { &(*addr_of!(DATA)).0 };
        let namespace = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        if namespace == 0 {
            return Err(Error::NoNamespace);
        }

        command[1] = namespace;
        command[10] = IDENTIFY_NAMESPACE;
        self.submit(true, OPCODE_IDENTIFY, command)?;
        // SAFETY: Identify completed into the data page.
        let data = unsafe { &(*addr_of!(DATA)).0 };
        let block_count = u64::from_le_bytes(data[0..8].try_into().unwrap_or([0; 8]));
        let format = usize::from(data[26] & 0x0f);
        let block_shift = u32::from(data[128 + format * 4 + 2]);
        let block_size = 1_u32.checked_shl(block_shift).unwrap_or(0);
        if !(512..=4096).contains(&block_size) {
            return Err(Error::UnsupportedBlockSize(block_size));
        }
        self.namespace = namespace;
        self.block_size = block_size;
        self.block_count = block_count;
        Ok(())
    }

    fn create_io_queues(&mut self) -> Result<(), Error> {
        let size = u32::from(QUEUE_ENTRIES - 1) << 16;
        let mut command = [0_u32; 16];
        command[6] = self.io.completions as u32;
        command[7] = (self.io.completions as u64 >> 32) as u32;
        command[10] = size | 1;
        // Physically contiguous, interrupts disabled.
        command[11] = 1;
        self.submit(true, OPCODE_CREATE_IO_COMPLETION_QUEUE, command)?;

        command[6] = self.io.entries as u32;
        command[7] = (self.io.entries as u64 >> 32) as u32;
        command[10] = size | 1;
        // Completion queue 1, physically contiguous.
        command[11] = (1 << 16) | 1;
        self.submit(true, OPCODE_CREATE_IO_SUBMISSION_QUEUE, command)
    }

    fn submit(&mut self, admin: bool, opcode: u8, mut command: [u32; 16]) -> Result<(), Error> {
        let identifier = self.next_command;
        self.next_command = self.next_command.wrapping_add(1);
        command[0] = u32::from(opcode) | u32::from(identifier) << 16;
        let queue = if admin { &mut self.admin } else { &mut self.io };
        // SAFETY: the queue memory is a static DMA page owned by this driver.
        unsafe {
            let slot = queue
                .entries
                .add(usize::from(queue.tail) * 64)
                .cast::<u32>();
            for (index, word) in command.iter().enumerate() {
                slot.add(index).write_volatile(*word);
            }
        }
        queue.tail = (queue.tail + 1) % QUEUE_ENTRIES;
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write32(queue.submission_doorbell, 0, u32::from(queue.tail));

        let completion = queue.completions as usize + usize::from(queue.head) * 16;
        let phase = queue.phase;
        if !wait_until(COMMAND_TIMEOUT_SECONDS, || {
            (read32(completion, 12) >> 16 & 1 != 0) == phase
        }) {
            return Err(Error::CommandTimedOut(opcode));
        }
        let status = (read32(completion, 12) >> 17) as u16;
        queue.head += 1;
        if queue.head == QUEUE_ENTRIES {
            queue.head = 0;
            queue.phase = !queue.phase;
        }
        write32(queue.completion_doorbell, 0, u32::from(queue.head));
        if status & 0x7ff != 0 {
            return Err(Error::CommandFailed(opcode, status));
        }
        Ok(())
    }
}

impl Queue {
    fn new(
        entries: *mut u8,
        completions: *mut u8,
        submission_doorbell: usize,
        completion_doorbell: usize,
    ) -> Self {
        // SAFETY: both pointers are static DMA pages owned by this driver.
        unsafe {
            entries.write_bytes(0, 4096);
            completions.write_bytes(0, 4096);
        }
        Self {
            entries,
            completions,
            tail: 0,
            head: 0,
            phase: true,
            submission_doorbell,
            completion_doorbell,
        }
    }
}

fn data_address() -> u64 {
    addr_of!(DATA) as u64
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: callers pass identity-mapped controller registers or DMA memory.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read32.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}

fn read64(base: usize, offset: usize) -> u64 {
    u64::from(read32(base, offset)) | u64::from(read32(base, offset + 4)) << 32
}

fn write64(base: usize, offset: usize, value: u64) {
    write32(base, offset, value as u32);
    write32(base, offset + 4, (value >> 32) as u32);
}

impl BlockDevice for Controller {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn read_blocks(&mut self, block: u64, count: u32) -> Option<&[u8]> {
        self.read(block, count).ok()
    }
}
