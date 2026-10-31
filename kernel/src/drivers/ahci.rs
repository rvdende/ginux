//! Read-only polling AHCI (SATA) driver.
//!
//! Like the NVMe driver, this driver only issues IDENTIFY DEVICE and READ DMA
//! EXT, so it never modifies a disk. It drives one command slot per port
//! without interrupts.

use core::ptr::{addr_of, addr_of_mut};

use super::pci::Function;
use super::{wait_until_ms, BlockDevice, DmaPage, DmaRegion};

const HBA_GLOBAL_CONTROL: usize = 0x04;
const HBA_PORTS_IMPLEMENTED: usize = 0x0c;
const HBA_VERSION: usize = 0x10;
const HBA_CAPABILITIES_2: usize = 0x24;
const HBA_HANDOFF: usize = 0x28;
const GLOBAL_AHCI_ENABLE: u32 = 1 << 31;
const HANDOFF_SUPPORTED: u32 = 1 << 0;
const HANDOFF_BIOS_OWNED: u32 = 1 << 0;
const HANDOFF_OS_OWNED: u32 = 1 << 1;
const PORT_BASE: usize = 0x100;
const PORT_STRIDE: usize = 0x80;
const PORT_COMMAND_LIST: usize = 0x00;
const PORT_FIS_BASE: usize = 0x08;
const PORT_INTERRUPT_STATUS: usize = 0x10;
const PORT_INTERRUPT_ENABLE: usize = 0x14;
const PORT_COMMAND: usize = 0x18;
const PORT_TASK_FILE: usize = 0x20;
const PORT_SIGNATURE: usize = 0x24;
const PORT_STATUS: usize = 0x28;
const PORT_ERROR: usize = 0x30;
const PORT_COMMAND_ISSUE: usize = 0x38;
const COMMAND_START: u32 = 1 << 0;
const COMMAND_FIS_RECEIVE: u32 = 1 << 4;
const COMMAND_FIS_RUNNING: u32 = 1 << 14;
const COMMAND_LIST_RUNNING: u32 = 1 << 15;
const TASK_FILE_BUSY: u32 = 1 << 7;
const TASK_FILE_DATA_REQUEST: u32 = 1 << 3;
const TASK_FILE_ERROR: u32 = 1 << 0;
const INTERRUPT_TASK_FILE_ERROR: u32 = 1 << 30;
const STATUS_DEVICE_PRESENT: u32 = 3;
const SIGNATURE_ATA: u32 = 0x0000_0101;
const FIS_HOST_TO_DEVICE: u8 = 0x27;
const ATA_IDENTIFY_DEVICE: u8 = 0xec;
const ATA_READ_DMA_EXT: u8 = 0x25;
const COMMAND_TIMEOUT_MS: u64 = 5000;
/// Ports the driver can drive at once; each needs three DMA pages.
pub(crate) const MAX_PORTS: usize = 8;

static mut COMMAND_LISTS: [DmaPage; MAX_PORTS] = [DmaPage::ZERO; MAX_PORTS];
static mut COMMAND_TABLES: [DmaPage; MAX_PORTS] = [DmaPage::ZERO; MAX_PORTS];
static mut BUFFERS: [DmaPage; MAX_PORTS] = [DmaPage::ZERO; MAX_PORTS];

/// The memory AHCI controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 3] {
    [
        DmaRegion::of(addr_of!(COMMAND_LISTS)),
        DmaRegion::of(addr_of!(COMMAND_TABLES)),
        DmaRegion::of(addr_of!(BUFFERS)),
    ]
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    NoDevice,
    NotAta(u32),
    StopTimedOut,
    CommandTimedOut(u8),
    CommandFailed(u8, u32),
}

/// An ATA disk on one AHCI port.
pub(crate) struct Disk {
    port: usize,
    registers: usize,
    slot: usize,
    pub(crate) sectors: u64,
    pub(crate) sector_size: u32,
    pub(crate) model: [u8; 40],
    pub(crate) serial: [u8; 20],
}

/// Takes the controller from firmware, enables AHCI mode, and returns its
/// register base and the bitmap of implemented ports.
///
/// # Safety
///
/// `function` must be an AHCI controller that no other code drives, with its
/// registers identity mapped.
pub(crate) unsafe fn open_controller(function: Function) -> Result<(usize, u32, u32), Error> {
    let base = function.memory_bar(5).ok_or(Error::NoMemoryBar)? as usize;
    function.enable_memory_and_bus_master();
    if read32(base, HBA_CAPABILITIES_2) & HANDOFF_SUPPORTED != 0 {
        write32(
            base,
            HBA_HANDOFF,
            read32(base, HBA_HANDOFF) | HANDOFF_OS_OWNED,
        );
        let _ = wait_until_ms(2000, || read32(base, HBA_HANDOFF) & HANDOFF_BIOS_OWNED == 0);
    }
    write32(
        base,
        HBA_GLOBAL_CONTROL,
        read32(base, HBA_GLOBAL_CONTROL) | GLOBAL_AHCI_ENABLE,
    );
    Ok((
        base,
        read32(base, HBA_PORTS_IMPLEMENTED),
        read32(base, HBA_VERSION),
    ))
}

impl Disk {
    /// Brings up `port` of the controller at `base` and identifies its disk.
    /// `slot` selects which of the driver's DMA page sets the port uses.
    ///
    /// # Safety
    ///
    /// The controller must have been opened with [`open_controller`], and no
    /// other code may use `port` or DMA set `slot`.
    pub(crate) unsafe fn open(base: usize, port: usize, slot: usize) -> Result<Self, Error> {
        if slot >= MAX_PORTS {
            return Err(Error::NoDevice);
        }
        let registers = base + PORT_BASE + port * PORT_STRIDE;
        if read32(registers, PORT_STATUS) & 0xf != STATUS_DEVICE_PRESENT {
            return Err(Error::NoDevice);
        }
        let signature = read32(registers, PORT_SIGNATURE);
        if signature != SIGNATURE_ATA {
            return Err(Error::NotAta(signature));
        }
        // Stop the command engine before moving its structures.
        let command = read32(registers, PORT_COMMAND);
        write32(
            registers,
            PORT_COMMAND,
            command & !(COMMAND_START | COMMAND_FIS_RECEIVE),
        );
        if !wait_until_ms(500, || {
            read32(registers, PORT_COMMAND) & (COMMAND_LIST_RUNNING | COMMAND_FIS_RUNNING) == 0
        }) {
            return Err(Error::StopTimedOut);
        }
        let command_list = addr_of_mut!(COMMAND_LISTS).cast::<DmaPage>().add(slot);
        (*command_list).0.fill(0);
        // The command list uses the first 1 KiB; received FISes the next 256 bytes.
        let list = command_list as u64;
        let fis = list + 1024;
        write32(registers, PORT_COMMAND_LIST, list as u32);
        write32(registers, PORT_COMMAND_LIST + 4, (list >> 32) as u32);
        write32(registers, PORT_FIS_BASE, fis as u32);
        write32(registers, PORT_FIS_BASE + 4, (fis >> 32) as u32);
        write32(registers, PORT_ERROR, u32::MAX);
        write32(registers, PORT_INTERRUPT_STATUS, u32::MAX);
        write32(registers, PORT_INTERRUPT_ENABLE, 0);
        write32(
            registers,
            PORT_COMMAND,
            read32(registers, PORT_COMMAND) | COMMAND_FIS_RECEIVE,
        );
        write32(
            registers,
            PORT_COMMAND,
            read32(registers, PORT_COMMAND) | COMMAND_START,
        );

        let mut disk = Self {
            port,
            registers,
            slot,
            sectors: 0,
            sector_size: 512,
            model: [0; 40],
            serial: [0; 20],
        };
        disk.issue(ATA_IDENTIFY_DEVICE, 0, 0, 512)?;
        let identify = &(*addr_of!(BUFFERS).cast::<DmaPage>().add(slot)).0;
        let word =
            |index: usize| u16::from_le_bytes([identify[index * 2], identify[index * 2 + 1]]);
        // ATA strings store each pair of characters big-endian.
        for (index, pair) in disk.model.chunks_mut(2).enumerate() {
            pair.copy_from_slice(&word(27 + index).to_be_bytes());
        }
        for (index, pair) in disk.serial.chunks_mut(2).enumerate() {
            pair.copy_from_slice(&word(10 + index).to_be_bytes());
        }
        disk.sectors = (0..4).fold(0, |total, index| {
            total | u64::from(word(100 + index)) << (16 * index)
        });
        let sector_info = word(106);
        if sector_info & 0xc000 == 0x4000 && sector_info & (1 << 12) != 0 {
            disk.sector_size = (u32::from(word(117)) | u32::from(word(118)) << 16) * 2;
        }
        Ok(disk)
    }

    pub(crate) fn port(&self) -> usize {
        self.port
    }

    fn issue(&mut self, command: u8, lba: u64, count: u16, bytes: u32) -> Result<(), Error> {
        // SAFETY: the DMA pages for `slot` belong to this disk.
        unsafe {
            let header = addr_of_mut!(COMMAND_LISTS)
                .cast::<DmaPage>()
                .add(self.slot)
                .cast::<u32>();
            let table = addr_of_mut!(COMMAND_TABLES)
                .cast::<DmaPage>()
                .add(self.slot);
            let buffer = addr_of_mut!(BUFFERS).cast::<DmaPage>().add(self.slot);
            (*table).0.fill(0);
            // Header 0: five-dword FIS, device-to-host (read), one PRD entry.
            header.write_volatile(5 | 1 << 16);
            header.add(1).write_volatile(0);
            header.add(2).write_volatile(table as u32);
            header.add(3).write_volatile((table as u64 >> 32) as u32);
            let fis = &mut (*table).0;
            fis[0] = FIS_HOST_TO_DEVICE;
            fis[1] = 0x80;
            fis[2] = command;
            fis[4] = lba as u8;
            fis[5] = (lba >> 8) as u8;
            fis[6] = (lba >> 16) as u8;
            fis[7] = 0x40;
            fis[8] = (lba >> 24) as u8;
            fis[9] = (lba >> 32) as u8;
            fis[10] = (lba >> 40) as u8;
            fis[12] = count as u8;
            fis[13] = (count >> 8) as u8;
            let prd = table.cast::<u32>().add(0x80 / 4);
            prd.write_volatile(buffer as u32);
            prd.add(1).write_volatile((buffer as u64 >> 32) as u32);
            prd.add(3).write_volatile(bytes - 1);
        }
        let registers = self.registers;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            read32(registers, PORT_TASK_FILE) & (TASK_FILE_BUSY | TASK_FILE_DATA_REQUEST) == 0
        }) {
            return Err(Error::CommandTimedOut(command));
        }
        write32(registers, PORT_INTERRUPT_STATUS, u32::MAX);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write32(registers, PORT_COMMAND_ISSUE, 1);
        let mut failed = false;
        let finished = wait_until_ms(COMMAND_TIMEOUT_MS, || {
            if read32(registers, PORT_INTERRUPT_STATUS) & INTERRUPT_TASK_FILE_ERROR != 0 {
                failed = true;
                return true;
            }
            read32(registers, PORT_COMMAND_ISSUE) & 1 == 0
        });
        if failed || read32(registers, PORT_TASK_FILE) & TASK_FILE_ERROR != 0 {
            return Err(Error::CommandFailed(
                command,
                read32(registers, PORT_TASK_FILE),
            ));
        }
        if !finished {
            return Err(Error::CommandTimedOut(command));
        }
        Ok(())
    }
}

impl BlockDevice for Disk {
    fn block_size(&self) -> u32 {
        self.sector_size
    }

    fn read_blocks(&mut self, block: u64, count: u32) -> Option<&[u8]> {
        let bytes = u64::from(count) * u64::from(self.sector_size);
        if count == 0
            || bytes > 4096
            || block
                .checked_add(u64::from(count))
                .is_none_or(|end| end > self.sectors)
        {
            return None;
        }
        self.issue(ATA_READ_DMA_EXT, block, count as u16, bytes as u32)
            .ok()?;
        // SAFETY: the read completed into this disk's buffer page.
        let page = unsafe { &*addr_of!(BUFFERS).cast::<DmaPage>().add(self.slot) };
        Some(&page.0[..bytes as usize])
    }
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: callers pass identity-mapped controller registers.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read32.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}
