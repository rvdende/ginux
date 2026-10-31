//! AMD I/O MMU (AMD-Vi) support: a report of what firmware set up, and DMA
//! remapping that confines each device Ginux drives to its own buffers.
//!
//! Remapping uses one device table for every unit, since a unit only sees
//! the requester IDs behind it. Each device gets one of three policies:
//! blocked (the default, including IDs no PCI function claims), passthrough
//! (display controllers, whose firmware framebuffer may live in system
//! memory), or a private I/O page table that identity-maps only the regions
//! its driver owns. Interrupt remapping is left off; bring-up drivers poll.
//! IVMD unity ranges are not applied yet.

use core::ptr::{addr_of, addr_of_mut};

use super::{wait_until_ms, DmaPage, DmaRegion};

const DEVICE_TABLE_BASE: usize = 0x00;
const COMMAND_BUFFER_BASE: usize = 0x08;
const EVENT_LOG_BASE: usize = 0x10;
const CONTROL: usize = 0x18;
const EXTENDED_FEATURES: usize = 0x30;
const COMMAND_HEAD: usize = 0x2000;
const COMMAND_TAIL: usize = 0x2008;
const EVENT_HEAD: usize = 0x2010;
const EVENT_TAIL: usize = 0x2018;
const STATUS: usize = 0x2020;
const CONTROL_ENABLE: u64 = 1 << 0;
const CONTROL_EVENT_LOG: u64 = 1 << 2;
const CONTROL_COMMAND_BUFFER: u64 = 1 << 12;
const FEATURE_PREFETCH: u64 = 1 << 0;
const FEATURE_PPR: u64 = 1 << 1;
const FEATURE_X2APIC: u64 = 1 << 2;
const FEATURE_NX: u64 = 1 << 3;
const FEATURE_GUEST_TRANSLATION: u64 = 1 << 4;
const FEATURE_INVALIDATE_ALL: u64 = 1 << 6;
const FEATURE_GUEST_APIC: u64 = 1 << 7;
const FEATURE_PERFORMANCE_COUNTERS: u64 = 1 << 9;
/// Device table entries cover every 16-bit requester ID: 512 pages.
const DEVICE_IDS: usize = 1 << 16;
const DEVICE_TABLE_PAGES: u64 = (DEVICE_IDS * 32 / 4096) as u64;
/// The command buffer and event log each hold 2^8 entries of 16 bytes.
const RING_LENGTH_LOG2: u64 = 8;
const RING_BYTES: usize = 4096;
const ENTRY_VALID: u64 = 1 << 0;
const ENTRY_TRANSLATION_VALID: u64 = 1 << 1;
const ENTRY_MODE_SHIFT: u32 = 9;
const ENTRY_READ: u64 = 1 << 61;
const ENTRY_WRITE: u64 = 1 << 62;
/// Three page-table levels translate a 39-bit address space.
const PAGING_LEVELS: u64 = 3;
const PAGE_PRESENT: u64 = 1 << 0;
const PAGE_NEXT_LEVEL_SHIFT: u32 = 9;
const PAGE_TABLE_POOL_PAGES: usize = 64;
const OPCODE_COMPLETION_WAIT: u32 = 1;
const OPCODE_INVALIDATE_DEVICE_ENTRY: u32 = 2;
const OPCODE_INVALIDATE_PAGES: u32 = 3;
const OPCODE_INVALIDATE_ALL: u32 = 8;
const EVENT_IO_PAGE_FAULT: u32 = 2;
const COMMAND_TIMEOUT_MS: u64 = 100;
/// The most requester IDs a table assigns explicitly, which are also the
/// entries invalidated one by one when a unit is enabled.
const ASSIGNED_LIMIT: usize = 512;

#[repr(C, align(4096))]
struct DeviceTable([[u64; 4]; DEVICE_IDS]);

static mut DEVICE_TABLE: DeviceTable = DeviceTable([[0; 4]; DEVICE_IDS]);
static mut COMMANDS: DmaPage = DmaPage::ZERO;
static mut EVENTS: DmaPage = DmaPage::ZERO;
static mut COMPLETION: DmaPage = DmaPage::ZERO;
static mut PAGE_TABLES: [DmaPage; PAGE_TABLE_POOL_PAGES] = [DmaPage::ZERO; PAGE_TABLE_POOL_PAGES];
static mut PAGE_TABLES_USED: usize = 0;

/// What one AMD-Vi unit reports.
pub(crate) struct Report {
    pub(crate) enabled: bool,
    pub(crate) features: u64,
    pub(crate) status: u64,
}

impl Report {
    /// Writes the names of notable supported features.
    pub(crate) fn write_features(&self, output: &mut impl core::fmt::Write) -> core::fmt::Result {
        const NAMES: [(u64, &str); 8] = [
            (FEATURE_PREFETCH, "prefetch"),
            (FEATURE_PPR, "ppr"),
            (FEATURE_X2APIC, "x2apic"),
            (FEATURE_NX, "nx"),
            (FEATURE_GUEST_TRANSLATION, "guest-translation"),
            (FEATURE_INVALIDATE_ALL, "invalidate-all"),
            (FEATURE_GUEST_APIC, "guest-apic"),
            (FEATURE_PERFORMANCE_COUNTERS, "perf-counters"),
        ];
        let mut first = true;
        for (bit, name) in NAMES {
            if self.features & bit != 0 {
                if !first {
                    output.write_char(' ')?;
                }
                output.write_str(name)?;
                first = false;
            }
        }
        if first {
            output.write_str("none")?;
        }
        Ok(())
    }
}

/// Reads the registers of the unit at physical address `base`.
///
/// # Safety
///
/// `base` must be an AMD-Vi MMIO block from IVRS that is identity mapped.
/// Reading these registers has no side effects.
pub(crate) unsafe fn probe(base: u64) -> Report {
    Report {
        enabled: read64(base as usize, CONTROL) & CONTROL_ENABLE != 0,
        features: read64(base as usize, EXTENDED_FEATURES),
        status: read64(base as usize, STATUS),
    }
}

/// How a device may use DMA once remapping is on.
pub(crate) enum Access<'a> {
    Blocked,
    Passthrough,
    /// Only these regions, identity mapped for reads and writes.
    Regions(&'a [DmaRegion]),
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Error {
    OutOfPageTables,
    TooManyDomains,
    TooManyDevices,
    CommandTimedOut,
}

/// A fault the unit logged for a DMA it refused.
pub(crate) struct Fault {
    pub(crate) device: u16,
    pub(crate) address: u64,
    /// The event code; 2 is an I/O page fault.
    pub(crate) code: u32,
}

/// The policies to install. Building a table is separate from enabling it
/// so that every unit shares one device table.
pub(crate) struct DeviceTableBuilder {
    next_domain: u16,
    assigned: [u16; ASSIGNED_LIMIT],
    assigned_count: usize,
}

impl DeviceTableBuilder {
    /// Starts a device table in which every requester ID is blocked.
    ///
    /// # Safety
    ///
    /// No unit may be using the device table or page-table pool, and only
    /// one builder may exist.
    pub(crate) unsafe fn new() -> Self {
        let table = &mut *addr_of_mut!(DEVICE_TABLE);
        for entry in table.0.iter_mut() {
            *entry = [ENTRY_VALID | ENTRY_TRANSLATION_VALID, 0, 0, 0];
        }
        PAGE_TABLES_USED = 0;
        Self {
            next_domain: 1,
            assigned: [0; ASSIGNED_LIMIT],
            assigned_count: 0,
        }
    }

    /// Sets the policy of requester ID `device`.
    pub(crate) fn assign(&mut self, device: u16, access: Access<'_>) -> Result<(), Error> {
        if self.assigned_count == ASSIGNED_LIMIT {
            return Err(Error::TooManyDevices);
        }
        self.assigned[self.assigned_count] = device;
        self.assigned_count += 1;
        let entry = match access {
            Access::Blocked => [ENTRY_VALID | ENTRY_TRANSLATION_VALID, 0, 0, 0],
            Access::Passthrough => [
                ENTRY_VALID | ENTRY_TRANSLATION_VALID | ENTRY_READ | ENTRY_WRITE,
                0,
                0,
                0,
            ],
            Access::Regions(regions) => {
                let domain = self.next_domain;
                self.next_domain = domain.checked_add(1).ok_or(Error::TooManyDomains)?;
                let root = allocate_page_table()?;
                for region in regions {
                    let start = region.start & !0xfff;
                    let end = (region.start + region.length + 0xfff) & !0xfff;
                    for page in (start..end).step_by(4096) {
                        map_identity(root, page)?;
                    }
                }
                [
                    ENTRY_VALID
                        | ENTRY_TRANSLATION_VALID
                        | PAGING_LEVELS << ENTRY_MODE_SHIFT
                        | root
                        | ENTRY_READ
                        | ENTRY_WRITE,
                    u64::from(domain),
                    0,
                    0,
                ]
            }
        };
        // SAFETY: the builder owns the device table until units use it.
        unsafe { (*addr_of_mut!(DEVICE_TABLE)).0[usize::from(device)] = entry };
        Ok(())
    }

    /// The number of devices given private page tables.
    pub(crate) fn domains(&self) -> u16 {
        self.next_domain - 1
    }

    /// The requester IDs given an explicit policy.
    pub(crate) fn assigned(&self) -> &[u16] {
        &self.assigned[..self.assigned_count]
    }
}

/// One unit with remapping turned on.
pub(crate) struct Remapping {
    base: usize,
}

impl Remapping {
    /// Points the unit at `base` to the device table built so far, enables
    /// its command buffer and event log, turns on translation, and flushes
    /// whatever firmware left in its caches.
    ///
    /// # Safety
    ///
    /// `base` must be an identity-mapped AMD-Vi unit from IVRS that nothing
    /// else drives, and the device table must not change while it is on.
    pub(crate) unsafe fn enable(base: u64, table: &DeviceTableBuilder) -> Result<Self, Error> {
        let base = base as usize;
        let control = read64(base, CONTROL);
        write64(
            base,
            CONTROL,
            control & !(CONTROL_ENABLE | CONTROL_COMMAND_BUFFER | CONTROL_EVENT_LOG),
        );
        (*addr_of_mut!(COMMANDS)).0.fill(0);
        (*addr_of_mut!(EVENTS)).0.fill(0);
        write64(
            base,
            DEVICE_TABLE_BASE,
            addr_of!(DEVICE_TABLE) as u64 | (DEVICE_TABLE_PAGES - 1),
        );
        write64(
            base,
            COMMAND_BUFFER_BASE,
            addr_of!(COMMANDS) as u64 | RING_LENGTH_LOG2 << 56,
        );
        write64(
            base,
            EVENT_LOG_BASE,
            addr_of!(EVENTS) as u64 | RING_LENGTH_LOG2 << 56,
        );
        for register in [COMMAND_HEAD, COMMAND_TAIL, EVENT_HEAD, EVENT_TAIL] {
            write64(base, register, 0);
        }
        write64(
            base,
            CONTROL,
            control | CONTROL_COMMAND_BUFFER | CONTROL_EVENT_LOG | CONTROL_ENABLE,
        );
        let mut unit = Self { base };
        // Invalidate each assigned entry even when the unit can invalidate
        // everything at once: emulated units such as QEMU's re-read device
        // policies on these.
        if read64(base, EXTENDED_FEATURES) & FEATURE_INVALIDATE_ALL != 0 {
            unit.command([0, OPCODE_INVALIDATE_ALL << 28, 0, 0])?;
        }
        for device in table.assigned() {
            unit.command([
                u32::from(*device),
                OPCODE_INVALIDATE_DEVICE_ENTRY << 28,
                0,
                0,
            ])?;
        }
        for domain in 0..=table.domains() {
            // S=1 with every address bit set invalidates the whole domain.
            unit.command([
                0,
                u32::from(domain) | OPCODE_INVALIDATE_PAGES << 28,
                0xffff_f000 | 0b11,
                0x7fff_ffff,
            ])?;
        }
        unit.wait()?;
        Ok(unit)
    }

    /// Returns the next fault in the event log, if any.
    pub(crate) fn next_fault(&mut self) -> Option<Fault> {
        let head = read64(self.base, EVENT_HEAD) as usize & (RING_BYTES - 1);
        let tail = read64(self.base, EVENT_TAIL) as usize & (RING_BYTES - 1);
        if head == tail {
            return None;
        }
        // SAFETY: the unit finished writing entries before moving the tail.
        let entry = unsafe {
            let events = addr_of!(EVENTS).cast::<u32>().add(head / 4);
            [
                events.read_volatile(),
                events.add(1).read_volatile(),
                events.add(2).read_volatile(),
                events.add(3).read_volatile(),
            ]
        };
        write64(self.base, EVENT_HEAD, ((head + 16) % RING_BYTES) as u64);
        Some(Fault {
            device: entry[0] as u16,
            address: u64::from(entry[2]) | u64::from(entry[3]) << 32,
            code: entry[1] >> 28,
        })
    }

    /// Queues one command, waiting for room in the buffer.
    fn command(&mut self, words: [u32; 4]) -> Result<(), Error> {
        let tail = read64(self.base, COMMAND_TAIL) as usize & (RING_BYTES - 1);
        let next = (tail + 16) % RING_BYTES;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            read64(self.base, COMMAND_HEAD) as usize & (RING_BYTES - 1) != next
        }) {
            return Err(Error::CommandTimedOut);
        }
        // SAFETY: the slot at the tail is not visible to the unit until the
        // tail moves past it.
        unsafe {
            let slot = addr_of_mut!(COMMANDS).cast::<u32>().add(tail / 4);
            for (index, word) in words.iter().enumerate() {
                slot.add(index).write_volatile(*word);
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write64(self.base, COMMAND_TAIL, next as u64);
        Ok(())
    }

    /// Waits until the unit has finished every queued command.
    fn wait(&mut self) -> Result<(), Error> {
        let store = addr_of_mut!(COMPLETION).cast::<u64>();
        // SAFETY: the completion page is only written here and by the unit.
        unsafe { store.write_volatile(0) };
        let address = store as u64;
        self.command([
            address as u32 | 1,
            (address >> 32) as u32 & 0xf_ffff | OPCODE_COMPLETION_WAIT << 28,
            1,
            0,
        ])?;
        // SAFETY: as above.
        if wait_until_ms(COMMAND_TIMEOUT_MS, || unsafe { store.read_volatile() } == 1) {
            Ok(())
        } else {
            Err(Error::CommandTimedOut)
        }
    }
}

impl Fault {
    /// Whether this is an I/O page fault: a DMA the page tables refused.
    pub(crate) fn is_page_fault(&self) -> bool {
        self.code == EVENT_IO_PAGE_FAULT
    }
}

fn allocate_page_table() -> Result<u64, Error> {
    // SAFETY: the builder has exclusive use of the pool.
    unsafe {
        if PAGE_TABLES_USED == PAGE_TABLE_POOL_PAGES {
            return Err(Error::OutOfPageTables);
        }
        let page = addr_of_mut!(PAGE_TABLES[PAGE_TABLES_USED]);
        PAGE_TABLES_USED += 1;
        (*page).0.fill(0);
        Ok(page as u64)
    }
}

/// Maps `page` to itself, readable and writable, in the three-level table
/// rooted at `root`, adding intermediate tables as needed.
fn map_identity(root: u64, page: u64) -> Result<(), Error> {
    let mut table = root;
    for level in (1..=PAGING_LEVELS).rev() {
        let index = ((page >> (12 + 9 * (level - 1))) & 0x1ff) as usize;
        // SAFETY: every table address came from the page-table pool.
        let entry = unsafe { (table as *mut u64).add(index) };
        if level == 1 {
            // A leaf has next level 0.
            unsafe { entry.write_volatile(page | ENTRY_READ | ENTRY_WRITE | PAGE_PRESENT) };
            return Ok(());
        }
        let current = unsafe { entry.read_volatile() };
        table = if current & PAGE_PRESENT != 0 {
            current & 0x000f_ffff_ffff_f000
        } else {
            let next = allocate_page_table()?;
            unsafe {
                entry.write_volatile(
                    next | (level - 1) << PAGE_NEXT_LEVEL_SHIFT
                        | ENTRY_READ
                        | ENTRY_WRITE
                        | PAGE_PRESENT,
                )
            };
            next
        };
    }
    Ok(())
}

fn read64(base: usize, offset: usize) -> u64 {
    // SAFETY: callers pass identity-mapped unit registers.
    unsafe { ((base + offset) as *const u64).read_volatile() }
}

fn write64(base: usize, offset: usize, value: u64) {
    // SAFETY: as for read64.
    unsafe { ((base + offset) as *mut u64).write_volatile(value) }
}
