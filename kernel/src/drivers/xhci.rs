//! Polling xHCI driver for USB HID boot keyboards on root ports.
//!
//! The driver takes each controller from firmware, resets it, and brings up
//! the command and event rings without interrupts. It enumerates root ports
//! and configures every device that exposes a HID boot keyboard interface,
//! keeping one report transfer queued per keyboard. Each controller draws its
//! DMA memory from a static pool, so several controllers can run at once; a
//! controller without keyboards returns its pages. Hubs are not supported yet,
//! so keyboards must be on root ports.

use core::ptr::addr_of_mut;

use super::pci::Function;
use super::{delay_ms, say, wait_until_ms, DmaPage};

const CAP_LENGTH: usize = 0x00;
const CAP_STRUCTURAL_1: usize = 0x04;
const CAP_STRUCTURAL_2: usize = 0x08;
const CAP_CAPABILITY_1: usize = 0x10;
const CAP_DOORBELL_OFFSET: usize = 0x14;
const CAP_RUNTIME_OFFSET: usize = 0x18;
const OP_COMMAND: usize = 0x00;
const OP_STATUS: usize = 0x04;
const OP_COMMAND_RING: usize = 0x18;
const OP_DEVICE_CONTEXTS: usize = 0x30;
const OP_CONFIGURE: usize = 0x38;
const OP_PORTS: usize = 0x400;
const COMMAND_RUN: u32 = 1 << 0;
const COMMAND_RESET: u32 = 1 << 1;
const STATUS_HALTED: u32 = 1 << 0;
const STATUS_NOT_READY: u32 = 1 << 11;
const PORT_CONNECTED: u32 = 1 << 0;
const PORT_ENABLED: u32 = 1 << 1;
const PORT_RESET: u32 = 1 << 4;
const PORT_POWER: u32 = 1 << 9;
const PORT_RESET_CHANGE: u32 = 1 << 21;
// Bits that keep their value when written back; all others are RW1C/RW1S.
const PORT_PRESERVE: u32 = PORT_POWER | (0xf << 5) | (3 << 14) | (7 << 25);
const PORT_CHANGE_BITS: u32 = 0x7f << 17;
const LEGACY_SUPPORT: u32 = 1;
const LEGACY_BIOS_OWNED: u32 = 1 << 16;
const LEGACY_OS_OWNED: u32 = 1 << 24;
const LEGACY_DISABLE_SMI: u32 = (0x7 << 1) | (0xff << 5) | (0x7 << 17);
const LEGACY_SMI_EVENTS: u32 = 0x7 << 29;

const TRB_NORMAL: u32 = 1;
const TRB_SETUP: u32 = 2;
const TRB_DATA: u32 = 3;
const TRB_STATUS: u32 = 4;
const TRB_LINK: u32 = 6;
const TRB_ENABLE_SLOT: u32 = 9;
const TRB_ADDRESS_DEVICE: u32 = 11;
const TRB_CONFIGURE_ENDPOINT: u32 = 12;
const TRB_EVALUATE_CONTEXT: u32 = 13;
const TRB_TRANSFER_EVENT: u32 = 32;
const TRB_COMMAND_COMPLETION: u32 = 33;
const TRB_CYCLE: u32 = 1 << 0;
const TRB_TOGGLE_CYCLE: u32 = 1 << 1;
const TRB_INTERRUPT_ON_COMPLETION: u32 = 1 << 5;
const TRB_IMMEDIATE_DATA: u32 = 1 << 6;
const TRB_DIRECTION_IN: u32 = 1 << 16;
const COMPLETION_SUCCESS: u32 = 1;
const COMPLETION_SHORT_PACKET: u32 = 13;
const RING_TRBS: usize = 256;
const MAX_SLOTS: u32 = 32;
const MAX_SCRATCHPADS: usize = 256;
/// Keyboards configured on one controller.
pub(crate) const MAX_KEYBOARDS: usize = 4;
const ENDPOINT_CONTROL: u32 = 4;
const ENDPOINT_INTERRUPT_IN: u32 = 7;
const SPEED_FULL: u32 = 1;
const SPEED_LOW: u32 = 2;
const SPEED_HIGH: u32 = 3;
const REQUEST_GET_DESCRIPTOR: u8 = 6;
const REQUEST_SET_CONFIGURATION: u8 = 9;
const REQUEST_HID_SET_IDLE: u8 = 0x0a;
const REQUEST_HID_SET_PROTOCOL: u8 = 0x0b;
const DESCRIPTOR_DEVICE: u16 = 1;
const DESCRIPTOR_CONFIGURATION: u16 = 2;
const COMMAND_TIMEOUT_MS: u64 = 1000;
const POOL_PAGES: usize = 1536;

static mut POOL: [DmaPage; POOL_PAGES] = [DmaPage::ZERO; POOL_PAGES];
static mut POOL_NEXT: usize = 0;

/// Takes `count` zeroed, contiguous pages from the DMA pool.
fn pool_pages(count: usize) -> Option<*mut DmaPage> {
    // SAFETY: bring-up is single-threaded; pages are handed out once.
    unsafe {
        let next = POOL_NEXT;
        let end = next.checked_add(count).filter(|end| *end <= POOL_PAGES)?;
        POOL_NEXT = end;
        let pages = addr_of_mut!(POOL).cast::<DmaPage>().add(next);
        pages.cast::<u8>().write_bytes(0, count * 4096);
        Some(pages)
    }
}

fn pool_mark() -> usize {
    // SAFETY: as for pool_pages.
    unsafe { POOL_NEXT }
}

fn pool_release_to(mark: usize) {
    // SAFETY: callers release only pages they took after `mark` and no longer use.
    unsafe { POOL_NEXT = mark.min(POOL_NEXT) }
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    HaltTimedOut,
    ResetTimedOut,
    OutOfDmaMemory,
    TooManyScratchpads(usize),
    CommandTimedOut(u32),
    CommandFailed(u32, u32),
    TransferTimedOut,
    TransferFailed(u32),
    NotConnected,
    PortResetFailed,
    NotBootKeyboard(u16, u16),
    NoKeyboard,
}

struct Ring {
    trbs: *mut u32,
    index: usize,
    cycle: bool,
}

impl Ring {
    /// Builds a ring in the zeroed page `page`.
    fn new(page: *mut DmaPage) -> Self {
        let trbs = page.cast::<u32>();
        // SAFETY: the page is a zeroed pool page owned by this ring.
        unsafe {
            // The last TRB links back to the start and toggles the cycle state.
            let link = trbs.add((RING_TRBS - 1) * 4);
            let base = trbs as u64;
            link.write_volatile(base as u32);
            link.add(1).write_volatile((base >> 32) as u32);
        }
        Self {
            trbs,
            index: 0,
            cycle: true,
        }
    }

    fn address(&self) -> u64 {
        self.trbs as u64
    }

    /// Writes one TRB and returns its physical address.
    fn push(&mut self, parameter: u64, status: u32, control: u32) -> u64 {
        // SAFETY: index stays below the link TRB; the ring is a pool page.
        unsafe {
            let trb = self.trbs.add(self.index * 4);
            trb.write_volatile(parameter as u32);
            trb.add(1).write_volatile((parameter >> 32) as u32);
            trb.add(2).write_volatile(status);
            trb.add(3)
                .write_volatile(control | (u32::from(self.cycle) * TRB_CYCLE));
            let address = trb as u64;
            self.index += 1;
            if self.index == RING_TRBS - 1 {
                let link = self.trbs.add(self.index * 4);
                link.add(3).write_volatile(
                    TRB_LINK << 10 | TRB_TOGGLE_CYCLE | (u32::from(self.cycle) * TRB_CYCLE),
                );
                self.index = 0;
                self.cycle = !self.cycle;
            }
            address
        }
    }
}

struct Event {
    parameter: u64,
    status: u32,
    control: u32,
}

impl Event {
    fn kind(&self) -> u32 {
        (self.control >> 10) & 0x3f
    }

    fn completion(&self) -> u32 {
        self.status >> 24
    }

    fn slot(&self) -> u32 {
        self.control >> 24
    }
}

/// A configured boot keyboard.
pub(crate) struct Keyboard {
    pub(crate) port: u32,
    pub(crate) vendor: u16,
    pub(crate) product: u16,
    slot: u32,
    endpoint: u32,
    interrupt: Ring,
    report: *mut DmaPage,
}

/// Per-device DMA pages used while addressing and configuring a device.
struct DevicePages {
    output: *mut DmaPage,
    input: *mut DmaPage,
    control: *mut DmaPage,
    interrupt: *mut DmaPage,
    buffer: *mut DmaPage,
}

/// A running controller with at least one configured keyboard.
pub(crate) struct Controller {
    operational: usize,
    runtime: usize,
    doorbells: usize,
    context_size: usize,
    device_contexts: *mut u64,
    commands: Ring,
    events: *mut u32,
    event_index: usize,
    event_cycle: bool,
    keyboards: [Option<Keyboard>; MAX_KEYBOARDS],
}

impl Controller {
    /// Takes over `function`, resets it, and configures every boot keyboard
    /// on its root ports. On failure the controller is halted and its DMA
    /// pages are returned to the pool.
    ///
    /// # Safety
    ///
    /// `function` must be an xHCI controller that no other code drives, and
    /// its registers and the DMA pool must be identity mapped.
    pub(crate) unsafe fn open(function: Function) -> Result<Self, Error> {
        let mark = pool_mark();
        let result = Self::open_inner(function);
        if result.is_err() {
            pool_release_to(mark);
        }
        result
    }

    unsafe fn open_inner(function: Function) -> Result<Self, Error> {
        let base = function.memory_bar(0).ok_or(Error::NoMemoryBar)? as usize;
        function.enable_memory_and_bus_master();
        take_from_firmware(base);

        let operational = base + usize::from(read32(base, CAP_LENGTH) as u8);
        let structural_1 = read32(base, CAP_STRUCTURAL_1);
        let structural_2 = read32(base, CAP_STRUCTURAL_2);
        let capability_1 = read32(base, CAP_CAPABILITY_1);
        let ports = structural_1 >> 24;
        let scratchpads =
            ((((structural_2 >> 21) & 0x1f) << 5) | ((structural_2 >> 27) & 0x1f)) as usize;
        let context_size = if capability_1 & (1 << 2) != 0 { 64 } else { 32 };

        write32(
            operational,
            OP_COMMAND,
            read32(operational, OP_COMMAND) & !COMMAND_RUN,
        );
        if !wait_until_ms(100, || read32(operational, OP_STATUS) & STATUS_HALTED != 0) {
            return Err(Error::HaltTimedOut);
        }
        write32(operational, OP_COMMAND, COMMAND_RESET);
        if !wait_until_ms(1000, || {
            read32(operational, OP_COMMAND) & COMMAND_RESET == 0
                && read32(operational, OP_STATUS) & STATUS_NOT_READY == 0
        }) {
            return Err(Error::ResetTimedOut);
        }

        if scratchpads > MAX_SCRATCHPADS {
            return Err(Error::TooManyScratchpads(scratchpads));
        }
        let device_contexts = pool_pages(1).ok_or(Error::OutOfDmaMemory)?.cast::<u64>();
        if scratchpads != 0 {
            let array = pool_pages(1).ok_or(Error::OutOfDmaMemory)?.cast::<u64>();
            let pages = pool_pages(scratchpads).ok_or(Error::OutOfDmaMemory)?;
            for index in 0..scratchpads {
                array.add(index).write(pages.add(index) as u64);
            }
            device_contexts.write(array as u64);
        }
        let slots = (structural_1 & 0xff).min(MAX_SLOTS);
        write32(operational, OP_CONFIGURE, slots);
        write64(operational, OP_DEVICE_CONTEXTS, device_contexts as u64);

        let commands = Ring::new(pool_pages(1).ok_or(Error::OutOfDmaMemory)?);
        write64(operational, OP_COMMAND_RING, commands.address() | 1);

        let events = pool_pages(1).ok_or(Error::OutOfDmaMemory)?.cast::<u32>();
        let segments = pool_pages(1).ok_or(Error::OutOfDmaMemory)?.cast::<u32>();
        segments.write(events as u32);
        segments.add(1).write((events as u64 >> 32) as u32);
        segments.add(2).write(RING_TRBS as u32);
        let runtime = base + (read32(base, CAP_RUNTIME_OFFSET) & !0x1f) as usize;
        let interrupter = runtime + 0x20;
        write32(interrupter, 0x08, 1);
        write64(interrupter, 0x18, events as u64);
        write64(interrupter, 0x10, segments as u64);

        write32(operational, OP_COMMAND, COMMAND_RUN);
        if !wait_until_ms(100, || read32(operational, OP_STATUS) & STATUS_HALTED == 0) {
            return Err(Error::HaltTimedOut);
        }

        let mut controller = Self {
            operational,
            runtime,
            doorbells: base + (read32(base, CAP_DOORBELL_OFFSET) & !0x3) as usize,
            context_size,
            device_contexts,
            commands,
            events,
            event_index: 0,
            event_cycle: true,
            keyboards: [const { None }; MAX_KEYBOARDS],
        };
        if capability_1 & (1 << 3) != 0 {
            for port in 1..=ports {
                let register = controller.port_register(port);
                write32(
                    register,
                    0,
                    read32(register, 0) & PORT_PRESERVE | PORT_POWER,
                );
            }
        }
        // Devices reconnect after the controller reset; allow a debounce period.
        let connected = |controller: &Self| {
            (1..=ports).any(|port| read32(controller.port_register(port), 0) & PORT_CONNECTED != 0)
        };
        if wait_until_ms(1000, || connected(&controller)) {
            delay_ms(100);
        }
        let mut found = 0;
        for port in 1..=ports {
            if found == MAX_KEYBOARDS {
                break;
            }
            // A device that fails after its slot is enabled keeps its pages:
            // the controller may still write to its contexts.
            match controller.try_port(port) {
                Ok(keyboard) => {
                    controller.keyboards[found] = Some(keyboard);
                    found += 1;
                }
                Err(error) => {
                    if !matches!(error, Error::NotConnected) {
                        say!("ginux:     port {}: {:?}\n", port, error);
                    }
                }
            }
        }
        if found == 0 {
            controller.stop();
            return Err(Error::NoKeyboard);
        }
        for index in 0..found {
            controller.queue_report(index);
        }
        Ok(controller)
    }

    /// Returns the configured keyboards.
    pub(crate) fn keyboards(&self) -> impl Iterator<Item = &Keyboard> {
        self.keyboards.iter().flatten()
    }

    /// Returns the next keyboard report and the index of the keyboard that
    /// sent it, if one has arrived.
    pub(crate) fn poll(&mut self) -> Option<(usize, [u8; 8])> {
        let event = self.next_event()?;
        if event.kind() != TRB_TRANSFER_EVENT {
            return None;
        }
        let index = self.keyboards.iter().position(|keyboard| {
            keyboard
                .as_ref()
                .is_some_and(|keyboard| keyboard.slot == event.slot())
        })?;
        let keyboard = self.keyboards[index].as_ref()?;
        let report = if matches!(
            event.completion(),
            COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
        ) {
            // SAFETY: the controller completed the transfer into the report page.
            let page = unsafe { &*keyboard.report };
            page.0[..8].try_into().ok()
        } else {
            None
        };
        self.queue_report(index);
        report.map(|report| (index, report))
    }

    /// Halts the controller.
    pub(crate) fn stop(&mut self) {
        write32(
            self.operational,
            OP_COMMAND,
            read32(self.operational, OP_COMMAND) & !COMMAND_RUN,
        );
        let _ = wait_until_ms(100, || {
            read32(self.operational, OP_STATUS) & STATUS_HALTED != 0
        });
    }

    fn port_register(&self, port: u32) -> usize {
        self.operational + OP_PORTS + 0x10 * (port as usize - 1)
    }

    fn try_port(&mut self, port: u32) -> Result<Keyboard, Error> {
        let register = self.port_register(port);
        let status = read32(register, 0);
        if status & PORT_CONNECTED == 0 {
            return Err(Error::NotConnected);
        }
        if status & PORT_ENABLED == 0 {
            write32(register, 0, status & PORT_PRESERVE | PORT_RESET);
            if !wait_until_ms(500, || read32(register, 0) & PORT_RESET_CHANGE != 0) {
                return Err(Error::PortResetFailed);
            }
            delay_ms(20);
        }
        let status = read32(register, 0);
        write32(
            register,
            0,
            status & PORT_PRESERVE | (status & PORT_CHANGE_BITS),
        );
        if status & PORT_ENABLED == 0 {
            return Err(Error::PortResetFailed);
        }
        let speed = (status >> 10) & 0xf;
        let pages = DevicePages {
            output: pool_pages(1).ok_or(Error::OutOfDmaMemory)?,
            input: pool_pages(1).ok_or(Error::OutOfDmaMemory)?,
            control: pool_pages(1).ok_or(Error::OutOfDmaMemory)?,
            interrupt: pool_pages(1).ok_or(Error::OutOfDmaMemory)?,
            buffer: pool_pages(1).ok_or(Error::OutOfDmaMemory)?,
        };
        let mut device = DeviceSetup {
            controller: self,
            pages: &pages,
            control: Ring::new(pages.control),
            slot: 0,
            port,
            speed,
        };
        let (vendor, product) = device.address()?;
        say!(
            "ginux:     port {}: device {:04x}:{:04x} at speed {}\n",
            port,
            vendor,
            product,
            speed
        );
        let (slot, endpoint) = device.configure_keyboard().map_err(|error| match error {
            Error::NoKeyboard => Error::NotBootKeyboard(vendor, product),
            other => other,
        })?;
        Ok(Keyboard {
            port,
            vendor,
            product,
            slot,
            endpoint,
            interrupt: Ring::new(pages.interrupt),
            report: pages.buffer,
        })
    }

    fn queue_report(&mut self, index: usize) {
        let Some(keyboard) = self.keyboards[index].as_mut() else {
            return;
        };
        keyboard.interrupt.push(
            keyboard.report as u64,
            8,
            TRB_NORMAL << 10 | TRB_INTERRUPT_ON_COMPLETION,
        );
        let (slot, endpoint) = (keyboard.slot, keyboard.endpoint);
        self.ring(slot, endpoint);
    }

    fn command(&mut self, parameter: u64, control: u32) -> Result<Event, Error> {
        let kind = (control >> 10) & 0x3f;
        let address = self.commands.push(parameter, 0, control);
        self.ring(0, 0);
        let mut result = Err(Error::CommandTimedOut(kind));
        wait_until_ms(COMMAND_TIMEOUT_MS, || {
            let Some(event) = self.next_event() else {
                return false;
            };
            if event.kind() != TRB_COMMAND_COMPLETION || event.parameter != address {
                return false;
            }
            result = if event.completion() == COMPLETION_SUCCESS {
                Ok(event)
            } else {
                Err(Error::CommandFailed(kind, event.completion()))
            };
            true
        });
        result
    }

    fn ring(&self, slot: u32, target: u32) {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write32(self.doorbells, slot as usize * 4, target);
    }

    fn next_event(&mut self) -> Option<Event> {
        // SAFETY: event_index stays within the event ring page.
        let trb = unsafe { self.events.add(self.event_index * 4) };
        let control = unsafe { trb.add(3).read_volatile() };
        if (control & TRB_CYCLE != 0) != self.event_cycle {
            return None;
        }
        let event = unsafe {
            Event {
                parameter: u64::from(trb.read_volatile())
                    | u64::from(trb.add(1).read_volatile()) << 32,
                status: trb.add(2).read_volatile(),
                control,
            }
        };
        self.event_index += 1;
        if self.event_index == RING_TRBS {
            self.event_index = 0;
            self.event_cycle = !self.event_cycle;
        }
        let dequeue = self.events as u64 + (self.event_index * 16) as u64;
        // Bit 3 (EHB) is write-one-to-clear and acknowledges the event.
        write64(self.runtime + 0x20, 0x18, dequeue | 1 << 3);
        Some(event)
    }
}

/// State for addressing and configuring one device.
struct DeviceSetup<'a> {
    controller: &'a mut Controller,
    pages: &'a DevicePages,
    control: Ring,
    slot: u32,
    port: u32,
    speed: u32,
}

impl DeviceSetup<'_> {
    /// Enables a slot, addresses the device, and returns its vendor and
    /// product IDs.
    fn address(&mut self) -> Result<(u16, u16), Error> {
        let completion = self.controller.command(0, TRB_ENABLE_SLOT << 10)?;
        self.slot = completion.slot();
        // SAFETY: the device-context array holds MAX_SLOTS + 1 entries.
        unsafe {
            self.controller
                .device_contexts
                .add(self.slot as usize)
                .write(self.pages.output as u64);
        }
        let packet = match self.speed {
            SPEED_LOW => 8,
            SPEED_FULL | SPEED_HIGH => 64,
            _ => 512,
        };
        self.clear_input();
        self.input(0, 1, 0b11);
        self.input(1, 0, self.speed << 20 | 1 << 27);
        self.input(1, 1, self.port << 16);
        self.write_endpoint0(packet);
        self.controller.command(
            self.pages.input as u64,
            TRB_ADDRESS_DEVICE << 10 | self.slot << 24,
        )?;

        // Read the first eight bytes to learn the real default-pipe packet size.
        self.control_in(REQUEST_GET_DESCRIPTOR, DESCRIPTOR_DEVICE << 8, 0, 8)?;
        let reported = u32::from(self.buffer()[7]);
        // USB 3 devices report the default-pipe packet size as a power of two.
        let actual = if self.speed > SPEED_HIGH {
            1_u32.checked_shl(reported).unwrap_or(0)
        } else {
            reported
        };
        if actual != packet && actual != 0 {
            self.clear_input();
            self.input(0, 1, 0b10);
            self.write_endpoint0(actual);
            self.controller.command(
                self.pages.input as u64,
                TRB_EVALUATE_CONTEXT << 10 | self.slot << 24,
            )?;
        }
        self.control_in(REQUEST_GET_DESCRIPTOR, DESCRIPTOR_DEVICE << 8, 0, 18)?;
        let device = self.buffer();
        Ok((
            u16::from_le_bytes([device[8], device[9]]),
            u16::from_le_bytes([device[10], device[11]]),
        ))
    }

    /// Selects the boot keyboard interface, configures its interrupt-IN
    /// endpoint, and returns the slot and endpoint context index.
    fn configure_keyboard(&mut self) -> Result<(u32, u32), Error> {
        self.control_in(REQUEST_GET_DESCRIPTOR, DESCRIPTOR_CONFIGURATION << 8, 0, 9)?;
        let total = u16::from_le_bytes([self.buffer()[2], self.buffer()[3]]).min(4096);
        self.control_in(
            REQUEST_GET_DESCRIPTOR,
            DESCRIPTOR_CONFIGURATION << 8,
            0,
            total,
        )?;
        let descriptors = self.buffer();
        let configuration = descriptors[5];
        let (mut interface, mut keyboard) = (None, None);
        let mut offset = 0;
        while offset + 2 <= usize::from(total) {
            let length = usize::from(descriptors[offset]);
            if length < 2 || offset + length > usize::from(total) {
                break;
            }
            match descriptors[offset + 1] {
                4 => {
                    let boot_keyboard = descriptors[offset + 5] == 3
                        && descriptors[offset + 6] == 1
                        && descriptors[offset + 7] == 1;
                    interface = boot_keyboard.then_some(descriptors[offset + 2]);
                }
                5 if interface.is_some() && keyboard.is_none() => {
                    let address = descriptors[offset + 2];
                    if address & 0x80 != 0 && descriptors[offset + 3] & 3 == 3 {
                        let packet =
                            u16::from_le_bytes([descriptors[offset + 4], descriptors[offset + 5]]);
                        keyboard = Some((
                            interface.unwrap_or(0),
                            address & 0x0f,
                            packet & 0x7ff,
                            descriptors[offset + 6],
                        ));
                    }
                }
                _ => {}
            }
            offset += length;
        }
        let Some((interface, number, packet, interval)) = keyboard else {
            return Err(Error::NoKeyboard);
        };

        self.control_out(0x00, REQUEST_SET_CONFIGURATION, u16::from(configuration), 0)?;
        self.control_out(0x21, REQUEST_HID_SET_PROTOCOL, 0, u16::from(interface))?;
        // SET_IDLE is optional; some keyboards stall it.
        let _ = self.control_out(0x21, REQUEST_HID_SET_IDLE, 0, u16::from(interface));

        let endpoint = u32::from(number) * 2 + 1;
        let exponent = match self.speed {
            SPEED_LOW | SPEED_FULL => {
                // Frames of 1 ms, expressed as 2^n microframes of 125 us.
                let microframes = u32::from(interval.max(1)) * 8;
                (31 - microframes.leading_zeros()).clamp(3, 10)
            }
            _ => u32::from(interval.clamp(1, 16)) - 1,
        };
        let ring = self.pages.interrupt as u64 | 1;
        self.clear_input();
        self.input(0, 1, 1 | 1 << endpoint);
        self.input(1, 0, self.speed << 20 | endpoint << 27);
        self.input(1, 1, self.port << 16);
        let context = 1 + endpoint as usize;
        self.input(context, 0, exponent << 16);
        self.input(
            context,
            1,
            3 << 1 | ENDPOINT_INTERRUPT_IN << 3 | u32::from(packet) << 16,
        );
        self.input(context, 2, ring as u32);
        self.input(context, 3, (ring >> 32) as u32);
        self.input(context, 4, 8 | u32::from(packet) << 16);
        self.controller.command(
            self.pages.input as u64,
            TRB_CONFIGURE_ENDPOINT << 10 | self.slot << 24,
        )?;
        Ok((self.slot, endpoint))
    }

    fn write_endpoint0(&mut self, packet: u32) {
        let ring = self.control.address() | 1;
        self.input(2, 1, 3 << 1 | ENDPOINT_CONTROL << 3 | packet << 16);
        self.input(2, 2, ring as u32);
        self.input(2, 3, (ring >> 32) as u32);
        self.input(2, 4, 8);
    }

    fn clear_input(&mut self) {
        // SAFETY: the input context page belongs to this device setup.
        unsafe { (*self.pages.input).0.fill(0) };
    }

    /// Writes dword `word` of input context entry `index` (0 is the input
    /// control context, 1 the slot, 2 endpoint 0, and so on).
    fn input(&mut self, index: usize, word: usize, value: u32) {
        let offset = index * self.controller.context_size + word * 4;
        // SAFETY: offset stays within the 4 KiB input context page for the
        // entries this driver writes (at most 32 contexts of 64 bytes).
        unsafe {
            self.pages
                .input
                .cast::<u8>()
                .add(offset)
                .cast::<u32>()
                .write_volatile(value);
        }
    }

    /// The device's transfer buffer, read after its transfer completed.
    fn buffer(&self) -> &'static [u8; 4096] {
        // SAFETY: the buffer page belongs to this device and the transfer
        // that filled it has completed.
        unsafe { &(*self.pages.buffer).0 }
    }

    fn control_in(
        &mut self,
        request: u8,
        value: u16,
        index: u16,
        length: u16,
    ) -> Result<(), Error> {
        let setup = 0x80
            | u64::from(request) << 8
            | u64::from(value) << 16
            | u64::from(index) << 32
            | u64::from(length) << 48;
        self.control
            .push(setup, 8, TRB_SETUP << 10 | TRB_IMMEDIATE_DATA | 3 << 16);
        self.control.push(
            self.pages.buffer as u64,
            u32::from(length),
            TRB_DATA << 10 | TRB_DIRECTION_IN,
        );
        let status = self
            .control
            .push(0, 0, TRB_STATUS << 10 | TRB_INTERRUPT_ON_COMPLETION);
        self.transfer(status)
    }

    fn control_out(
        &mut self,
        request_type: u8,
        request: u8,
        value: u16,
        index: u16,
    ) -> Result<(), Error> {
        let setup = u64::from(request_type)
            | u64::from(request) << 8
            | u64::from(value) << 16
            | u64::from(index) << 32;
        self.control
            .push(setup, 8, TRB_SETUP << 10 | TRB_IMMEDIATE_DATA);
        let status = self.control.push(
            0,
            0,
            TRB_STATUS << 10 | TRB_INTERRUPT_ON_COMPLETION | TRB_DIRECTION_IN,
        );
        self.transfer(status)
    }

    /// Rings endpoint 0 and waits for the transfer event of the TRB at
    /// `last`. An error on any earlier TRB of the transfer ends the wait.
    fn transfer(&mut self, last: u64) -> Result<(), Error> {
        self.controller.ring(self.slot, 1);
        let mut result = Err(Error::TransferTimedOut);
        wait_until_ms(COMMAND_TIMEOUT_MS, || {
            let Some(event) = self.controller.next_event() else {
                return false;
            };
            if event.kind() != TRB_TRANSFER_EVENT {
                return false;
            }
            if !matches!(
                event.completion(),
                COMPLETION_SUCCESS | COMPLETION_SHORT_PACKET
            ) {
                result = Err(Error::TransferFailed(event.completion()));
                return true;
            }
            if event.parameter == last {
                result = Ok(());
                return true;
            }
            false
        });
        result
    }
}

/// Performs the USB legacy-support handoff so firmware stops driving the
/// controller through SMIs.
fn take_from_firmware(base: usize) {
    let mut offset = ((read32(base, CAP_CAPABILITY_1) >> 16) as usize) * 4;
    while offset != 0 {
        let capability = read32(base, offset);
        if capability & 0xff == LEGACY_SUPPORT {
            write32(base, offset, capability | LEGACY_OS_OWNED);
            let _ = wait_until_ms(1000, || read32(base, offset) & LEGACY_BIOS_OWNED == 0);
            let control = read32(base, offset + 4);
            write32(
                base,
                offset + 4,
                (control & LEGACY_DISABLE_SMI) | LEGACY_SMI_EVENTS,
            );
            return;
        }
        let next = ((capability >> 8) & 0xff) as usize * 4;
        if next == 0 {
            return;
        }
        offset += next;
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

fn write64(base: usize, offset: usize, value: u64) {
    write32(base, offset, value as u32);
    write32(base, offset + 4, (value >> 32) as u32);
}
