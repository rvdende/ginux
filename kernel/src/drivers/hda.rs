//! Intel High Definition Audio controllers, which also cover the AMD HD
//! Audio and GPU HDMI/DP audio functions: controller reset, codec discovery
//! through the CORB/RIRB command rings, and a report of each codec's output
//! pins. Playback is not implemented yet.

use core::ptr::{addr_of, addr_of_mut};

use super::pci::{Function, Identity};
use super::{delay_ms, wait_until_ms, DmaPage, DmaRegion};

const GLOBAL_CONTROL: usize = 0x08;
const STATE_CHANGE: usize = 0x0e;
const CORB_LOW: usize = 0x40;
const CORB_HIGH: usize = 0x44;
const CORB_WRITE: usize = 0x48;
const CORB_READ: usize = 0x4a;
const CORB_CONTROL: usize = 0x4c;
const CORB_SIZE: usize = 0x4e;
const RIRB_LOW: usize = 0x50;
const RIRB_HIGH: usize = 0x54;
const RIRB_WRITE: usize = 0x58;
const RESPONSE_COUNT: usize = 0x5a;
const RIRB_CONTROL: usize = 0x5c;
const RIRB_STATUS: usize = 0x5d;
const RIRB_SIZE: usize = 0x5e;
const CONTROL_RUN: u32 = 1 << 0;
const RING_RUN: u8 = 1 << 1;
const CORB_READ_RESET: u16 = 1 << 15;
const RIRB_WRITE_RESET: u16 = 1 << 15;
/// The response-interrupt and overrun bits, both write-one-to-clear.
const RIRB_STATUS_CLEAR: u8 = 0x05;
/// Size selector for 256-entry rings.
const RING_256: u8 = 2;
const RING_ENTRIES: usize = 256;
const VERB_GET_PARAMETER: u32 = 0xf00;
const VERB_GET_CONFIGURATION: u32 = 0xf1c;
const PARAMETER_VENDOR: u32 = 0x00;
const PARAMETER_NODES: u32 = 0x04;
const PARAMETER_FUNCTION_TYPE: u32 = 0x05;
const PARAMETER_WIDGET: u32 = 0x09;
const FUNCTION_AUDIO: u32 = 1;
const WIDGET_OUTPUT: u32 = 0;
const WIDGET_PIN: u32 = 4;
const COMMAND_TIMEOUT_MS: u64 = 50;
const MAX_CODECS: usize = 15;

static mut CORB: DmaPage = DmaPage::ZERO;
static mut RIRB: DmaPage = DmaPage::ZERO;

/// Returns whether `device` is a High Definition Audio controller.
pub(crate) fn is_supported(device: &Identity) -> bool {
    (device.class, device.subclass) == (0x04, 0x03)
}

/// The memory HD Audio controllers may reach by DMA.
pub(crate) fn dma_regions() -> [DmaRegion; 2] {
    [DmaRegion::of(addr_of!(CORB)), DmaRegion::of(addr_of!(RIRB))]
}

// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) enum Error {
    NoMemoryBar,
    ResetTimedOut,
    NoCodecs,
    CommandTimedOut,
}

/// One output pin of a codec, as its default configuration describes it.
#[derive(Clone, Copy)]
pub(crate) struct Pin {
    pub(crate) node: u8,
    /// The configuration default register (verb F1Ch).
    pub(crate) configuration: u32,
}

impl Pin {
    /// What the pin is wired as, from the default-device field.
    pub(crate) fn device_name(&self) -> &'static str {
        match (self.configuration >> 20) & 0xf {
            0x0 => "line out",
            0x1 => "speaker",
            0x2 => "headphone",
            0x3 => "CD",
            0x4 => "S/PDIF out",
            0x5 => "digital out",
            0x6 => "modem line",
            0x7 => "modem handset",
            0x8 => "line in",
            0x9 => "aux",
            0xa => "microphone",
            0xb => "telephony",
            0xc => "S/PDIF in",
            0xd => "digital in",
            _ => "other",
        }
    }

    /// Whether anything is attached according to the port-connectivity
    /// field (bits 31:30 are 1 for "no physical connection").
    pub(crate) fn connected(&self) -> bool {
        self.configuration >> 30 != 1
    }

    pub(crate) fn is_output(&self) -> bool {
        matches!((self.configuration >> 20) & 0xf, 0x0..=0x2 | 0x4 | 0x5)
    }
}

/// What one codec reports.
pub(crate) struct Codec {
    pub(crate) address: u8,
    pub(crate) vendor: u16,
    pub(crate) device: u16,
    pub(crate) converters: usize,
    pub(crate) pins: [Option<Pin>; 16],
}

/// A reset controller with its command rings running.
pub(crate) struct Controller {
    base: usize,
    corb_write: u16,
    rirb_read: u16,
    codecs: u16,
}

impl Controller {
    /// Resets `function` and starts its CORB and RIRB.
    ///
    /// # Safety
    ///
    /// `function` must be an HD Audio controller that nothing else drives,
    /// with its registers and this driver's DMA pages identity mapped. Only
    /// one controller may be open at a time.
    pub(crate) unsafe fn open(function: Function) -> Result<Self, Error> {
        let base = function.memory_bar(0).ok_or(Error::NoMemoryBar)? as usize;
        function.enable_memory_and_bus_master();
        write8(base, CORB_CONTROL, 0);
        write8(base, RIRB_CONTROL, 0);
        write32(
            base,
            GLOBAL_CONTROL,
            read32(base, GLOBAL_CONTROL) & !CONTROL_RUN,
        );
        if !wait_until_ms(100, || read32(base, GLOBAL_CONTROL) & CONTROL_RUN == 0) {
            return Err(Error::ResetTimedOut);
        }
        delay_ms(1);
        write32(
            base,
            GLOBAL_CONTROL,
            read32(base, GLOBAL_CONTROL) | CONTROL_RUN,
        );
        if !wait_until_ms(100, || read32(base, GLOBAL_CONTROL) & CONTROL_RUN != 0) {
            return Err(Error::ResetTimedOut);
        }
        // Codecs need 521 us after reset to request an address.
        delay_ms(2);
        let codecs = read16(base, STATE_CHANGE) & 0x7fff;
        if codecs == 0 {
            return Err(Error::NoCodecs);
        }

        (*addr_of_mut!(CORB)).0.fill(0);
        (*addr_of_mut!(RIRB)).0.fill(0);
        let corb = addr_of!(CORB) as u64;
        let rirb = addr_of!(RIRB) as u64;
        write32(base, CORB_LOW, corb as u32);
        write32(base, CORB_HIGH, (corb >> 32) as u32);
        write8(base, CORB_SIZE, RING_256);
        write16(base, CORB_WRITE, 0);
        write16(base, CORB_READ, CORB_READ_RESET);
        let _ = wait_until_ms(10, || read16(base, CORB_READ) & CORB_READ_RESET != 0);
        write16(base, CORB_READ, 0);
        let _ = wait_until_ms(10, || read16(base, CORB_READ) & CORB_READ_RESET == 0);
        write32(base, RIRB_LOW, rirb as u32);
        write32(base, RIRB_HIGH, (rirb >> 32) as u32);
        write8(base, RIRB_SIZE, RING_256);
        write16(base, RIRB_WRITE, RIRB_WRITE_RESET);
        // Controllers may stop writing responses once this many are
        // unacknowledged, so allow the most and acknowledge each one.
        write16(base, RESPONSE_COUNT, 0xff);
        write8(base, RIRB_STATUS, RIRB_STATUS_CLEAR);
        write8(base, CORB_CONTROL, RING_RUN);
        write8(base, RIRB_CONTROL, RING_RUN);
        Ok(Self {
            base,
            corb_write: 0,
            rirb_read: 0,
            codecs,
        })
    }

    /// Discovers each codec's audio function group and its pins.
    pub(crate) fn codecs(&mut self) -> impl Iterator<Item = Result<Codec, Error>> + '_ {
        let present = self.codecs;
        (0..MAX_CODECS as u8)
            .filter(|address| present & 1 << address != 0)
            .collect::<CodecAddresses>()
            .into_iter()
            .map(move |address| self.codec(address))
    }

    fn codec(&mut self, address: u8) -> Result<Codec, Error> {
        let identity = self.parameter(address, 0, PARAMETER_VENDOR)?;
        let mut codec = Codec {
            address,
            vendor: (identity >> 16) as u16,
            device: identity as u16,
            converters: 0,
            pins: [None; 16],
        };
        let (first_group, groups) = node_range(self.parameter(address, 0, PARAMETER_NODES)?);
        for group in first_group..first_group + groups {
            if self.parameter(address, group, PARAMETER_FUNCTION_TYPE)? & 0xff != FUNCTION_AUDIO {
                continue;
            }
            let (first, count) = node_range(self.parameter(address, group, PARAMETER_NODES)?);
            let mut pins = 0;
            for node in first..first + count {
                let kind = (self.parameter(address, node, PARAMETER_WIDGET)? >> 20) & 0xf;
                if kind == WIDGET_OUTPUT {
                    codec.converters += 1;
                } else if kind == WIDGET_PIN && pins < codec.pins.len() {
                    let configuration = self.command(address, node, VERB_GET_CONFIGURATION, 0)?;
                    codec.pins[pins] = Some(Pin {
                        node,
                        configuration,
                    });
                    pins += 1;
                }
            }
        }
        Ok(codec)
    }

    fn parameter(&mut self, codec: u8, node: u8, parameter: u32) -> Result<u32, Error> {
        self.command(codec, node, VERB_GET_PARAMETER, parameter)
    }

    /// Sends one 12-bit verb with an 8-bit payload and returns the response.
    fn command(&mut self, codec: u8, node: u8, verb: u32, payload: u32) -> Result<u32, Error> {
        let command = u32::from(codec) << 28 | u32::from(node) << 20 | verb << 8 | payload;
        self.corb_write = (self.corb_write + 1) % RING_ENTRIES as u16;
        // SAFETY: the CORB page belongs to this driver, and the controller
        // only reads entries up to the write pointer.
        unsafe {
            addr_of_mut!(CORB)
                .cast::<u32>()
                .add(usize::from(self.corb_write))
                .write_volatile(command);
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        write16(self.base, CORB_WRITE, self.corb_write);
        let next = (self.rirb_read + 1) % RING_ENTRIES as u16;
        if !wait_until_ms(COMMAND_TIMEOUT_MS, || {
            read16(self.base, RIRB_WRITE) & 0xff == next
        }) {
            return Err(Error::CommandTimedOut);
        }
        self.rirb_read = next;
        // SAFETY: the controller wrote the response before moving its
        // write pointer; each entry is a response and a codec tag.
        let response = unsafe {
            addr_of!(RIRB)
                .cast::<u32>()
                .add(usize::from(next) * 2)
                .read_volatile()
        };
        write8(self.base, RIRB_STATUS, RIRB_STATUS_CLEAR);
        Ok(response)
    }
}

/// The addresses of present codecs, collected so commands can borrow the
/// controller mutably while iterating.
struct CodecAddresses {
    addresses: [u8; MAX_CODECS],
    count: usize,
}

impl FromIterator<u8> for CodecAddresses {
    fn from_iter<T: IntoIterator<Item = u8>>(iterator: T) -> Self {
        let mut collected = Self {
            addresses: [0; MAX_CODECS],
            count: 0,
        };
        for address in iterator.into_iter().take(MAX_CODECS) {
            collected.addresses[collected.count] = address;
            collected.count += 1;
        }
        collected
    }
}

impl IntoIterator for CodecAddresses {
    type Item = u8;
    type IntoIter = core::iter::Take<core::array::IntoIter<u8, MAX_CODECS>>;

    fn into_iter(self) -> Self::IntoIter {
        self.addresses.into_iter().take(self.count)
    }
}

/// Decodes a subordinate-node-count response into a first node and count.
fn node_range(response: u32) -> (u8, u8) {
    ((response >> 16) as u8, response as u8)
}

fn read16(base: usize, offset: usize) -> u16 {
    // SAFETY: callers pass identity-mapped controller registers.
    unsafe { ((base + offset) as *const u16).read_volatile() }
}

fn read32(base: usize, offset: usize) -> u32 {
    // SAFETY: as for read16.
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn write8(base: usize, offset: usize, value: u8) {
    // SAFETY: as for read16.
    unsafe { ((base + offset) as *mut u8).write_volatile(value) }
}

fn write16(base: usize, offset: usize, value: u16) {
    // SAFETY: as for read16.
    unsafe { ((base + offset) as *mut u16).write_volatile(value) }
}

fn write32(base: usize, offset: usize, value: u32) {
    // SAFETY: as for read16.
    unsafe { ((base + offset) as *mut u32).write_volatile(value) }
}
