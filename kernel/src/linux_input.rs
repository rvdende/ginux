//! Linux evdev input devices (/dev/input/eventN) for domains.
//!
//! Input drivers register a device and push events into its queue; Linux
//! processes read them as 24-byte `struct input_event` records. Each device
//! keeps a fixed ring of events, dropping the oldest when a reader falls
//! behind, as the Linux evdev buffer does before it reports SYN_DROPPED.

use core::sync::atomic::{AtomicBool, Ordering};

pub(crate) const DEVICE_LIMIT: usize = 4;
pub(crate) const EVENT_SIZE: usize = 24;
const QUEUE_LENGTH: usize = 256;

pub(crate) const EV_SYN: u16 = 0;
pub(crate) const EV_KEY: u16 = 1;
pub(crate) const EV_REL: u16 = 2;
pub(crate) const EV_ABS: u16 = 3;
pub(crate) const SYN_REPORT: u16 = 0;
pub(crate) const REL_X: u16 = 0;
pub(crate) const REL_Y: u16 = 1;
pub(crate) const REL_WHEEL: u16 = 8;
pub(crate) const ABS_X: u16 = 0;
pub(crate) const ABS_Y: u16 = 1;
pub(crate) const BTN_LEFT: u16 = 0x110;
pub(crate) const BTN_RIGHT: u16 = 0x111;
pub(crate) const BTN_MIDDLE: u16 = 0x112;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceKind {
    Keyboard,
    /// A relative pointer such as a USB boot mouse.
    Mouse,
    /// An absolute pointer such as QEMU's USB tablet; axes span 0..=maximum.
    Tablet {
        maximum: i32,
    },
}

#[derive(Clone, Copy)]
struct Event {
    microseconds: u64,
    kind: u16,
    code: u16,
    value: i32,
}

struct Device {
    kind: Option<DeviceKind>,
    name: &'static [u8],
    events: [Event; QUEUE_LENGTH],
    head: usize,
    length: usize,
}

impl Device {
    const EMPTY: Self = Self {
        kind: None,
        name: b"",
        events: [Event {
            microseconds: 0,
            kind: 0,
            code: 0,
            value: 0,
        }; QUEUE_LENGTH],
        head: 0,
        length: 0,
    };
}

static mut DEVICES: [Device; DEVICE_LIMIT] = [const { Device::EMPTY }; DEVICE_LIMIT];
static mut CONSOLE: Console = Console::EMPTY;

/// Keyboard input translated for the text console (the controller prompt
/// and attached domain shells), which otherwise reads only the serial port.
struct Console {
    bytes: [u8; 64],
    head: usize,
    length: usize,
    shift: bool,
    control: bool,
    caps_lock: bool,
}

impl Console {
    const EMPTY: Self = Self {
        bytes: [0; 64],
        head: 0,
        length: 0,
        shift: false,
        control: false,
        caps_lock: false,
    };

    fn push(&mut self, bytes: &[u8]) {
        for byte in bytes {
            if self.length == self.bytes.len() {
                return;
            }
            self.bytes[(self.head + self.length) % self.bytes.len()] = *byte;
            self.length += 1;
        }
    }

    fn key(&mut self, code: u16, pressed: bool) {
        match code {
            42 | 54 => self.shift = pressed,
            29 | 97 => self.control = pressed,
            58 if pressed => self.caps_lock = !self.caps_lock,
            _ if !pressed => {}
            28 => self.push(b"\r"),
            14 => self.push(&[0x7f]),
            15 => self.push(b"\t"),
            1 => self.push(&[0x1b]),
            103 => self.push(b"\x1b[A"),
            108 => self.push(b"\x1b[B"),
            106 => self.push(b"\x1b[C"),
            105 => self.push(b"\x1b[D"),
            code => {
                if let Some(character) = us_character(code, self.shift, self.caps_lock) {
                    let byte = if self.control && character.is_ascii_alphabetic()
                        || self.control && matches!(character, b'[' | b']' | b'\\')
                    {
                        character & 0x1f
                    } else {
                        character
                    };
                    self.push(&[byte]);
                }
            }
        }
    }
}

/// Maps an evdev key code to ASCII on a US keyboard.
fn us_character(code: u16, shift: bool, caps_lock: bool) -> Option<u8> {
    const ROWS: [(u16, &[u8], &[u8]); 4] = [
        (2, b"1234567890-=", b"!@#$%^&*()_+"),
        (16, b"qwertyuiop[]", b"QWERTYUIOP{}"),
        (30, b"asdfghjkl;'`", b"ASDFGHJKL:\"~"),
        (44, b"zxcvbnm,./", b"ZXCVBNM<>?"),
    ];
    match code {
        43 => return Some(if shift { b'|' } else { b'\\' }),
        57 => return Some(b' '),
        _ => {}
    }
    ROWS.iter().find_map(|(first, plain, shifted)| {
        let index = usize::from(code.checked_sub(*first)?);
        let character = *plain.get(index)?;
        let upper = if character.is_ascii_alphabetic() {
            shift != caps_lock
        } else {
            shift
        };
        if upper {
            shifted.get(index).copied()
        } else {
            Some(character)
        }
    })
}
static BUSY: AtomicBool = AtomicBool::new(false);
/// Polls input hardware for new reports; set by the driver that registers
/// devices, and called whenever a reader looks for events.
static mut PUMP: Option<fn()> = None;

/// Runs `body` with exclusive access to the device table. Returns `None`
/// if the table is in use, for example by an interrupted reader.
fn with_devices<T>(body: impl FnOnce(&mut [Device; DEVICE_LIMIT]) -> T) -> Option<T> {
    if BUSY.swap(true, Ordering::Acquire) {
        return None;
    }
    // SAFETY: BUSY grants exclusive access to DEVICES.
    let result = body(unsafe { &mut *core::ptr::addr_of_mut!(DEVICES) });
    BUSY.store(false, Ordering::Release);
    Some(result)
}

/// Adds a device, returning its N in /dev/input/eventN.
pub(crate) fn register(kind: DeviceKind, name: &'static [u8]) -> Option<usize> {
    with_devices(|devices| {
        let index = devices.iter().position(|device| device.kind.is_none())?;
        devices[index] = Device::EMPTY;
        devices[index].kind = Some(kind);
        devices[index].name = name;
        Some(index)
    })
    .flatten()
}

/// Sets the function that polls input hardware for reports.
pub(crate) fn set_pump(pump: fn()) {
    // SAFETY: written once while drivers start, before readers exist.
    unsafe { PUMP = Some(pump) };
}

pub(crate) fn pump() {
    // SAFETY: PUMP is only written by set_pump during driver start-up.
    if let Some(pump) = unsafe { PUMP } {
        pump();
    }
}

pub(crate) fn device_kind(device: usize) -> Option<DeviceKind> {
    with_devices(|devices| devices.get(device).and_then(|device| device.kind)).flatten()
}

pub(crate) fn device_name(device: usize) -> &'static [u8] {
    with_devices(|devices| devices.get(device).map_or(&b""[..], |device| device.name))
        .unwrap_or(b"")
}

fn monotonic_microseconds() -> u64 {
    let ticks = crate::arch::x86_64::timer::timestamp_counter();
    crate::arch::x86_64::timer::monotonic_frequency()
        .filter(|frequency| *frequency != 0)
        .map_or(0, |frequency| {
            (u128::from(ticks) * 1_000_000 / u128::from(frequency)) as u64
        })
}

/// Queues one event; drivers end each report with [`sync`].
pub(crate) fn push(device: usize, kind: u16, code: u16, value: i32) {
    let microseconds = monotonic_microseconds();
    let _ = with_devices(|devices| {
        let Some(device) = devices
            .get_mut(device)
            .filter(|device| device.kind.is_some())
        else {
            return;
        };
        if device.length == QUEUE_LENGTH {
            device.head = (device.head + 1) % QUEUE_LENGTH;
            device.length -= 1;
        }
        let tail = (device.head + device.length) % QUEUE_LENGTH;
        device.events[tail] = Event {
            microseconds,
            kind,
            code,
            value,
        };
        device.length += 1;
    });
}

pub(crate) fn sync(device: usize) {
    push(device, EV_SYN, SYN_REPORT, 0);
}

pub(crate) fn pending(device: usize) -> bool {
    pump();
    with_devices(|devices| devices.get(device).is_some_and(|device| device.length != 0))
        .unwrap_or(false)
}

/// Moves whole events into `output`, returning the bytes written.
pub(crate) fn read(device: usize, output: &mut [u8]) -> usize {
    pump();
    with_devices(|devices| {
        let Some(device) = devices.get_mut(device) else {
            return 0;
        };
        let mut written = 0;
        while device.length != 0 && output.len() - written >= EVENT_SIZE {
            let event = device.events[device.head];
            device.head = (device.head + 1) % QUEUE_LENGTH;
            device.length -= 1;
            let record = &mut output[written..written + EVENT_SIZE];
            record[0..8].copy_from_slice(&(event.microseconds / 1_000_000).to_ne_bytes());
            record[8..16].copy_from_slice(&(event.microseconds % 1_000_000).to_ne_bytes());
            record[16..18].copy_from_slice(&event.kind.to_ne_bytes());
            record[18..20].copy_from_slice(&event.code.to_ne_bytes());
            record[20..24].copy_from_slice(&event.value.to_ne_bytes());
            written += EVENT_SIZE;
        }
        written
    })
    .unwrap_or(0)
}

/// Moves keyboard events into the console's byte queue while no domain owns
/// the screen; once a compositor maps /dev/fb0 the keyboard is left to it.
fn fill_console() {
    if crate::framebuffer::owned() {
        return;
    }
    pump();
    let _ = with_devices(|devices| {
        // SAFETY: BUSY, held by with_devices, also guards CONSOLE.
        let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
        for device in devices
            .iter_mut()
            .filter(|device| device.kind == Some(DeviceKind::Keyboard))
        {
            while device.length != 0 {
                let event = device.events[device.head];
                device.head = (device.head + 1) % QUEUE_LENGTH;
                device.length -= 1;
                if event.kind == EV_KEY {
                    console.key(event.code, event.value != 0);
                }
            }
        }
    });
}

/// Whether a typed byte is waiting for the text console.
pub(crate) fn console_byte_ready() -> bool {
    fill_console();
    with_devices(|_| {
        // SAFETY: BUSY, held by with_devices, also guards CONSOLE.
        unsafe { (*core::ptr::addr_of!(CONSOLE)).length != 0 }
    })
    .unwrap_or(false)
}

/// Takes the next byte typed for the text console.
pub(crate) fn take_console_byte() -> Option<u8> {
    fill_console();
    with_devices(|_| {
        // SAFETY: BUSY, held by with_devices, also guards CONSOLE.
        let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
        (console.length != 0).then(|| {
            let byte = console.bytes[console.head];
            console.head = (console.head + 1) % console.bytes.len();
            console.length -= 1;
            byte
        })
    })
    .flatten()
}

/// Drops every queued event, for example when the domain reading them stops.
pub(crate) fn flush() {
    let _ = with_devices(|devices| {
        for device in devices {
            device.head = 0;
            device.length = 0;
        }
    });
}
