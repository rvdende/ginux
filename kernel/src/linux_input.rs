//! Linux evdev input devices (/dev/input/eventN) for domains.
//!
//! Input drivers register a device and push events into its queue; Linux
//! processes read them as 24-byte `struct input_event` records. Each device
//! keeps a fixed ring of events, dropping the oldest when a reader falls
//! behind, as the Linux evdev buffer does before it reports SYN_DROPPED.

// The producer side (register, push, sync, set_pump) is used by the USB HID
// input driver, which is being brought into the runtime separately.
#![allow(dead_code)]

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

/// Drops every queued event, for example when the domain reading them stops.
pub(crate) fn flush() {
    let _ = with_devices(|devices| {
        for device in devices {
            device.head = 0;
            device.length = 0;
        }
    });
}
