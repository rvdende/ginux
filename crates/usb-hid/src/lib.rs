#![forbid(unsafe_code)]
//! USB HID input reports as Linux input events: boot-protocol keyboards and
//! mice, and QEMU's USB tablet.
//!
//! Each decoder keeps what the previous report said and turns a new report
//! into the changes since, as Linux's HID drivers do, so the kernel only
//! forwards events to evdev. Key codes are Linux `KEY_*` values, translated
//! from HID keyboard usages with the table Linux's usbkbd and hid-input use.
//!
//! This is pure report logic so the xHCI driver stays thin and the decoding
//! can be tested on the host.

#![no_std]

#[cfg(test)]
extern crate std;

/// The largest coordinate QEMU's USB tablet reports on either axis.
pub const TABLET_MAXIMUM: i32 = 0x7fff;

/// The HID usage that fills every key slot when too many keys are down.
const USAGE_ERROR_ROLLOVER: u8 = 0x01;
/// Usages 1 to 3 report keyboard errors rather than keys.
const USAGE_FIRST_KEY: u8 = 0x04;
const BOOT_KEY_SLOTS: usize = 6;

/// Linux key codes for HID keyboard usages 0x00 to 0xff (page 0x07), as in
/// Linux's `usb_kbd_keycode` table; zero means the usage has no key code.
/// Usages 0xe0 to 0xe7 are the modifiers that boot reports send as bits.
#[rustfmt::skip]
const KEY_CODES: [u8; 256] = [
      0,   0,   0,   0,  30,  48,  46,  32,  18,  33,  34,  35,  23,  36,  37,  38,
     50,  49,  24,  25,  16,  19,  31,  20,  22,  47,  17,  45,  21,  44,   2,   3,
      4,   5,   6,   7,   8,   9,  10,  11,  28,   1,  14,  15,  57,  12,  13,  26,
     27,  43,  43,  39,  40,  41,  51,  52,  53,  58,  59,  60,  61,  62,  63,  64,
     65,  66,  67,  68,  87,  88,  99,  70, 119, 110, 102, 104, 111, 107, 109, 106,
    105, 108, 103,  69,  98,  55,  74,  78,  96,  79,  80,  81,  75,  76,  77,  71,
     72,  73,  82,  83,  86, 127, 116, 117, 183, 184, 185, 186, 187, 188, 189, 190,
    191, 192, 193, 194, 134, 138, 130, 132, 128, 129, 131, 137, 133, 135, 136, 113,
    115, 114,   0,   0,   0, 121,   0,  89,  93, 124,  92,  94,  95,   0,   0,   0,
    122, 123,  90,  91,  85,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
      0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,
     29,  42,  56, 125,  97,  54, 100, 126, 164, 166, 165, 163, 161, 115, 114, 113,
    150, 158, 159, 128, 136, 177, 178, 176, 142, 152, 173, 140,   0,   0,   0,   0,
];

/// The first modifier usage; modifier bit `n` of a boot report is usage
/// 0xe0 + `n` (left control, shift, alt, GUI, then the right-hand ones).
const USAGE_FIRST_MODIFIER: u8 = 0xe0;

/// Returns the Linux key code for HID keyboard usage `usage`.
pub fn key_code(usage: u8) -> Option<u16> {
    match KEY_CODES[usize::from(usage)] {
        0 => None,
        code => Some(u16::from(code)),
    }
}

/// A pointer button, in the order of the bits HID reports them in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Button {
    Left,
    Right,
    Middle,
}

const BUTTONS: [Button; 3] = [Button::Left, Button::Right, Button::Middle];

/// An axis that reports movement since the previous report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelativeAxis {
    X,
    /// Grows downwards.
    Y,
    /// Wheel detents; positive scrolls away from the user.
    Wheel,
}

/// An axis that reports a position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbsoluteAxis {
    X,
    /// Grows downwards.
    Y,
}

/// One change a report made.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Event {
    /// The key with Linux key code `code` went down or up.
    Key {
        code: u16,
        pressed: bool,
    },
    Button {
        button: Button,
        pressed: bool,
    },
    Relative {
        axis: RelativeAxis,
        delta: i32,
    },
    Absolute {
        axis: AbsoluteAxis,
        value: i32,
    },
}

/// A HID boot-protocol keyboard. Its reports are a modifier byte, a
/// reserved byte, and the usages of up to six keys that are down.
#[derive(Clone, Copy, Debug, Default)]
pub struct Keyboard {
    modifiers: u8,
    keys: [u8; BOOT_KEY_SLOTS],
}

impl Keyboard {
    pub const fn new() -> Self {
        Self {
            modifiers: 0,
            keys: [0; BOOT_KEY_SLOTS],
        }
    }

    /// Decodes one boot report, calling `emit` for each modifier that
    /// changed, then each key released, then each key pressed. A report
    /// whose key slots say too many keys are down changes only the
    /// modifiers, as in Linux.
    pub fn report(&mut self, report: &[u8], mut emit: impl FnMut(Event)) {
        let Some(&modifiers) = report.first() else {
            return;
        };
        let changed = self.modifiers ^ modifiers;
        for bit in (0..8).filter(|bit| changed & (1 << bit) != 0) {
            if let Some(code) = key_code(USAGE_FIRST_MODIFIER + bit) {
                emit(Event::Key {
                    code,
                    pressed: modifiers & (1 << bit) != 0,
                });
            }
        }
        self.modifiers = modifiers;

        let mut keys = [0; BOOT_KEY_SLOTS];
        for (slot, usage) in keys.iter_mut().zip(report.iter().skip(2)) {
            *slot = *usage;
        }
        if keys.contains(&USAGE_ERROR_ROLLOVER) {
            return;
        }
        for (pressed, from, to) in [(false, &self.keys, &keys), (true, &keys, &self.keys)] {
            for (index, usage) in from.iter().enumerate() {
                // A usage listed twice is one key.
                if *usage < USAGE_FIRST_KEY || to.contains(usage) || from[..index].contains(usage) {
                    continue;
                }
                if let Some(code) = key_code(*usage) {
                    emit(Event::Key { code, pressed });
                }
            }
        }
        self.keys = keys;
    }
}

/// A HID boot-protocol mouse. Its reports are a button byte, signed X and Y
/// movement, and on most mice a signed wheel byte.
#[derive(Clone, Copy, Debug, Default)]
pub struct Mouse {
    buttons: u8,
}

impl Mouse {
    pub const fn new() -> Self {
        Self { buttons: 0 }
    }

    /// Decodes one boot report, calling `emit` for each button that
    /// changed, then for each axis that moved.
    pub fn report(&mut self, report: &[u8], mut emit: impl FnMut(Event)) {
        let [buttons, x, y, rest @ ..] = report else {
            return;
        };
        report_buttons(&mut self.buttons, *buttons, &mut emit);
        let wheel = rest.first().copied().unwrap_or(0);
        for (axis, delta) in [
            (RelativeAxis::X, *x),
            (RelativeAxis::Y, *y),
            (RelativeAxis::Wheel, wheel),
        ] {
            if delta != 0 {
                emit(Event::Relative {
                    axis,
                    delta: i32::from(delta as i8),
                });
            }
        }
    }
}

/// QEMU's USB tablet (0627:0001 without a boot interface). Its reports are a
/// button byte, X and Y as little-endian 16-bit values in
/// 0..=[`TABLET_MAXIMUM`], and a signed wheel byte.
#[derive(Clone, Copy, Debug, Default)]
pub struct Tablet {
    buttons: u8,
    position: Option<(i32, i32)>,
}

impl Tablet {
    pub const fn new() -> Self {
        Self {
            buttons: 0,
            position: None,
        }
    }

    /// Decodes one report, calling `emit` for each button that changed,
    /// each coordinate that changed, and any wheel movement.
    pub fn report(&mut self, report: &[u8], mut emit: impl FnMut(Event)) {
        let [buttons, x_low, x_high, y_low, y_high, rest @ ..] = report else {
            return;
        };
        report_buttons(&mut self.buttons, *buttons, &mut emit);
        let coordinate =
            |low: u8, high: u8| i32::from(u16::from_le_bytes([low, high])).min(TABLET_MAXIMUM);
        let (x, y) = (coordinate(*x_low, *x_high), coordinate(*y_low, *y_high));
        let previous = self.position;
        if previous.is_none_or(|(previous, _)| previous != x) {
            emit(Event::Absolute {
                axis: AbsoluteAxis::X,
                value: x,
            });
        }
        if previous.is_none_or(|(_, previous)| previous != y) {
            emit(Event::Absolute {
                axis: AbsoluteAxis::Y,
                value: y,
            });
        }
        self.position = Some((x, y));
        if let Some(&wheel) = rest.first().filter(|wheel| **wheel != 0) {
            emit(Event::Relative {
                axis: RelativeAxis::Wheel,
                delta: i32::from(wheel as i8),
            });
        }
    }
}

/// Emits a press or release for each of the three buttons whose bit changed.
fn report_buttons(previous: &mut u8, buttons: u8, emit: &mut impl FnMut(Event)) {
    let changed = *previous ^ buttons;
    for (bit, button) in BUTTONS.into_iter().enumerate() {
        if changed & (1 << bit) != 0 {
            emit(Event::Button {
                button,
                pressed: buttons & (1 << bit) != 0,
            });
        }
    }
    *previous = buttons & 0b111;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn keyboard(keyboard: &mut Keyboard, report: [u8; 8]) -> Vec<Event> {
        let mut events = Vec::new();
        keyboard.report(&report, |event| events.push(event));
        events
    }

    fn key(code: u16, pressed: bool) -> Event {
        Event::Key { code, pressed }
    }

    #[test]
    fn translates_usages_like_linux() {
        let expected = [
            (0x04, 30),  // a
            (0x1d, 44),  // z
            (0x1e, 2),   // 1
            (0x27, 11),  // 0
            (0x28, 28),  // Enter
            (0x29, 1),   // Escape
            (0x2a, 14),  // Backspace
            (0x2b, 15),  // Tab
            (0x2c, 57),  // Space
            (0x39, 58),  // Caps Lock
            (0x3a, 59),  // F1
            (0x43, 68),  // F10
            (0x44, 87),  // F11
            (0x45, 88),  // F12
            (0x4c, 111), // Delete
            (0x4f, 106), // Right
            (0x50, 105), // Left
            (0x51, 108), // Down
            (0x52, 103), // Up
            (0x58, 96),  // Keypad Enter
            (0xe0, 29),  // Left Control
            (0xe7, 126), // Right GUI
        ];
        for (usage, code) in expected {
            assert_eq!(key_code(usage), Some(code), "usage {usage:#04x}");
        }
        for usage in [0x00, 0x01, 0x02, 0x03, 0x82, 0xa5, 0xdf, 0xff] {
            assert_eq!(key_code(usage), None, "usage {usage:#04x}");
        }
    }

    #[test]
    fn reports_presses_and_releases_once() {
        let mut state = Keyboard::new();
        assert_eq!(
            keyboard(&mut state, [0, 0, 0x04, 0, 0, 0, 0, 0]),
            [key(30, true)]
        );
        // A held key is not pressed again.
        assert_eq!(keyboard(&mut state, [0, 0, 0x04, 0, 0, 0, 0, 0]), []);
        // Keys may move between slots without changing state.
        assert_eq!(
            keyboard(&mut state, [0, 0, 0x05, 0x04, 0, 0, 0, 0]),
            [key(48, true)]
        );
        assert_eq!(
            keyboard(&mut state, [0, 0, 0x05, 0, 0, 0, 0, 0]),
            [key(30, false)]
        );
        assert_eq!(keyboard(&mut state, [0; 8]), [key(48, false)]);
    }

    #[test]
    fn releases_before_presses() {
        let mut state = Keyboard::new();
        keyboard(&mut state, [0, 0, 0x28, 0, 0, 0, 0, 0]);
        assert_eq!(
            keyboard(&mut state, [0, 0, 0x29, 0, 0, 0, 0, 0]),
            [key(28, false), key(1, true)]
        );
    }

    #[test]
    fn reports_modifier_bits_as_keys() {
        let mut state = Keyboard::new();
        assert_eq!(
            keyboard(&mut state, [0x22, 0, 0, 0, 0, 0, 0, 0]),
            [key(42, true), key(54, true)]
        );
        assert_eq!(
            keyboard(&mut state, [0x21, 0, 0x04, 0, 0, 0, 0, 0]),
            [key(29, true), key(42, false), key(30, true)]
        );
        assert_eq!(
            keyboard(&mut state, [0xcc, 0, 0x04, 0, 0, 0, 0, 0]),
            [
                key(29, false),
                key(56, true),
                key(125, true),
                key(54, false),
                key(100, true),
                key(126, true),
            ]
        );
        assert_eq!(
            keyboard(&mut state, [0x10, 0, 0, 0, 0, 0, 0, 0]),
            [
                key(56, false),
                key(125, false),
                key(97, true),
                key(100, false),
                key(126, false),
                key(30, false),
            ]
        );
    }

    #[test]
    fn ignores_keys_of_a_rollover_report() {
        let mut state = Keyboard::new();
        keyboard(&mut state, [0, 0, 0x04, 0x05, 0, 0, 0, 0]);
        assert_eq!(
            keyboard(&mut state, [0x02, 0, 1, 1, 1, 1, 1, 1]),
            [key(42, true)]
        );
        // The keys held before the rollover are still down.
        assert_eq!(
            keyboard(&mut state, [0x02, 0, 0x04, 0, 0, 0, 0, 0]),
            [key(48, false)]
        );
    }

    #[test]
    fn counts_a_repeated_usage_once_and_skips_unknown_ones() {
        let mut state = Keyboard::new();
        assert_eq!(
            keyboard(&mut state, [0, 0, 0x2c, 0x2c, 0xa5, 0x02, 0, 0]),
            [key(57, true)]
        );
        assert_eq!(keyboard(&mut state, [0; 8]), [key(57, false)]);
    }

    #[test]
    fn decodes_short_keyboard_reports() {
        let mut state = Keyboard::new();
        let mut events = Vec::new();
        state.report(&[0, 0, 0x04], |event| events.push(event));
        state.report(&[], |event| events.push(event));
        assert_eq!(events, [key(30, true)]);
    }

    fn mouse(mouse: &mut Mouse, report: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        mouse.report(report, |event| events.push(event));
        events
    }

    fn button(button: Button, pressed: bool) -> Event {
        Event::Button { button, pressed }
    }

    fn relative(axis: RelativeAxis, delta: i32) -> Event {
        Event::Relative { axis, delta }
    }

    #[test]
    fn decodes_boot_mouse_reports() {
        let mut state = Mouse::new();
        assert_eq!(
            mouse(&mut state, &[0x01, 5, 0xfd, 0]),
            [
                button(Button::Left, true),
                relative(RelativeAxis::X, 5),
                relative(RelativeAxis::Y, -3),
            ]
        );
        assert_eq!(
            mouse(&mut state, &[0x06, 0, 0, 0xff]),
            [
                button(Button::Left, false),
                button(Button::Right, true),
                button(Button::Middle, true),
                relative(RelativeAxis::Wheel, -1),
            ]
        );
        // Three-byte reports have no wheel; extra button bits are ignored.
        assert_eq!(
            mouse(&mut state, &[0xfe, 0x80, 0x7f]),
            [
                relative(RelativeAxis::X, -128),
                relative(RelativeAxis::Y, 127)
            ]
        );
        assert_eq!(
            mouse(&mut state, &[0, 0, 0]),
            [button(Button::Right, false), button(Button::Middle, false)]
        );
        assert_eq!(mouse(&mut state, &[1, 2]), []);
    }

    fn tablet(tablet: &mut Tablet, report: &[u8]) -> Vec<Event> {
        let mut events = Vec::new();
        tablet.report(report, |event| events.push(event));
        events
    }

    fn absolute(axis: AbsoluteAxis, value: i32) -> Event {
        Event::Absolute { axis, value }
    }

    #[test]
    fn decodes_tablet_reports() {
        let mut state = Tablet::new();
        assert_eq!(
            tablet(&mut state, &[0, 0x00, 0x40, 0xff, 0x7f, 0]),
            [
                absolute(AbsoluteAxis::X, 0x4000),
                absolute(AbsoluteAxis::Y, TABLET_MAXIMUM),
            ]
        );
        // Unchanged coordinates are not repeated.
        assert_eq!(
            tablet(&mut state, &[0x01, 0x00, 0x40, 0x00, 0x10, 0]),
            [
                button(Button::Left, true),
                absolute(AbsoluteAxis::Y, 0x1000),
            ]
        );
        assert_eq!(
            tablet(&mut state, &[0, 0x00, 0x40, 0x00, 0x10, 0x01]),
            [
                button(Button::Left, false),
                relative(RelativeAxis::Wheel, 1),
            ]
        );
        // Coordinates past the maximum are clamped; short reports ignored.
        assert_eq!(
            tablet(&mut state, &[0, 0xff, 0xff, 0x00, 0x10]),
            [absolute(AbsoluteAxis::X, TABLET_MAXIMUM)]
        );
        assert_eq!(tablet(&mut state, &[0, 1, 2, 3]), []);
    }
}
