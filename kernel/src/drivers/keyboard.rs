//! Translation of USB HID boot-protocol keyboard reports into console bytes
//! for a US layout.

const MODIFIER_LEFT_CONTROL: u8 = 1 << 0;
const MODIFIER_LEFT_SHIFT: u8 = 1 << 1;
const MODIFIER_RIGHT_CONTROL: u8 = 1 << 4;
const MODIFIER_RIGHT_SHIFT: u8 = 1 << 5;
const USAGE_ERROR_ROLLOVER: u8 = 0x01;
const USAGE_CAPS_LOCK: u8 = 0x39;

/// Unshifted and shifted characters for usages 0x04 (a) through 0x38 (/).
const PRINTABLE: [(u8, u8); 53] = [
    (b'a', b'A'),
    (b'b', b'B'),
    (b'c', b'C'),
    (b'd', b'D'),
    (b'e', b'E'),
    (b'f', b'F'),
    (b'g', b'G'),
    (b'h', b'H'),
    (b'i', b'I'),
    (b'j', b'J'),
    (b'k', b'K'),
    (b'l', b'L'),
    (b'm', b'M'),
    (b'n', b'N'),
    (b'o', b'O'),
    (b'p', b'P'),
    (b'q', b'Q'),
    (b'r', b'R'),
    (b's', b'S'),
    (b't', b'T'),
    (b'u', b'U'),
    (b'v', b'V'),
    (b'w', b'W'),
    (b'x', b'X'),
    (b'y', b'Y'),
    (b'z', b'Z'),
    (b'1', b'!'),
    (b'2', b'@'),
    (b'3', b'#'),
    (b'4', b'$'),
    (b'5', b'%'),
    (b'6', b'^'),
    (b'7', b'&'),
    (b'8', b'*'),
    (b'9', b'('),
    (b'0', b')'),
    (b'\r', b'\r'),
    (0x1b, 0x1b),
    (0x7f, 0x7f),
    (b'\t', b'\t'),
    (b' ', b' '),
    (b'-', b'_'),
    (b'=', b'+'),
    (b'[', b'{'),
    (b']', b'}'),
    (b'\\', b'|'),
    (b'#', b'~'),
    (b';', b':'),
    (b'\'', b'"'),
    (b'`', b'~'),
    (b',', b'<'),
    (b'.', b'>'),
    (b'/', b'?'),
];

/// Keeps the previous report so only newly pressed keys produce input.
pub(crate) struct Keyboard {
    previous: [u8; 6],
    caps_lock: bool,
}

impl Keyboard {
    pub(crate) const fn new() -> Self {
        Self {
            previous: [0; 6],
            caps_lock: false,
        }
    }

    /// Decodes one 8-byte boot report, calling `emit` with the bytes of each
    /// newly pressed key.
    pub(crate) fn report(&mut self, report: &[u8; 8], mut emit: impl FnMut(&[u8])) {
        let keys: [u8; 6] = report[2..8].try_into().unwrap_or([0; 6]);
        if keys.contains(&USAGE_ERROR_ROLLOVER) {
            return;
        }
        let modifiers = report[0];
        let shift = modifiers & (MODIFIER_LEFT_SHIFT | MODIFIER_RIGHT_SHIFT) != 0;
        let control = modifiers & (MODIFIER_LEFT_CONTROL | MODIFIER_RIGHT_CONTROL) != 0;
        for key in keys {
            if key == 0 || self.previous.contains(&key) {
                continue;
            }
            if key == USAGE_CAPS_LOCK {
                self.caps_lock = !self.caps_lock;
                continue;
            }
            match key {
                0x4f => emit(b"\x1b[C"),
                0x50 => emit(b"\x1b[D"),
                0x51 => emit(b"\x1b[B"),
                0x52 => emit(b"\x1b[A"),
                0x04..=0x38 => {
                    let (lower, upper) = PRINTABLE[usize::from(key - 0x04)];
                    let letter = lower.is_ascii_lowercase();
                    let shifted = if letter {
                        shift ^ self.caps_lock
                    } else {
                        shift
                    };
                    let byte = if shifted { upper } else { lower };
                    if control && letter {
                        emit(&[lower - b'a' + 1]);
                    } else {
                        emit(&[byte]);
                    }
                }
                _ => {}
            }
        }
        self.previous = keys;
    }
}
