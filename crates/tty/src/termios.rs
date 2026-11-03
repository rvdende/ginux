//! Terminal settings as Linux's x86-64 ABI lays them out: `struct termios`
//! (TCGETS), `struct termios2` (TCGETS2) and the older `struct termio`
//! (TCGETA), with the flag bits and control-character slots the line
//! discipline reads.

/// Control characters a `struct termios` carries.
pub const NCCS: usize = 19;
/// Control characters the older `struct termio` carries.
const NCC: usize = 8;

/// Bytes of `struct termios`: four flag words, the line, the characters.
pub const TERMIOS_SIZE: usize = 36;
/// Bytes of `struct termios2`: `struct termios` and the two speeds.
pub const TERMIOS2_SIZE: usize = 44;
/// Bytes of `struct termio`: four 16-bit flag words, the line, eight
/// characters and a byte of padding.
pub const TERMIO_SIZE: usize = 18;

// Input flags.
pub const ISTRIP: u32 = 0o40;
pub const INLCR: u32 = 0o100;
pub const IGNCR: u32 = 0o200;
pub const ICRNL: u32 = 0o400;
pub const IUCLC: u32 = 0o1000;
pub const IXON: u32 = 0o2000;
pub const IXANY: u32 = 0o4000;
pub const IUTF8: u32 = 0o40000;

// Output flags.
pub const OPOST: u32 = 0o1;
pub const OLCUC: u32 = 0o2;
pub const ONLCR: u32 = 0o4;
pub const OCRNL: u32 = 0o10;
pub const ONOCR: u32 = 0o20;
pub const ONLRET: u32 = 0o40;
pub const TABDLY: u32 = 0o14000;
/// The tab delay that expands tabs to spaces.
pub const XTABS: u32 = 0o14000;

// Control flags.
pub const CBAUD: u32 = 0o10017;
pub const B38400: u32 = 0o17;
pub const CSIZE: u32 = 0o60;
pub const CS8: u32 = 0o60;
pub const CREAD: u32 = 0o200;
pub const PARENB: u32 = 0o400;
pub const HUPCL: u32 = 0o2000;
/// The baud field names no standard rate: the speed fields say it.
pub const BOTHER: u32 = 0o10000;
/// The input rate's baud field, `CBAUD` shifted up.
const CIBAUD_SHIFT: u32 = 16;

// Local flags.
pub const ISIG: u32 = 0o1;
pub const ICANON: u32 = 0o2;
pub const ECHO: u32 = 0o10;
pub const ECHOE: u32 = 0o20;
pub const ECHOK: u32 = 0o40;
pub const ECHONL: u32 = 0o100;
pub const NOFLSH: u32 = 0o200;
pub const ECHOCTL: u32 = 0o1000;
pub const ECHOKE: u32 = 0o4000;
pub const IEXTEN: u32 = 0o100000;
pub const EXTPROC: u32 = 0o200000;

// Control-character slots.
pub const VINTR: usize = 0;
pub const VQUIT: usize = 1;
pub const VERASE: usize = 2;
pub const VKILL: usize = 3;
pub const VEOF: usize = 4;
pub const VTIME: usize = 5;
pub const VMIN: usize = 6;
pub const VSTART: usize = 8;
pub const VSTOP: usize = 9;
pub const VSUSP: usize = 10;
pub const VEOL: usize = 11;
pub const VREPRINT: usize = 12;
pub const VWERASE: usize = 14;
pub const VLNEXT: usize = 15;
pub const VEOL2: usize = 16;

/// A control character set to this is turned off.
pub const DISABLED: u8 = 0;

/// ^C ^\ DEL ^U ^D, VTIME 0, VMIN 1, -, ^Q ^S ^Z, -, ^R ^O ^W ^V, -:
/// Linux's defaults.
const DEFAULT_CHARACTERS: [u8; NCCS] = [
    3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0,
];

/// The rates of the baud codes 0 to 15, then of `BOTHER | 1` to `| 15`.
const RATES: [u32; 31] = [
    0, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19_200, 38_400, 57_600,
    115_200, 230_400, 460_800, 500_000, 576_000, 921_600, 1_000_000, 1_152_000, 1_500_000,
    2_000_000, 2_500_000, 3_000_000, 3_500_000, 4_000_000,
];

/// The rate a baud code names, or `None` for `BOTHER` (the speed fields
/// hold it) and unknown codes.
fn rate(code: u32) -> Option<u32> {
    match code {
        0..=15 => Some(RATES[code as usize]),
        _ if code & BOTHER != 0 && code & !BOTHER != 0 => {
            RATES.get(15 + (code & !BOTHER) as usize).copied()
        }
        _ => None,
    }
}

/// One terminal's settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Termios {
    pub iflag: u32,
    pub oflag: u32,
    pub cflag: u32,
    pub lflag: u32,
    pub line: u8,
    pub cc: [u8; NCCS],
    pub ispeed: u32,
    pub ospeed: u32,
}

impl Termios {
    /// A pseudo-terminal slave's settings when its pair is made: canonical
    /// input with echo and signals, CR read as NL, NL written as CR NL, at
    /// 38400 baud.
    pub const fn slave() -> Self {
        Self {
            iflag: ICRNL | IXON,
            oflag: OPOST | ONLCR,
            cflag: B38400 | CS8 | CREAD,
            lflag: ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
            line: 0,
            cc: DEFAULT_CHARACTERS,
            ispeed: 38_400,
            ospeed: 38_400,
        }
    }

    /// A pseudo-terminal master's settings: no input or output processing.
    /// Termios calls on the master reach the slave's settings, so these
    /// never change.
    pub const fn master() -> Self {
        Self {
            iflag: 0,
            oflag: 0,
            lflag: 0,
            ..Self::slave()
        }
    }

    pub(crate) fn input(&self, flag: u32) -> bool {
        self.iflag & flag != 0
    }

    pub(crate) fn output(&self, flag: u32) -> bool {
        self.oflag & flag != 0
    }

    pub(crate) fn local(&self, flag: u32) -> bool {
        self.lflag & flag != 0
    }

    /// Whether input is read a line at a time: ICANON without EXTPROC,
    /// which leaves line editing to the program at the other end.
    pub fn canonical(&self) -> bool {
        self.local(ICANON) && !self.local(EXTPROC)
    }

    /// `struct termios`, as TCGETS returns it.
    pub fn to_termios(&self) -> [u8; TERMIOS_SIZE] {
        let mut bytes = [0; TERMIOS_SIZE];
        for (chunk, flag) in bytes[..16]
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip([self.iflag, self.oflag, self.cflag, self.lflag])
        {
            chunk.copy_from_slice(&flag.to_ne_bytes());
        }
        bytes[16] = self.line;
        bytes[17..].copy_from_slice(&self.cc);
        bytes
    }

    /// `struct termios2`, as TCGETS2 returns it.
    pub fn to_termios2(&self) -> [u8; TERMIOS2_SIZE] {
        let mut bytes = [0; TERMIOS2_SIZE];
        bytes[..TERMIOS_SIZE].copy_from_slice(&self.to_termios());
        bytes[36..40].copy_from_slice(&self.ispeed.to_ne_bytes());
        bytes[40..].copy_from_slice(&self.ospeed.to_ne_bytes());
        bytes
    }

    /// `struct termio`, as TCGETA returns it: the low half of each flag
    /// word and the first eight characters.
    pub fn to_termio(&self) -> [u8; TERMIO_SIZE] {
        let mut bytes = [0; TERMIO_SIZE];
        for (chunk, flag) in bytes[..8]
            .as_chunks_mut::<2>()
            .0
            .iter_mut()
            .zip([self.iflag, self.oflag, self.cflag, self.lflag])
        {
            chunk.copy_from_slice(&(flag as u16).to_ne_bytes());
        }
        bytes[8] = self.line;
        bytes[9..9 + NCC].copy_from_slice(&self.cc[..NCC]);
        bytes
    }

    /// These settings with `struct termios` (TCSETS) applied: the speeds
    /// follow the baud fields unless those say `BOTHER`.
    pub fn with_termios(&self, bytes: &[u8; TERMIOS_SIZE]) -> Self {
        let word = |index: usize| {
            u32::from_ne_bytes([
                bytes[index * 4],
                bytes[index * 4 + 1],
                bytes[index * 4 + 2],
                bytes[index * 4 + 3],
            ])
        };
        let mut cc = [0; NCCS];
        cc.copy_from_slice(&bytes[17..]);
        Self {
            iflag: word(0),
            oflag: word(1),
            cflag: word(2),
            lflag: word(3),
            line: bytes[16],
            cc,
            ..*self
        }
        .with_speeds_from_flags()
    }

    /// These settings with `struct termios2` (TCSETS2) applied, speeds
    /// included.
    pub fn with_termios2(&self, bytes: &[u8; TERMIOS2_SIZE]) -> Self {
        let mut termios = [0; TERMIOS_SIZE];
        termios.copy_from_slice(&bytes[..TERMIOS_SIZE]);
        let speed = |offset: usize| {
            u32::from_ne_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        };
        Self {
            ispeed: speed(36),
            ospeed: speed(40),
            ..*self
        }
        .with_termios(&termios)
    }

    /// These settings with `struct termio` (TCSETA) applied: it replaces
    /// the low half of each flag word and the first eight characters.
    pub fn with_termio(&self, bytes: &[u8; TERMIO_SIZE]) -> Self {
        let half =
            |index: usize| u32::from(u16::from_ne_bytes([bytes[index * 2], bytes[index * 2 + 1]]));
        let mut cc = self.cc;
        cc[..NCC].copy_from_slice(&bytes[9..9 + NCC]);
        Self {
            iflag: self.iflag & 0xffff_0000 | half(0),
            oflag: self.oflag & 0xffff_0000 | half(1),
            cflag: self.cflag & 0xffff_0000 | half(2),
            lflag: self.lflag & 0xffff_0000 | half(3),
            line: bytes[8],
            cc,
            ..*self
        }
        .with_speeds_from_flags()
    }

    /// Loads the speed fields from the baud fields, as Linux does for every
    /// settings change: the input field, when zero, means the output rate.
    fn with_speeds_from_flags(mut self) -> Self {
        if let Some(output) = rate(self.cflag & CBAUD) {
            self.ospeed = output;
        }
        let input = (self.cflag >> CIBAUD_SHIFT) & CBAUD;
        if input == 0 {
            self.ispeed = self.ospeed;
        } else if let Some(input) = rate(input) {
            self.ispeed = input;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layouts_round_trip() {
        let termios = Termios::slave();
        assert_eq!(termios.with_termios(&termios.to_termios()), termios);
        assert_eq!(termios.with_termios2(&termios.to_termios2()), termios);
        assert_eq!(termios.with_termio(&termios.to_termio()), termios);
        assert_eq!(termios.to_termios()[..4], (ICRNL | IXON).to_ne_bytes());
        assert_eq!(termios.to_termios()[17 + VEOF], 4);
    }

    #[test]
    fn baud_fields_set_the_speeds() {
        let mut bytes = Termios::slave().to_termios();
        let cflag = (Termios::slave().cflag & !CBAUD) | 0o15; // B9600
        bytes[8..12].copy_from_slice(&cflag.to_ne_bytes());
        let changed = Termios::slave().with_termios(&bytes);
        assert_eq!((changed.ispeed, changed.ospeed), (9600, 9600));
        let mut bytes = changed.to_termios2();
        let cflag = (cflag & !CBAUD) | BOTHER;
        bytes[8..12].copy_from_slice(&cflag.to_ne_bytes());
        bytes[36..40].copy_from_slice(&12_345_u32.to_ne_bytes());
        bytes[40..44].copy_from_slice(&12_345_u32.to_ne_bytes());
        let changed = changed.with_termios2(&bytes);
        assert_eq!((changed.ispeed, changed.ospeed), (12_345, 12_345));
    }

    #[test]
    fn termio_keeps_the_high_flag_bits() {
        let mut termios = Termios::slave();
        termios.lflag |= EXTPROC;
        let mut bytes = termios.to_termio();
        bytes[6..8].copy_from_slice(&(ECHO as u16).to_ne_bytes());
        let changed = termios.with_termio(&bytes);
        assert_eq!(changed.lflag, EXTPROC | ECHO);
    }
}
