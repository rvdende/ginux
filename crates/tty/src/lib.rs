#![forbid(unsafe_code)]
//! Pseudo-terminal pairs and the terminal line discipline, as Linux's pty
//! driver and `n_tty` define them.
//!
//! A [`Pair`] is a master and a slave joined back to back: bytes written to
//! one end arrive as input at the other. Each end's input first lands in a
//! receive queue (Linux's flip buffer, 64 KiB) and then passes through that
//! end's line discipline into its read buffer (4 KiB), which is what reads
//! and polls see. The slave's settings ([`termios::Termios`]) drive the
//! discipline: canonical line editing with erase, kill and end-of-file,
//! echo of what arrives back to the master, CR/NL translation, signal
//! characters, flow control, and output processing of what the slave
//! writes (NL to CR NL). The master's settings do no processing, and every
//! settings call on the master reaches the slave's, as on Linux.
//!
//! The kernel keeps the pairs, counts the descriptors open on each end,
//! copies to and from user memory, waits when [`Error::WouldBlock`] says
//! so, and sends the signals the slave's input raised ([`Pair::take_signals`])
//! to its foreground process group. This is pure state, so it is tested on
//! the host.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod termios;

use alloc::collections::VecDeque;

use termios::*;

/// Bytes a line discipline holds for its reader: Linux's N_TTY_BUF_SIZE.
const READ_BUFFER: usize = 4096;
/// Bytes received and not yet through the line discipline: Linux's limit
/// on a tty's flip buffers, and so what a writer may get ahead of a reader.
pub const RECEIVE_LIMIT: usize = 64 * 1024;

/// A read-buffer cell ends a line (canonical mode).
const LINE_END: u16 = 1 << 8;
/// A read-buffer cell is the end-of-file character: it ends its line and
/// is not read.
const END_OF_FILE: u16 = 1 << 9;

/// Signal numbers the slave's input can raise.
pub const SIGINT: u8 = 2;
pub const SIGQUIT: u8 = 3;
pub const SIGTSTP: u8 = 20;

/// The status byte a master in packet mode (TIOCPKT) reads.
pub mod packet {
    /// Data follows.
    pub const DATA: u8 = 0;
    pub const FLUSHREAD: u8 = 1;
    pub const FLUSHWRITE: u8 = 2;
    pub const STOP: u8 = 4;
    pub const START: u8 = 8;
    pub const NOSTOP: u8 = 16;
    pub const DOSTOP: u8 = 32;
    pub const IOCTL: u8 = 64;
}

/// One end of a pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    Master,
    Slave,
}

impl End {
    pub fn other(self) -> Self {
        match self {
            Self::Master => Self::Slave,
            Self::Slave => Self::Master,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Nothing to read, or no room to write: a blocking caller waits and
    /// tries again, a non-blocking one gets EAGAIN.
    WouldBlock,
    /// The other end is gone (EIO).
    Io,
}

/// What `poll` reports for an end.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Readiness {
    pub readable: bool,
    pub writable: bool,
    /// The other end has closed.
    pub hangup: bool,
    /// A packet-mode status byte waits (POLLPRI).
    pub priority: bool,
}

/// Input and output state of one end.
#[derive(Default)]
struct Side {
    /// Bytes written by the other end, not yet through the discipline.
    received: VecDeque<u8>,
    /// The read buffer: each cell a byte with `LINE_END` and `END_OF_FILE`.
    cells: VecDeque<u16>,
    /// Cells at the front that make complete lines (canonical mode); the
    /// rest is the line being edited.
    canon: usize,
    /// The next character is taken literally (VLNEXT).
    lnext: bool,
    /// The output column, for tabs and erasing, and the column the line
    /// being edited started at.
    column: usize,
    canon_column: usize,
    /// Output is stopped (VSTOP or TCOOFF); `stopped_by_call` when TCOOFF
    /// did it, which only TCOON undoes.
    stopped: bool,
    stopped_by_call: bool,
}

impl Side {
    fn reset_input(&mut self) {
        self.received.clear();
        self.cells.clear();
        self.canon = 0;
        self.lnext = false;
    }

    fn editing(&self) -> bool {
        self.cells.len() > self.canon
    }
}

/// A pseudo-terminal pair.
pub struct Pair {
    /// The slave's settings, which termios calls on either end reach.
    termios: Termios,
    master: Side,
    slave: Side,
    window: [u8; 8],
    locked: bool,
    packet: bool,
    packet_status: u8,
    master_closed: bool,
    slave_closed: bool,
    /// Signals (bit `n - 1` for signal `n`) the slave's input raised.
    signals: u32,
}

impl Default for Pair {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether Linux's `iscntrl` holds: C0, DEL and C1.
fn control(c: u8) -> bool {
    c < 0x20 || (0x7f..=0x9f).contains(&c)
}

fn continuation(termios: &Termios, c: u8) -> bool {
    termios.input(IUTF8) && c & 0xc0 == 0x80
}

/// Writes `c` into `queue` as `termios` asks, tracking `side`'s column;
/// false when the queue has no room for all it would write.
fn output_char(side: &mut Side, termios: &Termios, c: u8, queue: &mut VecDeque<u8>) -> bool {
    let room = RECEIVE_LIMIT.saturating_sub(queue.len());
    if room == 0 {
        return false;
    }
    if !termios.output(OPOST) {
        queue.push_back(c);
        return true;
    }
    let mut c = c;
    match c {
        b'\n' => {
            if termios.output(ONLRET) {
                side.column = 0;
            }
            if termios.output(ONLCR) {
                if room < 2 {
                    return false;
                }
                side.column = 0;
                side.canon_column = 0;
                queue.extend(*b"\r\n");
                return true;
            }
            side.canon_column = side.column;
        }
        b'\r' => {
            if termios.output(ONOCR) && side.column == 0 {
                return true;
            }
            if termios.output(OCRNL) {
                c = b'\n';
                if termios.output(ONLRET) {
                    side.column = 0;
                    side.canon_column = 0;
                }
            } else {
                side.column = 0;
                side.canon_column = 0;
            }
        }
        b'\t' => {
            let spaces = 8 - (side.column & 7);
            if termios.oflag & TABDLY == XTABS {
                if room < spaces {
                    return false;
                }
                side.column += spaces;
                queue.extend(core::iter::repeat_n(b' ', spaces));
                return true;
            }
            side.column += spaces;
        }
        0x08 => side.column = side.column.saturating_sub(1),
        _ if !control(c) => {
            if termios.output(OLCUC) {
                c = c.to_ascii_uppercase();
            }
            if !continuation(termios, c) {
                side.column += 1;
            }
        }
        _ => {}
    }
    queue.push_back(c);
    true
}

/// How an erase character erases (Linux's eraser).
#[derive(Clone, Copy, Eq, PartialEq)]
enum Erase {
    Character,
    Word,
    Line,
}

impl Pair {
    /// A pair as opening /dev/ptmx makes it: locked until TIOCSPTLCK
    /// unlocks it, with a zero window size.
    pub fn new() -> Self {
        Self {
            termios: Termios::slave(),
            master: Side::default(),
            slave: Side::default(),
            window: [0; 8],
            locked: true,
            packet: false,
            packet_status: 0,
            master_closed: false,
            slave_closed: false,
            signals: 0,
        }
    }

    fn side(&self, end: End) -> &Side {
        match end {
            End::Master => &self.master,
            End::Slave => &self.slave,
        }
    }

    fn side_mut(&mut self, end: End) -> &mut Side {
        match end {
            End::Master => &mut self.master,
            End::Slave => &mut self.slave,
        }
    }

    /// `end` and the other end.
    fn sides(&mut self, end: End) -> (&mut Side, &mut Side) {
        match end {
            End::Master => (&mut self.master, &mut self.slave),
            End::Slave => (&mut self.slave, &mut self.master),
        }
    }

    fn termios_of(&self, end: End) -> Termios {
        match end {
            End::Master => Termios::master(),
            End::Slave => self.termios,
        }
    }

    /// The slave's settings.
    pub fn termios(&self) -> Termios {
        self.termios
    }

    /// Applies new settings to the slave. A pty always has eight data bits
    /// and no parity. Turning canonical mode on or off makes what is
    /// buffered one line or plain bytes; turning IXON off restarts output
    /// it stopped.
    pub fn set_termios(&mut self, new: Termios) {
        let old = self.termios;
        let mut new = new;
        new.cflag = new.cflag & !(CSIZE | PARENB) | CS8 | CREAD;
        if self.packet {
            let flow = |termios: &Termios| {
                termios.input(IXON) && termios.cc[VSTOP] == 0o23 && termios.cc[VSTART] == 0o21
            };
            if flow(&old) != flow(&new) {
                self.packet_status &= !(packet::DOSTOP | packet::NOSTOP);
                self.packet_status |= if flow(&new) {
                    packet::DOSTOP
                } else {
                    packet::NOSTOP
                };
            }
            if (old.lflag | new.lflag) & EXTPROC != 0 {
                self.packet_status |= packet::IOCTL;
            }
        }
        self.termios = new;
        if (old.lflag ^ new.lflag) & (ICANON | EXTPROC) != 0 {
            let side = &mut self.slave;
            for cell in side.cells.iter_mut() {
                *cell &= 0xff;
            }
            side.canon = 0;
            side.lnext = false;
            if new.local(ICANON) {
                if let Some(last) = side.cells.back_mut() {
                    *last |= LINE_END;
                    side.canon = side.cells.len();
                }
            }
        }
        if old.input(IXON) && !new.input(IXON) && !self.slave.stopped_by_call {
            self.start(End::Slave);
        }
        self.push(End::Slave);
    }

    pub fn window(&self) -> [u8; 8] {
        self.window
    }

    /// Sets the window size; true when it changed (SIGWINCH is due).
    pub fn set_window(&mut self, window: [u8; 8]) -> bool {
        let changed = self.window != window;
        self.window = window;
        changed
    }

    pub fn locked(&self) -> bool {
        self.locked
    }

    pub fn set_locked(&mut self, locked: bool) {
        self.locked = locked;
    }

    pub fn packet(&self) -> bool {
        self.packet
    }

    /// Turns the master's packet mode on or off; turning it on clears any
    /// status left from before.
    pub fn set_packet(&mut self, on: bool) {
        if on && !self.packet {
            self.packet_status = 0;
        }
        self.packet = on;
    }

    /// The signals the slave's input raised since the last call, bit
    /// `n - 1` for signal `n`.
    pub fn take_signals(&mut self) -> u32 {
        core::mem::take(&mut self.signals)
    }

    /// The master has closed: the slave is hung up.
    pub fn hung_up(&self) -> bool {
        self.master_closed
    }

    /// Opens the slave: EIO while the pair is locked or its master gone.
    pub fn open_slave(&mut self) -> Result<(), Error> {
        if self.locked || self.master_closed {
            return Err(Error::Io);
        }
        self.slave_closed = false;
        Ok(())
    }

    /// The slave's last descriptor has closed: the master reads EIO once
    /// it has read what is left, and polls as hung up.
    pub fn close_slave(&mut self) {
        self.slave_closed = true;
    }

    /// The master has closed: the slave reads end-of-file and writes EIO.
    pub fn close_master(&mut self) {
        self.master_closed = true;
        self.packet = false;
    }

    /// Moves what `end` received through its line discipline, as far as
    /// its read buffer has room. A canonical line that fills the buffer
    /// keeps taking characters over its last one, so a newline still ends
    /// it.
    fn push(&mut self, end: End) {
        loop {
            let termios = self.termios_of(end);
            let side = self.side_mut(end);
            let Some(&c) = side.received.front() else {
                break;
            };
            let held = side.cells.len();
            if held + 1 >= READ_BUFFER {
                if !(termios.local(ICANON) && side.canon == 0) {
                    break;
                }
                if held >= READ_BUFFER {
                    side.cells.pop_back();
                }
            }
            side.received.pop_front();
            self.receive(end, &termios, c);
        }
    }

    fn queue(&mut self, end: End, c: u8) {
        self.side_mut(end).cells.push_back(u16::from(c));
    }

    /// Ends the line being edited with `c` (or end-of-file).
    fn end_line(&mut self, end: End, c: u8, end_of_file: bool) {
        let side = self.side_mut(end);
        let flags = if end_of_file {
            LINE_END | END_OF_FILE
        } else {
            LINE_END
        };
        side.cells.push_back(u16::from(c) | flags);
        side.canon = side.cells.len();
    }

    /// Echoes `c` as written, through output processing.
    fn echo_raw(&mut self, end: End, termios: &Termios, c: u8) {
        let (side, other) = self.sides(end);
        let _ = output_char(side, termios, c, &mut other.received);
    }

    /// Echoes `c`, a control character as `^X` under ECHOCTL.
    fn echo_char(&mut self, end: End, termios: &Termios, c: u8) {
        if termios.local(ECHOCTL) && control(c) && c != b'\t' {
            let (side, other) = self.sides(end);
            if RECEIVE_LIMIT - other.received.len() >= 2 {
                other.received.extend([b'^', c ^ 0o100]);
                side.column += 2;
            }
        } else {
            self.echo_raw(end, termios, c);
        }
    }

    /// Notes the column the line being edited starts at, before echoing its
    /// first character.
    fn mark_line_start(&mut self, end: End) {
        let side = self.side_mut(end);
        if !side.editing() {
            side.canon_column = side.column;
        }
    }

    fn backspaces(&mut self, end: End, count: usize) {
        let (side, other) = self.sides(end);
        for _ in 0..count {
            if other.received.len() >= RECEIVE_LIMIT {
                break;
            }
            other.received.push_back(0x08);
            side.column = side.column.saturating_sub(1);
        }
    }

    /// Restarts `end`'s output, unless TCOOFF stopped it.
    fn start(&mut self, end: End) {
        let side = self.side_mut(end);
        if !side.stopped || side.stopped_by_call {
            return;
        }
        side.stopped = false;
        if end == End::Slave && self.packet {
            self.packet_status &= !packet::STOP;
            self.packet_status |= packet::START;
        }
    }

    fn stop(&mut self, end: End) {
        if self.side(end).stopped {
            return;
        }
        self.side_mut(end).stopped = true;
        if end == End::Slave && self.packet {
            self.packet_status &= !packet::START;
            self.packet_status |= packet::STOP;
        }
    }

    /// Whether `c` takes the discipline's special handling under `termios`.
    fn special(termios: &Termios, c: u8) -> bool {
        let cc = &termios.cc;
        let canonical = termios.local(ICANON);
        let extended = canonical && termios.local(IEXTEN);
        c != DISABLED
            && (c == b'\r' && (termios.input(IGNCR) || termios.input(ICRNL))
                || c == b'\n' && termios.input(INLCR)
                || canonical
                    && (c == b'\n' || [VERASE, VKILL, VEOF, VEOL].iter().any(|&i| cc[i] == c))
                || extended && [VWERASE, VLNEXT, VEOL2].iter().any(|&i| cc[i] == c)
                || extended && termios.local(ECHO) && cc[VREPRINT] == c
                || termios.input(IXON) && (cc[VSTART] == c || cc[VSTOP] == c)
                || termios.local(ISIG) && [VINTR, VQUIT, VSUSP].iter().any(|&i| cc[i] == c))
    }

    /// One received character through the discipline.
    fn receive(&mut self, end: End, termios: &Termios, c: u8) {
        let mut c = c;
        if termios.input(ISTRIP) {
            c &= 0x7f;
        }
        if termios.input(IUCLC) && termios.local(IEXTEN) {
            c = c.to_ascii_lowercase();
        }
        if core::mem::take(&mut self.side_mut(end).lnext) {
            self.receive_plain(end, termios, c);
        } else if termios.local(EXTPROC) {
            self.queue(end, c);
        } else if Self::special(termios, c) {
            self.receive_special(end, termios, c);
        } else {
            self.receive_plain(end, termios, c);
        }
    }

    /// Output stopped by VSTOP restarts on any input under IXANY.
    fn restart_on_any(&mut self, end: End, termios: &Termios) {
        let side = self.side(end);
        if side.stopped && !side.stopped_by_call && termios.input(IXON) && termios.input(IXANY) {
            self.start(end);
        }
    }

    fn receive_plain(&mut self, end: End, termios: &Termios, c: u8) {
        self.restart_on_any(end, termios);
        if termios.local(ECHO) {
            self.mark_line_start(end);
            self.echo_char(end, termios, c);
        }
        self.queue(end, c);
    }

    fn receive_special(&mut self, end: End, termios: &Termios, c: u8) {
        let cc = termios.cc;
        if termios.input(IXON) && (c == cc[VSTART] || c == cc[VSTOP]) {
            if c == cc[VSTART] {
                self.start(end);
            } else {
                self.stop(end);
            }
            return;
        }
        if termios.local(ISIG) {
            let signal = [(VINTR, SIGINT), (VQUIT, SIGQUIT), (VSUSP, SIGTSTP)]
                .into_iter()
                .find(|&(slot, _)| cc[slot] == c);
            if let Some((_, signal)) = signal {
                self.signal_char(end, termios, signal, c);
                return;
            }
        }
        self.restart_on_any(end, termios);
        let mut c = c;
        if c == b'\r' {
            if termios.input(IGNCR) {
                return;
            }
            if termios.input(ICRNL) {
                c = b'\n';
            }
        } else if c == b'\n' && termios.input(INLCR) {
            c = b'\r';
        }
        if termios.local(ICANON) && self.receive_canonical(end, termios, c) {
            return;
        }
        if termios.local(ECHO) {
            if c == b'\n' {
                self.echo_raw(end, termios, c);
            } else {
                self.mark_line_start(end);
                self.echo_char(end, termios, c);
            }
        }
        self.queue(end, c);
    }

    /// A signal character: the signal for the foreground group, a flush of
    /// both directions unless NOFLSH, and the character's echo.
    fn signal_char(&mut self, end: End, termios: &Termios, signal: u8, c: u8) {
        if end == End::Slave {
            self.signals |= 1 << (signal - 1);
        }
        if !termios.local(NOFLSH) {
            self.side_mut(end.other()).received.clear();
            let side = self.side_mut(end);
            side.cells.clear();
            side.canon = 0;
            side.lnext = false;
            if end == End::Slave && self.packet {
                self.packet_status |= packet::FLUSHREAD | packet::FLUSHWRITE;
            }
        }
        if termios.input(IXON) {
            self.start(end);
        }
        if termios.local(ECHO) {
            self.echo_char(end, termios, c);
        }
    }

    /// Canonical-mode line editing; false when `c` is an ordinary character.
    fn receive_canonical(&mut self, end: End, termios: &Termios, c: u8) -> bool {
        let cc = termios.cc;
        let extended = termios.local(IEXTEN);
        let echo = termios.local(ECHO);
        if c == cc[VERASE] || c == cc[VKILL] || c == cc[VWERASE] && extended {
            self.erase(end, termios, c);
        } else if c == cc[VLNEXT] && extended {
            self.side_mut(end).lnext = true;
            if echo && termios.local(ECHOCTL) {
                self.echo_raw(end, termios, b'^');
                self.echo_raw(end, termios, 0x08);
            }
        } else if c == cc[VREPRINT] && echo && extended {
            self.echo_char(end, termios, c);
            self.echo_raw(end, termios, b'\n');
            let side = self.side(end);
            let line: VecDeque<u8> = side
                .cells
                .range(side.canon..)
                .map(|&cell| cell as u8)
                .collect();
            for c in line {
                self.echo_char(end, termios, c);
            }
        } else if c == b'\n' {
            if echo || termios.local(ECHONL) {
                self.echo_raw(end, termios, b'\n');
            }
            self.end_line(end, c, false);
        } else if c == cc[VEOF] {
            self.end_line(end, DISABLED, true);
        } else if c == cc[VEOL] || c == cc[VEOL2] && extended {
            if echo {
                self.mark_line_start(end);
                self.echo_char(end, termios, c);
            }
            self.end_line(end, c, false);
        } else {
            return false;
        }
        true
    }

    /// The erase, word-erase and kill characters: removes from the line
    /// being edited and echoes the removal.
    fn erase(&mut self, end: End, termios: &Termios, c: u8) {
        if !self.side(end).editing() {
            return;
        }
        let kind = if c == termios.cc[VERASE] {
            Erase::Character
        } else if c == termios.cc[VWERASE] {
            Erase::Word
        } else {
            Erase::Line
        };
        let echo = termios.local(ECHO);
        if kind == Erase::Line {
            if !echo {
                let side = self.side_mut(end);
                side.cells.truncate(side.canon);
                return;
            }
            if !termios.local(ECHOK) || !termios.local(ECHOKE) || !termios.local(ECHOE) {
                let side = self.side_mut(end);
                side.cells.truncate(side.canon);
                self.echo_char(end, termios, termios.cc[VKILL]);
                if termios.local(ECHOK) {
                    self.echo_raw(end, termios, b'\n');
                }
                return;
            }
        }
        let mut seen_alphanumerics = false;
        while self.side(end).editing() {
            let side = self.side(end);
            // One character, all of a UTF-8 sequence.
            let mut head = side.cells.len();
            let mut erased;
            loop {
                head -= 1;
                erased = side.cells[head] as u8;
                if !continuation(termios, erased) || head == side.canon {
                    break;
                }
            }
            if continuation(termios, erased) {
                break;
            }
            if kind == Erase::Word {
                if erased.is_ascii_alphanumeric() || erased == b'_' {
                    seen_alphanumerics = true;
                } else if seen_alphanumerics {
                    break;
                }
            }
            // The columns a tab took: back to the line's start or the tab
            // before it.
            let mut tab_columns = 0;
            let mut after_tab = false;
            if erased == b'\t' {
                for &cell in side.cells.range(side.canon..head).rev() {
                    let earlier = cell as u8;
                    if earlier == b'\t' {
                        after_tab = true;
                        break;
                    } else if control(earlier) {
                        if termios.local(ECHOCTL) {
                            tab_columns += 2;
                        }
                    } else if !continuation(termios, earlier) {
                        tab_columns += 1;
                    }
                }
            }
            self.side_mut(end).cells.truncate(head);
            if echo {
                if kind == Erase::Character && !termios.local(ECHOE) {
                    self.echo_char(end, termios, termios.cc[VERASE]);
                } else if erased == b'\t' {
                    if !after_tab {
                        tab_columns += self.side(end).canon_column;
                    }
                    self.backspaces(end, 8 - (tab_columns & 7));
                } else {
                    let rubouts = usize::from(control(erased) && termios.local(ECHOCTL))
                        + usize::from(!control(erased) || termios.local(ECHOCTL));
                    for _ in 0..rubouts {
                        for c in *b"\x08 \x08" {
                            self.echo_raw(end, termios, c);
                        }
                    }
                }
            }
            if kind == Erase::Character {
                break;
            }
        }
    }

    /// Writes `input` from `from` to the other end; returns the bytes
    /// taken. The slave's output is processed (OPOST); the master's goes
    /// as is.
    pub fn write(&mut self, from: End, input: &[u8]) -> Result<usize, Error> {
        if from == End::Slave && self.master_closed {
            return Err(Error::Io);
        }
        if input.is_empty() {
            return Ok(0);
        }
        if self.side(from).stopped {
            return Err(Error::WouldBlock);
        }
        let termios = self.termios_of(from);
        let (side, other) = self.sides(from);
        let written = input
            .iter()
            .take_while(|&&c| output_char(side, &termios, c, &mut other.received))
            .count();
        self.push(from.other());
        self.push(from);
        if written == 0 {
            Err(Error::WouldBlock)
        } else {
            Ok(written)
        }
    }

    /// Sends `c` to the other end as is, even with output stopped
    /// (TCIOFF and TCION).
    pub fn send_char(&mut self, from: End, c: u8) {
        let other = self.side_mut(from.other());
        if other.received.len() < RECEIVE_LIMIT {
            other.received.push_back(c);
        }
        self.push(from.other());
        self.push(from);
    }

    /// Takes `c` as if it had arrived at `end` (TIOCSTI).
    pub fn inject(&mut self, end: End, c: u8) {
        let side = self.side_mut(end);
        if side.received.len() < RECEIVE_LIMIT {
            side.received.push_back(c);
        }
        self.push(end);
        self.push(end.other());
    }

    /// Reads at `end` into `output`. In canonical mode a read returns at
    /// most one line, and a line ended by VEOF without data reads as 0
    /// (end-of-file). Otherwise VMIN and VTIME decide: a read waits for
    /// VMIN bytes (or as many as `output` holds), and with VTIME set, for
    /// that timer, which the caller runs and reports as `expired`.
    pub fn read(&mut self, end: End, output: &mut [u8], expired: bool) -> Result<usize, Error> {
        if end == End::Slave && self.master_closed {
            return Ok(0);
        }
        if output.is_empty() {
            return Ok(0);
        }
        let packet = end == End::Master && self.packet;
        if packet && self.packet_status != 0 {
            output[0] = core::mem::take(&mut self.packet_status);
            return Ok(1);
        }
        self.push(end);
        let termios = self.termios_of(end);
        let start = usize::from(packet);
        let side = self.side_mut(end);
        let ready = if termios.canonical() {
            side.canon > 0
        } else {
            let (minimum, time) = (usize::from(termios.cc[VMIN]), termios.cc[VTIME]);
            let held = side.cells.len();
            let wanted = if minimum > 0 {
                minimum.min(output.len() - start)
            } else {
                1
            };
            held >= wanted || held > 0 && (minimum == 0 || time > 0 && expired)
        };
        if !ready {
            if end == End::Master && self.slave_closed {
                return Err(Error::Io);
            }
            if !termios.canonical() && termios.cc[VMIN] == 0 && (termios.cc[VTIME] == 0 || expired)
            {
                return Ok(0);
            }
            return Err(Error::WouldBlock);
        }
        if packet {
            output[0] = packet::DATA;
        }
        let mut length = start;
        if termios.canonical() {
            while side.canon > 0 {
                let cell = side.cells[0];
                if cell & END_OF_FILE != 0 {
                    side.cells.pop_front();
                    side.canon -= 1;
                    break;
                }
                if length == output.len() {
                    break;
                }
                side.cells.pop_front();
                side.canon -= 1;
                output[length] = cell as u8;
                length += 1;
                if cell & LINE_END != 0 {
                    break;
                }
            }
        } else {
            let count = side.cells.len().min(output.len() - length);
            for (slot, cell) in output[length..].iter_mut().zip(side.cells.drain(..count)) {
                *slot = cell as u8;
            }
            side.canon = side.canon.saturating_sub(count);
            length += count;
        }
        self.push(end);
        Ok(length)
    }

    /// Whether a read at `end` would want a VTIME timer running: a
    /// non-canonical read with VTIME set that has data, or wants none.
    pub fn read_timer(&self, end: End) -> Option<u8> {
        let termios = self.termios_of(end);
        let time = termios.cc[VTIME];
        (!termios.canonical()
            && time > 0
            && (termios.cc[VMIN] == 0 || !self.side(end).cells.is_empty()))
        .then_some(time)
    }

    /// Bytes a read at `end` can take (FIONREAD): complete lines in
    /// canonical mode, less their end-of-file characters.
    pub fn readable_bytes(&mut self, end: End) -> usize {
        self.push(end);
        let termios = self.termios_of(end);
        let side = self.side(end);
        if termios.canonical() {
            side.cells
                .range(..side.canon)
                .filter(|&&cell| cell & END_OF_FILE == 0)
                .count()
        } else {
            side.cells.len()
        }
    }

    pub fn poll(&mut self, end: End) -> Readiness {
        self.push(end);
        let termios = self.termios_of(end);
        let side = self.side(end);
        let priority = end == End::Master && self.packet && self.packet_status != 0;
        let readable = priority
            || if termios.canonical() {
                side.canon > 0
            } else {
                let (minimum, time) = (termios.cc[VMIN], termios.cc[VTIME]);
                let wanted = if time == 0 && minimum > 0 {
                    usize::from(minimum)
                } else {
                    1
                };
                side.cells.len() >= wanted
            };
        let writable = !side.stopped && self.side(end.other()).received.len() < RECEIVE_LIMIT;
        Readiness {
            readable,
            writable,
            hangup: end == End::Master && self.slave_closed,
            priority,
        }
    }

    /// Discards what `end` has received and not read (TCIFLUSH).
    pub fn flush_input(&mut self, end: End) {
        self.side_mut(end).reset_input();
        if end == End::Slave && self.packet {
            self.packet_status |= packet::FLUSHREAD;
        }
    }

    /// Discards what `end` has written that has not reached the other
    /// end's read buffer (TCOFLUSH).
    pub fn flush_output(&mut self, end: End) {
        self.side_mut(end.other()).received.clear();
        if end == End::Slave && self.packet {
            self.packet_status |= packet::FLUSHWRITE;
        }
    }

    /// Stops `end`'s output (TCOOFF).
    pub fn suspend_output(&mut self, end: End) {
        if !self.side(end).stopped_by_call {
            self.stop(end);
            self.side_mut(end).stopped_by_call = true;
        }
    }

    /// Restarts output TCOOFF stopped (TCOON).
    pub fn resume_output(&mut self, end: End) {
        if self.side(end).stopped_by_call {
            self.side_mut(end).stopped_by_call = false;
            self.start(end);
            self.push(end.other());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn unlocked() -> Pair {
        let mut pair = Pair::new();
        pair.set_locked(false);
        pair.open_slave().unwrap();
        pair
    }

    fn read_all(pair: &mut Pair, end: End) -> Vec<u8> {
        let mut buffer = [0_u8; 8192];
        match pair.read(end, &mut buffer, false) {
            Ok(length) => buffer[..length].to_vec(),
            Err(_) => Vec::new(),
        }
    }

    fn set_local(pair: &mut Pair, on: u32, off: u32) {
        let mut termios = pair.termios();
        termios.lflag = termios.lflag & !off | on;
        pair.set_termios(termios);
    }

    #[test]
    fn a_locked_pair_refuses_the_slave() {
        let mut pair = Pair::new();
        assert_eq!(pair.open_slave(), Err(Error::Io));
        pair.set_locked(false);
        assert_eq!(pair.open_slave(), Ok(()));
    }

    #[test]
    fn canonical_lines_echo_and_translate() {
        let mut pair = unlocked();
        assert_eq!(pair.write(End::Master, b"Linux Test Project\n"), Ok(19));
        assert_eq!(read_all(&mut pair, End::Slave), b"Linux Test Project\n");
        // The echo comes back with NL as CR NL.
        assert_eq!(read_all(&mut pair, End::Master), b"Linux Test Project\r\n");
        assert_eq!(pair.write(End::Slave, b"out\n"), Ok(4));
        assert_eq!(read_all(&mut pair, End::Master), b"out\r\n");
    }

    #[test]
    fn a_read_waits_for_a_whole_line() {
        let mut pair = unlocked();
        pair.write(End::Master, b"abc").unwrap();
        let mut buffer = [0; 16];
        assert_eq!(
            pair.read(End::Slave, &mut buffer, false),
            Err(Error::WouldBlock)
        );
        assert_eq!(pair.readable_bytes(End::Slave), 0);
        pair.write(End::Master, b"\rdef\n").unwrap();
        assert_eq!(pair.readable_bytes(End::Slave), 8);
        assert_eq!(read_all(&mut pair, End::Slave), b"abc\n");
        let mut small = [0; 2];
        assert_eq!(pair.read(End::Slave, &mut small, false), Ok(2));
        assert_eq!(&small, b"de");
        assert_eq!(read_all(&mut pair, End::Slave), b"f\n");
    }

    #[test]
    fn end_of_file_ends_a_line_unread() {
        let mut pair = unlocked();
        pair.write(End::Master, b"ab\x04\x04").unwrap();
        assert_eq!(pair.readable_bytes(End::Slave), 2);
        assert_eq!(read_all(&mut pair, End::Slave), b"ab");
        let mut buffer = [0; 4];
        assert_eq!(pair.read(End::Slave, &mut buffer, false), Ok(0));
        assert_eq!(
            pair.read(End::Slave, &mut buffer, false),
            Err(Error::WouldBlock)
        );
    }

    #[test]
    fn erase_and_kill_edit_the_line() {
        let mut pair = unlocked();
        pair.write(End::Master, b"abx\x7fc\n").unwrap();
        assert_eq!(read_all(&mut pair, End::Slave), b"abc\n");
        assert_eq!(read_all(&mut pair, End::Master), b"abx\x08 \x08c\r\n");
        pair.write(End::Master, b"one two\x17three\n").unwrap();
        assert_eq!(read_all(&mut pair, End::Slave), b"one three\n");
        pair.write(End::Master, b"gone\x15kept\n").unwrap();
        assert_eq!(read_all(&mut pair, End::Slave), b"kept\n");
        pair.write(End::Master, b"x\x16\x7f\n").unwrap();
        assert_eq!(read_all(&mut pair, End::Slave), b"x\x7f\n");
    }

    #[test]
    fn raw_mode_reads_what_is_there() {
        let mut pair = unlocked();
        set_local(&mut pair, 0, ICANON | ECHO);
        pair.write(End::Master, b"\x04ab").unwrap();
        assert_eq!(read_all(&mut pair, End::Slave), b"\x04ab");
        assert!(read_all(&mut pair, End::Master).is_empty());
        let mut termios = pair.termios();
        termios.cc[VMIN] = 3;
        pair.set_termios(termios);
        pair.write(End::Master, b"xy").unwrap();
        let mut buffer = [0; 8];
        assert_eq!(
            pair.read(End::Slave, &mut buffer, false),
            Err(Error::WouldBlock)
        );
        assert!(!pair.poll(End::Slave).readable);
        pair.write(End::Master, b"z").unwrap();
        assert!(pair.poll(End::Slave).readable);
        assert_eq!(pair.read(End::Slave, &mut buffer, false), Ok(3));
        termios.cc[VMIN] = 0;
        termios.cc[VTIME] = 1;
        pair.set_termios(termios);
        assert_eq!(pair.read_timer(End::Slave), Some(1));
        assert_eq!(
            pair.read(End::Slave, &mut buffer, false),
            Err(Error::WouldBlock)
        );
        assert_eq!(pair.read(End::Slave, &mut buffer, true), Ok(0));
    }

    #[test]
    fn switching_to_canonical_makes_one_line() {
        let mut pair = unlocked();
        set_local(&mut pair, 0, ICANON);
        pair.write(End::Master, b"part").unwrap();
        set_local(&mut pair, ICANON, 0);
        assert_eq!(pair.readable_bytes(End::Slave), 4);
        assert_eq!(read_all(&mut pair, End::Slave), b"part");
    }

    #[test]
    fn signal_characters_raise_signals_and_flush() {
        let mut pair = unlocked();
        pair.write(End::Master, b"lost\x03").unwrap();
        assert_eq!(pair.take_signals(), 1 << (SIGINT - 1));
        assert_eq!(pair.take_signals(), 0);
        assert_eq!(pair.readable_bytes(End::Slave), 0);
        // The echo of what was flushed goes too.
        assert_eq!(read_all(&mut pair, End::Master), b"^C");
    }

    #[test]
    fn closing_the_slave_makes_the_master_read_eio() {
        let mut pair = unlocked();
        pair.write(End::Slave, b"bye").unwrap();
        pair.close_slave();
        assert!(pair.poll(End::Master).hangup);
        assert_eq!(read_all(&mut pair, End::Master), b"bye");
        let mut buffer = [0; 4];
        assert_eq!(pair.read(End::Master, &mut buffer, false), Err(Error::Io));
    }

    #[test]
    fn closing_the_master_hangs_up_the_slave() {
        let mut pair = unlocked();
        pair.write(End::Master, b"data\n").unwrap();
        pair.close_master();
        let mut buffer = [0; 8];
        assert_eq!(pair.read(End::Slave, &mut buffer, false), Ok(0));
        assert_eq!(pair.write(End::Slave, b"x"), Err(Error::Io));
        assert_eq!(pair.open_slave(), Err(Error::Io));
    }

    #[test]
    fn a_full_pair_refuses_more() {
        let mut pair = unlocked();
        set_local(&mut pair, 0, ICANON | ECHO);
        let block = [b'a'; 4096];
        let mut total = 0;
        while let Ok(written) = pair.write(End::Master, &block) {
            total += written;
        }
        assert_eq!(total, RECEIVE_LIMIT + READ_BUFFER - 1);
        assert!(!pair.poll(End::Master).writable);
        let mut buffer = [0; 8192];
        assert_eq!(
            pair.read(End::Slave, &mut buffer, false),
            Ok(READ_BUFFER - 1)
        );
        assert!(pair.poll(End::Master).writable);
    }

    #[test]
    fn flow_control_stops_the_slave() {
        let mut pair = unlocked();
        pair.write(End::Master, b"\x13").unwrap();
        assert_eq!(pair.write(End::Slave, b"x"), Err(Error::WouldBlock));
        pair.write(End::Master, b"\x11").unwrap();
        assert_eq!(pair.write(End::Slave, b"x"), Ok(1));
        pair.suspend_output(End::Slave);
        pair.write(End::Master, b"\x11").unwrap();
        assert_eq!(pair.write(End::Slave, b"x"), Err(Error::WouldBlock));
        pair.resume_output(End::Slave);
        assert_eq!(pair.write(End::Slave, b"x"), Ok(1));
    }

    #[test]
    fn packet_mode_prefixes_and_reports_flushes() {
        let mut pair = unlocked();
        pair.set_packet(true);
        set_local(&mut pair, 0, ECHO);
        pair.write(End::Slave, b"hi").unwrap();
        assert_eq!(read_all(&mut pair, End::Master), b"\0hi");
        pair.flush_input(End::Slave);
        assert!(pair.poll(End::Master).priority);
        assert_eq!(read_all(&mut pair, End::Master), [packet::FLUSHREAD]);
    }

    #[test]
    fn output_processing_expands_tabs() {
        let mut pair = unlocked();
        let mut termios = pair.termios();
        termios.oflag |= XTABS;
        pair.set_termios(termios);
        pair.write(End::Slave, b"ab\tc").unwrap();
        assert_eq!(read_all(&mut pair, End::Master), b"ab      c");
    }
}
