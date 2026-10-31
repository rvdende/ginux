//! Text console on the linear framebuffer left active by UEFI.
//!
//! Physical machines rarely expose a serial port, so every byte written to the
//! serial console is mirrored here. The console keeps a model of the text grid
//! and redraws only the cells that changed, so scrolling never reads from video
//! memory. It understands the subset of ANSI escape sequences that the
//! controller, BusyBox, and bash emit: SGR colours, cursor positioning, and
//! screen and line erasure.

use core::sync::atomic::{AtomicBool, Ordering};

use font8x8::legacy::BASIC_LEGACY;

use crate::{BootFramebuffer, FRAMEBUFFER_FORMAT_BGRX, FRAMEBUFFER_FORMAT_RGBX};

const GLYPH_SIZE: usize = 8;
const MAX_COLUMNS: usize = 320;
const MAX_ROWS: usize = 160;
const MAX_CSI_PARAMETERS: usize = 8;
const DEFAULT_FOREGROUND: u8 = 7;
const DEFAULT_BACKGROUND: u8 = 0;
const TARGET_ROWS: usize = 50;

/// The sixteen VGA colours as 0xRRGGBB.
const PALETTE: [u32; 16] = [
    0x000000, 0xaa0000, 0x00aa00, 0xaa5500, 0x0000aa, 0xaa00aa, 0x00aaaa, 0xaaaaaa, 0x555555,
    0xff5555, 0x55ff55, 0xffff55, 0x5555ff, 0xff55ff, 0x55ffff, 0xffffff,
];

#[derive(Clone, Copy, Eq, PartialEq)]
struct Cell {
    glyph: u8,
    foreground: u8,
    background: u8,
}

const BLANK: Cell = Cell {
    glyph: b' ',
    foreground: DEFAULT_FOREGROUND,
    background: DEFAULT_BACKGROUND,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Escape {
    None,
    Started,
    Charset,
    Csi,
}

struct Console {
    base: usize,
    width: usize,
    height: usize,
    stride: usize,
    bgrx: bool,
    scale: usize,
    columns: usize,
    rows: usize,
    column: usize,
    row: usize,
    foreground: u8,
    background: u8,
    bold: bool,
    escape: Escape,
    parameters: [u16; MAX_CSI_PARAMETERS],
    parameter_count: usize,
    cells: [[Cell; MAX_COLUMNS]; MAX_ROWS],
    drawn: [[Cell; MAX_COLUMNS]; MAX_ROWS],
}

static READY: AtomicBool = AtomicBool::new(false);
static BUSY: AtomicBool = AtomicBool::new(false);
/// Set while a domain draws to the framebuffer through /dev/fb0; the console
/// keeps its text model but stops drawing until the screen is handed back.
static OWNED: AtomicBool = AtomicBool::new(false);
static mut DISPLAY: Option<Display> = None;

/// The firmware framebuffer as /dev/fb0 describes it to Linux programs.
#[derive(Clone, Copy)]
pub(crate) struct Display {
    pub(crate) physical: u64,
    pub(crate) width: u32,
    pub(crate) height: u32,
    /// Bytes per scan line.
    pub(crate) line_length: u32,
    pub(crate) length: usize,
    pub(crate) bgrx: bool,
}
static mut CONSOLE: Console = Console {
    base: 0,
    width: 0,
    height: 0,
    stride: 0,
    bgrx: true,
    scale: 1,
    columns: 0,
    rows: 0,
    column: 0,
    row: 0,
    foreground: DEFAULT_FOREGROUND,
    background: DEFAULT_BACKGROUND,
    bold: false,
    escape: Escape::None,
    parameters: [0; MAX_CSI_PARAMETERS],
    parameter_count: 0,
    cells: [[BLANK; MAX_COLUMNS]; MAX_ROWS],
    drawn: [[BLANK; MAX_COLUMNS]; MAX_ROWS],
};

/// Returns the byte length a framebuffer description covers, or `None` when
/// the description is absent, unsupported, or inconsistent.
pub(crate) fn mapped_length(info: &BootFramebuffer) -> Option<usize> {
    if !matches!(
        info.format,
        FRAMEBUFFER_FORMAT_RGBX | FRAMEBUFFER_FORMAT_BGRX
    ) || info.base == 0
        || info.width == 0
        || info.height == 0
        || info.stride < info.width
    {
        return None;
    }
    let length = (info.stride as usize)
        .checked_mul(info.height as usize)?
        .checked_mul(4)?;
    (length as u64 <= info.size).then_some(length)
}

/// Starts the console on a framebuffer reachable at `virtual_base`.
///
/// # Safety
///
/// `virtual_base` must map `mapped_length(info)` writable bytes of the
/// framebuffer described by `info` for as long as the console is used.
pub(crate) unsafe fn init(info: &BootFramebuffer, virtual_base: usize) -> bool {
    if mapped_length(info).is_none() || virtual_base == 0 {
        return false;
    }
    if BUSY.swap(true, Ordering::Acquire) {
        return false;
    }
    let console = &mut *core::ptr::addr_of_mut!(CONSOLE);
    DISPLAY = mapped_length(info).map(|length| Display {
        physical: info.base,
        width: info.width,
        height: info.height,
        line_length: info.stride * 4,
        length,
        bgrx: info.format == FRAMEBUFFER_FORMAT_BGRX,
    });
    console.base = virtual_base;
    console.width = info.width as usize;
    console.height = info.height as usize;
    console.stride = info.stride as usize;
    console.bgrx = info.format == FRAMEBUFFER_FORMAT_BGRX;
    console.scale = (console.height / (GLYPH_SIZE * TARGET_ROWS)).max(1);
    let cell = GLYPH_SIZE * console.scale;
    console.columns = (console.width / cell).min(MAX_COLUMNS);
    console.rows = (console.height / cell).min(MAX_ROWS);
    console.column = 0;
    console.row = 0;
    console.reset_attributes();
    console.escape = Escape::None;
    console.clear_all();
    console.fill(0, 0, console.width, console.height, DEFAULT_BACKGROUND);
    for row in 0..console.rows {
        console.drawn[row][..console.columns].fill(BLANK);
    }
    BUSY.store(false, Ordering::Release);
    READY.store(true, Ordering::Release);
    true
}

/// Moves the console to a new virtual address for the same framebuffer.
///
/// # Safety
///
/// `virtual_base` must map the framebuffer passed to [`init`].
pub(crate) unsafe fn relocate(virtual_base: usize) {
    if virtual_base == 0 || BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    (*core::ptr::addr_of_mut!(CONSOLE)).base = virtual_base;
    BUSY.store(false, Ordering::Release);
}

/// Mirrors console output. Output arriving while the console is busy, for
/// example from an exception handler, is dropped rather than interleaved.
pub(crate) fn write(bytes: &[u8]) {
    if !READY.load(Ordering::Acquire) || BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    // SAFETY: BUSY grants exclusive access to CONSOLE, and READY guarantees
    // that init mapped the framebuffer it describes.
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
    let owned = OWNED.load(Ordering::Acquire);
    if !owned {
        console.hide_cursor();
    }
    for byte in bytes.iter().copied() {
        console.byte(byte);
    }
    if !owned {
        console.show_cursor();
    }
    BUSY.store(false, Ordering::Release);
}

/// The framebuffer /dev/fb0 exposes, if the firmware left a usable one.
pub(crate) fn display() -> Option<Display> {
    // SAFETY: DISPLAY is written once by init, before Linux programs run.
    unsafe { *core::ptr::addr_of!(DISPLAY) }
}

/// Hands the screen to a Linux program, or takes it back for the console,
/// which then repaints everything the program drew over.
pub(crate) fn set_owned(owned: bool) {
    if OWNED.swap(owned, Ordering::AcqRel) == owned || owned {
        return;
    }
    if !READY.load(Ordering::Acquire) || BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    // SAFETY: BUSY grants exclusive access to CONSOLE.
    let console = unsafe { &mut *core::ptr::addr_of_mut!(CONSOLE) };
    console.fill(0, 0, console.width, console.height, DEFAULT_BACKGROUND);
    for row in 0..console.rows {
        for column in 0..console.columns {
            console.draw_cell(row, column);
        }
    }
    console.show_cursor();
    BUSY.store(false, Ordering::Release);
}

/// Copies between the framebuffer and `bytes` at a byte offset, for read(2)
/// and write(2) on /dev/fb0. Returns the bytes copied.
pub(crate) fn transfer(offset: usize, bytes: &mut [u8], write: bool) -> usize {
    let Some(display) = display() else {
        return 0;
    };
    if !READY.load(Ordering::Acquire) || offset >= display.length {
        return 0;
    }
    let length = bytes.len().min(display.length - offset);
    // SAFETY: CONSOLE.base maps display.length bytes of the framebuffer
    // (checked by init), and offset + length stays inside them.
    let base = unsafe { (*core::ptr::addr_of!(CONSOLE)).base } as *mut u8;
    unsafe {
        if write {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), base.add(offset), length);
        } else {
            core::ptr::copy_nonoverlapping(base.add(offset), bytes.as_mut_ptr(), length);
        }
    }
    length
}

impl Console {
    fn byte(&mut self, byte: u8) {
        match self.escape {
            Escape::Started => {
                self.escape = match byte {
                    b'[' => {
                        self.parameters = [0; MAX_CSI_PARAMETERS];
                        self.parameter_count = 0;
                        Escape::Csi
                    }
                    b'(' | b')' => Escape::Charset,
                    _ => Escape::None,
                };
                return;
            }
            Escape::Charset => {
                self.escape = Escape::None;
                return;
            }
            Escape::Csi => {
                self.csi(byte);
                return;
            }
            Escape::None => {}
        }
        match byte {
            0x1b => self.escape = Escape::Started,
            b'\r' => self.column = 0,
            b'\n' => {
                self.column = 0;
                self.line_feed();
            }
            0x08 => self.column = self.column.saturating_sub(1),
            b'\t' => {
                let next = (self.column / 8 + 1) * 8;
                while self.column < next.min(self.columns) {
                    self.put(b' ');
                }
            }
            // UTF-8 continuation bytes belong to a glyph already drawn.
            0x80..=0xbf => {}
            0xc0..=0xff => self.put(b'?'),
            0x20..=0x7e => self.put(byte),
            _ => {}
        }
    }

    fn csi(&mut self, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                self.parameter_count = self.parameter_count.max(1);
                let value = &mut self.parameters[self.parameter_count - 1];
                *value = value
                    .saturating_mul(10)
                    .saturating_add(u16::from(byte - b'0'));
            }
            b';' => {
                self.parameter_count = (self.parameter_count.max(1) + 1).min(MAX_CSI_PARAMETERS);
            }
            b'?' | b'>' | b'=' | b' ' => {}
            0x40..=0x7e => {
                self.escape = Escape::None;
                self.csi_final(byte);
            }
            _ => self.escape = Escape::None,
        }
    }

    fn parameter(&self, index: usize, default: usize) -> usize {
        match self.parameters.get(index) {
            Some(&value) if index < self.parameter_count && value != 0 => usize::from(value),
            _ => default,
        }
    }

    fn csi_final(&mut self, byte: u8) {
        match byte {
            b'm' => self.select_graphic_rendition(),
            b'H' | b'f' => {
                self.row = self.parameter(0, 1).min(self.rows) - 1;
                self.column = self.parameter(1, 1).min(self.columns) - 1;
            }
            b'A' => self.row = self.row.saturating_sub(self.parameter(0, 1)),
            b'B' => self.row = (self.row + self.parameter(0, 1)).min(self.rows - 1),
            b'C' => self.column = (self.column + self.parameter(0, 1)).min(self.columns - 1),
            b'D' => self.column = self.column.saturating_sub(self.parameter(0, 1)),
            b'G' => self.column = self.parameter(0, 1).min(self.columns) - 1,
            b'J' => match self.parameter(0, 0) {
                0 => {
                    self.erase_line(self.row, self.column, self.columns);
                    for row in self.row + 1..self.rows {
                        self.erase_line(row, 0, self.columns);
                    }
                }
                1 => {
                    for row in 0..self.row {
                        self.erase_line(row, 0, self.columns);
                    }
                    self.erase_line(self.row, 0, self.column + 1);
                }
                _ => {
                    self.clear_all();
                    self.row = 0;
                    self.column = 0;
                }
            },
            b'K' => match self.parameter(0, 0) {
                0 => self.erase_line(self.row, self.column, self.columns),
                1 => self.erase_line(self.row, 0, self.column + 1),
                _ => self.erase_line(self.row, 0, self.columns),
            },
            _ => {}
        }
        self.flush();
    }

    fn select_graphic_rendition(&mut self) {
        if self.parameter_count == 0 {
            self.reset_attributes();
            return;
        }
        for index in 0..self.parameter_count {
            match self.parameters[index] {
                0 => self.reset_attributes(),
                1 => self.bold = true,
                22 => self.bold = false,
                7 => core::mem::swap(&mut self.foreground, &mut self.background),
                code @ 30..=37 => self.foreground = (code - 30) as u8,
                39 => self.foreground = DEFAULT_FOREGROUND,
                code @ 40..=47 => self.background = (code - 40) as u8,
                49 => self.background = DEFAULT_BACKGROUND,
                code @ 90..=97 => self.foreground = (code - 90) as u8 + 8,
                code @ 100..=107 => self.background = (code - 100) as u8 + 8,
                _ => {}
            }
        }
    }

    fn reset_attributes(&mut self) {
        self.foreground = DEFAULT_FOREGROUND;
        self.background = DEFAULT_BACKGROUND;
        self.bold = false;
    }

    fn put(&mut self, glyph: u8) {
        if self.column >= self.columns {
            self.column = 0;
            self.line_feed();
        }
        let foreground = if self.bold && self.foreground < 8 {
            self.foreground + 8
        } else {
            self.foreground
        };
        self.cells[self.row][self.column] = Cell {
            glyph,
            foreground,
            background: self.background,
        };
        self.draw_cell(self.row, self.column);
        self.column += 1;
    }

    fn line_feed(&mut self) {
        if self.row + 1 < self.rows {
            self.row += 1;
            return;
        }
        self.cells.copy_within(1..self.rows, 0);
        self.cells[self.rows - 1][..self.columns].fill(BLANK);
        self.flush();
    }

    fn erase_line(&mut self, row: usize, start: usize, end: usize) {
        if row < self.rows {
            let blank = Cell {
                background: self.background,
                ..BLANK
            };
            self.cells[row][start.min(self.columns)..end.min(self.columns)].fill(blank);
        }
    }

    fn clear_all(&mut self) {
        for row in 0..self.rows {
            self.cells[row][..self.columns].fill(BLANK);
        }
    }

    fn flush(&mut self) {
        for row in 0..self.rows {
            for column in 0..self.columns {
                if self.cells[row][column] != self.drawn[row][column] {
                    self.draw_cell(row, column);
                }
            }
        }
    }

    fn draw_cell(&mut self, row: usize, column: usize) {
        let cell = self.cells[row][column];
        if OWNED.load(Ordering::Acquire) {
            return;
        }
        self.drawn[row][column] = cell;
        let glyph = BASIC_LEGACY[usize::from(cell.glyph & 0x7f)];
        let foreground = self.pixel(cell.foreground);
        let background = self.pixel(cell.background);
        let size = GLYPH_SIZE * self.scale;
        let origin_x = column * size;
        let origin_y = row * size;
        for y in 0..size {
            let bits = glyph[y / self.scale];
            let line =
                (self.base as *mut u32).wrapping_add((origin_y + y) * self.stride + origin_x);
            for x in 0..size {
                let lit = bits & (1 << (x / self.scale)) != 0;
                // SAFETY: the cell lies inside the width-by-height area that
                // init validated against the mapped framebuffer length.
                unsafe {
                    line.add(x)
                        .write_volatile(if lit { foreground } else { background });
                }
            }
        }
    }

    fn show_cursor(&mut self) {
        if self.row >= self.rows || self.column >= self.columns {
            return;
        }
        let size = GLYPH_SIZE * self.scale;
        let colour = self.pixel(DEFAULT_FOREGROUND);
        let thickness = self.scale.max(2);
        let x = self.column * size;
        let y = self.row * size + size - thickness;
        self.fill_pixels(x, y, size, thickness, colour);
    }

    fn hide_cursor(&mut self) {
        if self.row < self.rows && self.column < self.columns {
            self.draw_cell(self.row, self.column);
        }
    }

    fn fill(&mut self, x: usize, y: usize, width: usize, height: usize, colour: u8) {
        let pixel = self.pixel(colour);
        self.fill_pixels(x, y, width, height, pixel);
    }

    fn fill_pixels(&mut self, x: usize, y: usize, width: usize, height: usize, pixel: u32) {
        if OWNED.load(Ordering::Acquire) {
            return;
        }
        for row in y..(y + height).min(self.height) {
            let line = (self.base as *mut u32).wrapping_add(row * self.stride);
            for column in x..(x + width).min(self.width) {
                // SAFETY: row and column are clamped to the validated area.
                unsafe { line.add(column).write_volatile(pixel) };
            }
        }
    }

    fn pixel(&self, colour: u8) -> u32 {
        let rgb = PALETTE[usize::from(colour & 0x0f)];
        if self.bgrx {
            rgb
        } else {
            ((rgb & 0xff) << 16) | (rgb & 0xff00) | (rgb >> 16)
        }
    }
}
