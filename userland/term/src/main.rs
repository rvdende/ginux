//! ginux-term: a small Wayland terminal for Ginux. It runs an interactive
//! shell over pipes (Ginux has no pseudo-terminals yet), so it keeps its own
//! line editing: typed text is echoed locally and sent a line at a time.

use std::{
    ffi::c_void,
    io::{Read, Write},
    os::{
        fd::{AsFd, AsRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Child, ChildStdin, Command, ExitCode, Stdio},
};

use ginux_gfx::{Canvas, GLYPH};
use rustix::event::{poll, PollFd, PollFlags};
use wayland_client::{
    delegate_noop,
    globals::{registry_queue_init, GlobalListContents},
    protocol::{
        wl_buffer, wl_callback, wl_compositor, wl_keyboard, wl_registry, wl_seat, wl_shm,
        wl_shm_pool, wl_surface,
    },
    Connection, Dispatch, QueueHandle, WEnum,
};
use wayland_protocols::xdg::{
    decoration::zv1::client::{zxdg_decoration_manager_v1, zxdg_toplevel_decoration_v1},
    shell::client::{xdg_surface, xdg_toplevel, xdg_wm_base},
};

extern "C" {
    fn mmap(
        address: *mut c_void,
        length: usize,
        protection: i32,
        flags: i32,
        fd: i32,
        offset: i64,
    ) -> *mut c_void;
    fn munmap(address: *mut c_void, length: usize) -> i32;
}

const PADDING: i32 = 4;
const BACKGROUND: u32 = 0xff10_1418;
const FOREGROUND: u32 = 0xffd8_dee9;
const CURSOR: u32 = 0xff88_c0d0;

/// A grid of characters fed by the shell's output.
struct Grid {
    columns: usize,
    rows: usize,
    cells: Vec<char>,
    row: usize,
    column: usize,
    escape: Escape,
}

#[derive(PartialEq)]
enum Escape {
    None,
    Started,
    /// Inside a CSI sequence, collecting parameter bytes.
    Csi(String),
}

impl Grid {
    fn new(columns: usize, rows: usize) -> Self {
        Self {
            columns,
            rows,
            cells: vec![' '; columns * rows],
            row: 0,
            column: 0,
            escape: Escape::None,
        }
    }

    fn resize(&mut self, columns: usize, rows: usize) {
        if (columns, rows) == (self.columns, self.rows) {
            return;
        }
        let mut cells = vec![' '; columns * rows];
        // Keep the bottom rows, which hold the prompt and recent output.
        let skip = (self.row + 1).saturating_sub(rows);
        for row in 0..rows.min(self.rows - skip) {
            for column in 0..columns.min(self.columns) {
                cells[row * columns + column] = self.cells[(row + skip) * self.columns + column];
            }
        }
        self.cells = cells;
        self.columns = columns;
        self.rows = rows;
        self.row = (self.row - skip).min(rows - 1);
        self.column = self.column.min(columns - 1);
    }

    fn newline(&mut self) {
        self.column = 0;
        if self.row + 1 < self.rows {
            self.row += 1;
        } else {
            self.cells.drain(..self.columns);
            self.cells.extend(std::iter::repeat_n(' ', self.columns));
        }
    }

    fn put(&mut self, character: char) {
        if self.column >= self.columns {
            self.newline();
        }
        self.cells[self.row * self.columns + self.column] = character;
        self.column += 1;
    }

    fn backspace(&mut self) {
        if self.column > 0 {
            self.column -= 1;
        } else if self.row > 0 {
            self.row -= 1;
            self.column = self.columns - 1;
        }
        self.cells[self.row * self.columns + self.column] = ' ';
    }

    fn clear(&mut self) {
        self.cells.fill(' ');
        self.row = 0;
        self.column = 0;
    }

    fn feed(&mut self, text: &str) {
        for character in text.chars() {
            match std::mem::replace(&mut self.escape, Escape::None) {
                Escape::Started if character == '[' => self.escape = Escape::Csi(String::new()),
                Escape::Started => {}
                Escape::Csi(mut parameters) => {
                    if ('\x40'..='\x7e').contains(&character) {
                        self.control_sequence(&parameters, character);
                    } else {
                        parameters.push(character);
                        self.escape = Escape::Csi(parameters);
                    }
                }
                Escape::None => match character {
                    '\x1b' => self.escape = Escape::Started,
                    '\n' => self.newline(),
                    '\r' => self.column = 0,
                    '\x08' => self.column = self.column.saturating_sub(1),
                    '\t' => {
                        for _ in 0..8 - self.column % 8 {
                            self.put(' ');
                        }
                    }
                    character if character.is_control() => {}
                    character => self.put(character),
                },
            }
        }
    }

    /// Handles the few CSI sequences shells commonly emit; others are
    /// dropped.
    fn control_sequence(&mut self, parameters: &str, command: char) {
        let numbers: Vec<usize> = parameters
            .split(';')
            .map(|part| part.parse().unwrap_or(0))
            .collect();
        let first = numbers.first().copied().unwrap_or(0);
        match command {
            'J' if first == 2 || first == 3 => self.clear(),
            'J' => {
                let start = self.row * self.columns + self.column;
                self.cells[start..].fill(' ');
            }
            'K' => {
                let start = self.row * self.columns + self.column;
                self.cells[start..(self.row + 1) * self.columns].fill(' ');
            }
            'H' | 'f' => {
                self.row = first.saturating_sub(1).min(self.rows - 1);
                self.column = numbers
                    .get(1)
                    .copied()
                    .unwrap_or(1)
                    .saturating_sub(1)
                    .min(self.columns - 1);
            }
            _ => {}
        }
    }
}

/// Shared memory holding two frame buffers of the current window size.
struct Pool {
    address: *mut u8,
    length: usize,
    pool: wl_shm_pool::WlShmPool,
    buffers: Vec<(wl_buffer::WlBuffer, bool)>,
    width: i32,
    height: i32,
}

impl Drop for Pool {
    fn drop(&mut self) {
        for (buffer, _) in &self.buffers {
            buffer.destroy();
        }
        self.pool.destroy();
        // SAFETY: unmaps exactly the mapping made in Terminal::pool().
        unsafe { munmap(self.address.cast(), self.length) };
    }
}

struct Terminal {
    compositor: wl_compositor::WlCompositor,
    shm: wl_shm::WlShm,
    surface: wl_surface::WlSurface,
    keyboard: Option<wl_keyboard::WlKeyboard>,
    configured: bool,
    size: (i32, i32),
    requested: Option<(i32, i32)>,
    pool: Option<Pool>,
    waiting_for_frame: bool,
    dirty: bool,
    grid: Grid,
    scale: i32,
    line: String,
    shell: Child,
    stdin: Option<ChildStdin>,
    shift: bool,
    control: bool,
    caps_lock: bool,
    closed: bool,
}

impl Terminal {
    fn cell(&self) -> (i32, i32) {
        (GLYPH * self.scale, (GLYPH + 4) * self.scale)
    }

    /// Makes sure the pool matches the window size, recreating it if not.
    fn ensure_pool(&mut self, qh: &QueueHandle<Self>) -> Option<()> {
        let (width, height) = self.size;
        if self
            .pool
            .as_ref()
            .is_some_and(|pool| (pool.width, pool.height) != (width, height))
        {
            self.pool = None;
        }
        if self.pool.is_none() {
            let frame = (width * height * 4) as usize;
            let length = frame * 2;
            let fd: OwnedFd =
                rustix::fs::memfd_create("ginux-term", rustix::fs::MemfdFlags::CLOEXEC).ok()?;
            rustix::fs::ftruncate(&fd, length as u64).ok()?;
            // SAFETY: maps the memfd just sized to `length` bytes.
            let address = unsafe { mmap(std::ptr::null_mut(), length, 3, 1, fd.as_raw_fd(), 0) };
            if address as isize == -1 {
                return None;
            }
            let pool = self.shm.create_pool(fd.as_fd(), length as i32, qh, ());
            let buffers = (0..2)
                .map(|index| {
                    let buffer = pool.create_buffer(
                        (index * frame) as i32,
                        width,
                        height,
                        width * 4,
                        wl_shm::Format::Xrgb8888,
                        qh,
                        index,
                    );
                    (buffer, false)
                })
                .collect();
            self.pool = Some(Pool {
                address: address.cast(),
                length,
                pool,
                buffers,
                width,
                height,
            });
        }
        Some(())
    }

    fn draw(&mut self, qh: &QueueHandle<Self>) {
        let (width, height) = self.size;
        let (cell_width, cell_height) = self.cell();
        let scale = self.scale;
        if self.ensure_pool(qh).is_none() {
            return;
        }
        let Terminal {
            pool: Some(pool),
            grid,
            surface,
            ..
        } = self
        else {
            return;
        };
        let Some(index) = pool.buffers.iter().position(|(_, busy)| !busy) else {
            return;
        };
        let frame = (width * height) as usize;
        // SAFETY: buffer `index` occupies frame * 4 bytes at index * frame * 4
        // within the pool mapping, and the compositor only reads it.
        let pixels = unsafe {
            std::slice::from_raw_parts_mut(pool.address.cast::<u32>().add(index * frame), frame)
        };
        let mut canvas = Canvas::new(pixels, width, height);
        canvas.fill(0, 0, width, height, BACKGROUND);
        for row in 0..grid.rows {
            let y = PADDING + row as i32 * cell_height + 2 * scale;
            for column in 0..grid.columns {
                let character = grid.cells[row * grid.columns + column];
                if character != ' ' {
                    canvas.glyph(
                        PADDING + column as i32 * cell_width,
                        y,
                        character,
                        FOREGROUND,
                        scale,
                    );
                }
            }
        }
        canvas.fill(
            PADDING + grid.column.min(grid.columns - 1) as i32 * cell_width,
            PADDING + grid.row as i32 * cell_height + (GLYPH + 2) * scale,
            cell_width,
            2 * scale,
            CURSOR,
        );
        let buffer = &mut pool.buffers[index];
        buffer.1 = true;
        surface.attach(Some(&buffer.0), 0, 0);
        surface.damage_buffer(0, 0, width, height);
        surface.frame(qh, ());
        surface.commit();
        self.waiting_for_frame = true;
        self.dirty = false;
    }

    fn apply_size(&mut self) {
        let (cell_width, cell_height) = self.cell();
        if let Some((width, height)) = self.requested.take() {
            let columns = ((width - 2 * PADDING) / cell_width).max(10) as usize;
            let rows = ((height - 2 * PADDING) / cell_height).max(3) as usize;
            self.grid.resize(columns, rows);
        }
        self.size = (
            self.grid.columns as i32 * cell_width + 2 * PADDING,
            self.grid.rows as i32 * cell_height + 2 * PADDING,
        );
        self.dirty = true;
    }

    fn send(&mut self, text: &str) {
        if let Some(stdin) = &mut self.stdin {
            if stdin.write_all(text.as_bytes()).is_err() {
                self.stdin = None;
            }
        }
    }

    fn key(&mut self, code: u32, pressed: bool) {
        match code {
            42 | 54 => self.shift = pressed,
            29 | 97 => self.control = pressed,
            58 if pressed => self.caps_lock = !self.caps_lock,
            _ if !pressed => {}
            28 => {
                self.grid.newline();
                let line = std::mem::take(&mut self.line) + "\n";
                self.send(&line);
            }
            14 => {
                if self.line.pop().is_some() {
                    self.grid.backspace();
                }
            }
            _ if self.control => match code {
                // Ctrl+C interrupts the foreground command, Ctrl+D ends input
                // and Ctrl+L clears the screen.
                46 => {
                    let group = rustix::process::Pid::from_child(&self.shell);
                    let _ =
                        rustix::process::kill_process_group(group, rustix::process::Signal::INT);
                    self.line.clear();
                    self.grid.feed("^C\n");
                }
                32 if self.line.is_empty() => self.stdin = None,
                38 => {
                    self.grid.clear();
                    let line = self.line.clone();
                    self.grid.feed(&line);
                }
                _ => {}
            },
            code => {
                if let Some(character) = character(code, self.shift, self.caps_lock) {
                    self.line.push(character);
                    self.grid.put(character);
                }
            }
        }
        self.dirty = true;
    }
}

/// Maps an evdev key code to a character on a US keyboard.
fn character(code: u32, shift: bool, caps_lock: bool) -> Option<char> {
    const ROWS: [(u32, &str, &str); 4] = [
        (2, "1234567890-=", "!@#$%^&*()_+"),
        (16, "qwertyuiop[]", "QWERTYUIOP{}"),
        (30, "asdfghjkl;'`", "ASDFGHJKL:\"~"),
        (44, "zxcvbnm,./", "ZXCVBNM<>?"),
    ];
    match code {
        15 => return Some('\t'),
        43 => return Some(if shift { '|' } else { '\\' }),
        57 => return Some(' '),
        _ => {}
    }
    ROWS.iter().find_map(|(first, plain, shifted)| {
        let index = code.checked_sub(*first)? as usize;
        let character = plain.chars().nth(index)?;
        let upper = if character.is_ascii_alphabetic() {
            shift != caps_lock
        } else {
            shift
        };
        if upper {
            shifted.chars().nth(index)
        } else {
            Some(character)
        }
    })
}

impl Dispatch<wl_registry::WlRegistry, GlobalListContents> for Terminal {
    fn event(
        _: &mut Self,
        _: &wl_registry::WlRegistry,
        _: wl_registry::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
    }
}

delegate_noop!(Terminal: wl_compositor::WlCompositor);
delegate_noop!(Terminal: wl_shm_pool::WlShmPool);
delegate_noop!(Terminal: ignore wl_shm::WlShm);
delegate_noop!(Terminal: ignore wl_surface::WlSurface);
delegate_noop!(Terminal: zxdg_decoration_manager_v1::ZxdgDecorationManagerV1);
delegate_noop!(Terminal: ignore zxdg_toplevel_decoration_v1::ZxdgToplevelDecorationV1);

impl Dispatch<wl_buffer::WlBuffer, usize> for Terminal {
    fn event(
        terminal: &mut Self,
        _: &wl_buffer::WlBuffer,
        event: wl_buffer::Event,
        index: &usize,
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let (wl_buffer::Event::Release, Some(pool)) = (event, &mut terminal.pool) {
            if let Some(buffer) = pool.buffers.get_mut(*index) {
                buffer.1 = false;
            }
        }
    }
}

impl Dispatch<wl_callback::WlCallback, ()> for Terminal {
    fn event(
        terminal: &mut Self,
        _: &wl_callback::WlCallback,
        _: wl_callback::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        terminal.waiting_for_frame = false;
    }
}

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for Terminal {
    fn event(
        _: &mut Self,
        wm_base: &xdg_wm_base::XdgWmBase,
        event: xdg_wm_base::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_wm_base::Event::Ping { serial } = event {
            wm_base.pong(serial);
        }
    }
}

impl Dispatch<xdg_surface::XdgSurface, ()> for Terminal {
    fn event(
        terminal: &mut Self,
        xdg_surface: &xdg_surface::XdgSurface,
        event: xdg_surface::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        if let xdg_surface::Event::Configure { serial } = event {
            xdg_surface.ack_configure(serial);
            terminal.configured = true;
            terminal.apply_size();
        }
    }
}

impl Dispatch<xdg_toplevel::XdgToplevel, ()> for Terminal {
    fn event(
        terminal: &mut Self,
        _: &xdg_toplevel::XdgToplevel,
        event: xdg_toplevel::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            xdg_toplevel::Event::Configure { width, height, .. } if width > 0 && height > 0 => {
                terminal.requested = Some((width, height));
            }
            xdg_toplevel::Event::Close => terminal.closed = true,
            _ => {}
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for Terminal {
    fn event(
        terminal: &mut Self,
        seat: &wl_seat::WlSeat,
        event: wl_seat::Event,
        _: &(),
        _: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        if let wl_seat::Event::Capabilities {
            capabilities: WEnum::Value(capabilities),
        } = event
        {
            if capabilities.contains(wl_seat::Capability::Keyboard) && terminal.keyboard.is_none() {
                terminal.keyboard = Some(seat.get_keyboard(qh, ()));
            }
        }
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, ()> for Terminal {
    fn event(
        terminal: &mut Self,
        _: &wl_keyboard::WlKeyboard,
        event: wl_keyboard::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<Self>,
    ) {
        match event {
            wl_keyboard::Event::Key { key, state, .. } => {
                terminal.key(key, state == WEnum::Value(wl_keyboard::KeyState::Pressed));
            }
            wl_keyboard::Event::Leave { .. } => {
                terminal.shift = false;
                terminal.control = false;
            }
            _ => {}
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ginux-term: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut scale = 1;
    let mut command = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--scale" => {
                scale = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .ok_or("--scale needs a number")?
            }
            "-e" => command = arguments.by_ref().collect::<Vec<_>>().join(" "),
            _ => {
                return Err(format!(
                    "unknown argument {argument}; usage: ginux-term [--scale N] [-e COMMAND]"
                ))
            }
        }
    }
    let connection = Connection::connect_to_env().map_err(|error| error.to_string())?;
    let (globals, mut queue) =
        registry_queue_init::<Terminal>(&connection).map_err(|error| error.to_string())?;
    let qh = queue.handle();
    let bind_error = |error: wayland_client::globals::BindError| error.to_string();
    let compositor: wl_compositor::WlCompositor =
        globals.bind(&qh, 4..=5, ()).map_err(bind_error)?;
    let shm: wl_shm::WlShm = globals.bind(&qh, 1..=1, ()).map_err(bind_error)?;
    let wm_base: xdg_wm_base::XdgWmBase = globals.bind(&qh, 1..=3, ()).map_err(bind_error)?;
    let _seat: wl_seat::WlSeat = globals.bind(&qh, 1..=7, ()).map_err(bind_error)?;

    let mut shell = Command::new("/bin/sh");
    if command.contains(' ') {
        shell.arg("-c").arg(&command);
    } else {
        shell.arg("-c").arg(format!("exec {command} -i"));
    }
    let mut shell = shell
        .env("TERM", "dumb")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|error| format!("cannot start {command}: {error}"))?;
    let stdin = shell.stdin.take();
    let mut stdout = shell.stdout.take().ok_or("no shell stdout")?;
    let mut stderr = shell.stderr.take().ok_or("no shell stderr")?;

    let surface = compositor.create_surface(&qh, ());
    let xdg_surface = wm_base.get_xdg_surface(&surface, &qh, ());
    let toplevel = xdg_surface.get_toplevel(&qh, ());
    toplevel.set_title("Terminal".into());
    toplevel.set_app_id("ginux-term".into());
    if let Ok(manager) =
        globals.bind::<zxdg_decoration_manager_v1::ZxdgDecorationManagerV1, _, _>(&qh, 1..=1, ())
    {
        let decoration = manager.get_toplevel_decoration(&toplevel, &qh, ());
        decoration.set_mode(zxdg_toplevel_decoration_v1::Mode::ServerSide);
    }
    surface.commit();

    let mut terminal = Terminal {
        compositor,
        shm,
        surface,
        keyboard: None,
        configured: false,
        size: (0, 0),
        requested: None,
        pool: None,
        waiting_for_frame: false,
        dirty: true,
        grid: Grid::new(80, 25),
        scale,
        line: String::new(),
        shell,
        stdin,
        shift: false,
        control: false,
        caps_lock: false,
        closed: false,
    };
    let _ = &terminal.compositor;
    let mut open_streams = 2;
    let mut buffer = [0_u8; 4096];
    while !terminal.closed && open_streams > 0 {
        if terminal.configured && terminal.dirty && !terminal.waiting_for_frame {
            terminal.draw(&qh);
        }
        connection.flush().map_err(|error| error.to_string())?;
        let guard = loop {
            match queue.prepare_read() {
                Some(guard) => break guard,
                None => {
                    queue
                        .dispatch_pending(&mut terminal)
                        .map_err(|error| error.to_string())?;
                }
            }
        };
        let (wayland_ready, stdout_ready, stderr_ready) = {
            let mut fds = [
                PollFd::from_borrowed_fd(guard.connection_fd(), PollFlags::IN),
                PollFd::new(&stdout, PollFlags::IN),
                PollFd::new(&stderr, PollFlags::IN),
            ];
            match poll(&mut fds, None) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(format!("poll: {error}")),
            }
            let ready = |fd: &PollFd<'_>| !fd.revents().is_empty();
            (ready(&fds[0]), ready(&fds[1]), ready(&fds[2]))
        };
        if wayland_ready {
            if let Err(error) = guard.read() {
                if !matches!(&error, wayland_client::backend::WaylandError::Io(io) if io.kind() == std::io::ErrorKind::WouldBlock)
                {
                    return Err(error.to_string());
                }
            }
        } else {
            drop(guard);
        }
        queue
            .dispatch_pending(&mut terminal)
            .map_err(|error| error.to_string())?;
        for (ready, stream) in [
            (stdout_ready, &mut stdout as &mut dyn Read),
            (stderr_ready, &mut stderr),
        ] {
            if !ready {
                continue;
            }
            match stream.read(&mut buffer) {
                Ok(0) | Err(_) => open_streams -= 1,
                Ok(length) => {
                    terminal
                        .grid
                        .feed(&String::from_utf8_lossy(&buffer[..length]));
                    terminal.dirty = true;
                }
            }
        }
    }
    let group = rustix::process::Pid::from_child(&terminal.shell);
    let _ = rustix::process::kill_process_group(group, rustix::process::Signal::HUP);
    let _ = terminal.shell.wait();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(grid: &Grid) -> Vec<String> {
        grid.cells
            .chunks(grid.columns)
            .map(|row| row.iter().collect::<String>().trim_end().to_string())
            .collect()
    }

    #[test]
    fn grid_scrolls_and_handles_escapes() {
        let mut grid = Grid::new(6, 2);
        grid.feed("ab\x1b[1;32mc\x1b[0m\none\ntwo");
        assert_eq!(text(&grid), ["one", "two"]);
        grid.feed("\x1b[2J$ ");
        assert_eq!(text(&grid), ["$", ""]);
        assert_eq!((grid.row, grid.column), (0, 2));
    }

    #[test]
    fn grid_resize_keeps_recent_rows() {
        let mut grid = Grid::new(4, 3);
        grid.feed("a\nb\nc");
        grid.resize(4, 2);
        assert_eq!(text(&grid), ["b", "c"]);
        assert_eq!(grid.row, 1);
    }

    #[test]
    fn us_layout() {
        assert_eq!(character(30, false, false), Some('a'));
        assert_eq!(character(30, true, false), Some('A'));
        assert_eq!(character(30, false, true), Some('A'));
        assert_eq!(character(2, true, true), Some('!'));
        assert_eq!(character(53, false, false), Some('/'));
        assert_eq!(character(1, false, false), None);
    }
}
