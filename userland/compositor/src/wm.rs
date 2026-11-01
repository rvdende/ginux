//! Window management: surfaces and their committed contents, stacking
//! toplevel windows with server-side title bars, pointer and keyboard
//! focus, interactive moves, key bindings and software composition.

use std::{
    collections::HashMap,
    process::{Child, Command},
    time::{Duration, Instant},
};

use ginux_gfx::Canvas;
use wayland_protocols::xdg::shell::server::{xdg_surface::XdgSurface, xdg_toplevel};
use wayland_server::{
    backend::ObjectId,
    protocol::{
        wl_buffer::WlBuffer, wl_callback::WlCallback, wl_keyboard, wl_output::WlOutput, wl_pointer,
        wl_surface::WlSurface,
    },
    Resource,
};

use crate::{input::Event, protocol};

pub const TITLE_HEIGHT: i32 = 24;
const FRAME_INTERVAL: Duration = Duration::from_millis(16);
const BUTTON_SIZE: i32 = 16;

const KEY_ESC: u32 = 1;
const KEY_BACKSPACE: u32 = 14;
const KEY_TAB: u32 = 15;
const KEY_Q: u32 = 16;
const KEY_ENTER: u32 = 28;
const KEY_LEFTCTRL: u32 = 29;
const KEY_LEFTSHIFT: u32 = 42;
const KEY_M: u32 = 50;
const KEY_RIGHTSHIFT: u32 = 54;
const KEY_LEFTALT: u32 = 56;
const KEY_CAPSLOCK: u32 = 58;
const KEY_F4: u32 = 62;
const KEY_RIGHTCTRL: u32 = 97;
const KEY_RIGHTALT: u32 = 100;
const KEY_LEFTMETA: u32 = 125;
const KEY_RIGHTMETA: u32 = 126;
const BTN_LEFT: u32 = 0x110;

// xkb modifier masks for the standard real modifiers.
const MOD_SHIFT: u32 = 1;
const MOD_LOCK: u32 = 2;
const MOD_CONTROL: u32 = 4;
const MOD_ALT: u32 = 8;
const MOD_SUPER: u32 = 64;

/// State a client has set on a surface but not yet committed.
#[derive(Default)]
pub struct Pending {
    pub buffer: Option<Option<WlBuffer>>,
    pub callbacks: Vec<WlCallback>,
}

#[derive(Clone, PartialEq)]
pub enum Role {
    None,
    Toplevel(u64),
    Subsurface { parent: WlSurface, x: i32, y: i32 },
}

pub struct Surface {
    pub pending: Pending,
    /// Frame callbacks committed and waiting for the next composed frame.
    pub callbacks: Vec<WlCallback>,
    /// The committed buffer, held until the client commits another (it is
    /// drawn straight from the client's memory), and its width and height.
    pub buffer: Option<(WlBuffer, i32, i32)>,
    pub role: Role,
    /// Subsurfaces in stacking order, drawn above the surface.
    pub children: Vec<WlSurface>,
}

pub struct Window {
    pub id: u64,
    pub surface: WlSurface,
    pub xdg_surface: XdgSurface,
    pub toplevel: xdg_toplevel::XdgToplevel,
    pub title: String,
    /// Screen position of the window geometry's top-left corner.
    pub x: i32,
    pub y: i32,
    /// The client's window geometry within its surface, if it set one.
    pub geometry: Option<(i32, i32, i32, i32)>,
    pub configured: bool,
    pub mapped: bool,
    pub decorated: bool,
    /// Position and size to restore when the window is unmaximized.
    pub restore: Option<(i32, i32, i32, i32)>,
}

#[derive(Clone, Copy)]
enum Grab {
    Move { window: u64, dx: i32, dy: i32 },
}

#[derive(Clone, Copy, PartialEq)]
enum Hit {
    Title(usize),
    Close(usize),
    Maximize(usize),
    Content(usize),
}

pub struct Seat {
    pub pointers: Vec<wl_pointer::WlPointer>,
    pub keyboards: Vec<wl_keyboard::WlKeyboard>,
    pub x: f64,
    pub y: f64,
    pointer_focus: Option<WlSurface>,
    keyboard_focus: Option<u64>,
    grab: Option<Grab>,
    pressed: Vec<u32>,
    shift: u8,
    control: u8,
    alt: u8,
    super_key: u8,
    caps_lock: bool,
}

pub struct State {
    pub width: i32,
    pub height: i32,
    pub frame: Vec<u32>,
    background: Vec<u32>,
    pub surfaces: HashMap<ObjectId, Surface>,
    /// Toplevel windows from bottom to top of the stack.
    pub windows: Vec<Window>,
    next_window: u64,
    pub seat: Seat,
    pub outputs: Vec<WlOutput>,
    serial: u32,
    pub dirty: bool,
    next_frame: Instant,
    start: Instant,
    terminal: String,
    children: Vec<Child>,
    pub keymap: Option<Vec<u8>>,
    pub quit: bool,
}

impl State {
    pub fn new(width: i32, height: i32, terminal: String) -> Self {
        let size = (width * height) as usize;
        Self {
            width,
            height,
            frame: vec![0; size],
            background: background(width, height),
            surfaces: HashMap::new(),
            windows: Vec::new(),
            next_window: 1,
            seat: Seat {
                pointers: Vec::new(),
                keyboards: Vec::new(),
                x: f64::from(width / 2),
                y: f64::from(height / 2),
                pointer_focus: None,
                keyboard_focus: None,
                grab: None,
                pressed: Vec::new(),
                shift: 0,
                control: 0,
                alt: 0,
                super_key: 0,
                caps_lock: false,
            },
            outputs: Vec::new(),
            serial: 0,
            dirty: true,
            next_frame: Instant::now(),
            start: Instant::now(),
            terminal,
            children: Vec::new(),
            keymap: None,
            quit: false,
        }
    }

    pub fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1);
        self.serial
    }

    fn time(&self) -> u32 {
        self.start.elapsed().as_millis() as u32
    }

    pub fn spawn(&mut self, command: &str) {
        let display = std::env::var("WAYLAND_DISPLAY").unwrap_or_default();
        match Command::new("/bin/sh")
            .arg("-c")
            .arg(command)
            .env("WAYLAND_DISPLAY", display)
            .spawn()
        {
            Ok(child) => self.children.push(child),
            Err(error) => eprintln!("ginux-wm: cannot start {command}: {error}"),
        }
    }

    pub fn reap(&mut self) {
        self.children
            .retain_mut(|child| matches!(child.try_wait(), Ok(None)));
    }

    // ----- surfaces -------------------------------------------------------

    pub fn add_surface(&mut self, resource: WlSurface) {
        self.surfaces.insert(
            resource.id(),
            Surface {
                pending: Pending::default(),
                callbacks: Vec::new(),
                buffer: None,
                role: Role::None,
                children: Vec::new(),
            },
        );
    }

    pub fn remove_surface(&mut self, id: &ObjectId) {
        let Some(mut surface) = self.surfaces.remove(id) else {
            return;
        };
        if let Some((buffer, ..)) = surface.buffer.take() {
            buffer.release();
        }
        if let Role::Subsurface { parent, .. } = &surface.role {
            if let Some(parent) = self.surfaces.get_mut(&parent.id()) {
                parent.children.retain(|child| child.id() != *id);
            }
        }
        if let Role::Toplevel(window) = surface.role {
            self.remove_window(window);
        }
        if self
            .seat
            .pointer_focus
            .as_ref()
            .is_some_and(|focus| focus.id() == *id)
        {
            self.seat.pointer_focus = None;
        }
        self.dirty = true;
    }

    /// Applies a wl_surface.commit: takes the pending buffer's pixels (and
    /// releases the buffer at once, since the contents are copied) and
    /// queues the pending frame callbacks.
    pub fn commit(&mut self, id: &ObjectId) {
        let Some(surface) = self.surfaces.get_mut(id) else {
            return;
        };
        let callbacks = std::mem::take(&mut surface.pending.callbacks);
        surface.callbacks.extend(callbacks);
        if let Some(buffer) = surface.pending.buffer.take() {
            // The buffer shown so far goes back to the client, unless it
            // committed the same one again.
            if let Some((held, ..)) = surface.buffer.take() {
                if buffer.as_ref() != Some(&held) {
                    held.release();
                }
            }
            surface.buffer = buffer.and_then(|buffer| {
                let (width, height, _) = protocol::buffer_shape(&buffer)?;
                Some((buffer, width, height))
            });
        }
        let mapped = surface.buffer.is_some();
        let role = surface.role.clone();
        self.dirty = true;
        if let Role::Toplevel(window) = role {
            self.commit_toplevel(window, mapped);
        }
    }

    fn commit_toplevel(&mut self, id: u64, mapped: bool) {
        let Some(index) = self.window_index(id) else {
            return;
        };
        if !self.windows[index].configured {
            self.windows[index].configured = true;
            self.configure(index, None);
            return;
        }
        if mapped && !self.windows[index].mapped {
            let count = self.windows.iter().filter(|window| window.mapped).count() as i32;
            let window = &mut self.windows[index];
            window.mapped = true;
            window.x = 40 + (count * 32) % (self.width / 2).max(1);
            window.y = TITLE_HEIGHT + 24 + (count * 32) % (self.height / 2).max(1);
            self.focus(Some(id));
        } else if !mapped && self.windows[index].mapped {
            self.windows[index].mapped = false;
            if self.seat.keyboard_focus == Some(id) {
                self.focus_topmost();
            }
        }
    }

    // ----- windows --------------------------------------------------------

    pub fn add_window(
        &mut self,
        surface: WlSurface,
        xdg_surface: XdgSurface,
        toplevel: xdg_toplevel::XdgToplevel,
    ) -> u64 {
        let id = self.next_window;
        self.next_window += 1;
        if let Some(state) = self.surfaces.get_mut(&surface.id()) {
            state.role = Role::Toplevel(id);
        }
        self.windows.push(Window {
            id,
            surface,
            xdg_surface,
            toplevel,
            title: String::new(),
            x: 0,
            y: 0,
            geometry: None,
            configured: false,
            mapped: false,
            decorated: true,
            restore: None,
        });
        id
    }

    pub fn remove_window(&mut self, id: u64) {
        let Some(index) = self.window_index(id) else {
            return;
        };
        let window = self.windows.remove(index);
        if let Some(surface) = self.surfaces.get_mut(&window.surface.id()) {
            surface.role = Role::None;
            if let Some((buffer, ..)) = surface.buffer.take() {
                buffer.release();
            }
        }
        if matches!(self.seat.grab, Some(Grab::Move { window, .. }) if window == id) {
            self.seat.grab = None;
        }
        if self.seat.keyboard_focus == Some(id) {
            self.seat.keyboard_focus = None;
            self.focus_topmost();
        }
        self.dirty = true;
    }

    pub fn window_index(&self, id: u64) -> Option<usize> {
        self.windows.iter().position(|window| window.id == id)
    }

    pub fn window_mut(&mut self, id: u64) -> Option<&mut Window> {
        self.windows.iter_mut().find(|window| window.id == id)
    }

    /// Sends xdg_toplevel.configure followed by xdg_surface.configure.
    fn configure(&mut self, index: usize, size: Option<(i32, i32)>) {
        let serial = self.next_serial();
        let window = &self.windows[index];
        let mut states = Vec::new();
        if window.restore.is_some() {
            states.extend_from_slice(&(xdg_toplevel::State::Maximized as u32).to_ne_bytes());
        }
        if self.seat.keyboard_focus == Some(window.id) {
            states.extend_from_slice(&(xdg_toplevel::State::Activated as u32).to_ne_bytes());
        }
        let (width, height) = size.unwrap_or((0, 0));
        window.toplevel.configure(width, height, states);
        window.xdg_surface.configure(serial);
    }

    /// The window's visible size: its geometry, else its surface size.
    fn window_size(&self, window: &Window) -> (i32, i32) {
        if let Some((_, _, width, height)) = window.geometry {
            return (width, height);
        }
        self.surfaces
            .get(&window.surface.id())
            .and_then(|surface| surface.buffer.as_ref())
            .map_or((0, 0), |(_, width, height)| (*width, *height))
    }

    fn raise(&mut self, id: u64) {
        if let Some(index) = self.window_index(id) {
            let window = self.windows.remove(index);
            self.windows.push(window);
            self.dirty = true;
        }
    }

    /// Moves keyboard focus to a window (or nowhere), raising it and
    /// re-sending configure so both windows can show their activation.
    pub fn focus(&mut self, id: Option<u64>) {
        let previous = self.seat.keyboard_focus;
        if previous == id {
            if let Some(id) = id {
                self.raise(id);
            }
            return;
        }
        self.seat.keyboard_focus = id;
        let serial = self.next_serial();
        if let Some(index) = previous.and_then(|previous| self.window_index(previous)) {
            let surface = self.windows[index].surface.clone();
            for keyboard in self.client_keyboards(&surface) {
                keyboard.leave(serial, &surface);
            }
            self.configure(index, None);
        }
        if let Some(id) = id {
            self.raise(id);
            if let Some(index) = self.window_index(id) {
                let surface = self.windows[index].surface.clone();
                let modifiers = self.modifiers();
                for keyboard in self.client_keyboards(&surface) {
                    keyboard.enter(serial, &surface, Vec::new());
                    keyboard.modifiers(serial, modifiers, 0, self.locked(), 0);
                }
                self.configure(index, None);
            }
        }
        self.dirty = true;
    }

    fn focus_topmost(&mut self) {
        let top = self
            .windows
            .iter()
            .rev()
            .find(|window| window.mapped)
            .map(|window| window.id);
        self.focus(top);
    }

    /// Sends a newly bound keyboard the current focus, if it belongs to the
    /// focused client.
    pub fn keyboard_bound(&mut self, keyboard: &wl_keyboard::WlKeyboard) {
        let Some(index) = self
            .seat
            .keyboard_focus
            .and_then(|id| self.window_index(id))
        else {
            return;
        };
        let surface = self.windows[index].surface.clone();
        if keyboard.id().same_client_as(&surface.id()) {
            let serial = self.next_serial();
            keyboard.enter(serial, &surface, Vec::new());
            keyboard.modifiers(serial, self.modifiers(), 0, self.locked(), 0);
        }
    }

    fn toggle_maximize(&mut self, id: u64) {
        let Some(index) = self.window_index(id) else {
            return;
        };
        let (width, height) = self.window_size(&self.windows[index]);
        let window = &mut self.windows[index];
        if let Some((x, y, width, height)) = window.restore.take() {
            window.x = x;
            window.y = y;
            self.configure(index, Some((width, height)));
        } else {
            window.restore = Some((window.x, window.y, width, height));
            window.x = 0;
            window.y = TITLE_HEIGHT;
            let size = (self.width, self.height - TITLE_HEIGHT);
            self.configure(index, Some(size));
        }
        self.dirty = true;
    }

    fn close(&mut self, id: u64) {
        if let Some(window) = self.windows.iter().find(|window| window.id == id) {
            window.toplevel.close();
        }
    }

    pub fn start_move(&mut self, id: u64) {
        if let Some(index) = self.window_index(id) {
            let window = &self.windows[index];
            self.seat.grab = Some(Grab::Move {
                window: id,
                dx: self.seat.x as i32 - window.x,
                dy: self.seat.y as i32 - window.y,
            });
        }
    }

    // ----- input ----------------------------------------------------------

    fn client_pointers(&self, surface: &WlSurface) -> Vec<wl_pointer::WlPointer> {
        let id = surface.id();
        self.seat
            .pointers
            .iter()
            .filter(|pointer| pointer.id().same_client_as(&id))
            .cloned()
            .collect()
    }

    fn client_keyboards(&self, surface: &WlSurface) -> Vec<wl_keyboard::WlKeyboard> {
        let id = surface.id();
        self.seat
            .keyboards
            .iter()
            .filter(|keyboard| keyboard.id().same_client_as(&id))
            .cloned()
            .collect()
    }

    fn modifiers(&self) -> u32 {
        let mut mask = 0;
        if self.seat.shift != 0 {
            mask |= MOD_SHIFT;
        }
        if self.seat.control != 0 {
            mask |= MOD_CONTROL;
        }
        if self.seat.alt != 0 {
            mask |= MOD_ALT;
        }
        if self.seat.super_key != 0 {
            mask |= MOD_SUPER;
        }
        mask
    }

    fn locked(&self) -> u32 {
        if self.seat.caps_lock {
            MOD_LOCK
        } else {
            0
        }
    }

    /// Where a surface's origin is on screen, following subsurface parents
    /// up to their toplevel window.
    fn surface_origin(&self, surface: &WlSurface) -> Option<(i32, i32)> {
        let state = self.surfaces.get(&surface.id())?;
        match &state.role {
            Role::Toplevel(id) => {
                let window = self.windows.iter().find(|window| window.id == *id)?;
                let (gx, gy, _, _) = window.geometry.unwrap_or_default();
                Some((window.x - gx, window.y - gy))
            }
            Role::Subsurface { parent, x, y } => {
                let (px, py) = self.surface_origin(parent)?;
                Some((px + x, py + y))
            }
            Role::None => None,
        }
    }

    fn hit(&self, x: i32, y: i32) -> Option<Hit> {
        for (index, window) in self.windows.iter().enumerate().rev() {
            if !window.mapped {
                continue;
            }
            let (width, height) = self.window_size(window);
            if window.decorated && x >= window.x - 1 && x < window.x + width + 1 {
                let top = window.y - TITLE_HEIGHT;
                if y >= top && y < window.y {
                    let button = |offset: i32| {
                        let left = window.x + width - offset;
                        x >= left
                            && x < left + BUTTON_SIZE
                            && y >= top + 4
                            && y < top + 4 + BUTTON_SIZE
                    };
                    return Some(if button(20) {
                        Hit::Close(index)
                    } else if button(40) {
                        Hit::Maximize(index)
                    } else {
                        Hit::Title(index)
                    });
                }
            }
            if x >= window.x && x < window.x + width && y >= window.y && y < window.y + height {
                return Some(Hit::Content(index));
            }
        }
        None
    }

    /// The topmost surface of a window (a subsurface or the window's own
    /// surface) under a screen point, with surface-local coordinates.
    fn surface_at(&self, window: &Window, x: i32, y: i32) -> (WlSurface, f64, f64) {
        fn search(
            state: &State,
            surface: &WlSurface,
            origin: (i32, i32),
            point: (i32, i32),
        ) -> Option<(WlSurface, f64, f64)> {
            let data = state.surfaces.get(&surface.id())?;
            for child in data.children.iter().rev() {
                if let Some(Role::Subsurface { x, y, .. }) =
                    state.surfaces.get(&child.id()).map(|child| &child.role)
                {
                    if let Some(found) = search(state, child, (origin.0 + x, origin.1 + y), point) {
                        return Some(found);
                    }
                }
            }
            let &(_, width, height) = data.buffer.as_ref()?;
            let (local_x, local_y) = (point.0 - origin.0, point.1 - origin.1);
            (local_x >= 0 && local_y >= 0 && local_x < width && local_y < height)
                .then(|| (surface.clone(), f64::from(local_x), f64::from(local_y)))
        }
        let origin = self
            .surface_origin(&window.surface)
            .unwrap_or((window.x, window.y));
        search(self, &window.surface, origin, (x, y)).unwrap_or_else(|| {
            (
                window.surface.clone(),
                f64::from(x - origin.0),
                f64::from(y - origin.1),
            )
        })
    }

    /// Sends enter/leave as the surface under the pointer changes, then
    /// motion to the focused surface.
    fn update_pointer_focus(&mut self) {
        let (x, y) = (self.seat.x as i32, self.seat.y as i32);
        let target = match self.hit(x, y) {
            Some(Hit::Content(index)) if self.seat.grab.is_none() => {
                Some(self.surface_at(&self.windows[index], x, y))
            }
            _ => None,
        };
        let time = self.time();
        let current = self.seat.pointer_focus.clone();
        let same = match (&current, &target) {
            (Some(current), Some((surface, _, _))) => current.id() == surface.id(),
            (None, None) => true,
            _ => false,
        };
        if !same {
            let serial = self.next_serial();
            if let Some(current) = &current {
                for pointer in self.client_pointers(current) {
                    pointer.leave(serial, current);
                    frame(&pointer);
                }
            }
            if let Some((surface, local_x, local_y)) = &target {
                for pointer in self.client_pointers(surface) {
                    pointer.enter(serial, surface, *local_x, *local_y);
                    frame(&pointer);
                }
            }
            self.seat.pointer_focus = target.as_ref().map(|(surface, _, _)| surface.clone());
        } else if let Some((surface, local_x, local_y)) = &target {
            for pointer in self.client_pointers(surface) {
                pointer.motion(time, *local_x, *local_y);
                frame(&pointer);
            }
        }
    }

    pub fn input(&mut self, event: Event) {
        match event {
            Event::Motion { dx, dy } => {
                self.seat.x = (self.seat.x + dx).clamp(0.0, f64::from(self.width - 1));
                self.seat.y = (self.seat.y + dy).clamp(0.0, f64::from(self.height - 1));
                self.pointer_moved();
            }
            Event::Position { x, y } => {
                if let Some(x) = x {
                    self.seat.x = x * f64::from(self.width - 1);
                }
                if let Some(y) = y {
                    self.seat.y = y * f64::from(self.height - 1);
                }
                self.pointer_moved();
            }
            Event::Button { code, pressed } => self.button(code, pressed),
            Event::Scroll { clicks } => {
                if let Some(surface) = self.seat.pointer_focus.clone() {
                    let time = self.time();
                    for pointer in self.client_pointers(&surface) {
                        pointer.axis(time, wl_pointer::Axis::VerticalScroll, clicks * 15.0);
                        frame(&pointer);
                    }
                }
            }
            Event::Key { code, pressed } => self.key(code, pressed),
            Event::Frame => {}
        }
    }

    fn pointer_moved(&mut self) {
        if let Some(Grab::Move { window, dx, dy }) = self.seat.grab {
            let (x, y) = (self.seat.x as i32 - dx, self.seat.y as i32 - dy);
            if let Some(window) = self.window_mut(window) {
                window.x = x;
                window.y = y.max(TITLE_HEIGHT);
            }
        }
        self.update_pointer_focus();
        self.dirty = true;
    }

    fn button(&mut self, code: u32, pressed: bool) {
        if pressed {
            self.seat.pressed.push(code);
        } else {
            self.seat.pressed.retain(|button| *button != code);
        }
        if !pressed && self.seat.grab.is_some() {
            if self.seat.pressed.is_empty() {
                self.seat.grab = None;
                self.update_pointer_focus();
            }
            return;
        }
        let (x, y) = (self.seat.x as i32, self.seat.y as i32);
        if pressed {
            match self.hit(x, y) {
                Some(Hit::Close(index)) => {
                    let id = self.windows[index].id;
                    self.close(id);
                    return;
                }
                Some(Hit::Maximize(index)) => {
                    let id = self.windows[index].id;
                    self.toggle_maximize(id);
                    return;
                }
                Some(Hit::Title(index)) => {
                    let id = self.windows[index].id;
                    self.focus(Some(id));
                    if code == BTN_LEFT {
                        self.start_move(id);
                        self.update_pointer_focus();
                    }
                    return;
                }
                Some(Hit::Content(index)) => {
                    let id = self.windows[index].id;
                    self.focus(Some(id));
                    if code == BTN_LEFT && self.modifiers() & (MOD_ALT | MOD_SUPER) != 0 {
                        self.start_move(id);
                        self.update_pointer_focus();
                        return;
                    }
                }
                None => {}
            }
        }
        if let Some(surface) = self.seat.pointer_focus.clone() {
            let serial = self.next_serial();
            let time = self.time();
            let state = if pressed {
                wl_pointer::ButtonState::Pressed
            } else {
                wl_pointer::ButtonState::Released
            };
            for pointer in self.client_pointers(&surface) {
                pointer.button(serial, time, code, state);
                frame(&pointer);
            }
        }
    }

    fn key(&mut self, code: u32, pressed: bool) {
        let counter = match code {
            KEY_LEFTSHIFT | KEY_RIGHTSHIFT => Some(&mut self.seat.shift),
            KEY_LEFTCTRL | KEY_RIGHTCTRL => Some(&mut self.seat.control),
            KEY_LEFTALT | KEY_RIGHTALT => Some(&mut self.seat.alt),
            KEY_LEFTMETA | KEY_RIGHTMETA => Some(&mut self.seat.super_key),
            _ => None,
        };
        let modifier = counter.is_some();
        if let Some(counter) = counter {
            *counter = if pressed {
                counter.saturating_add(1)
            } else {
                counter.saturating_sub(1)
            };
        }
        if code == KEY_CAPSLOCK && pressed {
            self.seat.caps_lock = !self.seat.caps_lock;
        }
        if pressed && !modifier && self.binding(code) {
            return;
        }
        let Some(index) = self
            .seat
            .keyboard_focus
            .and_then(|id| self.window_index(id))
        else {
            return;
        };
        let surface = self.windows[index].surface.clone();
        let serial = self.next_serial();
        let time = self.time();
        let state = if pressed {
            wl_keyboard::KeyState::Pressed
        } else {
            wl_keyboard::KeyState::Released
        };
        let (modifiers, locked) = (self.modifiers(), self.locked());
        for keyboard in self.client_keyboards(&surface) {
            keyboard.key(serial, time, code, state);
            if modifier || code == KEY_CAPSLOCK {
                keyboard.modifiers(serial, modifiers, 0, locked, 0);
            }
        }
    }

    /// Handles the window manager's own key bindings, all on Alt or Super.
    fn binding(&mut self, code: u32) -> bool {
        let modifiers = self.modifiers();
        if modifiers & (MOD_ALT | MOD_SUPER) == 0 {
            return false;
        }
        let focused = self.seat.keyboard_focus;
        match code {
            KEY_ENTER => {
                let terminal = self.terminal.clone();
                self.spawn(&terminal);
            }
            KEY_TAB => {
                let mapped: Vec<u64> = self
                    .windows
                    .iter()
                    .filter(|window| window.mapped)
                    .map(|window| window.id)
                    .collect();
                // The focused window is on top, so cycling focuses the
                // bottom window, bringing each window up in turn.
                if let Some(first) = mapped.first().copied().filter(|_| mapped.len() > 1) {
                    self.focus(Some(first));
                }
            }
            KEY_F4 | KEY_Q => {
                if let Some(id) = focused {
                    self.close(id);
                }
            }
            KEY_M => {
                if let Some(id) = focused {
                    self.toggle_maximize(id);
                }
            }
            KEY_BACKSPACE | KEY_ESC if modifiers & MOD_CONTROL != 0 => self.quit = true,
            _ => return false,
        }
        true
    }

    // ----- composition ----------------------------------------------------

    /// Composes and presents a frame when something changed and the frame
    /// interval has passed, then answers frame callbacks.
    pub fn frame_due(&self, now: Instant) -> Option<Duration> {
        let waiting = self.dirty
            || self
                .surfaces
                .values()
                .any(|surface| !surface.callbacks.is_empty());
        waiting.then(|| self.next_frame.saturating_duration_since(now))
    }

    pub fn render_if_due(&mut self, now: Instant) -> bool {
        if self.frame_due(now) != Some(Duration::ZERO) {
            return false;
        }
        self.next_frame = now + FRAME_INTERVAL;
        let rendered = self.dirty;
        if self.dirty {
            self.render();
            self.dirty = false;
        }
        let time = self.time();
        for surface in self.surfaces.values_mut() {
            for callback in surface.callbacks.drain(..) {
                callback.done(time);
            }
        }
        rendered
    }

    fn render(&mut self) {
        self.frame.copy_from_slice(&self.background);
        let mut frame = std::mem::take(&mut self.frame);
        let mut canvas = Canvas::new(&mut frame, self.width, self.height);
        let focused = self.seat.keyboard_focus;
        for window in self.windows.iter().filter(|window| window.mapped) {
            let (width, height) = self.window_size(window);
            if window.decorated {
                draw_decoration(
                    &mut canvas,
                    window,
                    width,
                    height,
                    focused == Some(window.id),
                );
            }
            let origin = self
                .surface_origin(&window.surface)
                .unwrap_or((window.x, window.y));
            self.draw_surface(&mut canvas, &window.surface, origin);
        }
        canvas.cursor(self.seat.x as i32, self.seat.y as i32);
        self.frame = frame;
    }

    fn draw_surface(&self, canvas: &mut Canvas<'_>, surface: &WlSurface, origin: (i32, i32)) {
        let Some(data) = self.surfaces.get(&surface.id()) else {
            return;
        };
        if let Some((buffer, ..)) = &data.buffer {
            protocol::blit_buffer(canvas, origin, buffer);
        }
        for child in &data.children {
            if let Some(Role::Subsurface { x, y, .. }) =
                self.surfaces.get(&child.id()).map(|child| &child.role)
            {
                self.draw_surface(canvas, child, (origin.0 + x, origin.1 + y));
            }
        }
    }
}

fn frame(pointer: &wl_pointer::WlPointer) {
    if pointer.version() >= 5 {
        pointer.frame();
    }
}

fn draw_decoration(
    canvas: &mut Canvas<'_>,
    window: &Window,
    width: i32,
    height: i32,
    active: bool,
) {
    let (x, y) = (window.x, window.y);
    let top = y - TITLE_HEIGHT;
    canvas.shade(x + 6, y + height + 1, width, 6, 70);
    canvas.shade(x + width + 1, top + 6, 6, height + TITLE_HEIGHT - 5, 70);
    let bar = if active { 0xff2f_5d8c } else { 0xff40_4650 };
    canvas.fill(x - 1, top, width + 2, TITLE_HEIGHT, bar);
    canvas.outline(
        x - 1,
        top,
        width + 2,
        height + TITLE_HEIGHT + 1,
        0xff1a_1d22,
    );
    let title = if window.title.is_empty() {
        "untitled"
    } else {
        &window.title
    };
    canvas.text(x + 8, top + 8, title, 0xffff_ffff, 1, (width - 56).max(0));
    let close = x + width - 20;
    canvas.fill(close, top + 4, BUTTON_SIZE, BUTTON_SIZE, 0xffc0_392b);
    canvas.glyph(close + 4, top + 8, 'x', 0xffff_ffff, 1);
    let maximize = x + width - 40;
    canvas.fill(maximize, top + 4, BUTTON_SIZE, BUTTON_SIZE, 0xff5d_6d7e);
    canvas.outline(maximize + 4, top + 8, 8, 8, 0xffff_ffff);
}

/// A vertical gradient with a faint grid, rendered once.
fn background(width: i32, height: i32) -> Vec<u32> {
    let mut pixels = vec![0; (width * height) as usize];
    for y in 0..height {
        let t = y as u32 * 255 / height.max(1) as u32;
        let (red, green, blue) = (0x14 + t / 12, 0x20 + t / 8, 0x34 + t / 5);
        for x in 0..width {
            let line = x % 64 == 0 || y % 64 == 0;
            let lift = if line { 10 } else { 0 };
            pixels[(y * width + x) as usize] =
                0xff00_0000 | ((red + lift) << 16) | ((green + lift) << 8) | (blue + lift);
        }
    }
    let mut canvas = Canvas::new(&mut pixels, width, height);
    canvas.text(
        16,
        height - 24,
        "Ginux - Alt+Enter terminal, Alt+Tab cycle, Alt+Q close, Alt+M maximize",
        0xff9f_b3c8,
        1,
        width - 32,
    );
    pixels
}
