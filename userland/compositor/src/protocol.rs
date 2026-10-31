//! Wayland protocol objects: the globals the compositor advertises and the
//! requests clients send on them. Window-management decisions are left to
//! `wm::State`; this module translates protocol messages into its calls.

use std::{
    ffi::c_void,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    sync::{Arc, Mutex},
};

use ginux_gfx::Image;
use wayland_protocols::xdg::{
    decoration::zv1::server::{zxdg_decoration_manager_v1, zxdg_toplevel_decoration_v1},
    shell::server::{xdg_popup, xdg_positioner, xdg_surface, xdg_toplevel, xdg_wm_base},
};
use wayland_server::{
    backend::{ClientData, ClientId, DisconnectReason},
    protocol::{
        wl_buffer, wl_callback, wl_compositor, wl_data_device, wl_data_device_manager,
        wl_data_source, wl_keyboard, wl_output, wl_pointer, wl_region, wl_seat, wl_shm,
        wl_shm_pool, wl_subcompositor, wl_subsurface, wl_surface,
    },
    Client, DataInit, Dispatch, DisplayHandle, GlobalDispatch, New, Resource, WEnum,
};

use crate::wm::{Role, State};

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

pub struct ClientState;

impl ClientData for ClientState {
    fn initialized(&self, _client_id: ClientId) {}
    fn disconnected(&self, _client_id: ClientId, _reason: DisconnectReason) {}
}

pub fn create_globals(display: &DisplayHandle) {
    display.create_global::<State, wl_compositor::WlCompositor, ()>(5, ());
    display.create_global::<State, wl_subcompositor::WlSubcompositor, ()>(1, ());
    display.create_global::<State, wl_shm::WlShm, ()>(1, ());
    display.create_global::<State, wl_seat::WlSeat, ()>(7, ());
    display.create_global::<State, wl_output::WlOutput, ()>(3, ());
    display.create_global::<State, xdg_wm_base::XdgWmBase, ()>(3, ());
    display.create_global::<State, zxdg_decoration_manager_v1::ZxdgDecorationManagerV1, ()>(1, ());
    display.create_global::<State, wl_data_device_manager::WlDataDeviceManager, ()>(3, ());
}

/// Globals whose bind just creates the object.
macro_rules! simple_global {
    ($($interface:ty),* $(,)?) => {$(
        impl GlobalDispatch<$interface, ()> for State {
            fn bind(
                _state: &mut Self,
                _display: &DisplayHandle,
                _client: &Client,
                resource: New<$interface>,
                _data: &(),
                data_init: &mut DataInit<'_, Self>,
            ) {
                data_init.init(resource, ());
            }
        }
    )*};
}

simple_global!(
    wl_compositor::WlCompositor,
    wl_subcompositor::WlSubcompositor,
    xdg_wm_base::XdgWmBase,
    zxdg_decoration_manager_v1::ZxdgDecorationManagerV1,
    wl_data_device_manager::WlDataDeviceManager,
);

/// Objects with no requests the compositor acts on, beyond destruction.
macro_rules! inert_object {
    ($($interface:ty),* $(,)?) => {$(
        impl Dispatch<$interface, ()> for State {
            fn request(
                _state: &mut Self,
                _client: &Client,
                _resource: &$interface,
                _request: <$interface as Resource>::Request,
                _data: &(),
                _display: &DisplayHandle,
                _data_init: &mut DataInit<'_, Self>,
            ) {
            }
        }
    )*};
}

inert_object!(
    wl_region::WlRegion,
    wl_callback::WlCallback,
    xdg_positioner::XdgPositioner,
    xdg_popup::XdgPopup,
    wl_data_source::WlDataSource,
    wl_data_device::WlDataDevice,
    wl_output::WlOutput,
);

impl Dispatch<wl_compositor::WlCompositor, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_compositor::WlCompositor,
        request: wl_compositor::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_compositor::Request::CreateSurface { id } => {
                let surface = data_init.init(id, ());
                state.add_surface(surface);
            }
            wl_compositor::Request::CreateRegion { id } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_surface::WlSurface, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &wl_surface::WlSurface,
        request: wl_surface::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        let id = resource.id();
        match request {
            wl_surface::Request::Attach { buffer, .. } => {
                if let Some(surface) = state.surfaces.get_mut(&id) {
                    surface.pending.buffer = Some(buffer);
                }
            }
            wl_surface::Request::Frame { callback } => {
                let callback = data_init.init(callback, ());
                if let Some(surface) = state.surfaces.get_mut(&id) {
                    surface.pending.callbacks.push(callback);
                }
            }
            wl_surface::Request::Commit => state.commit(&id),
            wl_surface::Request::Destroy => state.remove_surface(&id),
            _ => {}
        }
    }

    fn destroyed(
        state: &mut Self,
        _client: ClientId,
        resource: &wl_surface::WlSurface,
        _data: &(),
    ) {
        state.remove_surface(&resource.id());
    }
}

impl Dispatch<wl_subcompositor::WlSubcompositor, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_subcompositor::WlSubcompositor,
        request: wl_subcompositor::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_subcompositor::Request::GetSubsurface {
            id,
            surface,
            parent,
        } = request
        {
            data_init.init(id, surface.clone());
            if let Some(child) = state.surfaces.get_mut(&surface.id()) {
                child.role = Role::Subsurface {
                    parent: parent.clone(),
                    x: 0,
                    y: 0,
                };
            }
            if let Some(parent) = state.surfaces.get_mut(&parent.id()) {
                parent.children.push(surface);
            }
        }
    }
}

impl Dispatch<wl_subsurface::WlSubsurface, wl_surface::WlSurface> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_subsurface::WlSubsurface,
        request: wl_subsurface::Request,
        surface: &wl_surface::WlSurface,
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_subsurface::Request::SetPosition { x: new_x, y: new_y } => {
                if let Some(Role::Subsurface { x, y, .. }) = state
                    .surfaces
                    .get_mut(&surface.id())
                    .map(|surface| &mut surface.role)
                {
                    *x = new_x;
                    *y = new_y;
                    state.dirty = true;
                }
            }
            wl_subsurface::Request::Destroy => {
                let parent = match state
                    .surfaces
                    .get(&surface.id())
                    .map(|surface| &surface.role)
                {
                    Some(Role::Subsurface { parent, .. }) => Some(parent.id()),
                    _ => None,
                };
                if let Some(parent) = parent.and_then(|parent| state.surfaces.get_mut(&parent)) {
                    parent.children.retain(|child| child.id() != surface.id());
                }
                if let Some(child) = state.surfaces.get_mut(&surface.id()) {
                    child.role = Role::None;
                }
                state.dirty = true;
            }
            _ => {}
        }
    }
}

// ----- shared memory ------------------------------------------------------

/// A client's wl_shm pool mapped read-only into the compositor.
pub struct Pool {
    mapping: Mutex<Mapping>,
}

struct Mapping {
    fd: OwnedFd,
    address: *mut u8,
    length: usize,
}

// SAFETY: the mapping is only read while the Mutex is held.
unsafe impl Send for Mapping {}

impl Mapping {
    fn new(fd: OwnedFd, length: usize) -> Option<Self> {
        // SAFETY: maps the client's pool read-only; a bad fd or size fails.
        let address = unsafe {
            mmap(
                std::ptr::null_mut(),
                length,
                1,
                1,
                fd.as_fd().as_raw_fd(),
                0,
            )
        };
        (address as isize != -1 && length != 0).then_some(Self {
            fd,
            address: address.cast(),
            length,
        })
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unmaps exactly what new() mapped.
        unsafe { munmap(self.address.cast(), self.length) };
    }
}

pub struct BufferData {
    pool: Arc<Pool>,
    offset: usize,
    width: i32,
    height: i32,
    stride: usize,
    opaque: bool,
}

/// Copies a wl_shm buffer's pixels out of its pool.
pub fn read_buffer(buffer: &wl_buffer::WlBuffer) -> Option<Image> {
    let data = buffer.data::<BufferData>()?;
    let mapping = data.pool.mapping.lock().ok()?;
    let rows = data.height as usize;
    let width = data.width as usize;
    let end = data.offset.checked_add(data.stride.checked_mul(rows)?)?;
    if end > mapping.length || data.stride < width * 4 {
        buffer.post_error(wl_shm::Error::InvalidStride, "buffer exceeds its pool");
        return None;
    }
    let mut pixels = Vec::with_capacity(width * rows);
    for row in 0..rows {
        // SAFETY: the row lies inside the mapping, checked above.
        let bytes = unsafe {
            std::slice::from_raw_parts(
                mapping.address.add(data.offset + row * data.stride),
                width * 4,
            )
        };
        pixels.extend(
            bytes
                .as_chunks::<4>()
                .0
                .iter()
                .map(|pixel| u32::from_le_bytes(*pixel)),
        );
    }
    Some(Image {
        width: data.width,
        height: data.height,
        pixels,
        opaque: data.opaque,
    })
}

impl GlobalDispatch<wl_shm::WlShm, ()> for State {
    fn bind(
        _state: &mut Self,
        _display: &DisplayHandle,
        _client: &Client,
        resource: New<wl_shm::WlShm>,
        _data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let shm = data_init.init(resource, ());
        shm.format(wl_shm::Format::Argb8888);
        shm.format(wl_shm::Format::Xrgb8888);
    }
}

impl Dispatch<wl_shm::WlShm, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        resource: &wl_shm::WlShm,
        request: wl_shm::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let wl_shm::Request::CreatePool { id, fd, size } = request {
            match Mapping::new(fd, size.max(0) as usize) {
                Some(mapping) => {
                    data_init.init(
                        id,
                        Arc::new(Pool {
                            mapping: Mutex::new(mapping),
                        }),
                    );
                }
                None => resource.post_error(wl_shm::Error::InvalidFd, "cannot map the pool"),
            }
        }
    }
}

impl Dispatch<wl_shm_pool::WlShmPool, Arc<Pool>> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        resource: &wl_shm_pool::WlShmPool,
        request: wl_shm_pool::Request,
        pool: &Arc<Pool>,
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_shm_pool::Request::CreateBuffer {
                id,
                offset,
                width,
                height,
                stride,
                format,
            } => {
                let opaque = match format {
                    WEnum::Value(wl_shm::Format::Xrgb8888) => true,
                    WEnum::Value(wl_shm::Format::Argb8888) => false,
                    _ => {
                        resource.post_error(wl_shm::Error::InvalidFormat, "unsupported format");
                        return;
                    }
                };
                if offset < 0 || width <= 0 || height <= 0 || stride < width * 4 {
                    resource.post_error(wl_shm::Error::InvalidStride, "invalid buffer geometry");
                    return;
                }
                data_init.init(
                    id,
                    BufferData {
                        pool: pool.clone(),
                        offset: offset as usize,
                        width,
                        height,
                        stride: stride as usize,
                        opaque,
                    },
                );
            }
            wl_shm_pool::Request::Resize { size } => {
                let Ok(mut mapping) = pool.mapping.lock() else {
                    return;
                };
                let Ok(fd) = mapping.fd.try_clone() else {
                    return;
                };
                match Mapping::new(fd, size.max(0) as usize) {
                    Some(grown) => *mapping = grown,
                    None => resource.post_error(wl_shm::Error::InvalidFd, "cannot remap the pool"),
                }
            }
            _ => {}
        }
    }
}

impl Dispatch<wl_buffer::WlBuffer, BufferData> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &wl_buffer::WlBuffer,
        _request: wl_buffer::Request,
        _data: &BufferData,
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }
}

// ----- seat ---------------------------------------------------------------

impl GlobalDispatch<wl_seat::WlSeat, ()> for State {
    fn bind(
        _state: &mut Self,
        _display: &DisplayHandle,
        _client: &Client,
        resource: New<wl_seat::WlSeat>,
        _data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let seat = data_init.init(resource, ());
        seat.capabilities(wl_seat::Capability::Pointer | wl_seat::Capability::Keyboard);
        if seat.version() >= 2 {
            seat.name("seat0".into());
        }
    }
}

impl Dispatch<wl_seat::WlSeat, ()> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        _resource: &wl_seat::WlSeat,
        request: wl_seat::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            wl_seat::Request::GetPointer { id } => {
                let pointer = data_init.init(id, ());
                state.seat.pointers.push(pointer);
            }
            wl_seat::Request::GetKeyboard { id } => {
                let keyboard = data_init.init(id, ());
                send_keymap(state, &keyboard);
                if keyboard.version() >= 4 {
                    keyboard.repeat_info(25, 600);
                }
                state.seat.keyboards.push(keyboard.clone());
                state.keyboard_bound(&keyboard);
            }
            _ => {}
        }
    }
}

/// Sends the configured XKB keymap in a memfd, or tells the client there is
/// no keymap and keys are raw evdev codes.
fn send_keymap(state: &State, keyboard: &wl_keyboard::WlKeyboard) {
    if let Some(keymap) = &state.keymap {
        let file = rustix::fs::memfd_create("keymap", rustix::fs::MemfdFlags::CLOEXEC)
            .ok()
            .filter(|fd| rustix::io::write(fd, keymap).ok() == Some(keymap.len()));
        if let Some(fd) = file {
            keyboard.keymap(
                wl_keyboard::KeymapFormat::XkbV1,
                fd.as_fd(),
                keymap.len() as u32,
            );
            return;
        }
    }
    if let Ok(null) = std::fs::File::open("/dev/null") {
        keyboard.keymap(wl_keyboard::KeymapFormat::NoKeymap, null.as_fd(), 0);
    }
}

impl Dispatch<wl_pointer::WlPointer, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &wl_pointer::WlPointer,
        _request: wl_pointer::Request,
        _data: &(),
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        // Client cursor images are ignored; the compositor draws its own.
    }

    fn destroyed(
        state: &mut Self,
        _client: ClientId,
        resource: &wl_pointer::WlPointer,
        _data: &(),
    ) {
        state
            .seat
            .pointers
            .retain(|pointer| pointer.id() != resource.id());
    }
}

impl Dispatch<wl_keyboard::WlKeyboard, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &wl_keyboard::WlKeyboard,
        _request: wl_keyboard::Request,
        _data: &(),
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
    }

    fn destroyed(
        state: &mut Self,
        _client: ClientId,
        resource: &wl_keyboard::WlKeyboard,
        _data: &(),
    ) {
        state
            .seat
            .keyboards
            .retain(|keyboard| keyboard.id() != resource.id());
    }
}

// ----- output -------------------------------------------------------------

impl GlobalDispatch<wl_output::WlOutput, ()> for State {
    fn bind(
        state: &mut Self,
        _display: &DisplayHandle,
        _client: &Client,
        resource: New<wl_output::WlOutput>,
        _data: &(),
        data_init: &mut DataInit<'_, Self>,
    ) {
        let output = data_init.init(resource, ());
        // Physical size assumes roughly 96 dots per inch.
        output.geometry(
            0,
            0,
            state.width * 254 / 960,
            state.height * 254 / 960,
            wl_output::Subpixel::Unknown,
            "Ginux".into(),
            "framebuffer".into(),
            wl_output::Transform::Normal,
        );
        output.mode(
            wl_output::Mode::Current | wl_output::Mode::Preferred,
            state.width,
            state.height,
            60_000,
        );
        if output.version() >= 2 {
            output.scale(1);
            output.done();
        }
        state.outputs.push(output);
    }
}

// ----- xdg-shell ----------------------------------------------------------

impl Dispatch<xdg_wm_base::XdgWmBase, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &xdg_wm_base::XdgWmBase,
        request: xdg_wm_base::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_wm_base::Request::CreatePositioner { id } => {
                data_init.init(id, ());
            }
            xdg_wm_base::Request::GetXdgSurface { id, surface } => {
                data_init.init(id, surface);
            }
            _ => {}
        }
    }
}

impl Dispatch<xdg_surface::XdgSurface, wl_surface::WlSurface> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &xdg_surface::XdgSurface,
        request: xdg_surface::Request,
        surface: &wl_surface::WlSurface,
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        match request {
            xdg_surface::Request::GetToplevel { id } => {
                let toplevel = data_init.init(id, Mutex::new(0_u64));
                let window = state.add_window(surface.clone(), resource.clone(), toplevel.clone());
                if let Some(slot) = toplevel.data::<Mutex<u64>>() {
                    *slot.lock().unwrap() = window;
                }
            }
            xdg_surface::Request::GetPopup { id, .. } => {
                // Popups are not placed yet; dismiss them so clients carry on.
                let popup = data_init.init(id, ());
                popup.popup_done();
            }
            xdg_surface::Request::SetWindowGeometry {
                x,
                y,
                width,
                height,
            } => {
                if let Some(Role::Toplevel(window)) = state
                    .surfaces
                    .get(&surface.id())
                    .map(|surface| surface.role.clone())
                {
                    if let Some(window) = state.window_mut(window) {
                        window.geometry =
                            (width > 0 && height > 0).then_some((x, y, width, height));
                    }
                    state.dirty = true;
                }
            }
            _ => {}
        }
    }
}

fn window_of(toplevel: &xdg_toplevel::XdgToplevel) -> Option<u64> {
    toplevel
        .data::<Mutex<u64>>()
        .and_then(|slot| slot.lock().ok().map(|id| *id))
}

impl Dispatch<xdg_toplevel::XdgToplevel, Mutex<u64>> for State {
    fn request(
        state: &mut Self,
        _client: &Client,
        resource: &xdg_toplevel::XdgToplevel,
        request: xdg_toplevel::Request,
        _data: &Mutex<u64>,
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        let Some(id) = window_of(resource) else {
            return;
        };
        match request {
            xdg_toplevel::Request::SetTitle { title } => {
                if let Some(window) = state.window_mut(id) {
                    window.title = title;
                }
                state.dirty = true;
            }
            xdg_toplevel::Request::Move { .. } => state.start_move(id),
            xdg_toplevel::Request::Destroy => state.remove_window(id),
            _ => {}
        }
    }

    fn destroyed(
        state: &mut Self,
        _client: ClientId,
        resource: &xdg_toplevel::XdgToplevel,
        _data: &Mutex<u64>,
    ) {
        if let Some(id) = window_of(resource) {
            state.remove_window(id);
        }
    }
}

impl Dispatch<zxdg_decoration_manager_v1::ZxdgDecorationManagerV1, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &zxdg_decoration_manager_v1::ZxdgDecorationManagerV1,
        request: zxdg_decoration_manager_v1::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        if let zxdg_decoration_manager_v1::Request::GetToplevelDecoration { id, .. } = request {
            let decoration = data_init.init(id, ());
            decoration.configure(zxdg_toplevel_decoration_v1::Mode::ServerSide);
        }
    }
}

impl Dispatch<zxdg_toplevel_decoration_v1::ZxdgToplevelDecorationV1, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        resource: &zxdg_toplevel_decoration_v1::ZxdgToplevelDecorationV1,
        request: zxdg_toplevel_decoration_v1::Request,
        _data: &(),
        _display: &DisplayHandle,
        _data_init: &mut DataInit<'_, Self>,
    ) {
        // Windows are always decorated by the compositor.
        if matches!(
            request,
            zxdg_toplevel_decoration_v1::Request::SetMode { .. }
                | zxdg_toplevel_decoration_v1::Request::UnsetMode
        ) {
            resource.configure(zxdg_toplevel_decoration_v1::Mode::ServerSide);
        }
    }
}

impl Dispatch<wl_data_device_manager::WlDataDeviceManager, ()> for State {
    fn request(
        _state: &mut Self,
        _client: &Client,
        _resource: &wl_data_device_manager::WlDataDeviceManager,
        request: wl_data_device_manager::Request,
        _data: &(),
        _display: &DisplayHandle,
        data_init: &mut DataInit<'_, Self>,
    ) {
        // Clipboard and drag-and-drop are not offered yet; the objects exist
        // so toolkits that require them can start.
        match request {
            wl_data_device_manager::Request::CreateDataSource { id } => {
                data_init.init(id, ());
            }
            wl_data_device_manager::Request::GetDataDevice { id, .. } => {
                data_init.init(id, ());
            }
            _ => {}
        }
    }
}
