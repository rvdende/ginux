//! USB keyboards and pointers as Linux evdev devices.
//!
//! Before the kernel builds its page tables, [`discover`] finds the xHCI
//! controllers and their register ranges so the device window can map them.
//! [`start`] then admits the controllers' DMA through the I/O MMU, opens
//! them, registers a [`crate::linux_input`] device for every HID boot
//! keyboard, boot mouse and QEMU USB tablet interface, and installs
//! [`pump`]. The controllers run without interrupts: readers of
//! /dev/input/eventN call the pump, which takes the reports that have
//! arrived and turns them into input events with `ginux_usb_hid`.

use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, Ordering};

use ginux_usb_hid as usb_hid;

use super::{pci, say, xhci};
use crate::linux_input;

/// xHCI controllers driven for input.
pub(crate) const MAX_CONTROLLERS: usize = 2;
/// The largest register range mapped for a controller.
const MAX_REGISTER_BYTES: u64 = 1 << 20;
/// Reports one pump call takes from each controller, so a stream of
/// reports cannot hold up the reader that called it.
const REPORTS_PER_PUMP: usize = 64;

/// An xHCI controller and the range its registers (BAR 0) occupy.
#[derive(Clone, Copy)]
struct Host {
    function: pci::Function,
    registers: u64,
    length: usize,
}

/// The xHCI controllers found at boot, in PCI order.
pub(crate) struct Hosts {
    hosts: [Option<Host>; MAX_CONTROLLERS],
    count: usize,
}

impl Hosts {
    /// The register range of each controller, for the device window: the
    /// first [`Hosts::len`] entries are used.
    pub(crate) fn regions(&self) -> [(u64, usize); MAX_CONTROLLERS] {
        self.hosts
            .map(|host| host.map_or((0, 0), |host| (host.registers, host.length)))
    }

    pub(crate) fn len(&self) -> usize {
        self.count
    }
}

/// Finds the xHCI controllers on bus 0 and behind its bridges, sizing each
/// one's register range. Reads PCI configuration space only.
pub(crate) fn discover() -> Hosts {
    let mut hosts = Hosts {
        hosts: [None; MAX_CONTROLLERS],
        count: 0,
    };
    pci::for_each_reachable_function(|device| {
        if !device.is_xhci() || hosts.count == MAX_CONTROLLERS {
            return;
        }
        let function = device.address;
        let (Some(registers), Some(length)) = (function.memory_bar(0), function.memory_bar_size(0))
        else {
            return;
        };
        if length > MAX_REGISTER_BYTES {
            return;
        }
        hosts.hosts[hosts.count] = Some(Host {
            function,
            registers,
            length: length as usize,
        });
        hosts.count += 1;
    });
    hosts
}

/// Turns one interface's reports into events on its evdev device.
enum Decoder {
    Keyboard(usb_hid::Keyboard),
    Mouse(usb_hid::Mouse),
    Tablet(usb_hid::Tablet),
}

struct Device {
    /// N in /dev/input/eventN.
    event: usize,
    decoder: Decoder,
}

impl Device {
    /// Queues the events of one report, ending them with a sync event.
    fn deliver(&mut self, report: &[u8]) {
        let device = self.event;
        let mut emitted = false;
        let mut emit = |event: usb_hid::Event| {
            let (kind, code, value) = evdev(event);
            linux_input::push(device, kind, code, value);
            emitted = true;
        };
        match &mut self.decoder {
            Decoder::Keyboard(keyboard) => keyboard.report(report, &mut emit),
            Decoder::Mouse(mouse) => mouse.report(report, &mut emit),
            Decoder::Tablet(tablet) => tablet.report(report, &mut emit),
        }
        if emitted {
            linux_input::sync(device);
        }
    }
}

/// The evdev type, code and value of a decoded change.
fn evdev(event: usb_hid::Event) -> (u16, u16, i32) {
    match event {
        usb_hid::Event::Key { code, pressed } => (linux_input::EV_KEY, code, pressed.into()),
        usb_hid::Event::Button { button, pressed } => {
            let code = match button {
                usb_hid::Button::Left => linux_input::BTN_LEFT,
                usb_hid::Button::Right => linux_input::BTN_RIGHT,
                usb_hid::Button::Middle => linux_input::BTN_MIDDLE,
            };
            (linux_input::EV_KEY, code, pressed.into())
        }
        usb_hid::Event::Relative { axis, delta } => {
            let code = match axis {
                usb_hid::RelativeAxis::X => linux_input::REL_X,
                usb_hid::RelativeAxis::Y => linux_input::REL_Y,
                usb_hid::RelativeAxis::Wheel => linux_input::REL_WHEEL,
            };
            (linux_input::EV_REL, code, delta)
        }
        usb_hid::Event::Absolute { axis, value } => {
            let code = match axis {
                usb_hid::AbsoluteAxis::X => linux_input::ABS_X,
                usb_hid::AbsoluteAxis::Y => linux_input::ABS_Y,
            };
            (linux_input::EV_ABS, code, value)
        }
    }
}

struct State {
    controllers: [Option<xhci::Controller>; MAX_CONTROLLERS],
    /// The evdev device of each controller's input interfaces, by the
    /// interface's index.
    devices: [[Option<Device>; xhci::MAX_INPUTS]; MAX_CONTROLLERS],
}

/// Written by [`start`] before the pump is installed, then owned by
/// whichever pump call holds [`PUMPING`].
static mut STATE: State = State {
    controllers: [const { None }; MAX_CONTROLLERS],
    devices: [const { [const { None }; xhci::MAX_INPUTS] }; MAX_CONTROLLERS],
};
static PUMPING: AtomicBool = AtomicBool::new(false);

/// Opens the controllers in `hosts`, whose registers are mapped at
/// `registers` (by index, `None` where mapping failed), and registers an
/// evdev device for each input interface. `admit` must let the controllers
/// (bus, device, function) reach the DMA regions (start, length) through
/// the I/O MMU for good, or return false; without it no controller starts.
/// A controller that does not start loses bus mastering, so one firmware
/// left running cannot fault DMA translations later.
pub(crate) fn start(
    hosts: &Hosts,
    registers: &[Option<usize>],
    admit: impl FnOnce(&[(u8, u8, u8)], &[(u64, u64)]) -> bool,
) {
    let found = &hosts.hosts[..hosts.count];
    if found.is_empty() {
        say!("ginux: no xHCI controller; USB input unavailable\n");
        return;
    }
    let functions = hosts.hosts.map(|host| {
        host.map_or((0, 0, 0), |host| {
            (
                host.function.bus,
                host.function.device,
                host.function.function,
            )
        })
    });
    let regions = xhci::dma_regions().map(|region| (region.start, region.length));
    if !admit(&functions[..hosts.count], &regions) {
        say!("ginux: USB input unavailable: the I/O MMU did not admit the xHCI controllers\n");
        for host in found.iter().flatten() {
            host.function.disable_bus_master();
        }
        return;
    }
    // SAFETY: the pump is not installed yet, so nothing else uses STATE.
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    let mut registered = 0;
    for (slot, host) in found.iter().flatten().enumerate() {
        let function = host.function;
        let Some(base) = registers.get(slot).copied().flatten() else {
            say!(
                "ginux: xHCI {:02x}:{:02x}.{}: registers not mapped\n",
                function.bus,
                function.device,
                function.function
            );
            function.disable_bus_master();
            continue;
        };
        // SAFETY: nothing else drives the controller, `base` maps its whole
        // BAR 0 uncached, and the DMA pool is identity mapped and admitted
        // through the I/O MMU above.
        let mut controller = match unsafe { xhci::Controller::open(function, base, false) } {
            Ok(controller) => controller,
            Err(error) => {
                say!(
                    "ginux: xHCI {:02x}:{:02x}.{}: {:?}\n",
                    function.bus,
                    function.device,
                    function.function,
                    error
                );
                function.disable_bus_master();
                continue;
            }
        };
        for (index, input) in controller.inputs().enumerate() {
            let (kind, name, decoder) = match input.kind {
                xhci::InputKind::Keyboard => (
                    linux_input::DeviceKind::Keyboard,
                    "USB keyboard",
                    Decoder::Keyboard(usb_hid::Keyboard::new()),
                ),
                xhci::InputKind::Mouse => (
                    linux_input::DeviceKind::Mouse,
                    "USB mouse",
                    Decoder::Mouse(usb_hid::Mouse::new()),
                ),
                xhci::InputKind::Tablet => (
                    linux_input::DeviceKind::Tablet {
                        maximum: usb_hid::TABLET_MAXIMUM,
                    },
                    "USB tablet",
                    Decoder::Tablet(usb_hid::Tablet::new()),
                ),
            };
            let Some(event) = linux_input::register(kind, name.as_bytes()) else {
                say!(
                    "ginux: input: no device left for the {} on port {}\n",
                    name,
                    input.location
                );
                continue;
            };
            say!(
                "ginux: input event{}: {} {:04x}:{:04x} on port {}\n",
                event,
                name,
                input.vendor,
                input.product,
                input.location
            );
            state.devices[slot][index] = Some(Device { event, decoder });
            registered += 1;
        }
        if state.devices[slot].iter().all(Option::is_none) {
            controller.stop();
            function.disable_bus_master();
            continue;
        }
        state.controllers[slot] = Some(controller);
    }
    if registered != 0 {
        linux_input::set_pump(pump);
    }
}

/// Takes the reports that have arrived on every controller and queues their
/// events. Cheap when nothing is pending: one memory read per controller.
/// A call made while another is running returns at once.
fn pump() {
    if PUMPING.swap(true, Ordering::Acquire) {
        return;
    }
    // SAFETY: PUMPING grants exclusive access to STATE, which start finished
    // writing before it installed the pump.
    let state = unsafe { &mut *addr_of_mut!(STATE) };
    for (controller, devices) in state.controllers.iter_mut().zip(&mut state.devices) {
        let Some(controller) = controller else {
            continue;
        };
        for _ in 0..REPORTS_PER_PUMP {
            let Some(report) = controller.poll() else {
                break;
            };
            if let Some(device) = devices.get_mut(report.input).and_then(Option::as_mut) {
                device.deliver(report.data());
            }
        }
    }
    PUMPING.store(false, Ordering::Release);
}
