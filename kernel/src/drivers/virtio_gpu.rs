//! virtio-gpu as the display, for the kernel console and /dev/fb0.
//!
//! A virtio-gpu has no framebuffer of its own: the guest draws into a 2D
//! resource's backing, which is ordinary guest memory, and tells the host
//! which rectangles to copy into the resource (`TRANSFER_TO_HOST_2D`) and
//! show (`RESOURCE_FLUSH`). The driver makes one resource the size of the
//! mode the host prefers (`GET_DISPLAY_INFO`), backs it with physically
//! contiguous kernel frames, and points a scanout at it. The console and
//! /dev/fb0 then use that backing exactly as they use the firmware
//! framebuffer: the console draws into it, and a domain maps it.
//!
//! Bring-up follows the xHCI input driver. [`discover`] finds the device
//! before the kernel builds its page tables, so its registers join the
//! device window. [`prepare`] opens it while DMA translation is still off,
//! creates and backs the resource, and returns the DMA regions to admit;
//! the I/O MMU admits them together with the USB controllers', as standing
//! devices. [`activate`] then shows the resource and moves the console and
//! /dev/fb0 onto it. Without a virtio-gpu, or if any step fails, the
//! firmware framebuffer stays the display.
//!
//! Flushing: the host only sees what the guest flushes.
//!
//! - The console reports the rectangle it drew after each write, and the
//!   same goes for write(2) to /dev/fb0. Damage accumulates in one atomic
//!   word, and whoever holds the GPU transfers and flushes it. A caller
//!   waits (briefly) for a flush already in progress rather than leave its
//!   own damage behind, so the last line written is always shown.
//! - A domain that maps /dev/fb0 writes it without the kernel seeing, so
//!   while a domain owns the screen the 1 kHz Linux timer tick flushes the
//!   whole surface at [`REFRESH_HZ`]. The tick never waits: when a flush
//!   is still in progress it tries again on the next tick.
//!
//! The control queue carries one batch of commands at a time, and the
//! device is polled, never interrupting. The GPU sits behind a latch that
//! is only ever tried, never waited on, because the console reaches it
//! from any context, interrupt handlers and code holding ranked locks
//! included: a caller that finds it held leaves its damage for the holder
//! or the next tick.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use ginux_virtio_gpu::{self as protocol, Command, Damage, DisplayInfo, Mode, Rect};

use super::device_memory::{DmaBuffer, Mmio};
use super::virtio::{self, Chain, Probe, SplitQueue, Transport};
use super::{pci, say, wait_until_ms};
use crate::framebuffer::{self, Display, Scanout};

/// The one resource the driver creates: the display surface.
const RESOURCE: u32 = 1;
/// Descriptors in the control queue: room for a batch of four commands.
const QUEUE_SIZE: u16 = 8;
/// Command slots in the command page, one per chain of a batch.
const SLOTS: usize = QUEUE_SIZE as usize / 2;
/// Bytes per command slot: the request, then the response.
const SLOT_BYTES: usize = 1024;
const RESPONSE_OFFSET: usize = 512;
/// The largest surface the driver backs (1920x1080 fits); larger host modes
/// fall back. The I/O MMU maps the surface with the USB controllers' DMA in
/// one standing table of at most 16 frames, so it cannot grow much.
const MAX_SURFACE_BYTES: usize = 8 << 20;
/// The mode used when the host enables no scanout that fits.
const FALLBACK_MODE: Mode = Mode {
    width: 1280,
    height: 800,
};
/// Full-surface flushes per second while a domain draws through /dev/fb0.
const REFRESH_HZ: u64 = 60;
/// Assumed timestamp-counter rate when the timer cannot tell.
const FALLBACK_COUNTER_HZ: u64 = 3_000_000_000;
/// How long boot waits for each setup command.
const SETUP_TIMEOUT_MS: u64 = 1000;
/// How long a console write waits for an earlier flush to complete.
const PRESENT_WAIT_MS: u64 = 20;
/// Flushes one present call makes for damage that arrived meanwhile.
const PRESENT_ROUNDS: usize = 4;
const PAGE_SIZE: usize = 4096;

const _: () = assert!(SLOTS * SLOT_BYTES <= PAGE_SIZE);
const _: () = assert!(
    RESPONSE_OFFSET >= protocol::MAX_REQUEST
        && SLOT_BYTES - RESPONSE_OFFSET >= protocol::MAX_RESPONSE
);

/// Finds the first virtio-gpu on bus 0 or behind its bridges. Reads PCI
/// configuration space only, apart from sizing the register BAR.
pub(crate) fn discover() -> Option<Probe> {
    let mut found = None;
    pci::for_each_reachable_function(|identity| {
        if found.is_none()
            && identity.vendor == virtio::VENDOR
            && identity.device == protocol::DEVICE_ID
        {
            found = virtio::probe(identity.address);
        }
    });
    found
}

/// Why the GPU did not become the display, or a flush failed.
// The fields are reported through Debug, which dead-code analysis ignores.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
enum Error {
    Transport(virtio::Error),
    /// The frame allocator had no contiguous run for a buffer.
    Memory,
    /// The device did not use a batch in time.
    Timeout,
    Command(Command, protocol::Error),
}

impl From<virtio::Error> for Error {
    fn from(error: virtio::Error) -> Self {
        Self::Transport(error)
    }
}

/// The device and its control queue, which runs one batch of commands at
/// a time. Fields drop in order: the transport resets the device before
/// the queue and command memory return to the allocator.
struct Device {
    transport: Transport,
    control: SplitQueue,
    /// [`SLOTS`] request/response pairs, one per chain of a batch.
    commands: DmaBuffer,
    /// The commands of the batch in flight, to check their replies.
    in_flight: [Option<Command>; SLOTS],
}

impl Device {
    fn open(probe: &Probe, registers: Mmio) -> Result<(Self, u64), Error> {
        let transport = Transport::new(probe, registers)?;
        // No optional features: 2D needs none. The 3D ones are reported.
        let offered = transport.negotiate(0)?;
        let ring = DmaBuffer::allocate(1).ok_or(Error::Memory)?;
        let control = transport.queue(protocol::CONTROL_QUEUE, QUEUE_SIZE, ring)?;
        let commands = DmaBuffer::allocate(1).ok_or(Error::Memory)?;
        transport.ready();
        let device = Self {
            transport,
            control,
            commands,
            in_flight: [None; SLOTS],
        };
        Ok((device, offered))
    }

    /// Writes `commands` into their slots and submits them as one batch.
    /// The previous batch must be complete.
    fn submit(&mut self, commands: &[Command]) -> bool {
        if commands.len() > SLOTS.min(self.control.capacity()) {
            return false;
        }
        let mut chains = [Chain {
            request: (0, 0),
            response: (0, 0),
        }; SLOTS];
        for (slot, command) in commands.iter().enumerate() {
            let request = command.encode();
            let base = slot * SLOT_BYTES;
            self.commands.write_bytes(base, request.as_bytes());
            // A reply the device never wrote then reads as type zero.
            self.commands
                .write_bytes(base + RESPONSE_OFFSET, &[0; protocol::HEADER_SIZE]);
            chains[slot] = Chain {
                request: (
                    self.commands.device_address(base),
                    request.as_bytes().len() as u32,
                ),
                response: (
                    self.commands.device_address(base + RESPONSE_OFFSET),
                    command.response_len() as u32,
                ),
            };
        }
        if !self.control.submit(&chains[..commands.len()]) {
            return false;
        }
        for (slot, command) in self.in_flight.iter_mut().zip(commands) {
            *slot = Some(*command);
        }
        true
    }

    /// The outcome of the batch in flight once the device has used all of
    /// it: the first command that failed, if any. `None` while it runs.
    fn reap(&mut self) -> Option<Result<(), Error>> {
        if !self.control.idle() {
            return None;
        }
        let mut outcome = Ok(());
        for (slot, command) in self.in_flight.iter_mut().enumerate() {
            let Some(command) = command.take() else {
                continue;
            };
            let mut header = [0_u8; protocol::HEADER_SIZE];
            self.commands
                .read_bytes(slot * SLOT_BYTES + RESPONSE_OFFSET, &mut header);
            if let (Ok(()), Err(error)) = (outcome, command.check(&header)) {
                outcome = Err(Error::Command(command, error));
            }
        }
        Some(outcome)
    }

    /// Waits up to `milliseconds` for the batch in flight, if any.
    fn wait(&mut self, milliseconds: u64) -> Option<Result<(), Error>> {
        let mut outcome = None;
        wait_until_ms(milliseconds, || {
            outcome = self.reap();
            outcome.is_some()
        });
        outcome
    }

    /// Runs `commands` as one batch and waits for them, at boot.
    fn execute(&mut self, commands: &[Command]) -> Result<(), Error> {
        self.wait(SETUP_TIMEOUT_MS).ok_or(Error::Timeout)??;
        if !self.submit(commands) {
            return Err(Error::Transport(virtio::Error::Queue));
        }
        self.wait(SETUP_TIMEOUT_MS).ok_or(Error::Timeout)?
    }

    /// Copies the response in `slot` of the last batch into `bytes`.
    fn response(&self, slot: usize, bytes: &mut [u8]) {
        self.commands
            .read_bytes(slot * SLOT_BYTES + RESPONSE_OFFSET, bytes);
    }
}

/// The GPU with its display surface: resource [`RESOURCE`], backed by
/// `surface`, which the console draws into and domains map as /dev/fb0.
/// The device drops first, so it stops reading the surface before the
/// surface's frames go back.
struct Gpu {
    device: Device,
    surface: DmaBuffer,
    scanout: u32,
    mode: Mode,
    /// Timestamp-counter ticks between full-surface refreshes.
    refresh_period: u64,
    last_refresh: u64,
}

impl Gpu {
    /// Opens the device, asks the host for its preferred mode, and creates
    /// a resource of that size backed by fresh contiguous frames.
    fn open(probe: &Probe, registers: Mmio) -> Result<(Self, u64), Error> {
        let (mut device, offered) = Device::open(probe, registers)?;
        device.execute(&[Command::GetDisplayInfo])?;
        let mut reply = [0_u8; protocol::MAX_RESPONSE];
        device.response(0, &mut reply);
        let info = DisplayInfo::parse(&reply)
            .map_err(|error| Error::Command(Command::GetDisplayInfo, error))?;
        let scanouts = device.transport.device_u32(protocol::CONFIG_NUM_SCANOUTS) as usize;
        let (scanout, mode) = info.choose(scanouts, MAX_SURFACE_BYTES, FALLBACK_MODE);
        let bytes = mode.bytes().ok_or(Error::Memory)?;
        let surface = DmaBuffer::allocate(bytes.div_ceil(PAGE_SIZE)).ok_or(Error::Memory)?;
        device.execute(&[
            Command::ResourceCreate2d {
                resource: RESOURCE,
                format: protocol::Format::B8G8R8X8,
                width: mode.width,
                height: mode.height,
            },
            Command::AttachBacking {
                resource: RESOURCE,
                address: surface.device_address(0),
                length: bytes as u32,
            },
        ])?;
        let counter_hz =
            crate::arch::x86_64::timer::monotonic_frequency().unwrap_or(FALLBACK_COUNTER_HZ);
        let gpu = Self {
            device,
            surface,
            scanout,
            mode,
            refresh_period: counter_hz / REFRESH_HZ,
            last_refresh: 0,
        };
        Ok((gpu, offered))
    }

    fn full(&self) -> Rect {
        Rect::full(self.mode.width, self.mode.height)
    }

    /// The display /dev/fb0 and the console see: the surface, tightly
    /// packed blue-green-red-unused pixels.
    fn display(&self) -> Display {
        let line_length = self.mode.width * protocol::BYTES_PER_PIXEL;
        Display {
            physical: self.surface.region().0,
            width: self.mode.width,
            height: self.mode.height,
            line_length,
            length: line_length as usize * self.mode.height as usize,
            bgrx: true,
            scanout: Scanout::VirtioGpu,
        }
    }

    /// Whether a periodic full refresh is due, starting the next period if
    /// so.
    fn refresh_due(&mut self) -> bool {
        let now = crate::arch::x86_64::timer::timestamp_counter();
        if now.wrapping_sub(self.last_refresh) < self.refresh_period {
            return false;
        }
        self.last_refresh = now;
        true
    }

    /// Finishes the flush in flight, waiting up to `wait_ms` for it, then
    /// starts one for the pending `damage`. Returns the outcome of the
    /// flush that finished, or `None` when the earlier one is still running
    /// (and the damage stays pending).
    fn flush(&mut self, damage: &AtomicU64, wait_ms: Option<u64>) -> Option<Result<(), Error>> {
        let outcome = match wait_ms {
            Some(milliseconds) => self.device.wait(milliseconds),
            None => self.device.reap(),
        }?;
        let taken = Damage::from_bits(damage.swap(Damage::EMPTY.bits(), Ordering::AcqRel));
        let Some(rect) = taken
            .rect()
            .map(|rect| rect.clamp(self.mode.width, self.mode.height))
            .filter(|rect| !rect.is_empty())
        else {
            return Some(outcome);
        };
        let stride = u64::from(self.mode.width * protocol::BYTES_PER_PIXEL);
        let offset =
            u64::from(rect.y) * stride + u64::from(rect.x) * u64::from(protocol::BYTES_PER_PIXEL);
        let submitted = self.device.submit(&[
            Command::TransferToHost2d {
                resource: RESOURCE,
                rect,
                offset,
            },
            Command::ResourceFlush {
                resource: RESOURCE,
                rect,
            },
        ]);
        if !submitted {
            add_damage(damage, taken);
        }
        Some(outcome)
    }
}

/// Adds `more` to the damage word, from any context.
fn add_damage(damage: &AtomicU64, more: Damage) {
    if more.is_empty() {
        return;
    }
    let mut current = damage.load(Ordering::Acquire);
    loop {
        let merged = Damage::from_bits(current).union(more).bits();
        match damage.compare_exchange_weak(current, merged, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

/// The GPU that scans out the console and /dev/fb0, once [`activate`] has
/// installed it, with the damage waiting to be flushed.
struct ScanoutOwner {
    /// Held by whoever is using `gpu`. Only ever tried, never waited on.
    held: AtomicBool,
    /// Pending damage as [`Damage::bits`]; updated without holding `held`.
    damage: AtomicU64,
    /// Set once a flush has failed and been reported.
    failure_reported: AtomicBool,
    gpu: UnsafeCell<Option<Gpu>>,
}

// SAFETY: `gpu` is reached only through a Claim, and `held` admits one
// Claim at a time on any CPU (acquire on taking it, release on dropping
// it). The other fields are atomics.
unsafe impl Sync for ScanoutOwner {}

static SCANOUT: ScanoutOwner = ScanoutOwner {
    held: AtomicBool::new(false),
    damage: AtomicU64::new(0),
    failure_reported: AtomicBool::new(false),
    gpu: UnsafeCell::new(None),
};

/// Exclusive use of the scanout GPU until dropped.
struct Claim<'a> {
    owner: &'a ScanoutOwner,
}

impl ScanoutOwner {
    /// The GPU, or `None` while another context is using it.
    fn claim(&self) -> Option<Claim<'_>> {
        // Lazily: a Claim made for a latch someone else holds would release
        // it when dropped.
        (!self.held.swap(true, Ordering::Acquire)).then(|| Claim { owner: self })
    }

    /// Flushes pending damage. With `wait_ms`, waits that long for a flush
    /// already in progress and repeats for damage added meanwhile; without
    /// it, gives up at once if the GPU is busy. `refresh` adds the whole
    /// surface when a periodic refresh is due.
    fn flush(&self, wait_ms: Option<u64>, refresh: bool) {
        for _ in 0..PRESENT_ROUNDS {
            let outcome = {
                let Some(mut claim) = self.claim() else {
                    return;
                };
                let Some(gpu) = claim.gpu() else {
                    return;
                };
                if refresh && gpu.refresh_due() {
                    add_damage(&self.damage, Damage::of(gpu.full()));
                }
                gpu.flush(&self.damage, wait_ms)
            };
            // Reported after the claim is released: the report is console
            // output, which comes back here.
            if let Some(Err(error)) = outcome {
                if !self.failure_reported.swap(true, Ordering::Relaxed) {
                    say!("ginux: virtio-gpu flush failed: {:?}\n", error);
                }
            }
            if wait_ms.is_none() || self.damage.load(Ordering::Acquire) == 0 {
                return;
            }
        }
    }
}

impl Claim<'_> {
    fn gpu(&mut self) -> Option<&mut Gpu> {
        // SAFETY: this claim holds `held`, so no other reference to `gpu`
        // exists until it drops.
        unsafe { (*self.owner.gpu.get()).as_mut() }
    }

    fn install(&mut self, gpu: Gpu) {
        // SAFETY: as for gpu.
        unsafe { *self.owner.gpu.get() = Some(gpu) };
    }
}

impl Drop for Claim<'_> {
    fn drop(&mut self) {
        self.owner.held.store(false, Ordering::Release);
    }
}

/// A GPU whose display resource exists and is backed, but not yet shown.
pub(crate) struct Prepared {
    gpu: Gpu,
    offered: u64,
    /// Whether the I/O MMU admitted the GPU's DMA.
    admitted: bool,
}

/// Opens the virtio-gpu found by [`discover`] and creates its display
/// resource in the mode the host prefers. DMA translation must be off.
/// Returns `None`, leaving the device reset, if any step fails.
///
/// # Safety
///
/// `registers` must map `probe.registers` uncached for the rest of the
/// kernel's life, and nothing else may drive the device.
pub(crate) unsafe fn prepare(probe: &Probe, registers: usize) -> Option<Prepared> {
    let function = probe.function;
    // SAFETY: the caller's contract.
    let registers = unsafe { Mmio::new(registers, probe.registers.1) };
    match Gpu::open(probe, registers) {
        Ok((gpu, offered)) => Some(Prepared {
            gpu,
            offered,
            admitted: false,
        }),
        Err(error) => {
            say!(
                "ginux: virtio-gpu {:02x}:{:02x}.{}: {:?}; keeping the firmware framebuffer\n",
                function.bus,
                function.device,
                function.function,
                error
            );
            None
        }
    }
}

/// A standing I/O MMU admission: (bus, device, function) of each device,
/// and the (start, length) of each DMA region they may reach.
type Admit<'a> = &'a dyn Fn(&[(u8, u8, u8)], &[(u64, u64)]) -> bool;

impl Prepared {
    /// The GPU's DMA regions: its control ring, its command page and the
    /// surface.
    fn regions(&self) -> [(u64, u64); 3] {
        [
            self.gpu.device.control.region(),
            self.gpu.device.commands.region(),
            self.gpu.surface.region(),
        ]
    }

    /// Admits the GPU through `admit`, which grants standing access once,
    /// together with another driver's `functions` and `regions`. When the
    /// two do not fit together the other driver is admitted alone, and the
    /// GPU is not. Returns whether the other driver was admitted.
    pub(crate) fn admit_alongside(
        &mut self,
        functions: &[(u8, u8, u8)],
        regions: &[(u64, u64)],
        admit: Admit<'_>,
    ) -> bool {
        const LIMIT: usize = 8;
        let own = self.regions();
        if functions.len() < LIMIT && regions.len() + own.len() <= LIMIT {
            let mut all_functions = [(0, 0, 0); LIMIT];
            let mut all_regions = [(0, 0); LIMIT];
            all_functions[..functions.len()].copy_from_slice(functions);
            all_functions[functions.len()] = self.gpu.device.transport.address();
            all_regions[..regions.len()].copy_from_slice(regions);
            all_regions[regions.len()..regions.len() + own.len()].copy_from_slice(&own);
            if admit(
                &all_functions[..=functions.len()],
                &all_regions[..regions.len() + own.len()],
            ) {
                self.admitted = true;
                return true;
            }
        }
        admit(functions, regions)
    }

    /// Admits the GPU by itself, when no other driver needs admission.
    pub(crate) fn admit_alone(&mut self, admit: Admit<'_>) {
        self.admitted = admit(&[self.gpu.device.transport.address()], &self.regions());
    }
}

/// Shows the prepared GPU's surface on its scanout and moves the console
/// and /dev/fb0 onto it. A GPU the I/O MMU did not admit is reset instead,
/// leaving the firmware framebuffer as the display. Called once, at boot.
pub(crate) fn activate(prepared: Prepared) {
    let Prepared {
        mut gpu,
        offered,
        admitted,
    } = prepared;
    let (bus, device, function) = gpu.device.transport.address();
    if !admitted {
        say!(
            "ginux: virtio-gpu {:02x}:{:02x}.{}: the I/O MMU did not admit it; keeping the firmware framebuffer\n",
            bus,
            device,
            function
        );
        return;
    }
    let shown = gpu.device.execute(&[Command::SetScanout {
        scanout: gpu.scanout,
        resource: RESOURCE,
        rect: gpu.full(),
    }]);
    if let Err(error) = shown {
        say!(
            "ginux: virtio-gpu {:02x}:{:02x}.{}: {:?}; keeping the firmware framebuffer\n",
            bus,
            device,
            function,
            error
        );
        return;
    }
    let display = gpu.display();
    let base = gpu.surface.kernel_address();
    let (mode, scanout) = (gpu.mode, gpu.scanout);
    {
        let Some(mut claim) = SCANOUT.claim() else {
            return;
        };
        if claim.gpu().is_some() {
            return;
        }
        claim.install(gpu);
    }
    // SAFETY: the surface now belongs to SCANOUT, which never drops or
    // replaces its GPU, so `base` maps `display.length` bytes of it, at
    // `display.physical`, for the rest of the kernel's life.
    if !unsafe { framebuffer::adopt(display, base) } {
        say!("ginux: virtio-gpu: the console did not move to the GPU surface\n");
        return;
    }
    say!(
        "ginux: virtio-gpu {:02x}:{:02x}.{} display {}x{} on scanout {}; host features",
        bus,
        device,
        function,
        mode.width,
        mode.height,
        scanout
    );
    let mut any = false;
    for (bit, name) in [
        (protocol::FEATURE_VIRGL, "virgl"),
        (protocol::FEATURE_EDID, "edid"),
        (protocol::FEATURE_RESOURCE_BLOB, "blob"),
        (protocol::FEATURE_CONTEXT_INIT, "context-init"),
    ] {
        if offered & bit != 0 {
            say!(" {}", name);
            any = true;
        }
    }
    say!("{}\n", if any { "" } else { " none" });
}

/// Queues `rect` of the surface for the host and flushes it, waiting
/// briefly for a flush already in progress.
pub(crate) fn present(rect: Rect) {
    add_damage(&SCANOUT.damage, Damage::of(rect));
    SCANOUT.flush(Some(PRESENT_WAIT_MS), false);
}

/// From the Linux timer tick: refreshes the whole surface periodically
/// while a domain draws through /dev/fb0 (`owned`), and retries damage an
/// earlier call left pending. Never waits.
pub(crate) fn refresh(owned: bool) {
    if owned || SCANOUT.damage.load(Ordering::Relaxed) != 0 {
        SCANOUT.flush(None, owned);
    }
}
