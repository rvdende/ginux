//! Hardware bring-up mode.
//!
//! The main boot path requires the QEMU reference devices (virtio block and
//! network behind an Intel IOMMU). When they are absent, as on a physical PC,
//! the kernel enters this mode instead of failing. It runs on the firmware page
//! tables with interrupts disabled, reports the platform on the console, and
//! exercises the physical-hardware drivers in `crate::drivers`. Nothing here
//! writes to storage.

use core::ptr::read_unaligned;

use crate::drivers::net::{self, Nic};
use crate::drivers::{
    ahci, amd_iommu, e1000e, gpt, hda, keyboard, nvme, pci, realtek, say, xhci, BlockDevice,
};
use crate::{BootInfo, UefiMemoryDescriptor, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA};

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_CONVENTIONAL_MEMORY: u32 = crate::EFI_CONVENTIONAL_MEMORY;
const FOUR_GIB: u64 = 1 << 32;
const MAX_CONTROLLERS: usize = 8;
const MAX_IOMMUS: usize = 8;
const LINE_CAPACITY: usize = 128;
const EFI_RESET_COLD: u32 = 0;
const EFI_RESET_SHUTDOWN: u32 = 2;
const MAX_LISTED_PARTITIONS: u32 = 128;

/// Reports the platform and runs the hardware drivers, then halts.
pub(crate) fn run(boot_info: &BootInfo) -> ! {
    say!("\nginux: QEMU reference devices not found; entering hardware bring-up mode\n");
    say!(
        "ginux: serial console {}\n",
        if crate::SERIAL_PRESENT.load(core::sync::atomic::Ordering::Acquire) {
            "present"
        } else {
            "absent"
        }
    );
    let framebuffer = &boot_info.framebuffer;
    if crate::framebuffer::mapped_length(framebuffer).is_some() {
        say!(
            "ginux: framebuffer {}x{} stride {} at {:#x}\n",
            framebuffer.width,
            framebuffer.height,
            framebuffer.stride,
            framebuffer.base
        );
    }
    report_memory(boot_info);
    let iommus = report_acpi(boot_info.acpi_rsdp as u64);
    report_pci();
    let mut remapping = enable_dma_remapping(&iommus);
    report_network();
    report_audio();
    report_disks(&mut remapping);
    let keyboards = open_keyboards();

    if keyboards.iter().all(Option::is_none)
        && !crate::SERIAL_PRESENT.load(core::sync::atomic::Ordering::Acquire)
    {
        say!("ginux: no keyboard or serial input; halted\n");
        halt();
    }
    shell(boot_info, keyboards)
}

fn halt() -> ! {
    loop {
        // SAFETY: bring-up runs with interrupts disabled and never resumes.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Collects the PCI functions that satisfy `wanted`.
fn functions(
    wanted: impl Fn(&pci::Identity) -> bool,
) -> ([Option<pci::Function>; MAX_CONTROLLERS], usize) {
    let mut found = [None; MAX_CONTROLLERS];
    let mut count = 0;
    pci::for_each_function(|device| {
        if wanted(&device) && count < MAX_CONTROLLERS {
            found[count] = Some(device.address);
            count += 1;
        }
    });
    (found, count)
}

fn report_pci() {
    say!("ginux: PCI devices:\n");
    pci::for_each_function(|device| {
        say!(
            "  {:02x}:{:02x}.{} {:04x}:{:04x} {:02x}{:02x}{:02x} {}\n",
            device.address.bus,
            device.address.device,
            device.address.function,
            device.vendor,
            device.device,
            device.class,
            device.subclass,
            device.interface,
            device.class_name()
        );
    });
}

fn report_network() {
    // One probe per boot is enough to tell offers apart.
    static mut TRANSACTION: u32 = 0x6769_6e00;
    pci::for_each_function(|device| {
        if device.class != 0x02 {
            return;
        }
        let address = device.address;
        say!(
            "ginux: network {:02x}:{:02x}.{}: ",
            address.bus,
            address.device,
            address.function
        );
        // SAFETY: bring-up runs on one CPU and only here uses the counter.
        let transaction = unsafe {
            TRANSACTION = TRANSACTION.wrapping_add(1);
            TRANSACTION
        };
        if e1000e::is_supported(&device) {
            // SAFETY: bring-up is the only driver of this controller, and the
            // firmware identity map covers its registers and DMA pages.
            let Some(mut nic) = (unsafe { e1000e::Controller::open(address) }) else {
                say!("Intel 82574 reset failed\n");
                return;
            };
            say!(
                "Intel 82574, MAC {}, {}\n",
                net::Mac(nic.mac()),
                if nic.link_up() { "link up" } else { "no link" }
            );
            report_dhcp(&mut nic, transaction);
            return;
        }
        if !realtek::is_supported(&device) {
            say!(
                "{:04x}:{:04x} has no driver yet\n",
                device.vendor,
                device.device
            );
            return;
        }
        // SAFETY: the device is a supported Realtek controller with an
        // identity-mapped BAR, and probing only reads registers.
        let Some(report) = (unsafe { realtek::probe(address) }) else {
            say!("Realtek {:04x} registers unavailable\n", device.device);
            return;
        };
        say!(
            "Realtek {:04x} chip {:#x}, MAC {}, ",
            device.device,
            report.chip,
            net::Mac(report.mac)
        );
        match report.speed {
            Some(speed) => say!(
                "link up at {} Mb/s {} duplex\n",
                speed,
                if report.full_duplex { "full" } else { "half" }
            ),
            None => say!("no link\n"),
        }
        if !realtek::can_transfer(&device) || report.speed.is_none() {
            return;
        }
        // SAFETY: as for the 82574 above.
        match unsafe { realtek::Controller::open(address) } {
            Some(mut nic) => {
                if nic.link_speed().is_none() {
                    say!("ginux:   link did not return after reset\n");
                }
                report_dhcp(&mut nic, transaction);
            }
            None => say!("ginux:   reset failed\n"),
        }
    });
}

/// Resets each HD Audio controller and lists its codecs and output pins.
fn report_audio() {
    pci::for_each_function(|device| {
        if !hda::is_supported(&device) {
            return;
        }
        let address = device.address;
        say!(
            "ginux: audio {:02x}:{:02x}.{}: {:04x}:{:04x} HD Audio",
            address.bus,
            address.device,
            address.function,
            device.vendor,
            device.device
        );
        // SAFETY: bring-up is the only driver of this controller, and the
        // firmware identity map covers its registers and DMA pages.
        let mut controller = match unsafe { hda::Controller::open(address) } {
            Ok(controller) => controller,
            Err(error) => {
                say!(", {:?}\n", error);
                return;
            }
        };
        say!("\n");
        for codec in controller.codecs() {
            let codec = match codec {
                Ok(codec) => codec,
                Err(error) => {
                    say!("ginux:   codec: {:?}\n", error);
                    continue;
                }
            };
            say!(
                "ginux:   codec {}: {:04x}:{:04x}, {} output converters, outputs:",
                codec.address,
                codec.vendor,
                codec.device,
                codec.converters
            );
            let mut outputs = codec
                .pins
                .iter()
                .flatten()
                .filter(|pin| pin.is_output() && pin.connected())
                .peekable();
            if outputs.peek().is_none() {
                say!(" none");
            }
            for pin in outputs {
                say!(" {} (node {})", pin.device_name(), pin.node);
            }
            say!("\n");
        }
    });
}

/// Plays a one-second tone on every HD Audio codec with a connected output.
fn play_test_tones() {
    pci::for_each_function(|device| {
        if !hda::is_supported(&device) {
            return;
        }
        // SAFETY: as in report_audio.
        let Ok(mut controller) = (unsafe { hda::Controller::open(device.address) }) else {
            return;
        };
        let mut codecs = [const { None }; 15];
        for (slot, codec) in codecs.iter_mut().zip(controller.codecs().flatten()) {
            *slot = Some(codec);
        }
        for codec in codecs.iter().flatten() {
            match controller.play_tone(codec, 1000) {
                Ok(advanced) => say!(
                    "ginux: codec {} played a 440 Hz tone; DMA moved {} bytes\n",
                    codec.address,
                    advanced
                ),
                Err(error) => say!("ginux: codec {}: {:?}\n", codec.address, error),
            }
        }
    });
}

/// Broadcasts a DHCP discover on `nic` and reports the offer, which shows
/// that the controller can send and receive.
fn report_dhcp(nic: &mut impl Nic, transaction: u32) {
    match net::dhcp_discover(nic, transaction) {
        Some(offer) => {
            say!(
                "ginux:   DHCP offer {} from {}",
                net::Ipv4(offer.address),
                net::Ipv4(offer.server)
            );
            if let Some(subnet) = offer.subnet {
                say!(", netmask {}", net::Ipv4(subnet));
            }
            if let Some(router) = offer.router {
                say!(", router {}", net::Ipv4(router));
            }
            if let Some(dns) = offer.dns {
                say!(", DNS {}", net::Ipv4(dns));
            }
            say!("\n");
        }
        None => say!("ginux:   no DHCP offer\n"),
    }
}

fn report_disks(remapping: &mut Remapping) {
    let (controllers, _) = functions(pci::Identity::is_nvme);
    for function in controllers.iter().flatten() {
        probe_nvme(*function, remapping);
    }
    let (controllers, _) = functions(pci::Identity::is_ahci);
    let mut slot = 0;
    for function in controllers.iter().flatten() {
        // SAFETY: bring-up mode is the only driver of these controllers, and
        // the firmware identity map covers their registers.
        let (base, ports, version) = match unsafe { ahci::open_controller(*function) } {
            Ok(opened) => opened,
            Err(error) => {
                say!(
                    "ginux: AHCI {:02x}:{:02x}.{}: {:?}\n",
                    function.bus,
                    function.device,
                    function.function,
                    error
                );
                continue;
            }
        };
        say!(
            "ginux: AHCI {:02x}:{:02x}.{}: version {}.{}, ports {:#x}\n",
            function.bus,
            function.device,
            function.function,
            version >> 16,
            (version >> 8) & 0xff,
            ports
        );
        for port in (0..32).filter(|port| ports & (1 << port) != 0) {
            if slot == ahci::MAX_PORTS {
                break;
            }
            // SAFETY: the controller was opened above and each port uses its
            // own DMA set.
            match unsafe { ahci::Disk::open(base, port, slot) } {
                Ok(mut disk) => {
                    slot += 1;
                    let bytes = disk.sectors.saturating_mul(u64::from(disk.sector_size));
                    say!(
                        "ginux:   port {}: {} (serial {}), {} sectors of {} bytes ({} MiB)\n",
                        disk.port(),
                        trimmed(&disk.model),
                        trimmed(&disk.serial),
                        disk.sectors,
                        disk.sector_size,
                        bytes >> 20
                    );
                    list_partitions(&mut disk);
                }
                Err(ahci::Error::NoDevice) => {}
                Err(error) => say!("ginux:   port {}: {:?}\n", port, error),
            }
        }
    }
}

/// Every USB controller with at least one boot keyboard.
type UsbKeyboards = [Option<xhci::Controller>; MAX_CONTROLLERS];

fn open_keyboards() -> UsbKeyboards {
    let mut opened = [const { None }; MAX_CONTROLLERS];
    let (controllers, count) = functions(pci::Identity::is_xhci);
    if count == 0 {
        say!("ginux: no xHCI controller\n");
    }
    for (slot, function) in controllers.iter().flatten().enumerate() {
        say!(
            "ginux: xHCI {:02x}:{:02x}.{}: looking for keyboards\n",
            function.bus,
            function.device,
            function.function
        );
        // SAFETY: bring-up mode is the only driver of these controllers, and
        // the firmware identity map covers their registers and the DMA pool.
        match unsafe { xhci::Controller::open(*function) } {
            Ok(controller) => {
                for speaker in controller.speakers() {
                    say!(
                        "ginux:   USB speaker {:04x}:{:04x} on port {}: {}, {} channels, {}-bit\n",
                        speaker.vendor,
                        speaker.product,
                        speaker.location,
                        speaker.name,
                        speaker.channels,
                        speaker.bits
                    );
                }
                for keyboard in controller.keyboards() {
                    say!(
                        "ginux:   keyboard {:04x}:{:04x} on port {}\n",
                        keyboard.vendor,
                        keyboard.product,
                        keyboard.location
                    );
                }
                opened[slot] = Some(controller);
            }
            Err(error) => say!("ginux:   {:?}\n", error),
        }
    }
    opened
}

fn shell(boot_info: &BootInfo, mut usb: UsbKeyboards) -> ! {
    say!("\nGinux bring-up shell. Type 'help' for commands.\n");
    let mut decoders: [[keyboard::Keyboard; xhci::MAX_KEYBOARDS]; MAX_CONTROLLERS] =
        core::array::from_fn(|_| core::array::from_fn(|_| keyboard::Keyboard::new()));
    let mut line = [0_u8; LINE_CAPACITY];
    let mut length = 0;
    say!("bring-up> ");
    loop {
        let mut pressed = [0_u8; 16];
        let mut count = 0;
        for (controller, decoders) in usb.iter_mut().zip(decoders.iter_mut()) {
            let Some((index, report)) = controller.as_mut().and_then(xhci::Controller::poll) else {
                continue;
            };
            decoders[index].report(&report, |bytes| {
                for byte in bytes {
                    if count < pressed.len() {
                        pressed[count] = *byte;
                        count += 1;
                    }
                }
            });
        }
        if crate::serial_input_ready() {
            pressed[count] = crate::serial_read_byte_blocking();
            count += 1;
        }
        for byte in pressed[..count].iter().copied() {
            match byte {
                b'\r' | b'\n' => {
                    say!("\n");
                    run_command(boot_info, &mut usb, &line[..length]);
                    length = 0;
                    say!("bring-up> ");
                }
                0x08 | 0x7f => {
                    if length > 0 {
                        length -= 1;
                        say!("\x08 \x08");
                    }
                }
                0x03 => {
                    length = 0;
                    say!("^C\nbring-up> ");
                }
                0x0c => {
                    say!("\x1b[2J\x1b[Hbring-up> ");
                    length = 0;
                }
                0x20..=0x7e if length < LINE_CAPACITY => {
                    line[length] = byte;
                    length += 1;
                    crate::serial_write_raw(&[byte]);
                }
                _ => {}
            }
        }
    }
}

fn run_command(boot_info: &BootInfo, usb: &mut UsbKeyboards, line: &[u8]) {
    let text = core::str::from_utf8(line).unwrap_or("").trim();
    let (command, argument) = text.split_once(' ').unwrap_or((text, ""));
    match command {
        "" => {}
        "help" => say!(
            "Commands: help, pci, acpi, mem, disks, disktest, net, beep, clear, echo TEXT, reboot, poweroff\n"
        ),
        "beep" => {
            play_test_tones();
            for controller in usb.iter_mut().flatten() {
                for index in 0..xhci::MAX_SPEAKERS {
                    let Some((vendor, product, name)) = controller
                        .speakers()
                        .nth(index)
                        .map(|speaker| (speaker.vendor, speaker.product, speaker.name))
                    else {
                        break;
                    };
                    if let Some(sent) = controller.play_tone(index, 1000) {
                        say!(
                            "ginux: USB speaker {:04x}:{:04x} played a 500 Hz tone ({} packets) on its {}\n",
                            vendor,
                            product,
                            sent,
                            name
                        );
                    }
                }
            }
        }
        "pci" => report_pci(),
        "net" => report_network(),
        "acpi" => {
            report_acpi(boot_info.acpi_rsdp as u64);
        }
        "mem" => report_memory(boot_info),
        "disks" => report_disks(&mut [const { None }; MAX_IOMMUS]),
        "disktest" => test_disk_writes(),
        "clear" => say!("\x1b[2J\x1b[H"),
        "echo" => say!("{}\n", argument),
        "reboot" => reset(boot_info, EFI_RESET_COLD),
        "poweroff" => reset(boot_info, EFI_RESET_SHUTDOWN),
        _ => say!("unknown command: {}\n", command),
    }
}

fn reset(boot_info: &BootInfo, kind: u32) {
    say!("ginux: resetting through UEFI runtime services\n");
    // SAFETY: bring-up never calls SetVirtualAddressMap, so the runtime
    // services remain callable through the firmware identity map.
    unsafe { (boot_info.reset_system)(kind, 0, 0, core::ptr::null()) };
}

fn report_memory(boot_info: &BootInfo) {
    let count = boot_info.memory_map_size / boot_info.memory_descriptor_size;
    let (mut usable, mut usable_low, mut highest) = (0_u64, 0_u64, 0_u64);
    for index in 0..count {
        // SAFETY: kernel_main validated the memory-map bounds and descriptor size.
        let descriptor = unsafe {
            read_unaligned(
                boot_info
                    .memory_map
                    .add(index * boot_info.memory_descriptor_size)
                    .cast::<UefiMemoryDescriptor>(),
            )
        };
        let start = descriptor.physical_start;
        let end = start.saturating_add(descriptor.page_count.saturating_mul(4096));
        highest = highest.max(end);
        if matches!(
            descriptor.memory_type,
            EFI_CONVENTIONAL_MEMORY
                | EFI_BOOT_SERVICES_CODE
                | EFI_BOOT_SERVICES_DATA
                | EFI_LOADER_CODE
                | EFI_LOADER_DATA
        ) {
            usable += end - start;
            usable_low += end.min(FOUR_GIB).saturating_sub(start.min(FOUR_GIB));
        }
    }
    say!(
        "ginux: memory {} MiB usable, {} MiB below 4 GiB, map ends at {:#x}\n",
        usable >> 20,
        usable_low >> 20,
        highest
    );
}

/// Reports the ACPI tables and returns the AMD-Vi units IVRS lists.
fn report_acpi(rsdp: u64) -> [u64; MAX_IOMMUS] {
    let mut iommus = [0_u64; MAX_IOMMUS];
    // SAFETY: the firmware identity map covers its ACPI tables; every read is
    // bounded by the table lengths the firmware recorded.
    unsafe {
        if rsdp == 0 || read_bytes::<8>(rsdp) != *b"RSD PTR " {
            say!("ginux: ACPI root pointer missing\n");
            return iommus;
        }
        let revision = read_unaligned((rsdp + 15) as *const u8);
        let (root, entry_size) = if revision >= 2 {
            (read_unaligned((rsdp + 24) as *const u64), 8)
        } else {
            (u64::from(read_unaligned((rsdp + 16) as *const u32)), 4)
        };
        let length = u64::from(read_unaligned((root + 4) as *const u32));
        say!("ginux: ACPI tables:");
        let mut offset = 36;
        while offset + entry_size <= length {
            let table = if entry_size == 8 {
                read_unaligned((root + offset) as *const u64)
            } else {
                u64::from(read_unaligned((root + offset) as *const u32))
            };
            offset += entry_size;
            if table == 0 {
                continue;
            }
            let signature = read_bytes::<4>(table);
            say!(" {}", core::str::from_utf8(&signature).unwrap_or("????"));
            match &signature {
                b"APIC" => report_madt(table),
                b"IVRS" => report_ivrs(table, &mut iommus),
                b"DMAR" => say!("[Intel VT-d]"),
                b"MCFG" => report_mcfg(table),
                b"HPET" => say!("[{:#x}]", read_unaligned((table + 44) as *const u64)),
                _ => {}
            }
        }
        say!("\n");
        for base in iommus.iter().copied().filter(|base| *base != 0) {
            // SAFETY: the base comes from IVRS and the firmware identity map
            // covers it; the registers read have no side effects.
            let report = amd_iommu::probe(base);
            say!(
                "ginux: AMD-Vi {:#x}: {} by firmware, status {:#x}, features ",
                base,
                if report.enabled {
                    "enabled"
                } else {
                    "disabled"
                },
                report.status
            );
            let _ = report.write_features(&mut crate::drivers::Console);
            say!("\n");
        }
    }
    iommus
}

/// The AMD-Vi units with remapping on.
type Remapping = [Option<amd_iommu::Remapping>; MAX_IOMMUS];

/// Turns on DMA remapping on every AMD-Vi unit. Devices Ginux drives reach
/// only their driver's buffers, display controllers keep untranslated access
/// for the firmware framebuffer, and every other device is blocked.
fn enable_dma_remapping(iommus: &[u64; MAX_IOMMUS]) -> Remapping {
    let mut units = [const { None }; MAX_IOMMUS];
    if iommus.iter().all(|base| *base == 0) {
        return units;
    }
    let (xhci, nvme, ahci) = (
        xhci::dma_regions(),
        nvme::dma_regions(),
        ahci::dma_regions(),
    );
    let (intel, realtek, audio) = (
        e1000e::dma_regions(),
        realtek::dma_regions(),
        hda::dma_regions(),
    );
    // SAFETY: no unit is enabled yet, and bring-up runs on one CPU.
    let mut table = unsafe { amd_iommu::DeviceTableBuilder::new() };
    let (mut confined, mut passthrough, mut blocked) = (0, 0, 0);
    let mut failure = None;
    pci::for_each_function(|device| {
        let access = if device.is_xhci() {
            amd_iommu::Access::Regions(&xhci)
        } else if device.is_nvme() {
            amd_iommu::Access::Regions(&nvme)
        } else if device.is_ahci() {
            amd_iommu::Access::Regions(&ahci)
        } else if e1000e::is_supported(&device) {
            amd_iommu::Access::Regions(&intel)
        } else if realtek::can_transfer(&device) {
            amd_iommu::Access::Regions(&realtek)
        } else if hda::is_supported(&device) {
            amd_iommu::Access::Regions(&audio)
        } else if device.class == 0x03 {
            amd_iommu::Access::Passthrough
        } else {
            amd_iommu::Access::Blocked
        };
        match access {
            amd_iommu::Access::Regions(_) => confined += 1,
            amd_iommu::Access::Passthrough => passthrough += 1,
            amd_iommu::Access::Blocked => blocked += 1,
        }
        if let Err(error) = table.assign(device.address.requester_id(), access) {
            failure = Some(error);
        }
    });
    if let Some(error) = failure {
        say!("ginux: AMD-Vi remapping not enabled: {:?}\n", error);
        return units;
    }
    for (slot, base) in iommus.iter().enumerate() {
        if *base == 0 {
            continue;
        }
        // SAFETY: the base comes from IVRS, the firmware identity map covers
        // it, and bring-up is the only code driving the unit.
        match unsafe { amd_iommu::Remapping::enable(*base, &table) } {
            Ok(unit) => {
                say!(
                    "ginux: AMD-Vi {:#x}: DMA remapping on; {} devices confined to their \
                     driver's buffers, {} displays passed through, {} blocked\n",
                    base,
                    confined,
                    passthrough,
                    blocked
                );
                units[slot] = Some(unit);
            }
            Err(error) => say!("ginux: AMD-Vi {:#x}: remapping failed: {:?}\n", base, error),
        }
    }
    units
}

/// Checks that remapping stops `controller` from writing outside its own
/// buffers, by asking it to read a block into a page it was not given.
fn verify_dma_confinement(
    controller: &mut nvme::Controller,
    function: pci::Function,
    remapping: &mut Remapping,
) {
    static mut PROBE: crate::drivers::DmaPage = crate::drivers::DmaPage::ZERO;
    let probe = core::ptr::addr_of_mut!(PROBE);
    // SAFETY: only this check uses the probe page.
    unsafe { (*probe).0.fill(0x5a) };
    let result = controller.read_block_to(0, probe as u64);
    // SAFETY: as above; a successful stray DMA would have changed it.
    let untouched = unsafe { (*probe).0.iter().all(|byte| *byte == 0x5a) };
    // Emulated units may log faults with nonstandard encodings, so any
    // event from the controller counts as evidence; the page is the test.
    let mut fault = None;
    for unit in remapping.iter_mut().flatten() {
        while let Some(event) = unit.next_fault() {
            if event.device == function.requester_id() {
                fault.get_or_insert(event);
            }
        }
    }
    if untouched {
        say!(
            "ginux:   AMD-Vi blocked a stray DMA from this controller to {:#x}",
            probe as u64
        );
        match fault {
            Some(fault) => say!(
                " (event {:#x} at {:#x}{})\n",
                fault.code,
                fault.address,
                if fault.is_page_fault() {
                    ", I/O page fault"
                } else {
                    ""
                }
            ),
            None => say!(" (no event logged)\n"),
        }
    } else {
        say!(
            "ginux:   WARNING: AMD-Vi did not stop a stray DMA to {:#x} (command {})\n",
            probe as u64,
            if result.is_ok() {
                "completed"
            } else {
                "failed"
            }
        );
    }
}

unsafe fn report_madt(table: u64) {
    let length = u64::from(read_unaligned((table + 4) as *const u32));
    let (mut enabled, mut capable) = (0, 0);
    let mut offset = 44;
    while offset + 2 <= length {
        let kind = read_unaligned((table + offset) as *const u8);
        let size = u64::from(read_unaligned((table + offset + 1) as *const u8));
        if size < 2 {
            break;
        }
        let flags = match kind {
            0 => Some(read_unaligned((table + offset + 4) as *const u32)),
            9 => Some(read_unaligned((table + offset + 8) as *const u32)),
            _ => None,
        };
        match flags {
            Some(flags) if flags & 1 != 0 => enabled += 1,
            Some(flags) if flags & 2 != 0 => capable += 1,
            _ => {}
        }
        offset += size;
    }
    say!("[{} CPUs", enabled);
    if capable != 0 {
        say!(" +{} hotplug", capable);
    }
    say!("]");
}

unsafe fn report_ivrs(table: u64, iommus: &mut [u64; MAX_IOMMUS]) {
    let length = u64::from(read_unaligned((table + 4) as *const u32));
    say!("[AMD-Vi");
    let mut offset = 48;
    while offset + 24 <= length {
        let kind = read_unaligned((table + offset) as *const u8);
        let size = u64::from(read_unaligned((table + offset + 2) as *const u16));
        if size == 0 {
            break;
        }
        if matches!(kind, 0x10 | 0x11 | 0x40) {
            let base = read_unaligned((table + offset + 8) as *const u64);
            say!(" {:#x}", base);
            // Several IVHD blocks of different types can describe one unit.
            if !iommus.contains(&base) {
                if let Some(free) = iommus.iter_mut().find(|slot| **slot == 0) {
                    *free = base;
                }
            }
        }
        offset += size;
    }
    say!("]");
}

unsafe fn report_mcfg(table: u64) {
    let length = u64::from(read_unaligned((table + 4) as *const u32));
    let mut offset = 44;
    while offset + 16 <= length {
        say!(
            "[{:#x} buses {}-{}]",
            read_unaligned((table + offset) as *const u64),
            read_unaligned((table + offset + 10) as *const u8),
            read_unaligned((table + offset + 11) as *const u8)
        );
        offset += 16;
    }
}

unsafe fn read_bytes<const N: usize>(address: u64) -> [u8; N] {
    read_unaligned(address as *const [u8; N])
}

/// Checks NVMe writes on every Ginux volume partition without changing it:
/// saves the partition's last block, writes a pattern, reads it back,
/// restores the block and reads that back, and checks that a write one block
/// past the partition is refused. Disks without such a partition are not
/// written at all.
fn test_disk_writes() {
    let (controllers, _) = functions(pci::Identity::is_nvme);
    for function in controllers.iter().flatten() {
        // SAFETY: bring-up mode is the only user of this controller, and the
        // firmware identity map covers its registers and the static DMA pages.
        let mut controller = match unsafe { nvme::Controller::open(*function) } {
            Ok((controller, _)) => controller,
            Err(error) => {
                say!(
                    "ginux: NVMe {:02x}:{:02x}.{}: {:?}\n",
                    function.bus,
                    function.device,
                    function.function,
                    error
                );
                continue;
            }
        };
        let extents = gpt::writable_extents(&mut controller);
        if extents.iter().all(Option::is_none) {
            say!(
                "ginux: NVMe {:02x}:{:02x}.{}: no Ginux volume partition; nothing written\n",
                function.bus,
                function.device,
                function.function
            );
        }
        for extent in extents.iter().flatten() {
            say!(
                "ginux: NVMe {:02x}:{:02x}.{}: Ginux volume blocks {}-{}: {}\n",
                function.bus,
                function.device,
                function.function,
                extent.first_lba(),
                extent.last_lba(),
                check_extent_writes(&mut controller, extent)
            );
        }
    }
}

fn check_extent_writes(
    controller: &mut nvme::Controller,
    extent: &gpt::WritableExtent,
) -> &'static str {
    let block = extent.last_lba();
    let size = controller.block_size as usize;
    if size > 4096 {
        return "block size unsupported";
    }
    let mut original = [0_u8; 4096];
    let mut pattern = [0_u8; 4096];
    match controller.read(block, 1) {
        Ok(data) => original[..size].copy_from_slice(data),
        Err(_) => return "reading the block failed",
    }
    for (index, byte) in pattern[..size].iter_mut().enumerate() {
        *byte = (index as u8) ^ 0x5a;
    }
    pattern[..8].copy_from_slice(b"GINUXWR1");
    if controller.write(extent, block, &pattern[..size]).is_err()
        || controller.read(block, 1).ok() != Some(&pattern[..size])
    {
        let _ = controller.write(extent, block, &original[..size]);
        return "write or read-back failed";
    }
    if controller.write(extent, block, &original[..size]).is_err()
        || controller.read(block, 1).ok() != Some(&original[..size])
    {
        return "restoring the block failed";
    }
    if controller
        .write(extent, block + 1, &pattern[..size])
        .is_ok()
    {
        return "a write past the partition was accepted";
    }
    "write verified, restored, and bounded"
}

fn probe_nvme(function: pci::Function, remapping: &mut Remapping) {
    say!(
        "ginux: NVMe {:02x}:{:02x}.{}: ",
        function.bus,
        function.device,
        function.function
    );
    // SAFETY: bring-up mode is the only user of this controller, and the
    // firmware identity map covers its registers and the static DMA pages.
    let (mut controller, identity) = match unsafe { nvme::Controller::open(function) } {
        Ok(opened) => opened,
        Err(error) => {
            say!("initialization failed: {:?}\n", error);
            return;
        }
    };
    say!(
        "{} (serial {}, firmware {}, NVMe {}.{})\n",
        trimmed(&identity.model),
        trimmed(&identity.serial),
        trimmed(&identity.firmware),
        identity.version >> 16,
        (identity.version >> 8) & 0xff
    );
    let bytes = controller
        .block_count
        .saturating_mul(u64::from(controller.block_size));
    let (size, unit) = if bytes >= 1 << 30 {
        (bytes >> 30, "GiB")
    } else {
        (bytes >> 20, "MiB")
    };
    say!(
        "ginux:   namespace {}: {} blocks of {} bytes ({} {})\n",
        controller.namespace,
        controller.block_count,
        controller.block_size,
        size,
        unit
    );
    list_partitions(&mut controller);
    if remapping.iter().any(Option::is_some) {
        verify_dma_confinement(&mut controller, function, remapping);
    }
}

fn list_partitions(disk: &mut impl BlockDevice) {
    let header = match disk.read_blocks(gpt::HEADER_LBA, 1) {
        Some(block) => gpt::parse_header(block),
        None => {
            say!("ginux:   reading the partition table failed\n");
            return;
        }
    };
    let Some(header) = header else {
        say!("ginux:   no valid GPT\n");
        return;
    };
    say!("ginux:   GPT disk {}\n", header.disk);
    let block_size = u64::from(disk.block_size());
    let entry_size = u64::from(header.entry_size);
    let mut cached_block = u64::MAX;
    let mut block = [0_u8; 4096];
    for index in 0..u64::from(header.entry_count.min(MAX_LISTED_PARTITIONS)) {
        let byte_offset = index * entry_size;
        let lba = header.entries_lba + byte_offset / block_size;
        if lba != cached_block {
            match disk.read_blocks(lba, 1) {
                Some(data) => block[..data.len()].copy_from_slice(data),
                None => {
                    say!("ginux:   reading partition entries failed\n");
                    return;
                }
            }
            cached_block = lba;
        }
        let start = (byte_offset % block_size) as usize;
        let Some(entry) = block.get(start..start + entry_size as usize) else {
            break;
        };
        let Some(partition) = gpt::parse_entry(entry) else {
            continue;
        };
        let size = (partition.last_lba + 1).saturating_sub(partition.first_lba) * block_size;
        say!(
            "ginux:   partition {}: {} MiB {} \"",
            index + 1,
            size >> 20,
            gpt::type_name(partition.kind)
        );
        let _ = partition.write_name(&mut crate::drivers::Console);
        say!("\"\n");
    }
}

fn trimmed(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes)
        .unwrap_or("?")
        .trim_matches(|character: char| character == ' ' || character == '\0')
}
