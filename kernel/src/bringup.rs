//! Hardware bring-up mode.
//!
//! The main boot path requires the QEMU reference devices (virtio block and
//! network behind an Intel IOMMU). When they are absent, as on a physical PC,
//! the kernel enters this mode instead of failing. It runs on the firmware page
//! tables with interrupts disabled, reports the platform on the console, and
//! exercises the physical-hardware drivers in `crate::drivers`. Nothing here
//! writes to storage.

use core::ptr::read_unaligned;

use crate::drivers::{ahci, gpt, keyboard, nvme, pci, say, xhci, BlockDevice};
use crate::{BootInfo, UefiMemoryDescriptor, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA};

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_CONVENTIONAL_MEMORY: u32 = crate::EFI_CONVENTIONAL_MEMORY;
const FOUR_GIB: u64 = 1 << 32;
const MAX_CONTROLLERS: usize = 8;
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
    report_acpi(boot_info.acpi_rsdp as u64);
    report_pci();
    report_disks();
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

fn report_disks() {
    let (controllers, _) = functions(pci::Identity::is_nvme);
    for function in controllers.iter().flatten() {
        probe_nvme(*function);
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
                for keyboard in controller.keyboards() {
                    say!(
                        "ginux:   keyboard {:04x}:{:04x} on port {}\n",
                        keyboard.vendor,
                        keyboard.product,
                        keyboard.port
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
                    run_command(boot_info, &line[..length]);
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

fn run_command(boot_info: &BootInfo, line: &[u8]) {
    let text = core::str::from_utf8(line).unwrap_or("").trim();
    let (command, argument) = text.split_once(' ').unwrap_or((text, ""));
    match command {
        "" => {}
        "help" => {
            say!("Commands: help, pci, acpi, mem, disks, clear, echo TEXT, reboot, poweroff\n")
        }
        "pci" => report_pci(),
        "acpi" => report_acpi(boot_info.acpi_rsdp as u64),
        "mem" => report_memory(boot_info),
        "disks" => report_disks(),
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

fn report_acpi(rsdp: u64) {
    // SAFETY: the firmware identity map covers its ACPI tables; every read is
    // bounded by the table lengths the firmware recorded.
    unsafe {
        if rsdp == 0 || read_bytes::<8>(rsdp) != *b"RSD PTR " {
            say!("ginux: ACPI root pointer missing\n");
            return;
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
                b"IVRS" => report_ivrs(table),
                b"DMAR" => say!("[Intel VT-d]"),
                b"MCFG" => report_mcfg(table),
                b"HPET" => say!("[{:#x}]", read_unaligned((table + 44) as *const u64)),
                _ => {}
            }
        }
        say!("\n");
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

unsafe fn report_ivrs(table: u64) {
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
            say!(" {:#x}", read_unaligned((table + offset + 8) as *const u64));
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

fn probe_nvme(function: pci::Function) {
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
