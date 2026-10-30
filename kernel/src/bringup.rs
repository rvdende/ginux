//! Hardware bring-up mode.
//!
//! The main boot path requires the QEMU reference devices (virtio block and
//! network behind an Intel IOMMU). When they are absent, as on a physical PC,
//! the kernel enters this mode instead of failing. It runs on the firmware page
//! tables with interrupts disabled, reports the platform on the console, and
//! exercises the physical-hardware drivers in `crate::drivers`. Nothing here
//! writes to storage.

use core::ptr::read_unaligned;

use crate::drivers::{gpt, nvme, pci, say};
use crate::{BootInfo, UefiMemoryDescriptor, EFI_BOOT_SERVICES_CODE, EFI_BOOT_SERVICES_DATA};

const EFI_LOADER_CODE: u32 = 1;
const EFI_LOADER_DATA: u32 = 2;
const EFI_CONVENTIONAL_MEMORY: u32 = crate::EFI_CONVENTIONAL_MEMORY;
const FOUR_GIB: u64 = 1 << 32;
const MAX_NVME_CONTROLLERS: usize = 8;
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

    let mut nvme_controllers = [None; MAX_NVME_CONTROLLERS];
    let mut nvme_count = 0;
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
        if device.is_nvme() && nvme_count < MAX_NVME_CONTROLLERS {
            nvme_controllers[nvme_count] = Some(device.address);
            nvme_count += 1;
        }
    });

    for function in nvme_controllers.iter().flatten() {
        probe_nvme(*function);
    }

    say!("ginux: bring-up complete; drivers for the remaining devices are not written yet\n");
    say!("ginux: halted\n");
    loop {
        // SAFETY: bring-up runs with interrupts disabled and never resumes.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) };
    }
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

fn list_partitions(controller: &mut nvme::Controller) {
    let header = match controller.read(gpt::HEADER_LBA, 1) {
        Ok(block) => gpt::parse_header(block),
        Err(error) => {
            say!("ginux:   reading the partition table failed: {:?}\n", error);
            return;
        }
    };
    let Some(header) = header else {
        say!("ginux:   no valid GPT\n");
        return;
    };
    say!("ginux:   GPT disk {}\n", header.disk);
    let block_size = u64::from(controller.block_size);
    let entry_size = u64::from(header.entry_size);
    let mut cached_block = u64::MAX;
    let mut block = [0_u8; 4096];
    for index in 0..u64::from(header.entry_count.min(MAX_LISTED_PARTITIONS)) {
        let byte_offset = index * entry_size;
        let lba = header.entries_lba + byte_offset / block_size;
        if lba != cached_block {
            match controller.read(lba, 1) {
                Ok(data) => block[..data.len()].copy_from_slice(data),
                Err(error) => {
                    say!("ginux:   reading partition entries failed: {:?}\n", error);
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
