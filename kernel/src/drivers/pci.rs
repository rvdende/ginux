//! PCI configuration access through the legacy 0xcf8/0xcfc ports and a
//! device inventory with human-readable class names.

use core::arch::asm;

const CONFIG_ADDRESS: u16 = 0xcf8;
const CONFIG_DATA: u16 = 0xcfc;
const COMMAND: u8 = 0x04;
const COMMAND_MEMORY: u16 = 1 << 1;
const COMMAND_BUS_MASTER: u16 = 1 << 2;
const COMMAND_INTERRUPT_DISABLE: u16 = 1 << 10;

/// A PCI function address.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Function {
    pub(crate) bus: u8,
    pub(crate) device: u8,
    pub(crate) function: u8,
}

/// The identifying registers of one PCI function.
#[derive(Clone, Copy)]
pub(crate) struct Identity {
    pub(crate) address: Function,
    pub(crate) vendor: u16,
    pub(crate) device: u16,
    pub(crate) class: u8,
    pub(crate) subclass: u8,
    pub(crate) interface: u8,
}

impl Function {
    pub(crate) fn read_u32(self, offset: u8) -> u32 {
        let address = 0x8000_0000
            | u32::from(self.bus) << 16
            | u32::from(self.device) << 11
            | u32::from(self.function) << 8
            | u32::from(offset & 0xfc);
        // SAFETY: configuration mechanism #1 is present on every x86-64 PC
        // chipset; the address register selects one dword of this function.
        unsafe {
            outl(CONFIG_ADDRESS, address);
            inl(CONFIG_DATA)
        }
    }

    pub(crate) fn write_u32(self, offset: u8, value: u32) {
        let address = 0x8000_0000
            | u32::from(self.bus) << 16
            | u32::from(self.device) << 11
            | u32::from(self.function) << 8
            | u32::from(offset & 0xfc);
        // SAFETY: as for read_u32; callers write only registers they own.
        unsafe {
            outl(CONFIG_ADDRESS, address);
            outl(CONFIG_DATA, value);
        }
    }

    /// Returns the physical address of a memory BAR, combining 64-bit pairs.
    pub(crate) fn memory_bar(self, index: u8) -> Option<u64> {
        let offset = 0x10 + index * 4;
        let low = self.read_u32(offset);
        if low & 1 != 0 {
            return None;
        }
        let base = u64::from(low & !0xf);
        let address = if (low >> 1) & 3 == 2 {
            base | u64::from(self.read_u32(offset + 4)) << 32
        } else {
            base
        };
        (address != 0).then_some(address)
    }

    /// Enables memory decoding only, for drivers that just read registers.
    pub(crate) fn enable_memory(self) {
        let command = self.read_u32(COMMAND);
        self.write_u32(COMMAND, (command | u32::from(COMMAND_MEMORY)) & 0xffff);
    }

    /// Enables memory decoding and bus mastering, and masks legacy INTx,
    /// because these drivers poll.
    pub(crate) fn enable_memory_and_bus_master(self) {
        let command = self.read_u32(COMMAND);
        let value =
            command | u32::from(COMMAND_MEMORY | COMMAND_BUS_MASTER | COMMAND_INTERRUPT_DISABLE);
        // The upper half is the status register, whose bits are write-one-to-clear.
        self.write_u32(COMMAND, value & 0xffff);
    }
}

impl Identity {
    fn read(address: Function) -> Option<Self> {
        let id = address.read_u32(0x00);
        if id & 0xffff == 0xffff {
            return None;
        }
        let class = address.read_u32(0x08);
        Some(Self {
            address,
            vendor: id as u16,
            device: (id >> 16) as u16,
            class: (class >> 24) as u8,
            subclass: (class >> 16) as u8,
            interface: (class >> 8) as u8,
        })
    }

    pub(crate) fn class_name(&self) -> &'static str {
        match (self.class, self.subclass, self.interface) {
            (0x01, 0x01, _) => "IDE controller",
            (0x01, 0x06, 0x01) => "SATA controller (AHCI)",
            (0x01, 0x06, _) => "SATA controller",
            (0x01, 0x08, 0x02) => "NVMe controller",
            (0x01, _, _) => "storage controller",
            (0x02, 0x00, _) => "Ethernet controller",
            (0x02, 0x80, _) => "network controller",
            (0x02, _, _) => "network controller",
            (0x03, 0x00, _) => "VGA display controller",
            (0x03, _, _) => "display controller",
            (0x04, 0x03, _) => "HD audio controller",
            (0x04, _, _) => "multimedia controller",
            (0x06, 0x00, _) => "host bridge",
            (0x06, 0x01, _) => "ISA bridge",
            (0x06, 0x04, _) => "PCI bridge",
            (0x06, _, _) => "bridge",
            (0x08, 0x06, _) => "IOMMU",
            (0x08, _, _) => "system peripheral",
            (0x0c, 0x03, 0x30) => "USB controller (xHCI)",
            (0x0c, 0x03, 0x20) => "USB controller (EHCI)",
            (0x0c, 0x03, _) => "USB controller",
            (0x0c, 0x05, _) => "SMBus controller",
            (0x0c, _, _) => "serial bus controller",
            (0x10, _, _) => "encryption controller",
            (0x11, _, _) => "signal processing controller",
            (0x13, _, _) => "non-essential instrumentation",
            _ => "other device",
        }
    }

    pub(crate) fn is_ahci(&self) -> bool {
        (self.class, self.subclass, self.interface) == (0x01, 0x06, 0x01)
    }

    pub(crate) fn is_xhci(&self) -> bool {
        (self.class, self.subclass, self.interface) == (0x0c, 0x03, 0x30)
    }

    pub(crate) fn is_nvme(&self) -> bool {
        (self.class, self.subclass, self.interface) == (0x01, 0x08, 0x02)
    }
}

/// Calls `visit` for every present PCI function on every bus.
pub(crate) fn for_each_function(mut visit: impl FnMut(Identity)) {
    for bus in 0..=255_u8 {
        for device in 0..32_u8 {
            let first = Function {
                bus,
                device,
                function: 0,
            };
            let Some(identity) = Identity::read(first) else {
                continue;
            };
            let multifunction = first.read_u32(0x0c) & (0x80 << 16) != 0;
            visit(identity);
            if multifunction {
                for function in 1..8_u8 {
                    if let Some(identity) = Identity::read(Function {
                        bus,
                        device,
                        function,
                    }) {
                        visit(identity);
                    }
                }
            }
        }
    }
}

unsafe fn outl(port: u16, value: u32) {
    asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
}

unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags));
    value
}
