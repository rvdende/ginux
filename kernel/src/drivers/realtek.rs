//! Identification of Realtek RTL8125 and RTL8168-family Ethernet controllers.
//!
//! This only reads registers: the MAC address, the chip identifier, and the
//! PHY link state. Packet transmit and receive are not implemented yet.

use super::pci::{Function, Identity};

const VENDOR_REALTEK: u16 = 0x10ec;
const MAC_ADDRESS: usize = 0x00;
const TRANSMIT_CONFIG: usize = 0x40;
const PHY_STATUS: usize = 0x6c;
const PHY_FULL_DUPLEX: u16 = 0x0001;
const PHY_LINK: u16 = 0x0002;
const PHY_10_MBPS: u16 = 0x0004;
const PHY_100_MBPS: u16 = 0x0008;
const PHY_1000_MBPS: u16 = 0x0010;
const PHY_2500_MBPS: u16 = 0x0400;

/// What the controller reports about itself and its link.
pub(crate) struct Report {
    pub(crate) mac: [u8; 6],
    /// The chip identifier, bits 30:20 of TxConfig as r8169 masks them.
    pub(crate) chip: u32,
    /// Link speed in Mb/s, or `None` without a link.
    pub(crate) speed: Option<u32>,
    pub(crate) full_duplex: bool,
}

/// Returns whether `device` is an RTL8125 or RTL8168-family controller.
pub(crate) fn is_supported(device: &Identity) -> bool {
    device.vendor == VENDOR_REALTEK && matches!(device.device, 0x8125 | 0x8126 | 0x8161 | 0x8168)
}

/// Reads the identity and link state of a supported controller.
///
/// # Safety
///
/// `function` must be a supported controller whose memory BAR is identity
/// mapped. Reading these registers has no side effects.
pub(crate) unsafe fn probe(function: Function) -> Option<Report> {
    // BAR 0 is I/O space on these chips; the registers are mirrored in BAR 2.
    let base = function.memory_bar(2)? as usize;
    function.enable_memory();
    let byte = |offset: usize| ((base + offset) as *const u8).read_volatile();
    let mut mac = [0_u8; 6];
    for (index, value) in mac.iter_mut().enumerate() {
        *value = byte(MAC_ADDRESS + index);
    }
    let transmit = ((base + TRANSMIT_CONFIG) as *const u32).read_volatile();
    let phy = ((base + PHY_STATUS) as *const u16).read_volatile();
    let speed = (phy & PHY_LINK != 0).then(|| {
        if phy & PHY_2500_MBPS != 0 {
            2500
        } else if phy & PHY_1000_MBPS != 0 {
            1000
        } else if phy & PHY_100_MBPS != 0 {
            100
        } else if phy & PHY_10_MBPS != 0 {
            10
        } else {
            0
        }
    });
    Some(Report {
        mac,
        chip: (transmit >> 20) & 0x7cf,
        speed,
        full_duplex: phy & PHY_FULL_DUPLEX != 0,
    })
}
