//! The kernel's own queues on a domain's virtio network device, which
//! smoltcp drives: one receive and one transmit buffer in a DMA page the
//! device reaches through its I/O MMU translation. Frames sent to one of the
//! interface's own addresses never reach the device; they wait in a
//! loopback queue and are received on the next pass.
//!
//! The unsafe code of the socket layer is here: volatile accesses to the DMA
//! page and the device's notification registers, which `start` vouches for.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, PacketMeta, RxToken, TxToken,
};
use smoltcp::time::Instant;
use smoltcp::wire::{
    Icmpv6Packet, Icmpv6Repr, IpProtocol, Ipv6Address, Ipv6Packet, Ipv6Repr, NdiscNeighborFlags,
    NdiscRepr, RawHardwareAddress,
};

use super::Platform;
use crate::arch::x86_64::{iommu::DeviceTranslation, pci};
use crate::memory;

const PAGE_SIZE: usize = 4096;
const QUEUE_SIZE: u16 = 8;
const RX_DESC_OFFSET: usize = 0x000;
const RX_AVAIL_OFFSET: usize = 0x080;
const RX_USED_OFFSET: usize = 0x100;
const TX_DESC_OFFSET: usize = 0x180;
const TX_AVAIL_OFFSET: usize = 0x200;
const TX_USED_OFFSET: usize = 0x280;
const RX_BUFFER_OFFSET: usize = 0x400;
const TX_BUFFER_OFFSET: usize = 0xa00;
const RX_DESCRIPTOR_LENGTH: usize = 0x5ff;
const VIRTIO_HEADER_LENGTH: usize = 12;
/// Loopback frames waiting to be received; a full queue drops frames, as a
/// busy wire would.
pub(super) const LOOPBACK_FRAME_COUNT: usize = 16;
const FRAME_SIZE: usize = 1514;

pub(super) struct VirtioNet {
    /// The DMA page's kernel address and the address the device uses.
    dma: usize,
    dma_device: u64,
    dma_frame: memory::FrameLease,
    translation: DeviceTranslation,
    rx_notify: usize,
    tx_notify: usize,
    local_address: u32,
    rx_avail: Cell<u16>,
    rx_used: Cell<u16>,
    tx_avail: Cell<u16>,
    tx_used: Cell<u16>,
    loopback: RefCell<VecDeque<Vec<u8>>>,
}

impl VirtioNet {
    /// Gives the device a DMA page, confined to it by the I/O MMU, and
    /// starts its queues, for an interface with IPv4 `local_address`.
    pub(super) fn start(platform: &Platform, local_address: u32) -> Option<Self> {
        let rx_notify = platform
            .notification
            .address(platform.initialization.receive_notification, 2)?;
        let tx_notify = platform
            .notification
            .address(platform.initialization.transmit_notification, 2)?;
        let [dma_frame] = memory::allocate_frames::<1>(memory::FrameOwner::KERNEL)?;
        let release = || memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[dma_frame]);
        let Some(dma) = dma_frame.direct_map_address() else {
            let _ = release();
            return None;
        };
        let Some(translation) = platform.iommu.activate(dma_frame) else {
            let _ = release();
            return None;
        };
        // SAFETY: the kernel owns the freshly allocated DMA page, and the
        // active translation confines the device to it; both live in the
        // returned value until `stop` resets the device.
        if !translation.is_active()
            || !unsafe {
                pci::activate_kernel_network_queues(
                    platform.device,
                    platform.common,
                    dma_frame.address(),
                    dma,
                )
            }
        {
            let _ = translation.finish();
            let _ = release();
            return None;
        }
        let device = Self {
            dma,
            dma_device: dma_frame.address(),
            dma_frame,
            translation,
            rx_notify,
            tx_notify,
            local_address,
            rx_avail: Cell::new(0),
            rx_used: Cell::new(0),
            tx_avail: Cell::new(0),
            tx_used: Cell::new(0),
            loopback: RefCell::new(VecDeque::new()),
        };
        device.post_receive();
        Some(device)
    }

    /// Resets the device and takes its DMA page back.
    pub(super) fn stop(self, platform: &Platform) -> bool {
        pci::quiesce_isolated_network(platform.device, platform.common)
            && self.translation.finish()
            && memory::scrub_and_release_frames(memory::FrameOwner::KERNEL, &[self.dma_frame])
    }

    pub(super) fn loopback_pending(&self) -> bool {
        !self.loopback.borrow().is_empty()
    }

    /// The receive queue's available and used positions, then the transmit
    /// queue's, for diagnostics.
    pub(super) fn queue_positions(&self) -> [u16; 4] {
        [
            self.rx_avail.get(),
            self.read_u16(RX_USED_OFFSET + 2),
            self.tx_avail.get(),
            self.read_u16(TX_USED_OFFSET + 2),
        ]
    }

    fn post_receive(&self) {
        self.write_u64(RX_DESC_OFFSET, self.dma_device + RX_BUFFER_OFFSET as u64);
        self.write_u32(RX_DESC_OFFSET + 8, RX_DESCRIPTOR_LENGTH as u32);
        self.write_u16(RX_DESC_OFFSET + 12, 2);
        self.write_u16(RX_DESC_OFFSET + 14, 0);
        let avail = self.rx_avail.get();
        self.write_u16(RX_AVAIL_OFFSET + 4 + usize::from(avail % QUEUE_SIZE) * 2, 0);
        self.rx_avail.set(avail.wrapping_add(1));
        compiler_fence(Ordering::SeqCst);
        self.write_u16(RX_AVAIL_OFFSET + 2, self.rx_avail.get());
        // SAFETY: start found the receive notification register in the
        // device's mapped notification window.
        unsafe { write_volatile(self.rx_notify as *mut u16, 0) };
    }

    fn post_transmit(&self, length: usize) {
        self.write_u64(TX_DESC_OFFSET, self.dma_device + TX_BUFFER_OFFSET as u64);
        self.write_u32(TX_DESC_OFFSET + 8, (length + VIRTIO_HEADER_LENGTH) as u32);
        self.write_u16(TX_DESC_OFFSET + 12, 0);
        self.write_u16(TX_DESC_OFFSET + 14, 0);
        let avail = self.tx_avail.get();
        self.write_u16(TX_AVAIL_OFFSET + 4 + usize::from(avail % QUEUE_SIZE) * 2, 0);
        self.tx_avail.set(avail.wrapping_add(1));
        compiler_fence(Ordering::SeqCst);
        self.write_u16(TX_AVAIL_OFFSET + 2, self.tx_avail.get());
        // SAFETY: as in post_receive, for the transmit register.
        unsafe { write_volatile(self.tx_notify as *mut u16, 1) };
    }

    /// Queues a copy of a frame for the interface itself.
    fn loop_back(&self, frame: &[u8]) {
        let mut queue = self.loopback.borrow_mut();
        if queue.len() == LOOPBACK_FRAME_COUNT
            || frame.len() > FRAME_SIZE
            || queue.try_reserve(1).is_err()
        {
            return;
        }
        let mut copy = Vec::new();
        if copy.try_reserve_exact(frame.len()).is_ok() {
            copy.extend_from_slice(frame);
            queue.push_back(copy);
        }
    }

    /// The address of `size` bytes at `offset` in the DMA page, which the
    /// device's buffers and rings all lie in.
    fn dma_address(&self, offset: usize, size: usize) -> usize {
        assert!(offset + size <= PAGE_SIZE);
        self.dma + offset
    }

    /// The address of a `size`-byte ring field at `offset`, which is
    /// aligned to its size.
    fn dma_field(&self, offset: usize, size: usize) -> usize {
        assert!(offset.is_multiple_of(size));
        self.dma_address(offset, size)
    }

    fn read_u16(&self, offset: usize) -> u16 {
        // SAFETY: start's DMA page stays mapped and owned while self lives.
        unsafe { read_volatile(self.dma_field(offset, 2) as *const u16) }
    }

    fn read_u32(&self, offset: usize) -> u32 {
        // SAFETY: as for read_u16.
        unsafe { read_volatile(self.dma_field(offset, 4) as *const u32) }
    }

    fn write_u16(&self, offset: usize, value: u16) {
        // SAFETY: as for read_u16.
        unsafe { write_volatile(self.dma_field(offset, 2) as *mut u16, value) };
    }

    fn write_u32(&self, offset: usize, value: u32) {
        // SAFETY: as for read_u16.
        unsafe { write_volatile(self.dma_field(offset, 4) as *mut u32, value) };
    }

    fn write_u64(&self, offset: usize, value: u64) {
        // SAFETY: as for read_u16.
        unsafe { write_volatile(self.dma_field(offset, 8) as *mut u64, value) };
    }
}

/// Whether an Ethernet frame is addressed to one of the interface's own
/// addresses: an IPv4 packet's destination or an ARP request's target, or
/// an IPv6 packet to loopback (::1).
fn frame_loops_back(frame: &[u8], local_address: u32) -> bool {
    if frame.get(12..14) == Some(&[0x86, 0xdd]) {
        return frame.get(38..54) == Some(&Ipv6Address::LOCALHOST.octets()[..]);
    }
    let target = match frame.get(12..14) {
        Some([0x08, 0x00]) => frame.get(30..34),
        Some([0x08, 0x06]) => frame.get(38..42),
        _ => None,
    };
    target
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .is_some_and(|octets| octets[0] == 127 || u32::from_be_bytes(octets) == local_address)
}

/// The answer to a neighbour solicitation for IPv6 loopback (::1): smoltcp
/// asks for ::1's link address as for any other, on a multicast group it
/// does not take for loopback, and a loopback link has no neighbours to
/// answer (Linux's lo does no neighbour discovery). The answer, a neighbour
/// advertisement of the interface's own address from ::1, is received in
/// the solicitation's place.
fn loopback_neighbor_advert(frame: &[u8]) -> Option<Vec<u8>> {
    const ETHERNET_HEADER: usize = 14;
    const IPV6_HEADER: usize = 40;
    const NEIGHBOR_SOLICITATION: u8 = 135;
    let loopback = Ipv6Address::LOCALHOST;
    let solicitation = frame.get(12..14) == Some(&[0x86, 0xdd])
        && frame.get(20) == Some(&u8::from(IpProtocol::Icmpv6))
        && frame.get(ETHERNET_HEADER + IPV6_HEADER) == Some(&NEIGHBOR_SOLICITATION)
        && frame.get(62..78) == Some(&loopback.octets()[..]);
    if !solicitation {
        return None;
    }
    let own = frame.get(6..12)?;
    let advert = Icmpv6Repr::Ndisc(NdiscRepr::NeighborAdvert {
        flags: NdiscNeighborFlags::SOLICITED | NdiscNeighborFlags::OVERRIDE,
        target_addr: loopback,
        lladdr: Some(RawHardwareAddress::from_bytes(own)),
    });
    let header = Ipv6Repr {
        src_addr: loopback,
        dst_addr: loopback,
        next_header: IpProtocol::Icmpv6,
        payload_len: advert.buffer_len(),
        hop_limit: 255,
    };
    let length = ETHERNET_HEADER + IPV6_HEADER + advert.buffer_len();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).ok()?;
    bytes.resize(length, 0);
    bytes[..6].copy_from_slice(own);
    bytes[6..12].copy_from_slice(own);
    bytes[12..14].copy_from_slice(&[0x86, 0xdd]);
    let (ip, message) = bytes[ETHERNET_HEADER..].split_at_mut(IPV6_HEADER);
    header.emit(&mut Ipv6Packet::new_unchecked(ip));
    advert.emit(
        &loopback,
        &loopback,
        &mut Icmpv6Packet::new_unchecked(message),
        &ChecksumCapabilities::default(),
    );
    Some(bytes)
}

/// A received frame: in the receive buffer (its length), or the first
/// loopback frame.
pub(super) struct ReceiveToken<'a> {
    device: &'a VirtioNet,
    length: Option<usize>,
}

pub(super) struct TransmitToken<'a>(&'a VirtioNet);

impl RxToken for ReceiveToken<'_> {
    fn consume<R, F>(self, callback: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        let device = self.device;
        let Some(length) = self.length else {
            let frame = device.loopback.borrow_mut().pop_front().unwrap_or_default();
            return callback(&frame);
        };
        let start = device.dma_address(RX_BUFFER_OFFSET + VIRTIO_HEADER_LENGTH, length);
        // SAFETY: the device wrote this frame into the receive buffer and
        // leaves the buffer alone until post_receive hands it back below.
        let bytes = unsafe { core::slice::from_raw_parts(start as *const u8, length) };
        let result = callback(bytes);
        device.rx_used.set(device.rx_used.get().wrapping_add(1));
        device.post_receive();
        result
    }

    fn meta(&self) -> PacketMeta {
        PacketMeta::default()
    }
}

impl TxToken for TransmitToken<'_> {
    fn consume<R, F>(self, length: usize, callback: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let device = self.0;
        let length = length.min(PAGE_SIZE - TX_BUFFER_OFFSET - VIRTIO_HEADER_LENGTH);
        let start = device.dma_address(TX_BUFFER_OFFSET, VIRTIO_HEADER_LENGTH + length);
        // SAFETY: the device has used every frame posted before (transmit
        // hands out a token only then), so the transmit buffer is the
        // driver's until post_transmit below.
        let buffer = unsafe {
            core::slice::from_raw_parts_mut(start as *mut u8, VIRTIO_HEADER_LENGTH + length)
        };
        let (header, frame) = buffer.split_at_mut(VIRTIO_HEADER_LENGTH);
        header.fill(0);
        let result = callback(frame);
        if let Some(advert) = loopback_neighbor_advert(frame) {
            device.loop_back(&advert);
        } else if frame_loops_back(frame, device.local_address) {
            device.loop_back(frame);
        } else {
            device.post_transmit(length);
        }
        result
    }
}

impl Device for VirtioNet {
    type RxToken<'a>
        = ReceiveToken<'a>
    where
        Self: 'a;
    type TxToken<'a>
        = TransmitToken<'a>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let device: &Self = self;
        if device.loopback_pending() {
            return Some((
                ReceiveToken {
                    device,
                    length: None,
                },
                TransmitToken(device),
            ));
        }
        let used = device.read_u16(RX_USED_OFFSET + 2);
        if used == device.rx_used.get() {
            return None;
        }
        let element = RX_USED_OFFSET + 4 + usize::from(device.rx_used.get() % QUEUE_SIZE) * 8;
        let length = (device.read_u32(element + 4) as usize)
            .checked_sub(VIRTIO_HEADER_LENGTH)?
            .min(RX_DESCRIPTOR_LENGTH - VIRTIO_HEADER_LENGTH);
        Some((
            ReceiveToken {
                device,
                length: Some(length),
            },
            TransmitToken(device),
        ))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let used = self.read_u16(TX_USED_OFFSET + 2);
        self.tx_used.set(used);
        (self.tx_used.get() == self.tx_avail.get()).then_some(TransmitToken(self))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut capabilities = DeviceCapabilities::default();
        capabilities.medium = Medium::Ethernet;
        capabilities.max_transmission_unit = FRAME_SIZE;
        capabilities
    }
}
