use core::{
    ptr::{read_volatile, write_volatile},
    sync::atomic::{fence, Ordering},
};

use crate::memory::{self, FrameLease, FrameOwner};

use super::paging::MmioMapping;

const VERSION_OFFSET: u64 = 0x00;
const CAPABILITY_OFFSET: u64 = 0x08;
const EXTENDED_CAPABILITY_OFFSET: u64 = 0x10;
const GLOBAL_STATUS_OFFSET: u64 = 0x1c;
const ROOT_TABLE_ADDRESS_OFFSET: u64 = 0x20;
const GLOBAL_COMMAND_OFFSET: u64 = 0x18;
const CONTEXT_COMMAND_OFFSET: u64 = 0x28;
const FAULT_STATUS_OFFSET: u64 = 0x34;
const CAPABILITY_FAULT_RECORD_OFFSET_SHIFT: u64 = 24;
const CAPABILITY_FAULT_RECORD_OFFSET_MASK: u64 = 0x3ff;
const CAPABILITY_FAULT_RECORD_COUNT_SHIFT: u64 = 40;
const CAPABILITY_FAULT_RECORD_COUNT_MASK: u64 = 0xff;
const FAULT_RECORD_STRIDE: u64 = 16;
const FAULT_RECORD_HIGH_DELTA: u64 = 8;
const PRIMARY_PENDING_FAULT: u32 = 1 << 1;
const FAULT_RECORD_VALID: u64 = 1 << 63;
const FAULT_RECORD_TRANSACTION_READ: u64 = 1 << 62;
const FAULT_RECORD_REASON_SHIFT: u64 = 32;
const FAULT_RECORD_REASON_MASK: u64 = 0xff;
const FAULT_RECORD_PASID_SHIFT: u64 = 40;
const FAULT_RECORD_NO_PASID: u64 = 0xffff;
const FAULT_RECORD_SOURCE_MASK: u64 = 0xffff;
const FAULT_INFORMATION_MASK: u64 = !0xfff;
const WRITE_PERMISSION_FAULT: u64 = 5;
const TRANSLATION_ENABLE_STATUS: u32 = 1 << 31;
const SET_ROOT_TABLE_POINTER: u32 = 1 << 30;
const ROOT_TABLE_POINTER_STATUS: u32 = 1 << 30;
const CONTEXT_INVALIDATE: u64 = 1 << 63;
const CONTEXT_GLOBAL_INVALIDATE: u64 = 1 << 61;
const IOTLB_INVALIDATE: u64 = 1 << 63;
const IOTLB_GLOBAL_INVALIDATE: u64 = 1 << 60;
const IOTLB_OFFSET_SHIFT: u64 = 8;
const IOTLB_OFFSET_MASK: u64 = 0x3ff;
const IOTLB_INVALIDATE_REGISTER_DELTA: u64 = 8;
const FAULT_STATUS_MASK: u32 = 0x73;
const STATUS_WAIT_LIMIT: usize = 1_000_000;
const SUPPORTED_ADDRESS_WIDTHS_SHIFT: u64 = 8;
const SUPPORTED_ADDRESS_WIDTHS_MASK: u64 = 0x1f;
const SUPPORTED_48_BIT_WIDTH: u64 = 1 << 2;
const PAGE_SIZE: u64 = 4096;
const TABLE_ENTRIES: usize = 512;
const TRANSLATION_FRAME_COUNT: usize = 6;
const ROOT_FRAME: usize = 0;
const CONTEXT_FRAME: usize = 1;
const PML4_FRAME: usize = 2;
const PDPT_FRAME: usize = 3;
const PAGE_DIRECTORY_FRAME: usize = 4;
const PAGE_TABLE_FRAME: usize = 5;
const PRESENT: u64 = 1;
const READ_WRITE: u64 = 3;
const ADDRESS_MASK_48: u64 = 0x0000_ffff_ffff_f000;
const CONTEXT_ADDRESS_WIDTH_48: u64 = 2;
const DOMAIN_ID: u16 = 1;
/// The domain of the standing devices' shared second-level table.
const STANDING_DOMAIN_ID: u16 = 2;
/// Functions that may hold a standing admission.
const STANDING_DEVICE_LIMIT: usize = 4;
/// Second-level table frames for the standing devices' DMA regions.
const STANDING_TABLE_LIMIT: usize = 16;
/// Root or context words a translation adds for the standing devices.
const STANDING_WORD_LIMIT: usize = 2 * STANDING_DEVICE_LIMIT;

/// Devices outside any one driver's translation that every translation
/// still admits, because they do DMA whenever they like: USB host
/// controllers, for instance, complete input transfers while a network or
/// volume translation is active. They share one second-level table that
/// maps only their DMA regions, at their physical addresses.
struct StandingDevices {
    /// Bus and device-function number of each admitted function.
    functions: [Option<(u8, usize)>; STANDING_DEVICE_LIMIT],
    /// One context table per bus with admitted functions, used by
    /// translations for devices on other buses.
    contexts: [Option<(u8, FrameLease)>; STANDING_DEVICE_LIMIT],
    /// The second-level table: its root first, then lower levels.
    tables: [FrameLease; STANDING_TABLE_LIMIT],
    table_count: usize,
}

/// Set once, while translation is off, and read by every later translation.
static mut STANDING: Option<StandingDevices> = None;

/// Table words that a translation adds for the standing devices.
#[derive(Clone, Copy)]
struct StandingWords {
    words: [(usize, u64); STANDING_WORD_LIMIT],
    count: usize,
}

impl StandingWords {
    const EMPTY: Self = Self {
        words: [(0, 0); STANDING_WORD_LIMIT],
        count: 0,
    };

    fn push(&mut self, index: usize, value: u64) {
        if let Some(word) = self.words.get_mut(self.count) {
            *word = (index, value);
            self.count += 1;
        }
    }

    fn as_slice(&self) -> &[(usize, u64)] {
        &self.words[..self.count]
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Capabilities {
    pub(crate) major_version: u8,
    pub(crate) minor_version: u8,
    pub(crate) capability: u64,
    pub(crate) extended_capability: u64,
}

pub(crate) struct InactiveTranslation {
    frames: [FrameLease; TRANSLATION_FRAME_COUNT],
    bus: u8,
    device: u8,
    function: u8,
    dma_page: u64,
}

pub(crate) struct ActiveTranslation {
    register_base: u64,
    mapping: MmioMapping,
    root_table_address: u64,
    iotlb_register: u64,
    fault_record_register: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct DeviceTranslationProfile {
    register_base: u64,
    mapping: MmioMapping,
    capabilities: Capabilities,
    bus: u8,
    device: u8,
    function: u8,
}

pub(crate) struct DeviceTranslation {
    inactive: InactiveTranslation,
    active: ActiveTranslation,
    evidence: TranslationEvidence,
}

#[derive(Clone, Copy)]
pub(crate) struct TranslationEvidence {
    table_frames: [FrameLease; TRANSLATION_FRAME_COUNT],
    dma_frame: FrameLease,
}

impl DeviceTranslationProfile {
    pub(crate) fn new(
        register_base: u64,
        mapping: MmioMapping,
        capabilities: Capabilities,
        bus: u8,
        device: u8,
        function: u8,
    ) -> Option<Self> {
        if device >= 32
            || function >= 8
            || !probe(register_base, mapping).is_some_and(|current| {
                current.capability == capabilities.capability
                    && current.extended_capability == capabilities.extended_capability
            })
        {
            return None;
        }
        Some(Self {
            register_base,
            mapping,
            capabilities,
            bus,
            device,
            function,
        })
    }

    pub(crate) fn matches_source(self, bus: u8, device: u8, function: u8) -> bool {
        self.bus == bus && self.device == device && self.function == function
    }

    pub(crate) fn activate(self, dma_frame: FrameLease) -> Option<DeviceTranslation> {
        let inactive = build_inactive_translation(
            self.capabilities,
            self.bus,
            self.device,
            self.function,
            dma_frame,
        )?;
        let evidence = TranslationEvidence {
            table_frames: inactive.frames,
            dma_frame,
        };
        let Some(active) = activate_translation(
            self.register_base,
            self.mapping,
            self.capabilities,
            &inactive,
            dma_frame,
        ) else {
            let _ = inactive.retire();
            return None;
        };
        Some(DeviceTranslation {
            inactive,
            active,
            evidence,
        })
    }

    pub(crate) fn is_inactive(self) -> bool {
        probe(self.register_base, self.mapping).is_some_and(|current| {
            current.capability == self.capabilities.capability
                && current.extended_capability == self.capabilities.extended_capability
        })
    }
}

impl DeviceTranslation {
    pub(crate) fn is_active(&self) -> bool {
        self.active.is_active()
            && self.inactive.is_exact(self.evidence.dma_frame)
            && memory::frames_owned_by(FrameOwner::KERNEL, &self.evidence.table_frames)
    }

    pub(crate) fn evidence(&self) -> TranslationEvidence {
        self.evidence
    }

    pub(crate) fn finish(self) -> bool {
        self.active.finish()
            && self.inactive.retire()
            && !memory::any_frame_lease_live(&self.evidence.table_frames)
    }
}

impl TranslationEvidence {
    pub(crate) fn is_retired(self) -> bool {
        !memory::any_frame_lease_live(&self.table_frames)
            && !memory::any_frame_lease_live(&[self.dma_frame])
    }

    pub(crate) fn is_fresh_after(self, prior: Self) -> bool {
        self.dma_frame != prior.dma_frame
            && self.table_frames.iter().all(|current| {
                prior
                    .table_frames
                    .iter()
                    .all(|previous| current != previous)
            })
    }
}

impl InactiveTranslation {
    pub(crate) fn root_table_address(&self) -> u64 {
        self.frames[ROOT_FRAME].address()
    }

    pub(crate) fn is_exact(&self, dma_frame: FrameLease) -> bool {
        if dma_frame.address() != self.dma_page
            || !memory::frames_owned_by(FrameOwner::KERNEL, &self.frames)
        {
            return false;
        }
        let devfn = usize::from(self.device) * 8 + usize::from(self.function);
        let indices = translation_indices(self.dma_page);
        let (standing_root, standing_context) = standing_words(self.bus, devfn);
        let mut root = [(0, 0); 1 + STANDING_WORD_LIMIT];
        root[0] = (
            usize::from(self.bus) * 2,
            self.frames[CONTEXT_FRAME].address() | PRESENT,
        );
        root[1..1 + standing_root.count].copy_from_slice(standing_root.as_slice());
        let mut context = [(0, 0); 2 + STANDING_WORD_LIMIT];
        context[0] = (devfn * 2, self.frames[PML4_FRAME].address() | PRESENT);
        context[1] = (
            devfn * 2 + 1,
            (u64::from(DOMAIN_ID) << 8) | CONTEXT_ADDRESS_WIDTH_48,
        );
        context[2..2 + standing_context.count].copy_from_slice(standing_context.as_slice());
        frame_words_are_exact(self.frames[ROOT_FRAME], &root[..1 + standing_root.count])
            && frame_words_are_exact(
                self.frames[CONTEXT_FRAME],
                &context[..2 + standing_context.count],
            )
            && frame_words_are_exact(
                self.frames[PML4_FRAME],
                &[(indices[0], self.frames[PDPT_FRAME].address() | READ_WRITE)],
            )
            && frame_words_are_exact(
                self.frames[PDPT_FRAME],
                &[(
                    indices[1],
                    self.frames[PAGE_DIRECTORY_FRAME].address() | READ_WRITE,
                )],
            )
            && frame_words_are_exact(
                self.frames[PAGE_DIRECTORY_FRAME],
                &[(
                    indices[2],
                    self.frames[PAGE_TABLE_FRAME].address() | READ_WRITE,
                )],
            )
            && frame_words_are_exact(
                self.frames[PAGE_TABLE_FRAME],
                &[(indices[3], self.dma_page | READ_WRITE)],
            )
    }

    pub(crate) fn evidence(&self, dma_frame: FrameLease) -> Option<TranslationEvidence> {
        self.is_exact(dma_frame).then_some(TranslationEvidence {
            table_frames: self.frames,
            dma_frame,
        })
    }

    pub(crate) fn retire(self) -> bool {
        memory::scrub_and_release_frames(FrameOwner::KERNEL, &self.frames)
            && !memory::any_frame_lease_live(&self.frames)
    }
}

impl ActiveTranslation {
    pub(crate) fn is_active(&self) -> bool {
        read_u32(self.mapping, self.register_base + GLOBAL_STATUS_OFFSET)
            .is_some_and(|status| status & TRANSLATION_ENABLE_STATUS != 0)
            && read_u64(self.mapping, self.register_base + ROOT_TABLE_ADDRESS_OFFSET)
                == Some(self.root_table_address)
            && fault_status_is_clear(self.mapping, self.register_base)
    }

    /// Validates and retires the one expected Q35 write fault while keeping
    /// translation active for a subsequent recovery transaction.
    pub(crate) fn recover_expected_write_fault(
        &self,
        bus: u8,
        device: u8,
        function: u8,
        fault_address: u64,
    ) -> bool {
        if device >= 32 || function >= 8 || !fault_address.is_multiple_of(PAGE_SIZE) {
            return false;
        }
        let Some(status) = read_u32(self.mapping, self.register_base + FAULT_STATUS_OFFSET) else {
            return false;
        };
        let Some(low) = read_u64(self.mapping, self.fault_record_register) else {
            return false;
        };
        let Some(high) = read_u64(
            self.mapping,
            self.fault_record_register + FAULT_RECORD_HIGH_DELTA,
        ) else {
            return false;
        };
        let source = (u64::from(bus) << 8) | (u64::from(device) << 3) | u64::from(function);
        let expected_high = FAULT_RECORD_VALID
            | (FAULT_RECORD_NO_PASID << FAULT_RECORD_PASID_SHIFT)
            | (WRITE_PERMISSION_FAULT << FAULT_RECORD_REASON_SHIFT)
            | source;
        if status & FAULT_STATUS_MASK != PRIMARY_PENDING_FAULT
            || low & FAULT_INFORMATION_MASK != fault_address
            || high != expected_high
            || high & FAULT_RECORD_TRANSACTION_READ != 0
            || high >> FAULT_RECORD_REASON_SHIFT & FAULT_RECORD_REASON_MASK
                != WRITE_PERMISSION_FAULT
            || high & FAULT_RECORD_SOURCE_MASK != source
            || read_u32(self.mapping, self.register_base + GLOBAL_STATUS_OFFSET)
                .is_none_or(|global| global & TRANSLATION_ENABLE_STATUS == 0)
            || read_u64(self.mapping, self.register_base + ROOT_TABLE_ADDRESS_OFFSET)
                != Some(self.root_table_address)
        {
            return false;
        }

        write_u64(
            self.mapping,
            self.fault_record_register + FAULT_RECORD_HIGH_DELTA,
            FAULT_RECORD_VALID,
        ) && fault_status_is_clear(self.mapping, self.register_base)
            && read_u64(
                self.mapping,
                self.fault_record_register + FAULT_RECORD_HIGH_DELTA,
            ) == Some(expected_high & !FAULT_RECORD_VALID)
            && invalidate_caches(self.mapping, self.register_base, self.iotlb_register)
            && self.is_active()
    }

    pub(crate) fn finish(self) -> bool {
        if !self.is_active()
            || !write_u32(self.mapping, self.register_base + GLOBAL_COMMAND_OFFSET, 0)
            || !wait_status(
                self.mapping,
                self.register_base,
                TRANSLATION_ENABLE_STATUS,
                false,
            )
            || !invalidate_caches(self.mapping, self.register_base, self.iotlb_register)
            || !write_u64(
                self.mapping,
                self.register_base + ROOT_TABLE_ADDRESS_OFFSET,
                0,
            )
            || !write_u32(
                self.mapping,
                self.register_base + GLOBAL_COMMAND_OFFSET,
                SET_ROOT_TABLE_POINTER,
            )
            || !wait_status(
                self.mapping,
                self.register_base,
                ROOT_TABLE_POINTER_STATUS,
                true,
            )
        {
            return false;
        }
        read_u64(self.mapping, self.register_base + ROOT_TABLE_ADDRESS_OFFSET) == Some(0)
            && fault_status_is_clear(self.mapping, self.register_base)
    }
}

pub(crate) fn probe(register_base: u64, mapping: MmioMapping) -> Option<Capabilities> {
    let version = read_u32(mapping, register_base.checked_add(VERSION_OFFSET)?)?;
    let capability = read_u64(mapping, register_base.checked_add(CAPABILITY_OFFSET)?)?;
    let extended_capability = read_u64(
        mapping,
        register_base.checked_add(EXTENDED_CAPABILITY_OFFSET)?,
    )?;
    let global_status = read_u32(mapping, register_base.checked_add(GLOBAL_STATUS_OFFSET)?)?;
    let root_table_address = read_u64(
        mapping,
        register_base.checked_add(ROOT_TABLE_ADDRESS_OFFSET)?,
    )?;
    let major_version = ((version >> 4) & 0x0f) as u8;
    let minor_version = (version & 0x0f) as u8;
    if major_version == 0
        || capability == 0
        || capability >> SUPPORTED_ADDRESS_WIDTHS_SHIFT & SUPPORTED_ADDRESS_WIDTHS_MASK == 0
        || global_status & TRANSLATION_ENABLE_STATUS != 0
        || root_table_address != 0
    {
        return None;
    }
    Some(Capabilities {
        major_version,
        minor_version,
        capability,
        extended_capability,
    })
}

pub(crate) fn build_inactive_translation(
    capabilities: Capabilities,
    bus: u8,
    device: u8,
    function: u8,
    dma_frame: FrameLease,
) -> Option<InactiveTranslation> {
    if capabilities.capability >> SUPPORTED_ADDRESS_WIDTHS_SHIFT
        & SUPPORTED_ADDRESS_WIDTHS_MASK
        & SUPPORTED_48_BIT_WIDTH
        == 0
        || device >= 32
        || function >= 8
        || !page_fits_48_bits(dma_frame.address())
    {
        return None;
    }
    let frames = memory::allocate_frames::<TRANSLATION_FRAME_COUNT>(FrameOwner::KERNEL)?;
    if frames
        .iter()
        .any(|frame| !page_fits_48_bits(frame.address()))
    {
        let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &frames);
        return None;
    }
    let translation = InactiveTranslation {
        frames,
        bus,
        device,
        function,
        dma_page: dma_frame.address(),
    };
    let devfn = usize::from(device) * 8 + usize::from(function);
    let indices = translation_indices(dma_frame.address());
    let initialized = write_word(
        frames[ROOT_FRAME],
        usize::from(bus) * 2,
        frames[CONTEXT_FRAME].address() | PRESENT,
    ) && write_word(
        frames[CONTEXT_FRAME],
        devfn * 2,
        frames[PML4_FRAME].address() | PRESENT,
    ) && write_word(
        frames[CONTEXT_FRAME],
        devfn * 2 + 1,
        (u64::from(DOMAIN_ID) << 8) | CONTEXT_ADDRESS_WIDTH_48,
    ) && write_word(
        frames[PML4_FRAME],
        indices[0],
        frames[PDPT_FRAME].address() | READ_WRITE,
    ) && write_word(
        frames[PDPT_FRAME],
        indices[1],
        frames[PAGE_DIRECTORY_FRAME].address() | READ_WRITE,
    ) && write_word(
        frames[PAGE_DIRECTORY_FRAME],
        indices[2],
        frames[PAGE_TABLE_FRAME].address() | READ_WRITE,
    ) && write_word(
        frames[PAGE_TABLE_FRAME],
        indices[3],
        dma_frame.address() | READ_WRITE,
    );
    let (root_words, context_words) = standing_words(bus, devfn);
    let initialized = initialized
        && root_words
            .as_slice()
            .iter()
            .all(|(index, value)| write_word(frames[ROOT_FRAME], *index, *value))
        && context_words
            .as_slice()
            .iter()
            .all(|(index, value)| write_word(frames[CONTEXT_FRAME], *index, *value));
    if !initialized || !translation.is_exact(dma_frame) {
        let _ = translation.retire();
        return None;
    }
    Some(translation)
}

pub(crate) fn activate_translation(
    register_base: u64,
    mapping: MmioMapping,
    capabilities: Capabilities,
    translation: &InactiveTranslation,
    dma_frame: FrameLease,
) -> Option<ActiveTranslation> {
    let iotlb_register = register_base.checked_add(
        ((capabilities.extended_capability >> IOTLB_OFFSET_SHIFT) & IOTLB_OFFSET_MASK)
            .checked_mul(16)?
            .checked_add(IOTLB_INVALIDATE_REGISTER_DELTA)?,
    )?;
    let fault_record_count = ((capabilities.capability >> CAPABILITY_FAULT_RECORD_COUNT_SHIFT)
        & CAPABILITY_FAULT_RECORD_COUNT_MASK)
        + 1;
    let fault_record_register = register_base.checked_add(
        ((capabilities.capability >> CAPABILITY_FAULT_RECORD_OFFSET_SHIFT)
            & CAPABILITY_FAULT_RECORD_OFFSET_MASK)
            .checked_mul(FAULT_RECORD_STRIDE)?,
    )?;
    if !translation.is_exact(dma_frame)
        || fault_record_count != 1
        || mapping.address(iotlb_register, size_of::<u64>()).is_none()
        || mapping
            .address(fault_record_register, FAULT_RECORD_STRIDE as usize)
            .is_none()
        || !probe(register_base, mapping).is_some_and(|current| {
            current.capability == capabilities.capability
                && current.extended_capability == capabilities.extended_capability
        })
        || !fault_status_is_clear(mapping, register_base)
    {
        return None;
    }
    fence(Ordering::SeqCst);
    let root_table_address = translation.root_table_address();
    let installed = write_u64(
        mapping,
        register_base + ROOT_TABLE_ADDRESS_OFFSET,
        root_table_address,
    ) && write_u32(
        mapping,
        register_base + GLOBAL_COMMAND_OFFSET,
        SET_ROOT_TABLE_POINTER,
    ) && wait_status(mapping, register_base, ROOT_TABLE_POINTER_STATUS, true)
        && invalidate_caches(mapping, register_base, iotlb_register)
        && write_u32(
            mapping,
            register_base + GLOBAL_COMMAND_OFFSET,
            TRANSLATION_ENABLE_STATUS,
        )
        && wait_status(mapping, register_base, TRANSLATION_ENABLE_STATUS, true);
    let active = ActiveTranslation {
        register_base,
        mapping,
        root_table_address,
        iotlb_register,
        fault_record_register,
    };
    if !installed || !active.is_active() {
        rollback_activation(mapping, register_base);
        return None;
    }
    Some(active)
}

pub(crate) fn verify_inactive_translation_rejections(
    capabilities: Capabilities,
    dma_frame: FrameLease,
) -> bool {
    let mut unsupported = capabilities;
    unsupported.capability &= !(SUPPORTED_48_BIT_WIDTH << SUPPORTED_ADDRESS_WIDTHS_SHIFT);
    build_inactive_translation(unsupported, 0, 2, 0, dma_frame).is_none()
        && build_inactive_translation(capabilities, 0, 32, 0, dma_frame).is_none()
        && build_inactive_translation(capabilities, 0, 2, 8, dma_frame).is_none()
}

/// Admits `functions` (bus, device, function) to every translation built
/// from now on, each reaching exactly the pages of `regions` (start, length)
/// at their physical addresses. Translation must be off, and admission
/// happens once; on failure nothing is admitted.
pub(crate) fn admit_standing_devices(
    register_base: u64,
    mapping: MmioMapping,
    capabilities: Capabilities,
    functions: &[(u8, u8, u8)],
    regions: &[(u64, u64)],
) -> bool {
    // SAFETY: bootstrap is single-processor and translation is checked to
    // be off below, so no translation reads STANDING while it changes.
    let standing = unsafe { &mut *core::ptr::addr_of_mut!(STANDING) };
    if standing.is_some()
        || functions.is_empty()
        || functions.len() > STANDING_DEVICE_LIMIT
        || functions
            .iter()
            .any(|(_, device, function)| *device >= 32 || *function >= 8)
        || capabilities.capability >> SUPPORTED_ADDRESS_WIDTHS_SHIFT
            & SUPPORTED_ADDRESS_WIDTHS_MASK
            & SUPPORTED_48_BIT_WIDTH
            == 0
        || !probe(register_base, mapping).is_some_and(|current| {
            current.capability == capabilities.capability
                && current.extended_capability == capabilities.extended_capability
        })
    {
        return false;
    }
    let mut devices = StandingDevices {
        functions: [None; STANDING_DEVICE_LIMIT],
        contexts: [None; STANDING_DEVICE_LIMIT],
        tables: [FrameLease::EMPTY; STANDING_TABLE_LIMIT],
        table_count: 0,
    };
    if !build_standing_devices(&mut devices, functions, regions) {
        for (_, frame) in devices.contexts.iter().flatten() {
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[*frame]);
        }
        if devices.table_count != 0 {
            let _ = memory::scrub_and_release_frames(
                FrameOwner::KERNEL,
                &devices.tables[..devices.table_count],
            );
        }
        return false;
    }
    *standing = Some(devices);
    true
}

fn build_standing_devices(
    devices: &mut StandingDevices,
    functions: &[(u8, u8, u8)],
    regions: &[(u64, u64)],
) -> bool {
    let Some(root) = standing_table(devices) else {
        return false;
    };
    for &(start, length) in regions {
        let Some(end) = start.checked_add(length).filter(|_| length != 0) else {
            return false;
        };
        let mut page = start & !(PAGE_SIZE - 1);
        while page < end {
            if !page_fits_48_bits(page) || !map_standing_page(devices, root, page) {
                return false;
            }
            page += PAGE_SIZE;
        }
    }
    let [low, high] = standing_context_entry(root);
    for (slot, &(bus, device, function)) in functions.iter().enumerate() {
        let devfn = usize::from(device) * 8 + usize::from(function);
        if devices.functions[..slot].contains(&Some((bus, devfn))) {
            return false;
        }
        devices.functions[slot] = Some((bus, devfn));
        let existing = devices
            .contexts
            .iter()
            .flatten()
            .find(|(other, _)| *other == bus)
            .map(|(_, frame)| *frame);
        let context = match existing {
            Some(frame) => frame,
            None => {
                let Some(free) = devices.contexts.iter().position(Option::is_none) else {
                    return false;
                };
                let Some([frame]) = memory::allocate_frames::<1>(FrameOwner::KERNEL) else {
                    return false;
                };
                devices.contexts[free] = Some((bus, frame));
                if !page_fits_48_bits(frame.address()) {
                    return false;
                }
                frame
            }
        };
        if !write_word(context, devfn * 2, low) || !write_word(context, devfn * 2 + 1, high) {
            return false;
        }
    }
    true
}

/// The context entry that points a function at the standing devices' table.
fn standing_context_entry(root: FrameLease) -> [u64; 2] {
    [
        root.address() | PRESENT,
        (u64::from(STANDING_DOMAIN_ID) << 8) | CONTEXT_ADDRESS_WIDTH_48,
    ]
}

/// Takes a zeroed frame for the standing devices' second-level table.
fn standing_table(devices: &mut StandingDevices) -> Option<FrameLease> {
    let slot = devices.tables.get_mut(devices.table_count)?;
    let [frame] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    *slot = frame;
    devices.table_count += 1;
    page_fits_48_bits(frame.address()).then_some(frame)
}

/// Maps `page` to itself in the standing devices' table under `root`.
fn map_standing_page(devices: &mut StandingDevices, root: FrameLease, page: u64) -> bool {
    let indices = translation_indices(page);
    let mut table = root;
    for index in &indices[..3] {
        let Some(entry) = read_word(table, *index) else {
            return false;
        };
        let next = if entry & PRESENT != 0 {
            devices.tables[..devices.table_count]
                .iter()
                .copied()
                .find(|frame| frame.address() == entry & ADDRESS_MASK_48)
        } else {
            standing_table(devices)
                .filter(|next| write_word(table, *index, next.address() | READ_WRITE))
        };
        let Some(next) = next else {
            return false;
        };
        table = next;
    }
    write_word(table, indices[3], page | READ_WRITE)
}

/// The root-table and context-table words that admit the standing devices
/// into a translation for the function at `bus` and `devfn`: a root entry
/// for each other bus with standing functions, and the context entries of
/// the standing functions on the translation's own bus.
fn standing_words(bus: u8, devfn: usize) -> (StandingWords, StandingWords) {
    let (mut root, mut context) = (StandingWords::EMPTY, StandingWords::EMPTY);
    // SAFETY: STANDING changes only once, while no translation exists.
    let Some(standing) = (unsafe { (*core::ptr::addr_of!(STANDING)).as_ref() }) else {
        return (root, context);
    };
    for (other, table) in standing.contexts.iter().flatten() {
        if *other != bus {
            root.push(usize::from(*other) * 2, table.address() | PRESENT);
        }
    }
    let [low, high] = standing_context_entry(standing.tables[0]);
    for (other, other_devfn) in standing.functions.iter().flatten() {
        if *other == bus && *other_devfn != devfn {
            context.push(other_devfn * 2, low);
            context.push(other_devfn * 2 + 1, high);
        }
    }
    (root, context)
}

fn translation_indices(address: u64) -> [usize; 4] {
    [
        ((address >> 39) & 0x1ff) as usize,
        ((address >> 30) & 0x1ff) as usize,
        ((address >> 21) & 0x1ff) as usize,
        ((address >> 12) & 0x1ff) as usize,
    ]
}

fn page_fits_48_bits(address: u64) -> bool {
    address.is_multiple_of(PAGE_SIZE)
        && address
            .checked_add(PAGE_SIZE - 1)
            .is_some_and(|end| end <= ADDRESS_MASK_48 | (PAGE_SIZE - 1))
}

fn write_word(frame: FrameLease, index: usize, value: u64) -> bool {
    let Some(address) = frame.direct_map_address() else {
        return false;
    };
    if index >= TABLE_ENTRIES {
        return false;
    }
    unsafe {
        (address as *mut u64).add(index).write(value.to_le());
    }
    true
}

fn read_word(frame: FrameLease, index: usize) -> Option<u64> {
    let address = frame.direct_map_address()?;
    (index < TABLE_ENTRIES)
        .then(|| u64::from_le(unsafe { (address as *const u64).add(index).read() }))
}

fn frame_words_are_exact(frame: FrameLease, expected: &[(usize, u64)]) -> bool {
    let Some(address) = frame.direct_map_address() else {
        return false;
    };
    if expected.iter().enumerate().any(|(index, (word, _))| {
        *word >= TABLE_ENTRIES
            || expected[..index]
                .iter()
                .any(|(prior_word, _)| prior_word == word)
    }) {
        return false;
    }
    (0..TABLE_ENTRIES).all(|index| {
        let actual = u64::from_le(unsafe { (address as *const u64).add(index).read() });
        let wanted = expected
            .iter()
            .find_map(|(word, value)| (*word == index).then_some(*value))
            .unwrap_or(0);
        actual == wanted
    })
}

fn read_u32(mapping: MmioMapping, physical: u64) -> Option<u32> {
    let address = mapping.address(physical, size_of::<u32>())?;
    Some(u32::from_le(unsafe {
        read_volatile(address as *const u32)
    }))
}

fn read_u64(mapping: MmioMapping, physical: u64) -> Option<u64> {
    let address = mapping.address(physical, size_of::<u64>())?;
    Some(u64::from_le(unsafe {
        read_volatile(address as *const u64)
    }))
}

fn write_u32(mapping: MmioMapping, physical: u64, value: u32) -> bool {
    let Some(address) = mapping.address(physical, size_of::<u32>()) else {
        return false;
    };
    unsafe {
        write_volatile(address as *mut u32, value.to_le());
    }
    true
}

fn write_u64(mapping: MmioMapping, physical: u64, value: u64) -> bool {
    let Some(address) = mapping.address(physical, size_of::<u64>()) else {
        return false;
    };
    unsafe {
        write_volatile(address as *mut u64, value.to_le());
    }
    true
}

fn wait_status(mapping: MmioMapping, register_base: u64, mask: u32, set: bool) -> bool {
    (0..STATUS_WAIT_LIMIT).any(|_| {
        read_u32(mapping, register_base + GLOBAL_STATUS_OFFSET)
            .is_some_and(|status| (status & mask != 0) == set)
    })
}

fn wait_u64_clear(mapping: MmioMapping, physical: u64, mask: u64) -> bool {
    (0..STATUS_WAIT_LIMIT)
        .any(|_| read_u64(mapping, physical).is_some_and(|value| value & mask == 0))
}

fn invalidate_caches(mapping: MmioMapping, register_base: u64, iotlb_register: u64) -> bool {
    let context_command = register_base + CONTEXT_COMMAND_OFFSET;
    write_u64(
        mapping,
        context_command,
        CONTEXT_INVALIDATE | CONTEXT_GLOBAL_INVALIDATE,
    ) && wait_u64_clear(mapping, context_command, CONTEXT_INVALIDATE)
        && write_u64(
            mapping,
            iotlb_register,
            IOTLB_INVALIDATE | IOTLB_GLOBAL_INVALIDATE,
        )
        && wait_u64_clear(mapping, iotlb_register, IOTLB_INVALIDATE)
}

fn fault_status_is_clear(mapping: MmioMapping, register_base: u64) -> bool {
    read_u32(mapping, register_base + FAULT_STATUS_OFFSET)
        .is_some_and(|status| status & FAULT_STATUS_MASK == 0)
}

fn rollback_activation(mapping: MmioMapping, register_base: u64) {
    let _ = write_u32(mapping, register_base + GLOBAL_COMMAND_OFFSET, 0);
    let _ = wait_status(mapping, register_base, TRANSLATION_ENABLE_STATUS, false);
    let _ = write_u64(mapping, register_base + ROOT_TABLE_ADDRESS_OFFSET, 0);
    let _ = write_u32(
        mapping,
        register_base + GLOBAL_COMMAND_OFFSET,
        SET_ROOT_TABLE_POINTER,
    );
    let _ = wait_status(mapping, register_base, ROOT_TABLE_POINTER_STATUS, true);
}
