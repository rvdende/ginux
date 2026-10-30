//! Read-only report of an AMD I/O MMU (AMD-Vi) found through ACPI IVRS.
//!
//! Full DMA remapping is not implemented yet; this reads the control and
//! extended-feature registers so bring-up can show what the platform offers.

const CONTROL: usize = 0x18;
const EXTENDED_FEATURES: usize = 0x30;
const STATUS: usize = 0x2020;
const CONTROL_ENABLE: u64 = 1 << 0;
const FEATURE_PREFETCH: u64 = 1 << 0;
const FEATURE_PPR: u64 = 1 << 1;
const FEATURE_X2APIC: u64 = 1 << 2;
const FEATURE_NX: u64 = 1 << 3;
const FEATURE_GUEST_TRANSLATION: u64 = 1 << 4;
const FEATURE_INVALIDATE_ALL: u64 = 1 << 6;
const FEATURE_GUEST_APIC: u64 = 1 << 7;
const FEATURE_PERFORMANCE_COUNTERS: u64 = 1 << 9;

/// What one AMD-Vi unit reports.
pub(crate) struct Report {
    pub(crate) enabled: bool,
    pub(crate) features: u64,
    pub(crate) status: u64,
}

impl Report {
    /// Writes the names of notable supported features.
    pub(crate) fn write_features(&self, output: &mut impl core::fmt::Write) -> core::fmt::Result {
        const NAMES: [(u64, &str); 8] = [
            (FEATURE_PREFETCH, "prefetch"),
            (FEATURE_PPR, "ppr"),
            (FEATURE_X2APIC, "x2apic"),
            (FEATURE_NX, "nx"),
            (FEATURE_GUEST_TRANSLATION, "guest-translation"),
            (FEATURE_INVALIDATE_ALL, "invalidate-all"),
            (FEATURE_GUEST_APIC, "guest-apic"),
            (FEATURE_PERFORMANCE_COUNTERS, "perf-counters"),
        ];
        let mut first = true;
        for (bit, name) in NAMES {
            if self.features & bit != 0 {
                if !first {
                    output.write_char(' ')?;
                }
                output.write_str(name)?;
                first = false;
            }
        }
        if first {
            output.write_str("none")?;
        }
        Ok(())
    }
}

/// Reads the registers of the unit at physical address `base`.
///
/// # Safety
///
/// `base` must be an AMD-Vi MMIO block from IVRS that is identity mapped.
/// Reading these registers has no side effects.
pub(crate) unsafe fn probe(base: u64) -> Report {
    let read64 = |offset: usize| ((base as usize + offset) as *const u64).read_volatile();
    Report {
        enabled: read64(CONTROL) & CONTROL_ENABLE != 0,
        features: read64(EXTENDED_FEATURES),
        status: read64(STATUS),
    }
}
