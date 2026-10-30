//! GUID partition table parsing.

use core::fmt;

pub(crate) const HEADER_LBA: u64 = 1;
const SIGNATURE: &[u8; 8] = b"EFI PART";
const MINIMUM_HEADER_SIZE: usize = 92;
const MINIMUM_ENTRY_SIZE: usize = 128;
const NAME_OFFSET: usize = 56;
const NAME_UNITS: usize = 36;

/// A GUID in its on-disk (mixed-endian) byte order.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Guid(pub(crate) [u8; 16]);

impl Guid {
    /// Builds a GUID from its textual fields, as in
    /// `80769f29-5413-45a3-abab-5b44b6125922`.
    pub(crate) const fn new(first: u32, second: u16, third: u16, rest: [u8; 8]) -> Self {
        let a = first.to_le_bytes();
        let b = second.to_le_bytes();
        let c = third.to_le_bytes();
        Self([
            a[0], a[1], a[2], a[3], b[0], b[1], c[0], c[1], rest[0], rest[1], rest[2], rest[3],
            rest[4], rest[5], rest[6], rest[7],
        ])
    }

    fn is_zero(&self) -> bool {
        self.0.iter().all(|byte| *byte == 0)
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            u16::from_le_bytes([b[4], b[5]]),
            u16::from_le_bytes([b[6], b[7]]),
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

/// Partition type reserved for a Ginux persistent volume. Ginux will only
/// ever write to partitions of this type.
pub(crate) const GINUX_VOLUME: Guid = Guid::new(
    0x8076_9f29,
    0x5413,
    0x45a3,
    [0xab, 0xab, 0x5b, 0x44, 0xb6, 0x12, 0x59, 0x22],
);

const KNOWN_TYPES: [(Guid, &str); 8] = [
    (GINUX_VOLUME, "Ginux volume"),
    (
        Guid::new(
            0xc12a_7328,
            0xf81f,
            0x11d2,
            [0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b],
        ),
        "EFI system",
    ),
    (
        Guid::new(
            0x0fc6_3daf,
            0x8483,
            0x4772,
            [0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4],
        ),
        "Linux filesystem",
    ),
    (
        Guid::new(
            0x0657_fd6d,
            0xa4ab,
            0x43c4,
            [0x84, 0xe5, 0x09, 0x33, 0xc8, 0x4b, 0x4f, 0x4f],
        ),
        "Linux swap",
    ),
    (
        Guid::new(
            0xe6d6_d379,
            0xf507,
            0x44c2,
            [0xa2, 0x3c, 0x23, 0x8f, 0x2a, 0x3d, 0xf9, 0x28],
        ),
        "Linux LVM",
    ),
    (
        Guid::new(
            0xebd0_a0a2,
            0xb9e5,
            0x4433,
            [0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7],
        ),
        "Microsoft basic data",
    ),
    (
        Guid::new(
            0xe3c9_e316,
            0x0b5c,
            0x4db8,
            [0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae],
        ),
        "Microsoft reserved",
    ),
    (
        Guid::new(
            0x2168_6148,
            0x6449,
            0x6e6f,
            [0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49],
        ),
        "BIOS boot",
    ),
];

pub(crate) fn type_name(guid: Guid) -> &'static str {
    KNOWN_TYPES
        .iter()
        .find(|(known, _)| *known == guid)
        .map_or("unknown type", |(_, name)| name)
}

/// The fields of a validated GPT header that locate the partition entries.
pub(crate) struct Header {
    pub(crate) entries_lba: u64,
    pub(crate) entry_count: u32,
    pub(crate) entry_size: u32,
    pub(crate) disk: Guid,
}

/// Validates the signature, size, and CRC32 of a GPT header block.
pub(crate) fn parse_header(block: &[u8]) -> Option<Header> {
    if block.get(..8)? != SIGNATURE {
        return None;
    }
    let header_size = read_u32(block, 12)? as usize;
    if !(MINIMUM_HEADER_SIZE..=block.len()).contains(&header_size) {
        return None;
    }
    let stored = read_u32(block, 16)?;
    let mut copy = [0_u8; 512];
    copy.get_mut(..header_size)?
        .copy_from_slice(&block[..header_size]);
    copy[16..20].fill(0);
    if crc32(&copy[..header_size]) != stored {
        return None;
    }
    let entry_size = read_u32(block, 84)?;
    if (entry_size as usize) < MINIMUM_ENTRY_SIZE || !entry_size.is_multiple_of(8) {
        return None;
    }
    Some(Header {
        entries_lba: read_u64(block, 72)?,
        entry_count: read_u32(block, 80)?,
        entry_size,
        disk: Guid(block.get(56..72)?.try_into().ok()?),
    })
}

/// One used partition entry.
pub(crate) struct Partition {
    pub(crate) kind: Guid,
    pub(crate) first_lba: u64,
    pub(crate) last_lba: u64,
    name: [u16; NAME_UNITS],
}

impl Partition {
    /// Writes the UTF-16 partition name, replacing non-ASCII units with '?'.
    pub(crate) fn write_name(&self, output: &mut impl fmt::Write) -> fmt::Result {
        for unit in self.name.iter().copied().take_while(|unit| *unit != 0) {
            let character = u8::try_from(unit)
                .ok()
                .filter(|byte| byte.is_ascii_graphic() || *byte == b' ')
                .map_or('?', char::from);
            output.write_char(character)?;
        }
        Ok(())
    }
}

/// Parses one partition entry, returning `None` for unused entries.
pub(crate) fn parse_entry(entry: &[u8]) -> Option<Partition> {
    let kind = Guid(entry.get(0..16)?.try_into().ok()?);
    if kind.is_zero() {
        return None;
    }
    let mut name = [0_u16; NAME_UNITS];
    for (index, unit) in name.iter_mut().enumerate() {
        let offset = NAME_OFFSET + index * 2;
        *unit = u16::from_le_bytes([*entry.get(offset)?, *entry.get(offset + 1)?]);
    }
    Some(Partition {
        kind,
        first_lba: read_u64(entry, 32)?,
        last_lba: read_u64(entry, 40)?,
        name,
    })
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
