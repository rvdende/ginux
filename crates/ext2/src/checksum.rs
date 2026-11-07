//! CRC32C (Castagnoli), which ext4's `metadata_csum` feature stores for
//! the superblock, group descriptors, bitmaps, inodes, extent and
//! directory blocks and attribute blocks.
//!
//! The format uses the reflected polynomial 0x82F63B78 with no inversion
//! before or after: a structure's checksum continues from a seed (the
//! filesystem's, or an inode's derived from it) over its bytes.

/// The table of the byte-at-a-time update.
const TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ 0x82f6_3b78
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
};

/// `crc` continued over `bytes`.
pub(crate) fn crc32c(mut crc: u32, bytes: &[u8]) -> u32 {
    for byte in bytes {
        crc = TABLE[((crc ^ u32::from(*byte)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// `crc` continued over `bytes` with the `zeroed` range (relative to
/// `bytes`) read as zeros: a checksum over a structure that holds it.
pub(crate) fn crc32c_skipping(crc: u32, bytes: &[u8], zeroed: core::ops::Range<usize>) -> u32 {
    let start = zeroed.start.min(bytes.len());
    let end = zeroed.end.min(bytes.len());
    let crc = crc32c(crc, &bytes[..start]);
    let crc = (start..end).fold(crc, |crc, _| crc32c(crc, &[0]));
    crc32c(crc, &bytes[end..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_standard_check_value() {
        // CRC-32C of "123456789" with the usual inversions is 0xE3069283.
        assert_eq!(!crc32c(!0, b"123456789"), 0xe306_9283);
    }

    #[test]
    fn skipping_reads_the_range_as_zeros() {
        let bytes = [1_u8, 2, 3, 4, 5, 6];
        assert_eq!(
            crc32c_skipping(7, &bytes, 2..4),
            crc32c(7, &[1, 2, 0, 0, 5, 6])
        );
    }
}
