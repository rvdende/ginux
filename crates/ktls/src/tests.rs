use alloc::vec;
use alloc::vec::Vec;

use super::*;

/// Records made by Python's `cryptography` from RFC 5288 and RFC 8446
/// (target/tmp/ptyprobe/tls_vectors.py in the tree that made them): two
/// TLS 1.2 AES-128-GCM records with setsockopt10's keys, and a TLS 1.3
/// AES-256-GCM handshake record.
const TLS12_FIRST: &str = "170303001d6976000000000000953b8130ddcb1d3800ac975454e9dcf4bc68358b06";
const TLS12_SECOND: &str = "150303001a6976000000000001b988225f0141135070061c8eb53f164b0965";
const TLS13_RECORD: &str = "170303001915c1e039e0c81f1ca059ce6761b236441e3a09ec1fac4159d0";

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

/// setsockopt10's tls12_crypto_info_aes_gcm_128.
fn setsockopt10_info() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TLS_1_2_VERSION.to_ne_bytes());
    bytes.extend_from_slice(&TLS_CIPHER_AES_GCM_128.to_ne_bytes());
    bytes.extend_from_slice(b"iv\0\0\0\0\0\0");
    bytes.extend_from_slice(b"key\0\0\0\0\0\0\0\0\0\0\0\0\0");
    bytes.extend_from_slice(b"salt");
    bytes.extend_from_slice(b"recs\0\0\0\0");
    bytes
}

fn tls13_info() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&TLS_1_3_VERSION.to_ne_bytes());
    bytes.extend_from_slice(&TLS_CIPHER_AES_GCM_256.to_ne_bytes());
    bytes.extend((100..108).collect::<Vec<u8>>());
    bytes.extend((0..32).collect::<Vec<u8>>());
    bytes.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    bytes.extend_from_slice(&7_u64.to_be_bytes());
    bytes
}

#[test]
fn tls12_records_match_an_independent_implementation() {
    let mut sealer = Sealer::new(CryptoInfo::parse(&setsockopt10_info()).unwrap());
    let mut output = Vec::new();
    sealer.seal(APPLICATION_DATA, b"hello", &mut output);
    assert_eq!(output, hex(TLS12_FIRST));
    output.clear();
    sealer.seal(ALERT, &[1, 0], &mut output);
    assert_eq!(output, hex(TLS12_SECOND));

    let mut opener = Opener::new(CryptoInfo::parse(&setsockopt10_info()).unwrap());
    opener.push(&hex(TLS12_FIRST));
    opener.push(&hex(TLS12_SECOND));
    assert_eq!(
        opener.open().unwrap(),
        Some((APPLICATION_DATA, b"hello".to_vec()))
    );
    assert_eq!(opener.open().unwrap(), Some((ALERT, vec![1, 0])));
    assert_eq!(opener.open().unwrap(), None);
}

#[test]
fn tls13_records_match_an_independent_implementation() {
    let mut sealer = Sealer::new(CryptoInfo::parse(&tls13_info()).unwrap());
    let mut output = Vec::new();
    sealer.seal(HANDSHAKE, b"hi there", &mut output);
    assert_eq!(output, hex(TLS13_RECORD));
    let mut opener = Opener::new(CryptoInfo::parse(&tls13_info()).unwrap());
    opener.push(&hex(TLS13_RECORD));
    assert_eq!(
        opener.open().unwrap(),
        Some((HANDSHAKE, b"hi there".to_vec()))
    );
}

#[test]
fn records_come_whole_and_in_pieces() {
    let record = hex(TLS12_FIRST);
    let mut opener = Opener::new(CryptoInfo::parse(&setsockopt10_info()).unwrap());
    for (at, byte) in record.iter().enumerate() {
        assert!(!opener.ready());
        assert_eq!(opener.open().unwrap(), None, "{at}");
        opener.push(&[*byte]);
    }
    assert!(opener.ready());
    assert_eq!(opener.open().unwrap().unwrap().1, b"hello");
}

#[test]
fn large_writes_split_into_records() {
    let info = CryptoInfo::parse(&setsockopt10_info()).unwrap();
    let mut sealer = Sealer::new(info.clone());
    let data: Vec<u8> = (0..40_000_u32).map(|value| value as u8).collect();
    let mut output = Vec::new();
    sealer.seal(APPLICATION_DATA, &data, &mut output);
    let mut opener = Opener::new(info);
    opener.push(&output);
    let mut lengths = Vec::new();
    let mut received = Vec::new();
    while let Some((kind, plaintext)) = opener.open().unwrap() {
        assert_eq!(kind, APPLICATION_DATA);
        lengths.push(plaintext.len());
        received.extend(plaintext);
    }
    assert_eq!(
        lengths,
        [MAX_PLAINTEXT, MAX_PLAINTEXT, 40_000 - 2 * MAX_PLAINTEXT]
    );
    assert_eq!(received, data);
    // An empty write is one empty record.
    let mut output = Vec::new();
    sealer.seal(APPLICATION_DATA, &[], &mut output);
    assert_eq!(output.len(), HEADER + 8 + 16);
}

#[test]
fn tampering_and_bad_headers_are_refused() {
    let info = CryptoInfo::parse(&setsockopt10_info()).unwrap();
    let mut record = hex(TLS12_FIRST);
    record[20] ^= 1;
    let mut opener = Opener::new(info.clone());
    opener.push(&record);
    assert_eq!(opener.open(), Err(EBADMSG));
    // Records out of order fail too: the sequence number is in the tag.
    let mut opener = Opener::new(info.clone());
    opener.push(&hex(TLS12_SECOND));
    assert_eq!(opener.open(), Err(EBADMSG));
    // The header's version must be TLS 1.2's; lengths are bounded.
    let mut opener = Opener::new(info.clone());
    opener.push(&[23, 3, 1, 0, 30]);
    assert_eq!(opener.open(), Err(EINVAL));
    let mut opener = Opener::new(info.clone());
    opener.push(&[23, 3, 3, 0xff, 0xff]);
    assert_eq!(opener.open(), Err(EMSGSIZE));
    let mut opener = Opener::new(info);
    opener.push(&[23, 3, 3, 0, 10]);
    assert!(opener.ready());
    assert_eq!(opener.open(), Err(EBADMSG));
}

#[test]
fn crypto_info_is_checked_as_linux_checks_it() {
    let good = setsockopt10_info();
    assert_eq!(CryptoInfo::parse(&good[..3]).err(), Some(EINVAL));
    assert_eq!(CryptoInfo::parse(&good[..39]).err(), Some(EINVAL));
    let mut bad_version = good.clone();
    bad_version[..2].copy_from_slice(&0x0302_u16.to_ne_bytes());
    assert_eq!(CryptoInfo::parse(&bad_version).err(), Some(EINVAL));
    let mut chacha = good.clone();
    chacha[2..4].copy_from_slice(&54_u16.to_ne_bytes());
    assert_eq!(CryptoInfo::parse(&chacha).err(), Some(EINVAL));
    assert_eq!(CryptoInfo::size(TLS_CIPHER_AES_GCM_128), Some(40));
    assert_eq!(CryptoInfo::size(TLS_CIPHER_AES_GCM_256), Some(56));
    // getsockopt shows the counters as they stand.
    let mut sealer = Sealer::new(CryptoInfo::parse(&good).unwrap());
    assert_eq!(sealer.crypto_info(), good);
    sealer.seal(APPLICATION_DATA, b"x", &mut Vec::new());
    let after = sealer.crypto_info();
    assert_eq!(&after[4..12], b"iv\0\0\0\0\0\x01");
    assert_eq!(&after[32..40], b"recs\0\0\0\x01");
}

#[test]
fn tls13_padding_and_empty_content() {
    let info = CryptoInfo::parse(&tls13_info()).unwrap();
    let mut sealer = Sealer::new(info.clone());
    let mut opener = Opener::new(info);
    let mut output = Vec::new();
    sealer.seal(APPLICATION_DATA, b"", &mut output);
    opener.push(&output);
    assert_eq!(opener.open().unwrap(), Some((APPLICATION_DATA, Vec::new())));
}
