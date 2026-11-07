use super::*;

const LOOPBACK: Ip = Ip::V4([127, 0, 0, 1]);
const LOOPBACK6: Ip = Ip::V6([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

#[test]
fn full_coverage_round_trips() {
    let datagram = encode(LOOPBACK, LOOPBACK, 4000, 5000, None, b"hello").unwrap();
    // The field holds the length when no coverage is set.
    assert_eq!(&datagram[4..6], &13_u16.to_be_bytes());
    let header = parse(LOOPBACK, LOOPBACK, &datagram).unwrap();
    assert_eq!(
        header,
        Header {
            source_port: 4000,
            destination_port: 5000,
            coverage: 13,
            partial: false,
        }
    );
    assert!(parse(
        LOOPBACK6,
        LOOPBACK6,
        &encode(LOOPBACK6, LOOPBACK6, 1, 2, None, b"x").unwrap()
    )
    .is_some());
}

#[test]
fn known_checksum() {
    // Worked by hand: pseudo-header 7f00 0001 7f00 0001 0088 000a, then
    // 0001 0002 000a 0000 abcd sums to 0xaa6f after folding.
    let datagram = encode(LOOPBACK, LOOPBACK, 1, 2, None, &[0xab, 0xcd]).unwrap();
    assert_eq!(&datagram[6..8], &(!0xaa6f_u16).to_be_bytes());
}

#[test]
fn partial_coverage_ignores_the_rest() {
    let mut datagram = encode(LOOPBACK, LOOPBACK, 1, 2, Some(10), b"covered-and-not").unwrap();
    assert_eq!(&datagram[4..6], &10_u16.to_be_bytes());
    // Damage past the covered bytes: still good.
    let last = datagram.len() - 1;
    datagram[last] ^= 0xff;
    let header = parse(LOOPBACK, LOOPBACK, &datagram).unwrap();
    assert_eq!((header.coverage, header.partial), (10, true));
    // Damage within them: dropped.
    datagram[9] ^= 0xff;
    assert_eq!(parse(LOOPBACK, LOOPBACK, &datagram), None);
}

#[test]
fn coverage_zero_or_past_the_end_is_all() {
    // Coverage 0 set: the field says 0, everything is covered.
    let datagram = encode(LOOPBACK, LOOPBACK, 1, 2, Some(0), b"abc").unwrap();
    assert_eq!(&datagram[4..6], &[0, 0]);
    assert!(!parse(LOOPBACK, LOOPBACK, &datagram).unwrap().partial);
    // Coverage at or past the length: the field holds the length.
    let datagram = encode(LOOPBACK, LOOPBACK, 1, 2, Some(500), b"abc").unwrap();
    assert_eq!(&datagram[4..6], &11_u16.to_be_bytes());
}

#[test]
fn bad_datagrams_are_dropped() {
    let good = encode(LOOPBACK, LOOPBACK, 1, 2, None, b"payload").unwrap();
    assert_eq!(parse(LOOPBACK, LOOPBACK, &good[..7]), None);
    let mut zero = good.clone();
    zero[6..8].fill(0);
    assert_eq!(parse(LOOPBACK, LOOPBACK, &zero), None);
    for field in [1_u16, 7, 16] {
        let mut bad = good.clone();
        bad[4..6].copy_from_slice(&field.to_be_bytes());
        assert_eq!(parse(LOOPBACK, LOOPBACK, &bad), None, "coverage {field}");
    }
    // The pseudo-header counts: another destination fails the sum.
    assert_eq!(parse(LOOPBACK, Ip::V4([127, 0, 0, 2]), &good), None);
    // Mixed families have no pseudo-header.
    assert_eq!(parse(LOOPBACK, LOOPBACK6, &good), None);
}

#[test]
fn a_zero_sum_goes_out_as_all_ones() {
    // Find a payload whose sum is 0 and check it is sent as 0xffff, which
    // the receiver accepts (0xffff and 0 are the same ones'-complement 0).
    let found = (0..=u16::MAX).find_map(|word| {
        let payload = word.to_be_bytes();
        let mut datagram = alloc::vec::Vec::from([0, 1, 0, 2, 0, 10, 0, 0]);
        datagram.extend_from_slice(&payload);
        (checksum(LOOPBACK, LOOPBACK, &datagram, 10) == Some(0)).then_some(payload)
    });
    let payload = found.unwrap();
    let datagram = encode(LOOPBACK, LOOPBACK, 1, 2, None, &payload).unwrap();
    assert_eq!(&datagram[6..8], &[0xff, 0xff]);
    assert!(parse(LOOPBACK, LOOPBACK, &datagram).is_some());
}

#[test]
fn receive_coverage_rules() {
    let partial = Header {
        source_port: 1,
        destination_port: 2,
        coverage: 20,
        partial: true,
    };
    let full = Header {
        partial: false,
        coverage: 100,
        ..partial
    };
    assert!(coverage_suffices(&partial, None));
    assert!(coverage_suffices(&partial, Some(20)));
    assert!(!coverage_suffices(&partial, Some(21)));
    assert!(!coverage_suffices(&partial, Some(0)));
    assert!(coverage_suffices(&full, Some(0)));
    assert!(coverage_suffices(&full, Some(5000)));
}

#[test]
fn options_are_stored_as_linux_stores_them() {
    assert_eq!(coverage_option(0), 0);
    assert_eq!(coverage_option(1), 8);
    assert_eq!(coverage_option(7), 8);
    assert_eq!(coverage_option(8), 8);
    assert_eq!(coverage_option(70_000), 65_535);
    assert_eq!(coverage_option(-3), 0);
}

#[test]
fn oversized_datagrams_are_refused() {
    let payload = alloc::vec![0_u8; 65_528];
    assert!(encode(LOOPBACK, LOOPBACK, 1, 2, None, &payload).is_none());
    assert!(encode(LOOPBACK, LOOPBACK6, 1, 2, None, b"x").is_none());
}
