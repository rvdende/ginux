use alloc::vec;
use alloc::vec::Vec;

use super::*;

const STACK: [u8; 6] = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
const MAC: [u8; 6] = [0x02, 0, 0x5e, 0, 0, 3];

const ROOT: Caller = Caller {
    user: 0,
    group: 0,
    groups: &[],
    administrator: true,
};
const NOBODY: Caller = Caller {
    user: 65_534,
    group: 65_534,
    groups: &[],
    administrator: false,
};

fn id(index: i32) -> Identity {
    Identity { index, mac: MAC }
}

fn none_taken(name: &[u8]) -> bool {
    name == b"lo" || name == b"eth0"
}

/// A device `name` (TUN or TAP), up, with 10.8.0.1/24.
fn device(tun: &mut Tun, flags: u16) -> (u64, i32) {
    let file = tun.open().unwrap();
    tun.set_iff(file, b"", flags, &ROOT, &none_taken, id(3))
        .unwrap();
    tun.add_address(
        3,
        Address {
            address: [10, 8, 0, 1],
            prefix: 24,
        },
    )
    .unwrap();
    tun.set_link(3, Some(true), None).unwrap();
    (file, 3)
}

/// An Ethernet frame from the stack: IPv4 from 10.8.0.1 to `destination`.
fn ipv4_frame(destination: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; 14 + 20];
    frame[..6].copy_from_slice(&MAC);
    frame[6..12].copy_from_slice(&STACK);
    frame[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    frame[14] = 0x45;
    frame[26..30].copy_from_slice(&[10, 8, 0, 1]);
    frame[30..34].copy_from_slice(&destination);
    frame.extend_from_slice(payload);
    frame
}

/// An ARP request from the stack for `target`.
fn arp_request(target: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0xff; 6];
    frame.extend_from_slice(&STACK);
    frame.extend_from_slice(&0x0806_u16.to_be_bytes());
    frame.extend_from_slice(&[0, 1, 8, 0, 6, 4, 0, 1]);
    frame.extend_from_slice(&STACK);
    frame.extend_from_slice(&[10, 8, 0, 1]);
    frame.extend_from_slice(&[0; 6]);
    frame.extend_from_slice(&target);
    frame
}

#[test]
fn names_follow_linux() {
    let mut tun = Tun::new();
    let first = tun.open().unwrap();
    let (name, flags) = tun
        .set_iff(first, b"", IFF_TUN | IFF_NO_PI, &ROOT, &none_taken, id(3))
        .unwrap();
    assert_eq!(name.as_bytes(), b"tun0");
    assert_eq!(flags, IFF_TUN | IFF_NO_PI);
    let second = tun.open().unwrap();
    let (name, _) = tun
        .set_iff(second, b"tun%d", IFF_TUN, &ROOT, &none_taken, id(4))
        .unwrap();
    assert_eq!(name.as_bytes(), b"tun1");
    let third = tun.open().unwrap();
    let (name, _) = tun
        .set_iff(third, b"", IFF_TAP, &ROOT, &none_taken, id(5))
        .unwrap();
    assert_eq!(name.as_bytes(), b"tap0");
    // Names lo and eth0 have, bad names, and two %s are refused.
    let fourth = tun.open().unwrap();
    assert_eq!(
        tun.set_iff(fourth, b"eth0", IFF_TUN, &ROOT, &none_taken, id(6)),
        Err(EEXIST)
    );
    assert_eq!(
        tun.set_iff(fourth, b"a/b", IFF_TUN, &ROOT, &none_taken, id(6)),
        Err(EINVAL)
    );
    assert_eq!(
        tun.set_iff(fourth, b"x%d%d", IFF_TUN, &ROOT, &none_taken, id(6)),
        Err(EINVAL)
    );
    assert_eq!(
        tun.set_iff(
            fourth,
            b"sixteen-chars-xx",
            IFF_TUN,
            &ROOT,
            &none_taken,
            id(6)
        ),
        Err(EINVAL)
    );
    // Neither TUN nor TAP.
    assert_eq!(
        tun.set_iff(fourth, b"", IFF_NO_PI, &ROOT, &none_taken, id(6)),
        Err(EINVAL)
    );
}

#[test]
fn making_needs_net_admin_attaching_the_owner() {
    let mut tun = Tun::new();
    let file = tun.open().unwrap();
    assert_eq!(
        tun.set_iff(file, b"t", IFF_TUN, &NOBODY, &none_taken, id(3)),
        Err(EPERM)
    );
    tun.set_iff(file, b"t", IFF_TUN, &ROOT, &none_taken, id(3))
        .unwrap();
    tun.set_owner(file, 65_534).unwrap();
    tun.set_persist(file, true).unwrap();
    assert_eq!(tun.close(file), Closed::Kept);
    // The owner may attach to the persistent device; others may not.
    let other = Caller {
        user: 1000,
        ..NOBODY
    };
    let file = tun.open().unwrap();
    assert_eq!(
        tun.set_iff(file, b"t", IFF_TUN, &other, &none_taken, id(9)),
        Err(EPERM)
    );
    let (name, flags) = tun
        .set_iff(file, b"t", IFF_TUN, &NOBODY, &none_taken, id(9))
        .unwrap();
    assert_eq!((name.as_bytes(), flags), (&b"t"[..], IFF_TUN | IFF_PERSIST));
    // A group admits its members, by supplementary groups too.
    tun.set_group(file, 4242).unwrap();
    assert_eq!(tun.set_owner(file, u32::MAX), Err(EINVAL));
    tun.set_persist(file, false).unwrap();
    let member = Caller {
        user: 65_534,
        group: 1,
        groups: &[4242],
        administrator: false,
    };
    let second = tun.open().unwrap();
    // Busy: a single-queue device takes one file.
    assert_eq!(
        tun.set_iff(second, b"t", IFF_TUN, &member, &none_taken, id(9)),
        Err(EBUSY)
    );
    assert_eq!(
        tun.close(file),
        Closed::Removed {
            index: 3,
            addresses: Vec::new()
        }
    );
    assert!(tun.devices().is_empty());
}

#[test]
fn attach_rules() {
    let mut tun = Tun::new();
    let file = tun.open().unwrap();
    tun.set_iff(
        file,
        b"q",
        IFF_TUN | IFF_MULTI_QUEUE,
        &ROOT,
        &none_taken,
        id(3),
    )
    .unwrap();
    // Twice on one file.
    assert_eq!(
        tun.set_iff(
            file,
            b"q",
            IFF_TUN | IFF_MULTI_QUEUE,
            &ROOT,
            &none_taken,
            id(3)
        ),
        Err(EEXIST)
    );
    let second = tun.open().unwrap();
    // The wrong type, the wrong queue mode, or IFF_TUN_EXCL.
    assert_eq!(
        tun.set_iff(
            second,
            b"q",
            IFF_TAP | IFF_MULTI_QUEUE,
            &ROOT,
            &none_taken,
            id(4)
        ),
        Err(EINVAL)
    );
    assert_eq!(
        tun.set_iff(second, b"q", IFF_TUN, &ROOT, &none_taken, id(4)),
        Err(EINVAL)
    );
    assert_eq!(
        tun.set_iff(
            second,
            b"q",
            IFF_TUN | IFF_MULTI_QUEUE | IFF_TUN_EXCL,
            &ROOT,
            &none_taken,
            id(4)
        ),
        Err(EBUSY)
    );
    tun.set_iff(
        second,
        b"q",
        IFF_TUN | IFF_MULTI_QUEUE,
        &ROOT,
        &none_taken,
        id(4),
    )
    .unwrap();
    assert_eq!(tun.devices()[0].queues.len(), 2);
    // A queue may detach and come back; its device stays meanwhile.
    tun.set_queue(second, IFF_DETACH_QUEUE, &ROOT).unwrap();
    assert_eq!(
        tun.get_iff(second).unwrap().1 & IFF_DETACH_QUEUE,
        IFF_DETACH_QUEUE
    );
    assert_eq!(tun.set_queue(second, IFF_DETACH_QUEUE, &ROOT), Err(EINVAL));
    assert_eq!(tun.close(file), Closed::Kept);
    tun.set_queue(second, IFF_ATTACH_QUEUE, &ROOT).unwrap();
    assert_eq!(tun.devices()[0].queues, [second]);
    // An unattached file has no device to ask about.
    let third = tun.open().unwrap();
    assert_eq!(tun.get_iff(third), Err(EBADFD));
    assert_eq!(tun.set_persist(third, true), Err(EBADFD));
    assert_eq!(tun.read(third, &mut [0; 64]), Err(EBADFD));
}

#[test]
fn tun_packets_go_to_the_reader_with_information() {
    let mut tun = Tun::new();
    let (file, _) = device(&mut tun, IFF_TUN);
    let frame = ipv4_frame([10, 8, 0, 2], b"hello");
    assert_eq!(tun.egress(&frame, STACK), Egress::Taken);
    assert_eq!(tun.readable(file), Some(true));
    let mut output = [0_u8; 128];
    let length = tun.read(file, &mut output).unwrap();
    assert_eq!(length, 4 + 20 + 5);
    assert_eq!(&output[..4], &[0, 0, 0x08, 0x00]);
    assert_eq!(&output[4 + 20..length], b"hello");
    assert_eq!(tun.read(file, &mut output), Err(EAGAIN));
    // A short read is cut and flagged.
    tun.egress(&frame, STACK);
    let length = tun.read(file, &mut output[..10]).unwrap();
    assert_eq!(length, 10);
    assert_eq!(u16::from_ne_bytes([output[0], output[1]]), TUN_PKT_STRIP);
    assert_eq!(tun.read(file, &mut output[..3]), Err(EINVAL));
}

#[test]
fn what_is_not_a_devices_passes_or_stays_local() {
    let mut tun = Tun::new();
    device(&mut tun, IFF_TUN | IFF_NO_PI);
    assert_eq!(
        tun.egress(&ipv4_frame([8, 8, 8, 8], b""), STACK),
        Egress::Pass
    );
    assert_eq!(
        tun.egress(&ipv4_frame([10, 8, 0, 1], b""), STACK),
        Egress::Local
    );
    assert_eq!(
        tun.egress(&arp_request([10, 8, 0, 1]), STACK),
        Egress::Local
    );
    assert_eq!(tun.egress(&arp_request([10, 0, 2, 2]), STACK), Egress::Pass);
    // Down: the device's traffic is dropped, not sent on.
    tun.set_link(3, Some(false), None).unwrap();
    assert_eq!(
        tun.egress(&ipv4_frame([10, 8, 0, 2], b""), STACK),
        Egress::Taken
    );
    assert_eq!(tun.write(1, &[0x45; 20], STACK), Err(EIO));
}

#[test]
fn tun_peers_are_answered_for() {
    let mut tun = Tun::new();
    device(&mut tun, IFF_TUN | IFF_NO_PI);
    let Egress::Answer(answer) = tun.egress(&arp_request([10, 8, 0, 2]), STACK) else {
        panic!("no answer");
    };
    assert_eq!(&answer[..6], &STACK);
    assert_eq!(&answer[6..12], &MAC);
    assert_eq!(&answer[20..22], &2_u16.to_be_bytes());
    assert_eq!(&answer[22..28], &MAC);
    assert_eq!(&answer[28..32], &[10, 8, 0, 2]);
    assert_eq!(&answer[32..38], &STACK);
    assert_eq!(&answer[38..42], &[10, 8, 0, 1]);
}

#[test]
fn tun_writes_become_frames() {
    let mut tun = Tun::new();
    let (file, _) = device(&mut tun, IFF_TUN);
    let mut packet = vec![0, 0, 0x08, 0x00];
    packet.extend_from_slice(&[0x45; 20]);
    let frame = tun.write(file, &packet, STACK).unwrap();
    assert_eq!(&frame[..6], &STACK);
    assert_eq!(&frame[6..12], &MAC);
    assert_eq!(&frame[12..14], &[0x08, 0x00]);
    assert_eq!(&frame[14..], &[0x45; 20]);
    assert_eq!(tun.write(file, &[0, 0], STACK), Err(EINVAL));
    // Without packet information the version says which protocol.
    let mut tun = Tun::new();
    let (file, _) = device(&mut tun, IFF_TUN | IFF_NO_PI);
    let frame = tun.write(file, &[0x60; 40], STACK).unwrap();
    assert_eq!(&frame[12..14], &[0x86, 0xdd]);
    assert_eq!(tun.write(file, &[0x10; 20], STACK), Err(EINVAL));
}

#[test]
fn tap_frames_carry_the_devices_address() {
    let mut tun = Tun::new();
    let (file, _) = device(&mut tun, IFF_TAP | IFF_NO_PI);
    // The stack's ARP request for a peer goes to the reader, from the
    // device's address.
    assert_eq!(
        tun.egress(&arp_request([10, 8, 0, 2]), STACK),
        Egress::Taken
    );
    let mut output = [0_u8; 128];
    let length = tun.read(file, &mut output).unwrap();
    assert_eq!(length, 42);
    assert_eq!(&output[6..12], &MAC);
    assert_eq!(&output[22..28], &MAC);
    // A frame to the device's address reaches the stack at its own.
    let mut reply = vec![0; 42];
    reply[..6].copy_from_slice(&MAC);
    reply[12..14].copy_from_slice(&0x0806_u16.to_be_bytes());
    let frame = tun.write(file, &reply, STACK).unwrap();
    assert_eq!(&frame[..6], &STACK);
    assert_eq!(tun.write(file, &[0; 10], STACK), Err(EINVAL));
    // IPv4 to a peer: the whole frame, from the device's address.
    tun.egress(&ipv4_frame([10, 8, 0, 9], b"x"), STACK);
    let length = tun.read(file, &mut output).unwrap();
    assert_eq!(length, 14 + 20 + 1);
    assert_eq!(&output[6..12], &MAC);
}

#[test]
fn multi_queue_flows_stay_on_a_queue() {
    let mut tun = Tun::new();
    let first = tun.open().unwrap();
    tun.set_iff(
        first,
        b"m",
        IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
        &ROOT,
        &none_taken,
        id(3),
    )
    .unwrap();
    let second = tun.open().unwrap();
    tun.set_iff(
        second,
        b"m",
        IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
        &ROOT,
        &none_taken,
        id(3),
    )
    .unwrap();
    tun.add_address(
        3,
        Address {
            address: [10, 8, 0, 1],
            prefix: 24,
        },
    )
    .unwrap();
    tun.set_link(3, Some(true), None).unwrap();
    let frame = ipv4_frame([10, 8, 0, 2], b"same flow");
    for _ in 0..4 {
        tun.egress(&frame, STACK);
    }
    let counts: Vec<usize> = [first, second]
        .iter()
        .map(|file| {
            let mut count = 0;
            while tun.read(*file, &mut [0; 64]).is_ok() {
                count += 1;
            }
            count
        })
        .collect();
    assert!(counts == [4, 0] || counts == [0, 4], "{counts:?}");
}

#[test]
fn addresses_and_links() {
    let mut tun = Tun::new();
    let (_, index) = device(&mut tun, IFF_TUN);
    let address = Address {
        address: [10, 8, 0, 1],
        prefix: 24,
    };
    assert_eq!(tun.add_address(index, address), Err(EEXIST));
    assert_eq!(
        tun.remove_address(
            index,
            Address {
                prefix: 16,
                ..address
            }
        ),
        Err(EADDRNOTAVAIL)
    );
    tun.remove_address(index, address).unwrap();
    assert!(tun.devices()[0].addresses.is_empty());
    assert_eq!(tun.set_link(index, None, Some(20)), Err(EINVAL));
    tun.set_link(index, None, Some(9000)).unwrap();
    assert_eq!(tun.devices()[0].mtu, 9000);
    let flags = tun.devices()[0].interface_flags();
    assert_eq!(
        flags & (NETDEVICE_UP | NETDEVICE_RUNNING | NETDEVICE_NOARP),
        NETDEVICE_UP | NETDEVICE_RUNNING | NETDEVICE_NOARP
    );
}

#[test]
fn queues_are_bounded() {
    let mut tun = Tun::new();
    let (file, _) = device(&mut tun, IFF_TUN | IFF_NO_PI);
    let frame = ipv4_frame([10, 8, 0, 2], b"");
    for _ in 0..QUEUE_LIMIT + 10 {
        tun.egress(&frame, STACK);
    }
    let mut count = 0;
    while tun.read(file, &mut [0; 64]).is_ok() {
        count += 1;
    }
    assert_eq!(count, QUEUE_LIMIT);
}
