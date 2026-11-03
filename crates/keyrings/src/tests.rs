//! Rules from the man pages and the LTP add_key, keyctl and request_key
//! tests; the LTP test each one follows is named where there is one.

use super::*;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use permission::{group, other, possessor, user, ALL};

const NOW: u64 = 1_000 * NANOSECONDS_PER_SECOND;
const SECOND: u64 = NANOSECONDS_PER_SECOND;
/// LTP's KEY_PERM_ALL and the masks derived from it.
const PERM_ALL: u32 = 0x3f3f_3f3f;

/// `rights` in all four bytes of a mask.
const fn every_class(rights: u32) -> u32 {
    rights * 0x0101_0101
}

fn root() -> Caller<'static> {
    Caller {
        uid: 0,
        gid: 0,
        groups: &[],
        real_uid: 0,
        real_gid: 0,
        pid: 100,
        tid: 100,
        privileged: true,
    }
}

/// An unprivileged single-threaded process of `uid`.
fn person(uid: u32, pid: u32) -> Caller<'static> {
    Caller {
        uid,
        gid: uid,
        groups: &[],
        real_uid: uid,
        real_gid: uid,
        pid,
        tid: pid,
        privileged: false,
    }
}

fn add_user(keys: &mut Keyrings, caller: &Caller, description: &str, ring: i32) -> i32 {
    keys.add_key(
        caller,
        b"user",
        description.as_bytes(),
        b"payload",
        ring,
        NOW,
    )
    .unwrap()
}

fn add_ring(keys: &mut Keyrings, caller: &Caller, description: &str, ring: i32) -> i32 {
    keys.add_key(caller, b"keyring", description.as_bytes(), &[], ring, NOW)
        .unwrap()
}

fn described(keys: &mut Keyrings, caller: &Caller, id: i32) -> String {
    let output = keys.describe(caller, id, NOW).unwrap();
    String::from_utf8(output.as_bytes().to_vec()).unwrap()
}

fn links(keys: &mut Keyrings, caller: &Caller, ring: i32) -> Vec<i32> {
    let output = keys.read(caller, ring, NOW).unwrap();
    output
        .as_bytes()
        .chunks(4)
        .map(|chunk| i32::from_ne_bytes(chunk.try_into().unwrap()))
        .collect()
}

/// The keys and bytes /proc/key-users shows for `uid`.
fn usage(keys: &Keyrings, uid: u32) -> Option<(u32, usize)> {
    let text = String::from_utf8(keys.proc_key_users().unwrap()).unwrap();
    let prefix = format!("{uid:5}:");
    let line = text.lines().find(|line| line.starts_with(&prefix))?;
    let fields: Vec<&str> = line[prefix.len()..].split_whitespace().collect();
    let count = |field: &str| -> usize { field.split('/').next().unwrap().parse().unwrap() };
    Some((count(fields[2]) as u32, count(fields[3])))
}

#[test]
fn add_key_checks_its_arguments_in_linux_order() {
    let mut keys = Keyrings::new();
    let caller = root();
    let add = |keys: &mut Keyrings, key_type: &[u8], description: &[u8], payload: &[u8], ring| {
        keys.add_key(&caller, key_type, description, payload, ring, NOW)
    };
    let long_payload = vec![0; PAYLOAD_LIMIT + 1];
    assert_eq!(
        add(&mut keys, b".user", b"d", &long_payload, THREAD_KEYRING),
        Err(Error::Invalid)
    );
    assert_eq!(
        add(&mut keys, b".user", b"d", b"x", THREAD_KEYRING),
        Err(Error::NotPermitted)
    );
    assert_eq!(
        add(&mut keys, b"", b"d", b"x", THREAD_KEYRING),
        Err(Error::Invalid)
    );
    assert_eq!(
        add(&mut keys, &[b'a'; TYPE_LIMIT], b"d", b"x", THREAD_KEYRING),
        Err(Error::Invalid)
    );
    assert_eq!(
        add(
            &mut keys,
            b"user",
            &[b'd'; DESCRIPTION_LIMIT],
            b"x",
            THREAD_KEYRING
        ),
        Err(Error::Invalid)
    );
    assert_eq!(
        add(&mut keys, b"keyring", b".ring", &[], THREAD_KEYRING),
        Err(Error::NotPermitted)
    );
    assert_eq!(
        add(&mut keys, b"user", b"d", b"x", GROUP_KEYRING),
        Err(Error::Invalid)
    );
    assert_eq!(add(&mut keys, b"user", b"d", b"x", 0), Err(Error::Invalid));
    assert_eq!(
        add(&mut keys, b"user", b"d", b"x", i32::MAX),
        Err(Error::NoKey)
    );
    // An unknown type is found out after the keyring, which gets created.
    assert_eq!(
        add(&mut keys, b"big_key", b"d", b"x", THREAD_KEYRING),
        Err(Error::NoDevice)
    );
    assert!(keys
        .get_keyring_id(&caller, THREAD_KEYRING, false, NOW)
        .is_ok());
    let plain = add_user(&mut keys, &caller, "plain", THREAD_KEYRING);
    assert_eq!(
        add(&mut keys, b"user", b"d", b"x", plain),
        Err(Error::NotDirectory)
    );
    assert_eq!(
        add(&mut keys, b"user", b"", b"x", THREAD_KEYRING),
        Err(Error::Invalid)
    );
}

/// add_key01.
#[test]
fn payload_sizes_follow_the_key_type() {
    let mut keys = Keyrings::new();
    let caller = root();
    let mut add = |key_type: &[u8], description: &[u8], length| {
        let payload = vec![b'x'; length];
        keys.add_key(
            &caller,
            key_type,
            description,
            &payload,
            THREAD_KEYRING,
            NOW,
        )
        .map(|_| ())
    };
    assert_eq!(add(b"keyring", b"abc", 0), Ok(()));
    assert_eq!(add(b"keyring", b"bcd", 1), Err(Error::Invalid));
    assert_eq!(add(b"user", b"cde", USER_PAYLOAD_LIMIT), Ok(()));
    assert_eq!(
        add(b"user", b"def", USER_PAYLOAD_LIMIT + 1),
        Err(Error::Invalid)
    );
    assert_eq!(add(b"user", b"empty", 0), Err(Error::Invalid));
    assert_eq!(add(b"logon", b"ef:g", USER_PAYLOAD_LIMIT), Ok(()));
    assert_eq!(
        add(b"logon", b"fg:h", USER_PAYLOAD_LIMIT + 1),
        Err(Error::Invalid)
    );
    assert_eq!(add(b"logon", b"unqualified", 8), Err(Error::Invalid));
    assert_eq!(add(b"logon", b":service", 8), Err(Error::Invalid));
    assert_eq!(add(b"big_key", b"ghi", 8), Err(Error::NoDevice));
}

#[test]
fn user_keys_update_in_place_and_keyrings_are_replaced() {
    let mut keys = Keyrings::new();
    let caller = root();
    let first = keys
        .add_key(&caller, b"user", b"k", b"one", PROCESS_KEYRING, NOW)
        .unwrap();
    let second = keys
        .add_key(&caller, b"user", b"k", b"two", PROCESS_KEYRING, NOW)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(keys.read(&caller, first, NOW).unwrap().as_bytes(), b"two");

    let old_ring = add_ring(&mut keys, &caller, "r", PROCESS_KEYRING);
    let new_ring = add_ring(&mut keys, &caller, "r", PROCESS_KEYRING);
    assert_ne!(old_ring, new_ring);
    assert_eq!(keys.describe(&caller, old_ring, NOW), Err(Error::NoKey));
    assert_eq!(
        links(&mut keys, &caller, PROCESS_KEYRING),
        [first, new_ring]
    );
}

#[test]
fn updating_in_place_needs_write_permission_on_the_key() {
    let mut keys = Keyrings::new();
    let caller = root();
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    keys.set_permissions(&caller, key, possessor(ALL & !WRITE), NOW)
        .unwrap();
    assert_eq!(
        keys.add_key(&caller, b"user", b"k", b"new", PROCESS_KEYRING, NOW),
        Err(Error::AccessDenied)
    );
}

/// keyctl02: a revoked key is displaced by the next add_key and, linked
/// nowhere else, is gone.
#[test]
fn a_revoked_key_is_displaced_and_dropped() {
    let mut keys = Keyrings::new();
    let caller = root();
    let revoked = add_user(&mut keys, &caller, "ltptestkey", PROCESS_KEYRING);
    assert_eq!(keys.revoke(&caller, revoked, NOW), Ok(()));
    assert_eq!(keys.revoke(&caller, revoked, NOW), Err(Error::KeyRevoked));
    assert_eq!(keys.read(&caller, revoked, NOW), Err(Error::KeyRevoked));
    let replacement = add_user(&mut keys, &caller, "ltptestkey", PROCESS_KEYRING);
    assert_ne!(replacement, revoked);
    assert_eq!(keys.revoke(&caller, revoked, NOW), Err(Error::NoKey));
}

/// keyctl06.
#[test]
fn keyring_reads_list_serials_and_a_short_buffer_gets_nothing() {
    let mut keys = Keyrings::new();
    let caller = root();
    let first = add_user(&mut keys, &caller, "key1", PROCESS_KEYRING);
    let second = add_user(&mut keys, &caller, "key2", PROCESS_KEYRING);
    let output = keys.read(&caller, PROCESS_KEYRING, NOW).unwrap();
    assert_eq!(output.len(), 8);
    assert!(output.for_buffer(4).is_empty());
    let mut expected = first.to_ne_bytes().to_vec();
    expected.extend_from_slice(&second.to_ne_bytes());
    assert_eq!(output.for_buffer(8), expected.as_slice());
    assert_eq!(output.for_buffer(100), expected.as_slice());
}

/// keyctl10 to keyctl13.
#[test]
fn describe_formats_the_key_and_copies_all_or_nothing() {
    let mut keys = Keyrings::new();
    let caller = person(1000, 10);
    keys.join_session_keyring(&caller, None).unwrap();
    let key = add_user(&mut keys, &caller, "ltpkeyctl10", PROCESS_KEYRING);
    keys.set_permissions(&caller, key, possessor(ALL) | user(ALL), NOW)
        .unwrap();
    let output = keys.describe(&caller, key, NOW).unwrap();
    let expected = b"user;1000;1000;3f3f0000;ltpkeyctl10\0";
    assert_eq!(output.as_bytes(), expected);
    assert_eq!(output.len(), expected.len());
    assert!(output.for_buffer(expected.len() - 1).is_empty());
    assert_eq!(output.for_buffer(expected.len()), expected);

    let user_keyring = keys
        .get_keyring_id(&caller, USER_KEYRING, false, NOW)
        .unwrap();
    assert_eq!(
        described(&mut keys, &caller, user_keyring),
        "keyring;1000;65534;1f3f0000;_uid.1000\0"
    );
}

/// keyctl14, keyctl15, keyctl16 and keyctl17.
#[test]
fn describe_and_get_security_refuse_differently_without_view() {
    let mut keys = Keyrings::new();
    let caller = root();
    keys.join_session_keyring(&caller, None).unwrap();
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    let label = keys.get_security(&caller, key, NOW).unwrap();
    assert_eq!(label.as_bytes(), [0]);
    assert_eq!(label.for_buffer(1), [0]);
    assert!(label.for_buffer(0).is_empty());

    let no_view = add_user(&mut keys, &caller, "k_no_view", PROCESS_KEYRING);
    keys.set_permissions(&caller, no_view, PERM_ALL & !every_class(VIEW), NOW)
        .unwrap();
    assert_eq!(keys.describe(&caller, i32::MAX, NOW), Err(Error::NoKey));
    assert_eq!(
        keys.describe(&caller, no_view, NOW),
        Err(Error::AccessDenied)
    );
    assert_eq!(keys.get_security(&caller, i32::MAX, NOW), Err(Error::NoKey));
    assert_eq!(keys.get_security(&caller, no_view, NOW), Err(Error::NoKey));
}

#[test]
fn permissions_take_one_class_plus_possession() {
    let mut keys = Keyrings::new();
    let owner = person(1000, 10);
    // Another thread of the owner's process, with no session keyring and
    // so possessing nothing of the first thread's.
    let owner_elsewhere = Caller { tid: 11, ..owner };
    let member = Caller {
        groups: &[1000],
        ..person(3000, 30)
    };
    let stranger = person(2000, 20);
    keys.join_session_keyring(&owner, None).unwrap();
    let key = add_user(&mut keys, &owner, "k", SESSION_KEYRING);

    // Default: everything for the possessor, view for the owner.
    assert!(keys.read(&owner, key, NOW).is_ok());
    assert!(keys.describe(&owner_elsewhere, key, NOW).is_ok());
    assert_eq!(
        keys.read(&owner_elsewhere, key, NOW),
        Err(Error::AccessDenied)
    );
    assert_eq!(keys.describe(&stranger, key, NOW), Err(Error::AccessDenied));

    // The classes are exclusive: the owner gets the user byte only.
    let mask = possessor(ALL) | other(VIEW | READ);
    keys.set_permissions(&owner, key, mask, NOW).unwrap();
    assert_eq!(
        keys.describe(&owner_elsewhere, key, NOW),
        Err(Error::AccessDenied)
    );
    assert!(keys.read(&stranger, key, NOW).is_ok());

    // The group byte applies to members only while it grants something.
    keys.set_permissions(&owner, key, possessor(ALL) | group(VIEW), NOW)
        .unwrap();
    assert!(keys.describe(&member, key, NOW).is_ok());
    assert_eq!(keys.describe(&stranger, key, NOW), Err(Error::AccessDenied));
    keys.set_permissions(&owner, key, possessor(ALL) | other(VIEW), NOW)
        .unwrap();
    assert!(keys.describe(&member, key, NOW).is_ok());
}

/// keyrings(7): a key that does not grant search permission is not
/// possessed; a possessed key may be read without read permission.
#[test]
fn possession_needs_search_and_grants_reading() {
    let mut keys = Keyrings::new();
    let owner = person(1000, 10);
    keys.join_session_keyring(&owner, None).unwrap();
    let key = add_user(&mut keys, &owner, "k", SESSION_KEYRING);
    let unsearchable = possessor(VIEW | READ | SET_ATTRIBUTE) | user(SET_ATTRIBUTE);
    keys.set_permissions(&owner, key, unsearchable, NOW)
        .unwrap();
    assert_eq!(keys.describe(&owner, key, NOW), Err(Error::AccessDenied));
    assert_eq!(keys.read(&owner, key, NOW), Err(Error::AccessDenied));

    keys.set_permissions(&owner, key, possessor(VIEW | SEARCH | SET_ATTRIBUTE), NOW)
        .unwrap();
    assert!(keys.describe(&owner, key, NOW).is_ok());
    assert_eq!(keys.read(&owner, key, NOW).unwrap().as_bytes(), b"payload");
}

#[test]
fn reading_depends_on_type_state_and_time() {
    let mut keys = Keyrings::new();
    let caller = root();
    let logon = keys
        .add_key(&caller, b"logon", b"svc:k", b"secret", PROCESS_KEYRING, NOW)
        .unwrap();
    assert_eq!(keys.read(&caller, logon, NOW), Err(Error::NotSupported));
    keys.revoke(&caller, logon, NOW).unwrap();
    assert_eq!(keys.read(&caller, logon, NOW), Err(Error::NotSupported));

    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    keys.set_timeout(&caller, key, 1, NOW).unwrap();
    assert!(keys.read(&caller, key, NOW + SECOND / 2).is_ok());
    assert_eq!(
        keys.read(&caller, key, NOW + SECOND),
        Err(Error::KeyExpired)
    );
    assert_eq!(
        keys.read(&caller, PROCESS_KEYRING, NOW + SECOND)
            .unwrap()
            .len(),
        8
    );
}

/// keyctl01 and keyctl04, and the special ids that never resolve.
#[test]
fn special_keyrings_are_created_on_demand() {
    let mut keys = Keyrings::new();
    let caller = root();
    assert_eq!(
        keys.get_keyring_id(&caller, THREAD_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    let thread = keys
        .get_keyring_id(&caller, THREAD_KEYRING, true, NOW)
        .unwrap();
    assert_eq!(
        keys.get_keyring_id(&caller, THREAD_KEYRING, false, NOW),
        Ok(thread)
    );
    assert_eq!(
        keys.set_request_default(&caller, request_default::THREAD),
        Ok(0)
    );
    assert_eq!(
        keys.get_keyring_id(&caller, THREAD_KEYRING, false, NOW),
        Ok(thread)
    );
    assert_eq!(
        keys.set_request_default(&caller, request_default::NO_CHANGE),
        Ok(1)
    );
    assert_eq!(
        described(&mut keys, &caller, thread),
        "keyring;0;0;3f010000;_tid\0"
    );

    assert_eq!(
        keys.get_keyring_id(&caller, PROCESS_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.set_request_default(&caller, request_default::PROCESS),
        Ok(1)
    );
    let process = keys
        .get_keyring_id(&caller, PROCESS_KEYRING, false, NOW)
        .unwrap();
    assert_eq!(
        described(&mut keys, &caller, process),
        "keyring;0;0;3f010000;_pid\0"
    );

    assert!(keys
        .get_keyring_id(&caller, USER_SESSION_KEYRING, false, NOW)
        .is_ok());
    assert_eq!(
        keys.get_keyring_id(&caller, GROUP_KEYRING, true, NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        keys.get_keyring_id(&caller, REQUEST_KEY_AUTH_KEY, true, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.get_keyring_id(&caller, REQUESTOR_KEYRING, true, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.get_keyring_id(&caller, -9, true, NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        keys.get_keyring_id(&caller, 0, true, NOW),
        Err(Error::Invalid)
    );
    assert_eq!(keys.revoke(&caller, i32::MAX, NOW), Err(Error::NoKey));

    for invalid in [request_default::GROUP, 8, -2] {
        assert_eq!(
            keys.set_request_default(&caller, invalid),
            Err(Error::Invalid)
        );
    }
}

#[test]
fn a_thread_without_a_session_gets_the_user_session_keyring() {
    let mut keys = Keyrings::new();
    let caller = person(1000, 10);
    let session = keys
        .get_keyring_id(&caller, SESSION_KEYRING, false, NOW)
        .unwrap();
    let user_session = keys
        .get_keyring_id(&caller, USER_SESSION_KEYRING, false, NOW)
        .unwrap();
    let user_keyring = keys
        .get_keyring_id(&caller, USER_KEYRING, false, NOW)
        .unwrap();
    assert_eq!(session, user_session);
    assert_eq!(
        described(&mut keys, &caller, session),
        "keyring;1000;65534;1f3f0000;_uid_ses.1000\0"
    );
    assert_eq!(links(&mut keys, &caller, session), [user_keyring]);

    // Changing the session keyring makes a real one first.
    let key = add_user(&mut keys, &caller, "k", SESSION_KEYRING);
    let new_session = keys
        .get_keyring_id(&caller, SESSION_KEYRING, false, NOW)
        .unwrap();
    assert_ne!(new_session, user_session);
    assert_eq!(
        described(&mut keys, &caller, new_session),
        "keyring;1000;1000;3f030000;_ses\0"
    );
    assert_eq!(links(&mut keys, &caller, new_session), [key]);
}

/// add_key03: keyrings named like another user's cannot become theirs.
#[test]
fn user_keyrings_are_found_by_uid_not_by_name() {
    let mut keys = Keyrings::new();
    let caller = root();
    let fake_user = add_ring(&mut keys, &caller, "_uid.1", PROCESS_KEYRING);
    let fake_session = add_ring(&mut keys, &caller, "_uid_ses.1", PROCESS_KEYRING);
    let user_one = person(1, 100);
    assert_ne!(
        keys.get_keyring_id(&user_one, USER_KEYRING, true, NOW),
        Ok(fake_user)
    );
    assert_ne!(
        keys.get_keyring_id(&user_one, USER_SESSION_KEYRING, true, NOW),
        Ok(fake_session)
    );
}

/// keyctl08, and joining by name.
#[test]
fn joining_session_keyrings() {
    let mut keys = Keyrings::new();
    let caller = root();
    let first = keys.join_session_keyring(&caller, None).unwrap();
    let second = keys.join_session_keyring(&caller, None).unwrap();
    assert_ne!(first, second);
    assert_eq!(keys.describe(&caller, first, NOW), Err(Error::NoKey));
    assert_eq!(
        keys.join_session_keyring(&caller, Some(b".builtin_trusted_keys")),
        Err(Error::NotPermitted)
    );

    let named = keys.join_session_keyring(&caller, Some(b"shared")).unwrap();
    assert_eq!(
        described(&mut keys, &caller, named),
        "keyring;0;0;3f130000;shared\0"
    );
    // Finding a keyring by name needs search permission granted without
    // possession, which a named session keyring does not give its owner by
    // default: joining the name again makes a new keyring of that name.
    let other_process = Caller {
        pid: 200,
        tid: 200,
        ..caller
    };
    let shadow = keys
        .join_session_keyring(&other_process, Some(b"shared"))
        .unwrap();
    assert_ne!(shadow, named);

    let searchable = NAMED_SESSION_PERMISSIONS | user(SEARCH);
    keys.set_permissions(&caller, named, searchable, NOW)
        .unwrap();
    assert_eq!(keys.join_session_keyring(&caller, Some(b"shared")), Ok(0));
    let third = Caller {
        pid: 300,
        tid: 300,
        ..caller
    };
    assert_eq!(
        keys.join_session_keyring(&third, Some(b"shared")),
        Ok(named)
    );
    assert_eq!(
        keys.get_keyring_id(&third, SESSION_KEYRING, false, NOW),
        Ok(named)
    );
    let stranger = person(1000, 400);
    assert_ne!(
        keys.join_session_keyring(&stranger, Some(b"shared")),
        Ok(named)
    );
}

/// add_key04: a forked child shares the session keyring.
#[test]
fn a_forked_child_shares_the_session_keyring_only() {
    let mut keys = Keyrings::new();
    let parent = root();
    let session = keys.join_session_keyring(&parent, None).unwrap();
    keys.get_keyring_id(&parent, THREAD_KEYRING, true, NOW)
        .unwrap();
    keys.get_keyring_id(&parent, PROCESS_KEYRING, true, NOW)
        .unwrap();
    keys.fork(&parent, 101).unwrap();
    let child = Caller {
        pid: 101,
        tid: 101,
        ..parent
    };
    for index in 0..16 {
        add_ring(
            &mut keys,
            &child,
            &format!("keyring{index}"),
            SESSION_KEYRING,
        );
    }
    let key = add_user(&mut keys, &child, "userkey", SESSION_KEYRING);
    assert_eq!(
        keys.get_keyring_id(&child, SESSION_KEYRING, false, NOW),
        Ok(session)
    );
    assert_eq!(
        links(&mut keys, &parent, SESSION_KEYRING).last(),
        Some(&key)
    );
    assert_eq!(
        keys.get_keyring_id(&child, THREAD_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.get_keyring_id(&child, PROCESS_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    keys.exit_thread(101);
    keys.exit_process(101);
    assert_eq!(links(&mut keys, &parent, SESSION_KEYRING).len(), 17);
}

#[test]
fn threads_share_the_process_keyring_and_get_their_own_thread_keyring() {
    let mut keys = Keyrings::new();
    let parent = root();
    let parent_thread = keys
        .get_keyring_id(&parent, THREAD_KEYRING, true, NOW)
        .unwrap();
    let process = keys
        .get_keyring_id(&parent, PROCESS_KEYRING, true, NOW)
        .unwrap();
    keys.spawn_thread(&parent, 102).unwrap();
    let thread = Caller { tid: 102, ..parent };
    assert_eq!(
        keys.get_keyring_id(&thread, PROCESS_KEYRING, false, NOW),
        Ok(process)
    );
    let own = keys
        .get_keyring_id(&thread, THREAD_KEYRING, false, NOW)
        .unwrap();
    assert_ne!(own, parent_thread);

    keys.exec(100, 100);
    assert_eq!(
        keys.get_keyring_id(&parent, THREAD_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.get_keyring_id(&parent, PROCESS_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.describe(&parent, parent_thread, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(keys.describe(&parent, process, NOW), Err(Error::NoKey));
}

#[test]
fn exiting_frees_keys_and_their_quota() {
    let mut keys = Keyrings::new();
    let caller = person(1000, 10);
    add_user(&mut keys, &caller, "k", THREAD_KEYRING);
    assert_eq!(usage(&keys, 1000).map(|(count, _)| count), Some(2));
    keys.exit_thread(10);
    keys.exit_process(10);
    assert_eq!(usage(&keys, 1000), None);
    assert!(keys.keys.is_empty());
}

/// request_key01.
#[test]
fn request_key_finds_keys_in_the_callers_keyrings() {
    let mut keys = Keyrings::new();
    let caller = root();
    let ring = add_ring(&mut keys, &caller, "ltp", THREAD_KEYRING);
    assert_eq!(
        keys.request_key(&caller, b"keyring", b"ltp", None, 0, NOW),
        Ok(ring)
    );
    assert_eq!(
        keys.request_key(&caller, b"user", b"absent", None, 0, NOW),
        Err(Error::NoKey)
    );
    // A destination gets a link to what was found.
    let destination = add_ring(&mut keys, &caller, "destination", PROCESS_KEYRING);
    assert_eq!(
        keys.request_key(&caller, b"keyring", b"ltp", None, destination, NOW),
        Ok(ring)
    );
    assert_eq!(links(&mut keys, &caller, destination), [ring]);
}

/// request_key02.
#[test]
fn request_key_reports_revoked_and_expired_matches() {
    let mut keys = Keyrings::new();
    let caller = root();
    let revoked = add_ring(&mut keys, &caller, "ltp2", THREAD_KEYRING);
    keys.revoke(&caller, revoked, NOW).unwrap();
    let expired = add_ring(&mut keys, &caller, "ltp3", THREAD_KEYRING);
    keys.set_timeout(&caller, expired, 1, NOW).unwrap();
    let later = NOW + 2 * SECOND;
    let request = |keys: &mut Keyrings, description: &[u8], destination| {
        keys.request_key(&caller, b"keyring", description, None, destination, later)
    };
    assert_eq!(request(&mut keys, b"ltp1", 0), Err(Error::NoKey));
    assert_eq!(request(&mut keys, b"ltp2", revoked), Err(Error::KeyRevoked));
    assert_eq!(request(&mut keys, b"ltp2", 0), Err(Error::KeyRevoked));
    assert_eq!(request(&mut keys, b"ltp3", expired), Err(Error::KeyExpired));
    assert_eq!(request(&mut keys, b"ltp3", 0), Err(Error::KeyExpired));
}

/// keyctl07 and request_key03: with callout data and nothing found, a
/// negative key is left behind; add_key instantiates it.
#[test]
fn request_key_with_a_callout_leaves_a_negative_key() {
    let mut keys = Keyrings::new();
    let caller = root();
    assert_eq!(
        keys.request_key(
            &caller,
            b"user",
            b"description",
            Some(b"callout_info"),
            PROCESS_KEYRING,
            NOW
        ),
        Err(Error::NoKey)
    );
    let found = links(&mut keys, &caller, PROCESS_KEYRING);
    assert_eq!(found.len(), 1);
    let negative = found[0];
    assert_eq!(keys.read(&caller, negative, NOW), Err(Error::NoKey));
    assert_eq!(keys.update(&caller, negative, b"x", NOW), Err(Error::NoKey));
    assert_eq!(
        described(&mut keys, &caller, negative),
        "user;0;0;3f010000;description\0"
    );
    assert_eq!(
        keys.request_key(
            &caller,
            b"user",
            b"description",
            Some(b"callout_info"),
            0,
            NOW
        ),
        Err(Error::NoKey)
    );
    assert_eq!(links(&mut keys, &caller, PROCESS_KEYRING), [negative]);

    let updated = keys
        .add_key(
            &caller,
            b"user",
            b"description",
            b"payload",
            PROCESS_KEYRING,
            NOW,
        )
        .unwrap();
    assert_eq!(updated, negative);
    assert_eq!(
        keys.read(&caller, negative, NOW + 3600 * SECOND)
            .unwrap()
            .as_bytes(),
        b"payload"
    );

    // keyctl03: a negative keyring in the thread keyring.
    assert_eq!(
        keys.request_key(
            &caller,
            b"keyring",
            b"foo",
            Some(b"bar"),
            THREAD_KEYRING,
            NOW
        ),
        Err(Error::NoKey)
    );
    let after_timeout = NOW + NEGATIVE_TIMEOUT_SECONDS * SECOND;
    assert_eq!(
        keys.request_key(&caller, b"keyring", b"foo", None, 0, after_timeout),
        Err(Error::KeyExpired)
    );
}

/// request_key04: the default destination must be writable.
#[test]
fn request_key_needs_write_permission_on_the_default_keyring() {
    let mut keys = Keyrings::new();
    let caller = root();
    keys.join_session_keyring(&caller, None).unwrap();
    keys.set_permissions(
        &caller,
        SESSION_KEYRING,
        possessor(SEARCH | READ | VIEW),
        NOW,
    )
    .unwrap();
    assert_eq!(
        keys.set_request_default(&caller, request_default::SESSION),
        Ok(0)
    );
    assert!(keys.read(&caller, SESSION_KEYRING, NOW).unwrap().is_empty());
    assert_eq!(
        keys.request_key(&caller, b"user", b"desc", Some(b"callout_info"), 0, NOW),
        Err(Error::AccessDenied)
    );
    assert!(keys.read(&caller, SESSION_KEYRING, NOW).unwrap().is_empty());
}

/// request_key05 and request_key06.
#[test]
fn request_key_refuses_reserved_and_unknown_types() {
    let mut keys = Keyrings::new();
    let caller = root();
    assert_eq!(
        keys.request_key(
            &caller,
            b".type",
            b"description",
            None,
            PROCESS_KEYRING,
            NOW
        ),
        Err(Error::NotPermitted)
    );
    assert_eq!(
        keys.request_key(&caller, b"dead", b"abc", Some(b"abc"), 0, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.request_key(&caller, b"user", b"d", Some(&[b'c'; CALLOUT_LIMIT]), 0, NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn search_descends_through_keyrings_it_may_search() {
    let mut keys = Keyrings::new();
    let caller = root();
    let outer = add_ring(&mut keys, &caller, "outer", PROCESS_KEYRING);
    let inner = add_ring(&mut keys, &caller, "inner", outer);
    let deep = add_user(&mut keys, &caller, "deep", inner);
    let search = |keys: &mut Keyrings, ring, key_type: &[u8], destination| {
        keys.search(&caller, ring, key_type, b"deep", destination, NOW)
    };
    assert_eq!(search(&mut keys, outer, b"user", 0), Ok(deep));
    assert_eq!(search(&mut keys, PROCESS_KEYRING, b"user", 0), Ok(deep));
    assert_eq!(search(&mut keys, outer, b"logon", 0), Err(Error::NoKey));
    assert_eq!(
        search(&mut keys, outer, b"nosuchtype", 0),
        Err(Error::NoKey)
    );
    assert_eq!(
        search(&mut keys, outer, b".type", 0),
        Err(Error::NotPermitted)
    );
    let plain = add_user(&mut keys, &caller, "plain", PROCESS_KEYRING);
    assert_eq!(
        search(&mut keys, plain, b"user", 0),
        Err(Error::NotDirectory)
    );

    let destination = add_ring(&mut keys, &caller, "destination", PROCESS_KEYRING);
    assert_eq!(search(&mut keys, outer, b"user", destination), Ok(deep));
    assert_eq!(links(&mut keys, &caller, destination), [deep]);
    keys.unlink(&caller, deep, destination, NOW).unwrap();

    // Keeping the owner's set-attribute right lets the mask be restored
    // once the keyring is no longer possessed.
    let mask = possessor(ALL & !SEARCH) | user(SET_ATTRIBUTE);
    keys.set_permissions(&caller, inner, mask, NOW).unwrap();
    assert_eq!(search(&mut keys, outer, b"user", 0), Err(Error::NoKey));

    // A matching key that may not be found reports EACCES.
    keys.set_permissions(&caller, inner, possessor(ALL), NOW)
        .unwrap();
    keys.set_permissions(&caller, deep, mask, NOW).unwrap();
    assert_eq!(
        search(&mut keys, outer, b"user", 0),
        Err(Error::AccessDenied)
    );
}

#[test]
fn links_refuse_cycles_and_deep_nesting() {
    let mut keys = Keyrings::new();
    let caller = root();
    let outer = add_ring(&mut keys, &caller, "a", PROCESS_KEYRING);
    let inner = add_ring(&mut keys, &caller, "b", outer);
    assert_eq!(keys.link(&caller, outer, outer, NOW), Err(Error::Deadlock));
    assert_eq!(keys.link(&caller, outer, inner, NOW), Err(Error::Deadlock));
    let plain = add_user(&mut keys, &caller, "plain", PROCESS_KEYRING);
    assert_eq!(
        keys.link(&caller, plain, plain, NOW),
        Err(Error::NotDirectory)
    );
    assert_eq!(keys.link(&caller, plain, outer, NOW), Ok(()));
    assert_eq!(keys.link(&caller, plain, outer, NOW), Ok(()));
    assert_eq!(links(&mut keys, &caller, outer), [inner, plain]);

    // A chain of eight keyrings: the top one nests seven deep.
    let mut chain = vec![add_ring(&mut keys, &caller, "r0", PROCESS_KEYRING)];
    for level in 1..8 {
        let parent = *chain.last().unwrap();
        chain.push(add_ring(&mut keys, &caller, &format!("r{level}"), parent));
    }
    let top = add_ring(&mut keys, &caller, "top", PROCESS_KEYRING);
    assert_eq!(keys.link(&caller, chain[0], top, NOW), Err(Error::TooDeep));
    assert_eq!(keys.link(&caller, chain[1], top, NOW), Ok(()));
}

#[test]
fn unlinking_needs_only_the_keyring() {
    let mut keys = Keyrings::new();
    let caller = root();
    let ring = add_ring(&mut keys, &caller, "ring", PROCESS_KEYRING);
    let key = add_user(&mut keys, &caller, "k", ring);
    let elsewhere = add_user(&mut keys, &caller, "elsewhere", PROCESS_KEYRING);
    assert_eq!(
        keys.unlink(&caller, elsewhere, ring, NOW),
        Err(Error::NotFound)
    );
    assert_eq!(
        keys.unlink(&caller, key, elsewhere, NOW),
        Err(Error::NotDirectory)
    );
    keys.revoke(&caller, key, NOW).unwrap();
    keys.set_permissions(&caller, elsewhere, 0, NOW).unwrap();
    assert_eq!(keys.unlink(&caller, key, ring, NOW), Ok(()));
    assert_eq!(
        keys.unlink(&caller, elsewhere, PROCESS_KEYRING, NOW),
        Ok(())
    );
    assert_eq!(keys.revoke(&caller, key, NOW), Err(Error::NoKey));
    assert_eq!(keys.revoke(&caller, elsewhere, NOW), Err(Error::NoKey));
}

/// keyctl18 to keyctl21.
#[test]
fn moving_keys_between_keyrings() {
    let mut keys = Keyrings::new();
    let caller = root();
    keys.join_session_keyring(&caller, None).unwrap();
    let ring_a = add_ring(&mut keys, &caller, "ltpkeyctl21_a", PROCESS_KEYRING);
    let ring_b = add_ring(&mut keys, &caller, "ltpkeyctl21_b", PROCESS_KEYRING);
    let ring_c = add_ring(&mut keys, &caller, "ltpkeyctl21_c", PROCESS_KEYRING);
    let no_write = add_ring(&mut keys, &caller, "ltpkeyctl21_nowrite", PROCESS_KEYRING);
    keys.set_permissions(&caller, no_write, PERM_ALL & !every_class(WRITE), NOW)
        .unwrap();
    let key_a = add_user(&mut keys, &caller, "ka", ring_a);
    let key_b = add_user(&mut keys, &caller, "kb", ring_b);
    let key_excl = add_user(&mut keys, &caller, "ka", ring_b);
    keys.link(&caller, key_excl, SESSION_KEYRING, NOW).unwrap();
    keys.link(&caller, ring_c, ring_b, NOW).unwrap();

    let bogus = i32::MAX;
    let cases = [
        (key_a, ring_a, ring_b, MOVE_EXCLUSIVE, Error::Exists),
        (key_a, ring_a, ring_b, 2, Error::Invalid),
        (bogus, ring_a, ring_b, 0, Error::NoKey),
        (key_a, bogus, ring_b, 0, Error::NoKey),
        (key_a, ring_a, bogus, 0, Error::NoKey),
        (key_a, key_b, ring_b, 0, Error::NotDirectory),
        (key_a, ring_a, key_b, 0, Error::NotDirectory),
        (key_b, ring_a, ring_b, 0, Error::NotFound),
        (ring_c, ring_b, ring_c, 0, Error::Deadlock),
        (key_a, ring_a, no_write, 0, Error::AccessDenied),
    ];
    for (key, from, to, flags, error) in cases {
        assert_eq!(
            keys.move_key(&caller, key, from, to, flags, NOW),
            Err(error)
        );
    }

    // keyctl20: the move displaces key_excl, which the session keeps.
    assert_eq!(
        keys.move_key(&caller, key_a, ring_a, ring_b, 0, NOW),
        Ok(())
    );
    assert_eq!(
        keys.search(&caller, ring_b, b"user", b"ka", 0, NOW),
        Ok(key_a)
    );
    assert_eq!(
        keys.search(&caller, ring_a, b"user", b"ka", 0, NOW),
        Err(Error::NoKey)
    );
    assert!(keys.describe(&caller, key_excl, NOW).is_ok());
    // keyctl19.
    assert_eq!(
        keys.move_key(&caller, key_a, ring_b, ring_b, 0, NOW),
        Ok(())
    );
    assert_eq!(
        keys.search(&caller, ring_b, b"user", b"ka", 0, NOW),
        Ok(key_a)
    );
    // keyctl18 run again: the key is linked back and moved onto itself.
    keys.link(&caller, key_a, ring_a, NOW).unwrap();
    assert_eq!(
        keys.move_key(&caller, key_a, ring_a, ring_b, 0, NOW),
        Ok(())
    );
    assert_eq!(
        keys.search(&caller, ring_a, b"user", b"ka", 0, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.search(&caller, ring_b, b"user", b"ka", 0, NOW),
        Ok(key_a)
    );
}

/// keyctl22, keyctl23 and keyctl24.
#[test]
fn restricting_keyrings() {
    let mut keys = Keyrings::new();
    let caller = root();
    keys.join_session_keyring(&caller, None).unwrap();
    let reject = add_ring(&mut keys, &caller, "ltpkeyctl22_reject", PROCESS_KEYRING);
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    assert_eq!(
        keys.restrict_keyring(&caller, reject, None, None, NOW),
        Ok(())
    );
    assert_eq!(
        keys.restrict_keyring(&caller, reject, None, None, NOW),
        Err(Error::Exists)
    );
    assert_eq!(
        keys.link(&caller, key, reject, NOW),
        Err(Error::NotPermitted)
    );
    assert_eq!(
        keys.add_key(&caller, b"user", b"k_rej", b"payload", reject, NOW),
        Err(Error::NotPermitted)
    );

    let fresh = add_ring(&mut keys, &caller, "ltpkeyctl24_fresh", PROCESS_KEYRING);
    let no_setattr = add_ring(
        &mut keys,
        &caller,
        "ltpkeyctl24_no_setattr",
        PROCESS_KEYRING,
    );
    keys.set_permissions(
        &caller,
        no_setattr,
        PERM_ALL & !every_class(SET_ATTRIBUTE),
        NOW,
    )
    .unwrap();
    let restrict =
        |keys: &mut Keyrings, id, key_type: Option<&[u8]>, restriction: Option<&[u8]>| {
            keys.restrict_keyring(&caller, id, key_type, restriction, NOW)
        };
    let trusted: Option<&[u8]> = Some(b"builtin_trusted");
    assert_eq!(
        restrict(&mut keys, fresh, None, trusted),
        Err(Error::Invalid)
    );
    assert_eq!(
        restrict(&mut keys, fresh, Some(b"asymmetric"), None),
        Err(Error::Invalid)
    );
    assert_eq!(
        restrict(&mut keys, key, None, None),
        Err(Error::NotDirectory)
    );
    assert_eq!(
        restrict(&mut keys, fresh, Some(b"nosuchtype"), trusted),
        Err(Error::NoKey)
    );
    assert_eq!(
        restrict(&mut keys, fresh, Some(b"user"), trusted),
        Err(Error::NotFound)
    );
    // keyctl_common.h's is_asym_supported(): ENOKEY would mean no
    // asymmetric keys; an unknown scheme is EINVAL.
    assert_eq!(
        restrict(&mut keys, fresh, Some(b"asymmetric"), Some(b"bogus")),
        Err(Error::Invalid)
    );
    assert_eq!(
        restrict(&mut keys, no_setattr, None, None),
        Err(Error::AccessDenied)
    );
    assert_eq!(restrict(&mut keys, fresh, None, None), Ok(()));
}

#[test]
fn revoking_needs_write_or_setattr_and_empties_keyrings() {
    let mut keys = Keyrings::new();
    let caller = root();
    let ring = add_ring(&mut keys, &caller, "ring", PROCESS_KEYRING);
    let inside = add_user(&mut keys, &caller, "inside", ring);
    keys.revoke(&caller, ring, NOW).unwrap();
    assert_eq!(keys.read(&caller, ring, NOW), Err(Error::KeyRevoked));
    assert_eq!(keys.describe(&caller, ring, NOW), Err(Error::KeyRevoked));
    assert_eq!(keys.describe(&caller, inside, NOW), Err(Error::NoKey));

    let setattr_only = add_user(&mut keys, &caller, "setattr", PROCESS_KEYRING);
    keys.set_permissions(
        &caller,
        setattr_only,
        possessor(VIEW | SEARCH | SET_ATTRIBUTE),
        NOW,
    )
    .unwrap();
    assert_eq!(keys.revoke(&caller, setattr_only, NOW), Ok(()));
    let neither = add_user(&mut keys, &caller, "neither", PROCESS_KEYRING);
    keys.set_permissions(&caller, neither, possessor(VIEW | SEARCH), NOW)
        .unwrap();
    assert_eq!(keys.revoke(&caller, neither, NOW), Err(Error::AccessDenied));
}

#[test]
fn invalidating_removes_a_key_everywhere() {
    let mut keys = Keyrings::new();
    let caller = person(1000, 10);
    let ring = add_ring(&mut keys, &caller, "ring", PROCESS_KEYRING);
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    keys.link(&caller, key, ring, NOW).unwrap();
    let before = usage(&keys, 1000).unwrap();
    assert_eq!(keys.invalidate(&caller, key, NOW), Ok(()));
    assert_eq!(keys.describe(&caller, key, NOW), Err(Error::NoKey));
    assert_eq!(links(&mut keys, &caller, PROCESS_KEYRING), [ring]);
    assert!(links(&mut keys, &caller, ring).is_empty());
    let after = usage(&keys, 1000).unwrap();
    let key_bytes = "k".len() + 1 + "payload".len();
    assert_eq!(after, (before.0 - 1, before.1 - key_bytes - 2 * 4));

    // An anchored keyring lingers, invalid, until its anchor lets go.
    let session = keys.join_session_keyring(&caller, None).unwrap();
    assert_eq!(keys.invalidate(&caller, SESSION_KEYRING, NOW), Ok(()));
    assert_eq!(
        keys.get_keyring_id(&caller, SESSION_KEYRING, false, NOW),
        Err(Error::NoKey)
    );
    assert_ne!(keys.join_session_keyring(&caller, None), Ok(session));
    assert!(keys.key(session).is_none());
}

#[test]
fn timeouts_expire_keys_until_add_key_updates_them() {
    let mut keys = Keyrings::new();
    let caller = root();
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    keys.set_timeout(&caller, key, 5, NOW).unwrap();
    assert!(keys.read(&caller, key, NOW + 4 * SECOND).is_ok());
    let expired = NOW + 5 * SECOND;
    assert_eq!(keys.read(&caller, key, expired), Err(Error::KeyExpired));
    assert_eq!(keys.describe(&caller, key, expired), Err(Error::KeyExpired));
    assert_eq!(
        keys.set_timeout(&caller, key, 0, expired),
        Err(Error::KeyExpired)
    );
    let updated = keys
        .add_key(&caller, b"user", b"k", b"fresh", PROCESS_KEYRING, expired)
        .unwrap();
    assert_eq!(updated, key);
    assert!(keys.read(&caller, key, NOW + 3600 * SECOND).is_ok());
    keys.set_timeout(&caller, key, 5, NOW).unwrap();
    keys.set_timeout(&caller, key, 0, NOW).unwrap();
    assert!(keys.read(&caller, key, NOW + 3600 * SECOND).is_ok());
}

#[test]
fn setting_permissions_and_owners() {
    let mut keys = Keyrings::new();
    let owner = Caller {
        groups: &[50],
        ..person(1000, 10)
    };
    let key = add_user(&mut keys, &owner, "k", PROCESS_KEYRING);
    assert_eq!(
        keys.set_permissions(&owner, key, 0x4000_0000, NOW),
        Err(Error::Invalid)
    );
    assert_eq!(keys.chown(&owner, i32::MAX, None, None, NOW), Ok(()));
    assert_eq!(
        keys.chown(&owner, key, Some(2000), None, NOW),
        Err(Error::AccessDenied)
    );
    assert_eq!(keys.chown(&owner, key, Some(1000), Some(50), NOW), Ok(()));
    assert_eq!(
        keys.chown(&owner, key, None, Some(60), NOW),
        Err(Error::AccessDenied)
    );
    assert_eq!(
        described(&mut keys, &owner, key),
        "user;1000;50;3f010000;k\0"
    );

    // Another user may set attributes but not permissions on a key it
    // does not own; privilege may do both.
    let stranger = person(2000, 20);
    keys.set_permissions(&owner, key, possessor(ALL) | other(ALL), NOW)
        .unwrap();
    assert_eq!(
        keys.set_permissions(&stranger, key, other(ALL), NOW),
        Err(Error::AccessDenied)
    );
    let admin = Caller {
        privileged: true,
        ..stranger
    };
    assert_eq!(keys.set_permissions(&admin, key, PERM_ALL, NOW), Ok(()));
    assert_eq!(keys.chown(&admin, key, Some(2000), Some(60), NOW), Ok(()));
    assert_eq!(
        described(&mut keys, &owner, key),
        "user;2000;60;3f3f3f3f;k\0"
    );
    let key_bytes = "k".len() + 1 + "payload".len();
    assert_eq!(usage(&keys, 2000), Some((1, key_bytes)));

    // The new owner's quota must have room.
    let limits = Limits {
        max_bytes: 5,
        ..Limits::LINUX
    };
    keys.set_limits(limits).unwrap();
    assert_eq!(
        keys.chown(&admin, key, Some(3000), None, NOW),
        Err(Error::QuotaExceeded)
    );
    assert_eq!(
        keys.set_limits(Limits {
            max_keys: 0,
            ..limits
        }),
        Err(Error::Invalid)
    );
}

/// add_key05: a user reaches the byte and key limits exactly.
#[test]
fn quotas_can_be_reached_exactly() {
    let mut keys = Keyrings::new();
    let payload = [b'x'; 64];
    let bytes_user = person(1001, 10);
    let add = |keys: &mut Keyrings, caller: &Caller, description: &str, payload: &[u8]| {
        keys.add_key(
            caller,
            b"user",
            description.as_bytes(),
            payload,
            THREAD_KEYRING,
            NOW,
        )
    };
    add(&mut keys, &bytes_user, "test1", &payload).unwrap();
    let (_, before) = usage(&keys, 1001).unwrap();
    add(&mut keys, &bytes_user, "test2", &payload).unwrap();
    let (_, used) = usage(&keys, 1001).unwrap();
    let delta = used - before - "test2".len() - 1 - 64;
    let max = Limits::LINUX.max_bytes as usize;
    let invalid = vec![b'x'; max - used - delta - "test_xxx".len()];
    assert_eq!(
        add(&mut keys, &bytes_user, "test_inv", &invalid),
        Err(Error::QuotaExceeded)
    );
    add(&mut keys, &bytes_user, "test3", &payload).unwrap();
    add(&mut keys, &bytes_user, "test4", &payload).unwrap();
    let (_, used) = usage(&keys, 1001).unwrap();
    let exact = vec![b'x'; max - used - delta - "test_xxx".len() - 1];
    assert!(add(&mut keys, &bytes_user, "test_max", &exact).is_ok());
    assert_eq!(usage(&keys, 1001).unwrap().1, max);

    let count_user = person(1002, 20);
    add(&mut keys, &count_user, "test1", &payload).unwrap();
    let (used, _) = usage(&keys, 1002).unwrap();
    for index in used + 1..=Limits::LINUX.max_keys {
        add(&mut keys, &count_user, &format!("abc{index}"), &payload).unwrap();
    }
    assert_eq!(
        add(&mut keys, &count_user, "test_invalid_key", &payload),
        Err(Error::QuotaExceeded)
    );
    assert_eq!(usage(&keys, 1002).unwrap().0, Limits::LINUX.max_keys);
}

#[test]
fn updates_need_an_updatable_type_and_room() {
    let mut keys = Keyrings::new();
    let caller = root();
    let ring = add_ring(&mut keys, &caller, "ring", PROCESS_KEYRING);
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    // keyctl05.
    keys.set_permissions(&caller, ring, possessor(ALL), NOW)
        .unwrap();
    assert_eq!(
        keys.update(&caller, ring, b"x", NOW),
        Err(Error::NotSupported)
    );
    assert_eq!(
        keys.update(&caller, key, &[0; UPDATE_LIMIT + 1], NOW),
        Err(Error::Invalid)
    );
    assert_eq!(keys.update(&caller, key, &[], NOW), Err(Error::Invalid));
    assert_eq!(keys.update(&caller, key, b"b", NOW), Ok(()));
    assert_eq!(keys.read(&caller, key, NOW).unwrap().as_bytes(), b"b");
    keys.set_permissions(&caller, key, possessor(ALL & !WRITE), NOW)
        .unwrap();
    assert_eq!(
        keys.update(&caller, key, b"c", NOW),
        Err(Error::AccessDenied)
    );

    let small = person(1000, 10);
    keys.set_limits(Limits {
        max_bytes: 30,
        ..Limits::LINUX
    })
    .unwrap();
    let key = add_user(&mut keys, &small, "k", THREAD_KEYRING);
    assert_eq!(
        keys.update(&small, key, &[b'x'; 30], NOW),
        Err(Error::QuotaExceeded)
    );
    assert_eq!(keys.read(&small, key, NOW).unwrap().as_bytes(), b"payload");
}

#[test]
fn clearing_empties_a_keyring() {
    let mut keys = Keyrings::new();
    let caller = root();
    let key = add_user(&mut keys, &caller, "k", PROCESS_KEYRING);
    assert_eq!(keys.clear(&caller, key, NOW), Err(Error::NotDirectory));
    assert_eq!(keys.clear(&caller, PROCESS_KEYRING, NOW), Ok(()));
    assert!(keys.read(&caller, PROCESS_KEYRING, NOW).unwrap().is_empty());
    assert_eq!(keys.describe(&caller, key, NOW), Err(Error::NoKey));
}

#[test]
fn capabilities_report_what_is_supported() {
    let capabilities = Keyrings::capabilities().unwrap();
    assert_eq!(capabilities.as_bytes(), [0xed, 0]);
    assert_eq!(capabilities.for_buffer(1), [0xed]);
    assert_eq!(capabilities.len(), 2);
}

#[test]
fn a_child_can_give_its_parent_its_session_keyring() {
    let mut keys = Keyrings::new();
    let parent = root();
    keys.fork(&parent, 101).unwrap();
    let child = Caller {
        pid: 101,
        tid: 101,
        ..parent
    };
    let session = keys.join_session_keyring(&child, None).unwrap();
    assert_eq!(keys.session_to_parent(&child, parent.tid, NOW), Ok(()));
    keys.exit_thread(child.tid);
    assert_eq!(
        keys.get_keyring_id(&parent, SESSION_KEYRING, false, NOW),
        Ok(session)
    );
}

/// cve-2016-7042 reads /proc/keys after updating a key.
#[test]
fn proc_files_show_what_the_reader_may_view() {
    let mut keys = Keyrings::new();
    let caller = root();
    let session = keys.join_session_keyring(&caller, None).unwrap();
    let key = keys
        .add_key(&caller, b"user", b"ltptestkey", b"a", SESSION_KEYRING, NOW)
        .unwrap();
    keys.update(&caller, key, b"b", NOW).unwrap();
    keys.set_timeout(&caller, key, 90, NOW).unwrap();
    let text = String::from_utf8(keys.proc_keys(&caller, NOW).unwrap()).unwrap();
    let expected = format!(
        "{session:08x} I--Q---     1 perm 3f030000     0     0 keyring   _ses: 1\n\
         {key:08x} I--Q---     1   1m 3f010000     0     0 user      ltptestkey: 1\n"
    );
    assert_eq!(text, expected);
    let stranger = person(2000, 20);
    assert!(keys.proc_keys(&stranger, NOW).unwrap().is_empty());

    let bytes = "_ses".len() + 1 + 4 + "ltptestkey".len() + 1 + 1;
    let users = String::from_utf8(keys.proc_key_users().unwrap()).unwrap();
    assert_eq!(
        users,
        format!("    0:     2 2/2 2/1000000 {bytes}/25000000\n")
    );

    keys.revoke(&caller, key, NOW).unwrap();
    let text = String::from_utf8(keys.proc_keys(&caller, NOW + 100 * SECOND).unwrap()).unwrap();
    assert!(text.ends_with(&format!(
        "{key:08x} IR-Q---     1 expd 3f010000     0     0 user      ltptestkey: 0\n"
    )));
}

#[test]
fn serials_increase_and_wrap_around_used_ones() {
    let mut keys = Keyrings::new();
    let caller = root();
    let first = keys
        .get_keyring_id(&caller, PROCESS_KEYRING, true, NOW)
        .unwrap();
    assert_eq!(first, 1);
    keys.next_serial = i32::MAX;
    assert_eq!(
        add_user(&mut keys, &caller, "last", PROCESS_KEYRING),
        i32::MAX
    );
    assert_eq!(add_user(&mut keys, &caller, "wrapped", PROCESS_KEYRING), 2);
    assert_eq!(links(&mut keys, &caller, PROCESS_KEYRING), [i32::MAX, 2]);
}

#[test]
fn errors_carry_linux_errno_values() {
    assert_eq!(Error::NoKey.errno(), 126);
    assert_eq!(Error::KeyExpired.errno(), 127);
    assert_eq!(Error::KeyRevoked.errno(), 128);
    assert_eq!(Error::QuotaExceeded.errno(), 122);
    assert_eq!(Error::NotSupported.errno(), 95);
}
