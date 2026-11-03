//! The key types beyond "user", "logon" and "keyring", and the
//! operations on them: KEYCTL_DH_COMPUTE (LTP keyctl25 to keyctl28),
//! asymmetric keys and KEYCTL_PKEY_QUERY (keyctl05, keyctl23, keyctl29,
//! keyctl30), encrypted keys (keyctl09) and DNS resolver keys (keyctl05),
//! with vectors made for them in `test_vectors`.

use super::*;
use crate::test_vectors::*;
use std::format;
use std::string::String;
use std::vec::Vec;

const NOW: u64 = 1_000 * NANOSECONDS_PER_SECOND;

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

/// Bytes 0, 1, 2, ... as the random source, so IVs are predictable.
fn counting(buffer: &mut [u8]) -> bool {
    for (index, byte) in buffer.iter_mut().enumerate() {
        *byte = index as u8;
    }
    true
}

fn add(
    keys: &mut Keyrings,
    key_type: &str,
    description: &str,
    payload: &[u8],
) -> Result<i32, Error> {
    keys.add_key(
        &root(),
        key_type.as_bytes(),
        description.as_bytes(),
        payload,
        PROCESS_KEYRING,
        NOW,
    )
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    let mut text = Vec::new();
    crypto::push_hex(&mut text, bytes).unwrap();
    text
}

#[test]
fn sha256_and_aes_match_known_answers() {
    assert_eq!(
        hex(&crypto::sha256::digest(&[b"ab", b"c"])),
        b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // RFC 4231 test case 2.
    assert_eq!(
        hex(&crypto::sha256::hmac(
            b"Jefe",
            &[b"what do ya want ", b"for nothing?"]
        )),
        b"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    );
    // FIPS 197 appendix C.3.
    let key: [u8; 32] = core::array::from_fn(|index| index as u8);
    let mut block: Vec<u8> = (0..16).map(|index| (index * 0x11) as u8).collect();
    let cipher = crypto::aes::Aes256::new(&key);
    cipher.encrypt_cbc(&[0; 16], &mut block);
    assert_eq!(hex(&block), b"8ea2b7ca516745bfeafc49904b496089");
    cipher.decrypt_cbc(&[0; 16], &mut block);
    assert_eq!(hex(&block), b"00112233445566778899aabbccddeeff");
}

#[test]
fn dh_compute_and_derive() {
    let mut keys = Keyrings::new();
    let caller = root();
    let prime = add(&mut keys, "user", "dh_prime", DH_PRIME).unwrap();
    let base = add(&mut keys, "user", "dh_base", DH_BASE).unwrap();
    let private = add(&mut keys, "user", "dh_private", DH_PRIVATE).unwrap();
    let secret = keys.dh_compute(&caller, private, prime, base, NOW).unwrap();
    assert_eq!(secret, DH_SECRET);
    let mut input = secret.clone();
    input.extend_from_slice(KDF_INFO);
    assert_eq!(dh::derive(b"sha256", &input, 48).unwrap(), KDF_OUTPUT);
    assert_eq!(dh::check_hash(b"sha9000"), Err(Error::NotFound));
    // keyctl28: a missing key, a key of another type.
    assert_eq!(
        keys.dh_compute(&caller, private, i32::MAX, base, NOW),
        Err(Error::NoKey)
    );
    assert_eq!(
        keys.dh_compute(&caller, private, PROCESS_KEYRING, base, NOW),
        Err(Error::NotSupported)
    );
    let small = add(&mut keys, "user", "small", &DH_PRIME[..128]).unwrap();
    assert_eq!(
        keys.dh_compute(&caller, private, small, base, NOW),
        Err(Error::Invalid)
    );
}

#[test]
fn certificates_make_asymmetric_keys() {
    let mut keys = Keyrings::new();
    let caller = root();
    let key = add(&mut keys, "asymmetric", "", CERTIFICATE).unwrap();
    let description = keys.describe(&caller, key, NOW).unwrap();
    let mut expected = String::from("asymmetric;0;0;39010000;Ginux Tests: ginux-keyrings-test: ");
    expected.push_str(core::str::from_utf8(SUBJECT_KEY_ID_HEX).unwrap());
    expected.push('\0');
    assert_eq!(description.as_bytes(), expected.as_bytes());
    // keyctl05: there is no update, and no read either.
    keys.set_permissions(&caller, key, possessor(permission::ALL), NOW)
        .unwrap();
    assert_eq!(
        keys.update(&caller, key, CERTIFICATE, NOW),
        Err(Error::NotSupported)
    );
    assert_eq!(keys.read(&caller, key, NOW), Err(Error::NotSupported));
    // keyctl29
    let query = keys.pkey_query(&caller, key, b"enc=pkcs1", NOW).unwrap();
    assert_eq!(
        query,
        PublicKeyQuery {
            supported_operations: public_key_operation::ENCRYPT | public_key_operation::VERIFY,
            key_size: 2048,
            max_data_size: 256,
            max_signature_size: 256,
            max_encrypted_size: 256,
            max_decrypted_size: 256,
        }
    );
    assert_eq!(
        keys.pkey_query(&caller, key, b"enc=pkcs1 hash=sha9000", NOW),
        Err(Error::NotFound)
    );
    assert_eq!(
        keys.pkey_query(&caller, key, b"enc=raw hash=sha256", NOW),
        Err(Error::Invalid)
    );
    assert_eq!(
        keys.pkey_query(&caller, key, b"enc=raw enc=raw", NOW),
        Err(Error::Invalid)
    );
    let user = add(&mut keys, "user", "u", b"x").unwrap();
    assert_eq!(
        keys.pkey_query(&caller, user, b"", NOW),
        Err(Error::NotSupported)
    );
    // A self-signature that does not verify.
    assert_eq!(
        add(&mut keys, "asymmetric", "bad", TAMPERED_CERTIFICATE),
        Err(Error::KeyRejected)
    );
    assert_eq!(add(&mut keys, "asymmetric", "x", b""), Err(Error::Invalid));
    assert_eq!(
        add(&mut keys, "asymmetric", "x", b"not a key"),
        Err(Error::BadMessage)
    );
}

#[test]
fn pkcs8_keys_are_private() {
    let mut keys = Keyrings::new();
    let caller = root();
    // A PKCS#8 key proposes no description.
    assert_eq!(
        add(&mut keys, "asymmetric", "", PRIVATE_KEY),
        Err(Error::Invalid)
    );
    let key = add(&mut keys, "asymmetric", "priv", PRIVATE_KEY).unwrap();
    let query = keys.pkey_query(&caller, key, b"enc=pkcs1", NOW).unwrap();
    use public_key_operation::{DECRYPT, ENCRYPT, SIGN, VERIFY};
    assert_eq!(
        query.supported_operations,
        ENCRYPT | DECRYPT | SIGN | VERIFY
    );
    assert_eq!(query.key_size, 2048);
    let raw = keys.pkey_query(&caller, key, b"", NOW).unwrap();
    assert_eq!(raw.supported_operations, ENCRYPT | DECRYPT);
}

#[test]
fn builtin_trusted_keyrings_take_nothing() {
    let mut keys = Keyrings::new();
    let caller = root();
    let ring = keys
        .add_key(&caller, b"keyring", b"builtin", &[], PROCESS_KEYRING, NOW)
        .unwrap();
    let user = add(&mut keys, "user", "k", b"payload").unwrap();
    let restrict = |keys: &mut Keyrings| {
        keys.restrict_keyring(
            &caller,
            ring,
            Some(b"asymmetric"),
            Some(b"builtin_trusted"),
            NOW,
        )
    };
    assert_eq!(restrict(&mut keys), Ok(()));
    assert_eq!(restrict(&mut keys), Err(Error::Exists));
    // keyctl23
    assert_eq!(
        keys.link(&caller, user, ring, NOW),
        Err(Error::NotSupported)
    );
    assert_eq!(
        keys.add_key(&caller, b"asymmetric", b"cert", CERTIFICATE, ring, NOW),
        Err(Error::NoKey)
    );
}

#[test]
fn key_or_keyring_restrictions_check_signatures() {
    let mut keys = Keyrings::new();
    let caller = root();
    let signer = add(&mut keys, "asymmetric", "signer", CERTIFICATE).unwrap();
    let ring = |keys: &mut Keyrings, name: &str| {
        keys.add_key(
            &caller,
            b"keyring",
            name.as_bytes(),
            &[],
            PROCESS_KEYRING,
            NOW,
        )
        .unwrap()
    };
    let restrict = |keys: &mut Keyrings, ring: i32, scheme: &str| {
        keys.restrict_keyring(
            &caller,
            ring,
            Some(b"asymmetric"),
            Some(scheme.as_bytes()),
            NOW,
        )
    };
    // keyctl24
    let fresh = ring(&mut keys, "fresh");
    assert_eq!(
        restrict(&mut keys, fresh, &format!("key_or_keyring:{}", i32::MAX)),
        Err(Error::NoKey)
    );
    assert_eq!(
        restrict(&mut keys, fresh, &format!("key_or_keyring:{fresh}:chain")),
        Err(Error::Deadlock)
    );
    assert_eq!(
        restrict(&mut keys, fresh, "key_or_keyring:0"),
        Err(Error::NoKey)
    );
    assert_eq!(
        restrict(&mut keys, fresh, &format!("key_or_keyring:{signer}:other")),
        Err(Error::Invalid)
    );
    // A certificate signed by the trusted key gets in; others do not.
    let trusting = ring(&mut keys, "trusting");
    assert_eq!(
        restrict(&mut keys, trusting, &format!("key_or_keyring:{signer}")),
        Ok(())
    );
    let user = add(&mut keys, "user", "u", b"x").unwrap();
    assert_eq!(
        keys.link(&caller, user, trusting, NOW),
        Err(Error::NotSupported)
    );
    assert!(keys
        .add_key(&caller, b"asymmetric", b"cert", CERTIFICATE, trusting, NOW)
        .is_ok());
    // A chain that starts empty has no signer.
    let chain = ring(&mut keys, "chain");
    assert_eq!(restrict(&mut keys, chain, "key_or_keyring:0:chain"), Ok(()));
    assert_eq!(
        keys.add_key(&caller, b"asymmetric", b"cert", CERTIFICATE, chain, NOW),
        Err(Error::NoKey)
    );
    // The restriction keeps its trusted key alive.
    keys.unlink(&caller, signer, PROCESS_KEYRING, NOW).unwrap();
    assert!(keys.describe(&caller, signer, NOW).is_ok());
}

#[test]
fn encrypted_keys_read_encrypted_and_load_back() {
    let mut keys = Keyrings::with_random(counting);
    let caller = root();
    add(&mut keys, "user", "masterkey", MASTER_KEY).unwrap();
    let mut command = Vec::from(&b"new user:masterkey 32 "[..]);
    command.extend_from_slice(&hex(ENCRYPTED_DATA));
    let key = add(&mut keys, "encrypted", "ltptestkey1", &command).unwrap();
    // keyctl09: a small buffer only learns the length.
    let measured = keys.read_into(&caller, key, 128, NOW).unwrap();
    assert_eq!(measured.len(), ENCRYPTED_READ.len());
    assert!(measured.for_buffer(128).is_empty());
    assert_eq!(
        keys.read(&caller, key, NOW).unwrap().as_bytes(),
        ENCRYPTED_READ
    );
    // The blob loads back into the same data.
    let blob = ENCRYPTED_READ.rsplit(|&byte| byte == b' ').next().unwrap();
    let mut load = Vec::from(&b"load default user:masterkey 32 "[..]);
    load.extend_from_slice(blob);
    let loaded = add(&mut keys, "encrypted", "loaded", &load).unwrap();
    assert_eq!(
        keys.read(&caller, loaded, NOW).unwrap().as_bytes(),
        ENCRYPTED_READ
    );
    let mut corrupt = load.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    assert_eq!(
        add(&mut keys, "encrypted", "corrupt", &corrupt),
        Err(Error::Invalid)
    );
    // keyctl09's invalid payload, and other malformed commands.
    for command in [
        &b"new enc32 user:masterkey 32 plaintext123@123!123@123!123@123plaintext123@123!123@123!123@123"[..],
        b"new user:masterkey 19",
        b"new enc32 user:masterkey 20",
        b"new other:masterkey 32",
        b"update user:masterkey",
        b"new",
    ] {
        assert_eq!(add(&mut keys, "encrypted", "bad", command), Err(Error::Invalid));
    }
    // Random data without a source of random numbers.
    let mut unseeded = Keyrings::new();
    assert_eq!(
        add(&mut unseeded, "encrypted", "k", b"new user:masterkey 32"),
        Err(Error::Io)
    );
    // An update changes the master key, keeping its kind.
    assert_eq!(keys.update(&caller, key, b"update user:other", NOW), Ok(()));
    assert_eq!(keys.read(&caller, key, NOW), Err(Error::NoKey));
    assert_eq!(
        keys.update(&caller, key, b"update trusted:other", NOW),
        Err(Error::Invalid)
    );
    let random = add(&mut keys, "encrypted", "random", b"new user:masterkey 64").unwrap();
    assert!(keys.read(&caller, random, NOW).is_ok());
}

#[test]
fn dns_resolver_keys() {
    let mut keys = Keyrings::new();
    let caller = root();
    // keyctl05's server list with a lookup not done: kept for a second.
    let list = [0x00, 0x00, 0x01, 0xff, 0x00, 0x00];
    let key = add(&mut keys, "dns_resolver", "desc", &list).unwrap();
    assert_eq!(keys.read(&caller, key, NOW).unwrap().as_bytes(), list);
    assert_eq!(
        keys.read(&caller, key, NOW + NANOSECONDS_PER_SECOND),
        Err(Error::KeyExpired)
    );
    keys.set_permissions(&caller, key, possessor(permission::ALL), NOW)
        .unwrap();
    assert_eq!(
        keys.update(&caller, key, &list, NOW),
        Err(Error::NotSupported)
    );
    let name = add(&mut keys, "dns_resolver", "host", b"192.0.2.1\0").unwrap();
    assert_eq!(
        keys.read(&caller, name, NOW).unwrap().as_bytes(),
        b"192.0.2.1"
    );
    let failed = add(&mut keys, "dns_resolver", "gone", b"#dnserror=6\0").unwrap();
    assert_eq!(keys.read(&caller, failed, NOW), Err(Error::Errno(6)));
    for bad in [
        &b"x"[..],
        b"no nul",
        b"a#dnserror=0\0",
        b"a#other=1\0",
        &list[..5],
    ] {
        assert_eq!(
            add(&mut keys, "dns_resolver", "bad", bad),
            Err(Error::Invalid)
        );
    }
}
