//! The "asymmetric" key type: an RSA key parsed from an X.509 certificate
//! or a PKCS#8 private key, as Linux's built-in x509 and pkcs8 parsers
//! read them (tried in that order; data neither recognises is EBADMSG).
//! A self-signed certificate's signature is checked when it is added.
//! Only RSA keys exist here; a certificate for another key algorithm is
//! ENOPKG, and a signature over a hash other than SHA-256 is kept
//! unchecked, as Linux keeps one whose hash it lacks.

use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::crypto::der::{
    self, Element, Reader, BIT_STRING, GENERALIZED_TIME, INTEGER, OBJECT_IDENTIFIER, OCTET_STRING,
    SEQUENCE, SET, UTC_TIME,
};
use crate::crypto::{bignum, push_hex, sha256};
use crate::keys::copy;
use crate::{no_memory, Error};

const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const ORGANIZATION: &[u8] = &[0x55, 0x04, 0x0a];
const EMAIL_ADDRESS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01];
const SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];
const AUTHORITY_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x23];
/// The DER DigestInfo header that precedes a SHA-256 digest in a PKCS#1
/// v1.5 signature.
const SHA256_DIGEST_INFO: &[u8] = &[
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];
/// The quota an asymmetric key's payload takes, whatever its size.
pub(crate) const QUOTA_BYTES: usize = 100;

/// KEYCTL_PKEY_QUERY's `supported_ops` bits (`KEYCTL_SUPPORTS_*`).
pub mod operation {
    pub const ENCRYPT: u32 = 0x01;
    pub const DECRYPT: u32 = 0x02;
    pub const SIGN: u32 = 0x04;
    pub const VERIFY: u32 = 0x08;
}

/// A key identifier: the bytes Linux's asymmetric_key_id holds.
pub(crate) type KeyId = Vec<u8>;

/// What signed a certificate, for checking it against the signer's key.
pub(crate) struct Signature {
    /// The signer: issuer name and serial, key identifier, issuer name.
    pub(crate) authority: [Option<KeyId>; 3],
    /// Whether it is an RSA signature (PKCS#1 v1.5 over SHA-256).
    rsa: bool,
    digest: [u8; sha256::DIGEST_BYTES],
    value: Vec<u8>,
}

/// An asymmetric key's payload.
pub(crate) struct Asymmetric {
    /// An RSAPublicKey, or an RSAPrivateKey from PKCS#8.
    key: Vec<u8>,
    private: bool,
    /// "X509" or "PKCS8", which /proc/keys shows.
    pub(crate) source: &'static str,
    /// A certificate's issuer-and-serial id, subject key id and subject
    /// id; none for a PKCS#8 key.
    pub(crate) ids: [Option<KeyId>; 3],
    /// A certificate's signature, unless its hash is not supported.
    pub(crate) signature: Option<Signature>,
}

impl Asymmetric {
    /// A certificate's subject key identifier, the end of which
    /// /proc/keys shows.
    pub(crate) fn subject_key_id(&self) -> Option<&[u8]> {
        self.ids[1].as_deref()
    }
}

/// A parsed payload and the description the parser proposes for a key
/// added without one.
pub(crate) struct Parsed {
    pub(crate) payload: Box<Asymmetric>,
    pub(crate) description: Option<Vec<u8>>,
}

/// asymmetric_key_preparse: an empty payload is EINVAL; data no parser
/// recognises is EBADMSG.
pub(crate) fn parse(data: &[u8]) -> Result<Parsed, Error> {
    if data.is_empty() {
        return Err(Error::Invalid);
    }
    match parse_certificate(data) {
        Err(Error::BadMessage) => parse_private_key(data),
        result => result,
    }
}

fn concatenate(first: &[u8], second: &[u8]) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(first.len() + second.len())
        .map_err(no_memory)?;
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(second);
    Ok(bytes)
}

/// The algorithm identifier's OID.
fn algorithm<'a>(element: Element<'a>) -> Result<&'a [u8], Error> {
    Ok(element.reader().expect(OBJECT_IDENTIFIER)?.contents)
}

/// The signature algorithms Linux knows: whether each is RSA over
/// SHA-256 (checkable here), another RSA one, or not RSA. An unknown one
/// is ENOPKG.
fn signature_algorithm(oid: &[u8]) -> Result<SignatureKind, Error> {
    const PKCS1: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01];
    const NIST_SIGNATURES: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03];
    const ECDSA_SHA1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01];
    const ECDSA_SHA2: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03];
    const GOST_2012: &[u8] = &[0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x03];
    let suffix = |prefix: &[u8]| {
        oid.strip_prefix(prefix)
            .and_then(|rest| <[u8; 1]>::try_from(rest).ok())
            .map(|[last]| last)
    };
    if oid == SHA256_WITH_RSA {
        return Ok(SignatureKind::RsaSha256);
    }
    let known = matches!(suffix(PKCS1), Some(0x05 | 0x0c..=0x0e))
        || matches!(suffix(NIST_SIGNATURES), Some(0x0a..=0x10))
        || oid == ECDSA_SHA1
        || matches!(suffix(ECDSA_SHA2), Some(0x01..=0x04))
        || matches!(suffix(GOST_2012), Some(0x02 | 0x03));
    if !known {
        return Err(Error::NoPackage);
    }
    let rsa = suffix(PKCS1).is_some() || matches!(suffix(NIST_SIGNATURES), Some(0x0e..=0x10));
    Ok(if rsa {
        SignatureKind::RsaOtherHash
    } else {
        SignatureKind::NotRsa
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SignatureKind {
    RsaSha256,
    /// RSA over a hash this kernel lacks: kept unchecked.
    RsaOtherHash,
    NotRsa,
}

/// The pieces of a Name: its raw contents and the name Linux makes of it
/// for descriptions (organization and common name, either, or the email
/// address).
fn name(element: Element<'_>) -> Result<Vec<u8>, Error> {
    let (mut common, mut organization, mut email) = (None, None, None);
    let mut sets = element.reader();
    while !sets.is_empty() {
        let mut attributes = sets.expect(SET)?.reader();
        while !attributes.is_empty() {
            let mut attribute = attributes.expect(SEQUENCE)?.reader();
            let oid = attribute.expect(OBJECT_IDENTIFIER)?.contents;
            let value = attribute.next()?.contents;
            match oid {
                COMMON_NAME => common = Some(value),
                ORGANIZATION => organization = Some(value),
                EMAIL_ADDRESS => email = Some(value),
                _ => {}
            }
        }
    }
    match (common, organization) {
        (Some(common), Some(organization))
            if !common.starts_with(organization)
                && !(common.len() >= 7
                    && organization.len() >= 7
                    && common[..7] == organization[..7]) =>
        {
            let mut joined = concatenate(organization, b": ")?;
            joined.try_reserve(common.len()).map_err(no_memory)?;
            joined.extend_from_slice(common);
            Ok(joined)
        }
        (Some(single), _) | (None, Some(single)) => copy(single),
        (None, None) => copy(email.unwrap_or_default()),
    }
}

/// x509_decode_time: UTCTime or GeneralizedTime in their Z forms, a real
/// date; anything else is EBADMSG.
fn check_time(element: Element<'_>) -> Result<(), Error> {
    let text = element.contents;
    let digits = |range: core::ops::Range<usize>| {
        text.get(range).and_then(|digits| {
            digits.iter().try_fold(0_u32, |value, &digit| {
                digit
                    .is_ascii_digit()
                    .then(|| value * 10 + u32::from(digit - b'0'))
            })
        })
    };
    let (year, rest) = match (element.tag, text.len()) {
        (UTC_TIME, 13) => {
            let year = digits(0..2).ok_or(Error::BadMessage)?;
            (if year >= 50 { 1900 + year } else { 2000 + year }, 2)
        }
        (GENERALIZED_TIME, 15) => {
            let year = digits(0..4).ok_or(Error::BadMessage)?;
            if (1950..=2049).contains(&year) {
                return Err(Error::BadMessage);
            }
            (year, 4)
        }
        _ => return Err(Error::BadMessage),
    };
    let field =
        |index: usize| digits(rest + index * 2..rest + index * 2 + 2).ok_or(Error::BadMessage);
    let (month, day, hour, minute, second) =
        (field(0)?, field(1)?, field(2)?, field(3)?, field(4)?);
    if text.last() != Some(&b'Z') || year < 1970 || !(1..=12).contains(&month) {
        return Err(Error::BadMessage);
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = match month {
        2 if leap => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    };
    if day < 1 || day > month_days || hour > 24 || minute > 59 || second > 60 {
        return Err(Error::BadMessage);
    }
    Ok(())
}

/// The certificate fields the key keeps.
struct Certificate<'a> {
    tbs: &'a [u8],
    serial: &'a [u8],
    issuer: &'a [u8],
    subject: &'a [u8],
    subject_name: Vec<u8>,
    key: &'a [u8],
    subject_key_id: Option<&'a [u8]>,
    authority: [Option<KeyId>; 3],
    kind: SignatureKind,
    signature: &'a [u8],
}

fn parse_certificate(data: &[u8]) -> Result<Parsed, Error> {
    let certificate = read_certificate(data)?;
    let id = concatenate(certificate.serial, certificate.issuer)?;
    let subject_key_id = certificate.subject_key_id.map(copy).transpose()?;
    let mut payload = Box::new(Asymmetric {
        key: copy(certificate.key)?,
        private: false,
        source: "X509",
        ids: [Some(id), subject_key_id, Some(copy(certificate.subject)?)],
        signature: None,
    });
    let mut signature = match certificate.kind {
        // Linux keeps no signature whose hash it lacks.
        SignatureKind::RsaOtherHash => None,
        kind => Some(Signature {
            authority: [None, None, None],
            rsa: kind == SignatureKind::RsaSha256,
            digest: sha256::digest(&[certificate.tbs]),
            value: copy(certificate.signature)?,
        }),
    };
    if certificate.issuer == certificate.subject {
        check_self_signed(&payload, signature.as_ref(), &certificate.authority)?;
    }
    if let Some(signature) = signature.as_mut() {
        signature.authority = certificate.authority;
    }
    payload.signature = signature;
    let mut description = concatenate(&certificate.subject_name, b": ")?;
    push_hex(
        &mut description,
        certificate.subject_key_id.unwrap_or(certificate.serial),
    )?;
    Ok(Parsed {
        payload,
        description: Some(description),
    })
}

/// x509_check_for_self_signed, for a certificate whose issuer is its
/// subject: if it names an authority, that must be this certificate (by
/// both ids when it gives both; matching neither means it is simply not
/// self-signed), and a self-signature that can be checked must verify.
fn check_self_signed(
    key: &Asymmetric,
    signature: Option<&Signature>,
    authority: &[Option<KeyId>; 3],
) -> Result<(), Error> {
    let [by_issuer, by_key_id, _] = authority;
    if by_issuer.is_some() || by_key_id.is_some() {
        let key_id_matches = key.ids[1].is_some() && key.ids[1] == *by_key_id;
        let issuer_matches = by_issuer.is_some() && key.ids[0] == *by_issuer;
        if !key_id_matches && !issuer_matches {
            return Ok(());
        }
        if key_id_matches != issuer_matches && by_issuer.is_some() && by_key_id.is_some() {
            return Err(Error::KeyRejected);
        }
    }
    match signature {
        Some(signature) => key.verify(signature),
        None => Ok(()),
    }
}

fn read_certificate(data: &[u8]) -> Result<Certificate<'_>, Error> {
    let mut fields = Reader::new(data).expect(SEQUENCE)?.reader();
    let tbs = fields.expect(SEQUENCE)?;
    let mut parts = tbs.reader();
    parts.optional(der::context(0, true))?;
    let serial = parts.expect(INTEGER)?.contents;
    let signature_oid = algorithm(parts.expect(SEQUENCE)?)?;
    let kind = signature_algorithm(signature_oid)?;
    let issuer = parts.expect(SEQUENCE)?;
    name(issuer)?;
    let mut validity = parts.expect(SEQUENCE)?.reader();
    check_time(validity.next()?)?;
    check_time(validity.next()?)?;
    let subject = parts.expect(SEQUENCE)?;
    let subject_name = name(subject)?;
    let mut key_info = parts.expect(SEQUENCE)?.reader();
    if algorithm(key_info.expect(SEQUENCE)?)? != RSA_ENCRYPTION {
        return Err(Error::NoPackage);
    }
    let key = key_info.expect(BIT_STRING)?.bit_string()?;
    parts.optional(der::context(1, false))?;
    parts.optional(der::context(2, false))?;
    let mut subject_key_id = None;
    let mut authority = [None, None, Some(copy(issuer.contents)?)];
    if let Some(extensions) = parts.optional(der::context(3, true))? {
        let mut list = extensions.reader().expect(SEQUENCE)?.reader();
        while !list.is_empty() {
            let mut extension = list.expect(SEQUENCE)?.reader();
            let oid = extension.expect(OBJECT_IDENTIFIER)?.contents;
            extension.optional(der::BOOLEAN)?;
            let value = extension.expect(OCTET_STRING)?.contents;
            match oid {
                SUBJECT_KEY_IDENTIFIER => {
                    let valid = subject_key_id.is_none()
                        && value.len() >= 3
                        && value[0] == OCTET_STRING
                        && usize::from(value[1]) == value.len() - 2;
                    if !valid {
                        return Err(Error::BadMessage);
                    }
                    subject_key_id = Some(&value[2..]);
                }
                AUTHORITY_KEY_IDENTIFIER => read_authority(value, &mut authority)?,
                _ => {}
            }
        }
    }
    // The algorithm outside the signed part must be the one inside it.
    if algorithm(fields.expect(SEQUENCE)?)? != signature_oid {
        return Err(Error::Invalid);
    }
    let signature = fields.expect(BIT_STRING)?.bit_string()?;
    Ok(Certificate {
        tbs: tbs.encoding,
        serial,
        issuer: issuer.contents,
        subject: subject.contents,
        subject_name,
        key,
        subject_key_id,
        authority,
        kind,
        signature,
    })
}

/// An AuthorityKeyIdentifier: its key identifier is the second authority
/// id, and its issuer name with its serial number the first.
fn read_authority(value: &[u8], authority: &mut [Option<KeyId>; 3]) -> Result<(), Error> {
    let mut fields = Reader::new(value).expect(SEQUENCE)?.reader();
    if let Some(key_id) = fields.optional(der::context(0, false))? {
        authority[1] = Some(copy(key_id.contents)?);
    }
    let mut issuer = None;
    if let Some(names) = fields.optional(der::context(1, true))? {
        let mut names = names.reader();
        while !names.is_empty() {
            let general_name = names.next()?;
            if general_name.tag == der::context(4, true) {
                let directory = general_name.reader().expect(SEQUENCE)?;
                name(directory)?;
                issuer = Some(directory.contents);
            }
        }
    }
    if let (Some(serial), Some(issuer)) = (fields.optional(der::context(2, false))?, issuer) {
        authority[0] = Some(concatenate(serial.contents, issuer)?);
    }
    Ok(())
}

/// A PKCS#8 PrivateKeyInfo holding an RSA key. It proposes no
/// description.
fn parse_private_key(data: &[u8]) -> Result<Parsed, Error> {
    let mut fields = Reader::new(data).expect(SEQUENCE)?.reader();
    if fields.expect(INTEGER)?.contents != [0] {
        return Err(Error::BadMessage);
    }
    let oid = algorithm(fields.expect(SEQUENCE)?)?;
    if oid != RSA_ENCRYPTION {
        return Err(Error::NoPackage);
    }
    let key = fields.expect(OCTET_STRING)?.contents;
    fields.optional(der::context(0, true))?;
    Ok(Parsed {
        payload: Box::new(Asymmetric {
            key: copy(key)?,
            private: true,
            source: "PKCS8",
            ids: [None, None, None],
            signature: None,
        }),
        description: None,
    })
}

/// An RSA key's numbers, without leading zeros.
struct Rsa<'a> {
    modulus: &'a [u8],
    public_exponent: &'a [u8],
    private: bool,
}

impl Rsa<'_> {
    /// The size Linux's RSA code gives operations: the modulus rounded up
    /// to whole 64-bit limbs.
    fn size(&self) -> usize {
        self.modulus.len().next_multiple_of(8)
    }
}

impl Asymmetric {
    /// The RSA key, as Linux's RSA code accepts it: well formed (EBADMSG)
    /// with a modulus of 512, 1024, 1536, 2048, 3072 or 4096 bits and a
    /// public exponent no longer than it (EINVAL).
    fn rsa(&self) -> Result<Rsa<'_>, Error> {
        let mut fields = Reader::new(&self.key).expect(SEQUENCE)?.reader();
        if self.private {
            fields.expect(INTEGER)?;
        }
        let modulus = bignum::significant(fields.expect(INTEGER)?.contents);
        let public_exponent = bignum::significant(fields.expect(INTEGER)?.contents);
        if self.private && bignum::significant(fields.expect(INTEGER)?.contents).is_empty() {
            return Err(Error::Invalid);
        }
        let key = Rsa {
            modulus,
            public_exponent,
            private: self.private,
        };
        let valid_size = matches!(key.size() * 8, 512 | 1024 | 1536 | 2048 | 3072 | 4096);
        if !valid_size || public_exponent.is_empty() || public_exponent.len() > modulus.len() {
            return Err(Error::Invalid);
        }
        Ok(key)
    }

    /// public_key_verify_signature for an RSA PKCS#1 v1.5 signature over
    /// SHA-256: another algorithm is EKEYREJECTED, a malformed padding
    /// EINVAL or EBADMSG, a wrong digest EKEYREJECTED.
    pub(crate) fn verify(&self, signature: &Signature) -> Result<(), Error> {
        if !signature.rsa {
            return Err(Error::KeyRejected);
        }
        let key = self.rsa()?;
        let size = key.size();
        if signature.value.len() != size || !bignum::less_than(&signature.value, key.modulus) {
            return Err(Error::Invalid);
        }
        let value = bignum::power_mod(&signature.value, key.public_exponent, key.modulus)?;
        let mut message = Vec::new();
        message.try_reserve_exact(size).map_err(no_memory)?;
        message.resize(size - value.len(), 0);
        message.extend_from_slice(&value);
        let Some((0, message)) = message.split_first() else {
            return Err(Error::Invalid);
        };
        let Some((1, padded)) = message.split_first() else {
            return Err(Error::BadMessage);
        };
        let filler = padded.iter().take_while(|&&byte| byte == 0xff).count();
        let Some((0, rest)) = padded[filler..].split_first() else {
            return Err(Error::BadMessage);
        };
        if filler < 8 {
            return Err(Error::BadMessage);
        }
        let digest = rest
            .strip_prefix(SHA256_DIGEST_INFO)
            .ok_or(Error::BadMessage)?;
        if digest != signature.digest {
            return Err(Error::KeyRejected);
        }
        Ok(())
    }

    /// KEYCTL_PKEY_QUERY with these parameters: "raw" (without a hash) or
    /// "pkcs1" encoding, another being EINVAL and an unknown hash ENOENT.
    pub(crate) fn query(&self, parameters: &Parameters<'_>) -> Result<Query, Error> {
        let signing = match (parameters.encoding, parameters.hash) {
            (b"pkcs1", hash) => {
                if hash.is_some_and(|hash| !PKCS1_HASHES.contains(&hash)) {
                    return Err(Error::NotFound);
                }
                true
            }
            (b"raw", None) => false,
            _ => return Err(Error::Invalid),
        };
        let key = self.rsa()?;
        let mut supported = operation::ENCRYPT;
        if signing {
            supported |= operation::VERIFY;
        }
        if key.private {
            supported |= operation::DECRYPT;
            if signing {
                supported |= operation::SIGN;
            }
        }
        let size = u16::try_from(key.size()).map_err(|_| Error::Invalid)?;
        Ok(Query {
            supported_operations: supported,
            key_size: u32::from(size) * 8,
            max_data_size: size,
            max_signature_size: size,
            max_encrypted_size: size,
            max_decrypted_size: size,
        })
    }
}

/// The hashes Linux's PKCS#1 padding can name.
const PKCS1_HASHES: &[&[u8]] = &[
    b"md5",
    b"sha1",
    b"rmd160",
    b"sha224",
    b"sha256",
    b"sha384",
    b"sha512",
    b"sha3-256",
    b"sha3-384",
    b"sha3-512",
];

/// The parameters of a public-key operation, from its info string of
/// "enc=" and "hash=" words separated by spaces or tabs.
pub(crate) struct Parameters<'a> {
    pub(crate) encoding: &'a [u8],
    pub(crate) hash: Option<&'a [u8]>,
}

impl<'a> Parameters<'a> {
    /// An unknown or repeated word, or one without a value, is EINVAL.
    pub(crate) fn parse(info: &'a [u8]) -> Result<Self, Error> {
        let mut encoding = None;
        let mut hash = None;
        for word in info.split(|&byte| byte == b' ' || byte == b'\t') {
            if word.is_empty() {
                continue;
            }
            let (slot, value) = if let Some(value) = word.strip_prefix(b"enc=") {
                (&mut encoding, value)
            } else if let Some(value) = word.strip_prefix(b"hash=") {
                (&mut hash, value)
            } else {
                return Err(Error::Invalid);
            };
            if slot.is_some() || value.is_empty() {
                return Err(Error::Invalid);
            }
            *slot = Some(value);
        }
        Ok(Self {
            encoding: encoding.unwrap_or(b"raw"),
            hash,
        })
    }
}

/// What KEYCTL_PKEY_QUERY reports (`struct keyctl_pkey_query`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Query {
    pub supported_operations: u32,
    /// In bits.
    pub key_size: u32,
    pub max_data_size: u16,
    pub max_signature_size: u16,
    pub max_encrypted_size: u16,
    pub max_decrypted_size: u16,
}

impl Query {
    /// The size of the structure in user memory.
    pub const BYTES: usize = 56;

    /// The structure as user memory holds it, its spare words zeroed.
    pub fn to_bytes(&self) -> [u8; Self::BYTES] {
        let mut bytes = [0; Self::BYTES];
        bytes[0..4].copy_from_slice(&self.supported_operations.to_ne_bytes());
        bytes[4..8].copy_from_slice(&self.key_size.to_ne_bytes());
        let sizes = [
            self.max_data_size,
            self.max_signature_size,
            self.max_encrypted_size,
            self.max_decrypted_size,
        ];
        for (slot, size) in bytes[8..16].as_chunks_mut::<2>().0.iter_mut().zip(sizes) {
            *slot = size.to_ne_bytes();
        }
        bytes
    }
}
