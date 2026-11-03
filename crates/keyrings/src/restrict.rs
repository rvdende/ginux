//! Keyring restrictions (KEYCTL_RESTRICT_KEYRING): which keys a keyring
//! accepts links to, as Linux's restrict_link_reject and the asymmetric
//! type's signature-checking schemes decide.

use crate::asymmetric::{Asymmetric, KeyId, Signature};
use crate::keys::{Match, Payload, Search, Searched};
use crate::{Caller, Error, KeyType, Keyrings};

/// What a restricted keyring accepts links to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Restriction {
    /// Nothing at all.
    Everything,
    /// Asymmetric keys signed by a key in the kernel's built-in (or
    /// secondary) trusted keyring. Ginux builds no certificates in, so
    /// those keyrings are empty and no key is ever accepted.
    BuiltinTrusted,
    /// "key_or_keyring:SERIAL[:chain]": asymmetric keys signed by the key
    /// `trusted`, or by a key in the keyring `trusted`, and with `chain`
    /// also by a key already in the restricted keyring. The restriction
    /// holds a reference to `trusted`.
    KeyOrKeyring { trusted: Option<i32>, chain: bool },
}

impl Restriction {
    pub(crate) fn trusted(self) -> Option<i32> {
        match self {
            Self::KeyOrKeyring { trusted, .. } => trusted,
            _ => None,
        }
    }
}

/// kstrtos32 with base 0: decimal, "0x" hex or leading-zero octal, with
/// an optional sign.
fn parse_serial(text: &[u8]) -> Option<i32> {
    let text = core::str::from_utf8(text).ok()?;
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let (radix, digits) = if let Some(hex) = digits
        .strip_prefix("0x")
        .or_else(|| digits.strip_prefix("0X"))
    {
        (16, hex)
    } else if digits.len() > 1 && digits.starts_with('0') {
        (8, &digits[1..])
    } else {
        (10, digits)
    };
    let value = i64::from_str_radix(digits, radix).ok()?;
    i32::try_from(if negative { -value } else { value }).ok()
}

impl Keyrings {
    /// The asymmetric type's lookup_restriction for `scheme`: a built-in
    /// keyring scheme, or "key_or_keyring:" naming an existing key (ENOKEY
    /// if there is none) or, with ":chain", possibly 0. Anything else is
    /// EINVAL.
    pub(crate) fn asymmetric_restriction(&self, scheme: &[u8]) -> Result<Restriction, Error> {
        if matches!(
            scheme,
            b"builtin_trusted" | b"builtin_and_secondary_trusted"
        ) {
            return Ok(Restriction::BuiltinTrusted);
        }
        let mut fields = scheme.splitn(3, |&byte| byte == b':');
        let (Some(b"key_or_keyring"), Some(serial)) = (fields.next(), fields.next()) else {
            return Err(Error::Invalid);
        };
        let chain = match fields.next() {
            None => false,
            Some(b"chain") => true,
            Some(_) => return Err(Error::Invalid),
        };
        let serial = parse_serial(serial).ok_or(Error::Invalid)?;
        let trusted = if serial == 0 && chain {
            None
        } else {
            Some(self.get(serial)?.serial)
        };
        Ok(Restriction::KeyOrKeyring { trusted, chain })
    }

    /// Whether giving `ring` `restriction` would make a chain of keyring
    /// restrictions lead back to it (EDEADLK).
    pub(crate) fn restriction_cycles(&self, ring: i32, restriction: Restriction) -> bool {
        let mut next = restriction.trusted();
        while let Some(serial) = next {
            let Some(key) = self.key(serial).filter(|key| key.is_keyring()) else {
                return false;
            };
            if serial == ring {
                return true;
            }
            next = key.restriction.and_then(Restriction::trusted);
        }
        false
    }

    /// Whether `ring`'s restriction lets a key of `kind` with `payload` be
    /// linked into it.
    pub(crate) fn check_restriction(
        &self,
        caller: &Caller,
        ring: i32,
        kind: KeyType,
        payload: &Payload,
        now: u64,
    ) -> Result<(), Error> {
        let Some(restriction) = self.get(ring)?.restriction else {
            return Ok(());
        };
        if restriction == Restriction::Everything {
            return Err(Error::NotPermitted);
        }
        if kind != KeyType::Asymmetric {
            return Err(Error::NotSupported);
        }
        let Payload::Asymmetric(key) = payload else {
            return Err(Error::NoPackage);
        };
        let signature = key.signature.as_ref().ok_or(Error::NoPackage)?;
        if signature.authority.iter().all(Option::is_none) {
            return Err(Error::NoKey);
        }
        let Restriction::KeyOrKeyring { trusted, chain } = restriction else {
            // No signer is in an empty built-in keyring.
            return Err(Error::NoKey);
        };
        let mut signer = None;
        if let Some(trusted) = trusted {
            let key = self.get(trusted)?;
            signer = match (&key.payload, key.kind) {
                (_, KeyType::Keyring) => self.find_signer(caller, trusted, signature, now),
                (Payload::Asymmetric(candidate), _) => {
                    signed_by(candidate, &signature.authority).then_some(trusted)
                }
                _ => return Err(Error::NotSupported),
            };
        }
        if chain && signer.is_none() {
            signer = self.find_signer(caller, ring, signature, now);
        }
        let signer = self.get(signer.ok_or(Error::NoKey)?)?;
        signer.validate(now)?;
        match &signer.payload {
            Payload::Asymmetric(signer) => signer.verify(signature),
            _ => Err(Error::NoKey),
        }
    }

    /// find_asymmetric_key: the asymmetric key under `keyring` that the
    /// first authority id the signature gives names (the issuer and
    /// serial or key identifier against a key's first two ids, else the
    /// issuer name against its third); given both of the first two ids,
    /// the key must match the second too.
    fn find_signer(
        &self,
        caller: &Caller,
        keyring: i32,
        signature: &Signature,
        now: u64,
    ) -> Option<i32> {
        let [by_issuer, by_key_id, by_name] = &signature.authority;
        let (id, name) = match (by_issuer, by_key_id) {
            (Some(id), _) | (None, Some(id)) => (id, false),
            (None, None) => (by_name.as_ref()?, true),
        };
        let search = Search {
            caller,
            matcher: Match::AsymmetricId(id, name),
            possessed: true,
            check_state: true,
            now,
        };
        let Searched::Found(serial) = self.search_tree(&search, keyring) else {
            return None;
        };
        if let (Some(_), Some(key_id)) = (by_issuer, by_key_id) {
            let Payload::Asymmetric(key) = &self.key(serial)?.payload else {
                return None;
            };
            if key.ids[1].as_ref() != Some(key_id) {
                return None;
            }
        }
        Some(serial)
    }
}

/// Whether the signer ids of `key` match a signature's authority ids as
/// Linux's key_or_keyring_common matches them against a trusted key.
fn signed_by(key: &Asymmetric, authority: &[Option<KeyId>; 3]) -> bool {
    let same = |a: &Option<KeyId>, b: &Option<KeyId>| a.is_some() && a == b;
    let either = |id: &Option<KeyId>| same(&key.ids[0], id) || same(&key.ids[1], id);
    match authority {
        [None, None, name] => same(&key.ids[2], name),
        [Some(_), None, _] | [None, Some(_), _] => either(&authority[0]) || either(&authority[1]),
        [issuer, key_id, _] => same(&key.ids[1], key_id) && either(issuer),
    }
}
