//! The "encrypted" key type: secret data that user space only ever sees
//! encrypted, under AES-256-CBC with a key derived from a master key and
//! authenticated with HMAC-SHA256, as Linux's encrypted-keys module keeps
//! it. Its payload is a command:
//!
//! - `new [FORMAT] MASTER LENGTH [DATA]` makes LENGTH (20 to 4096) bytes
//!   of random data, or takes DATA as hex digits (Linux's
//!   CONFIG_USER_DECRYPTED_DATA, which Ginux has);
//! - `load [FORMAT] MASTER LENGTH BLOB` decrypts a blob KEYCTL_READ gave;
//! - `update MASTER` (KEYCTL_UPDATE only) changes the master key.
//!
//! FORMAT is "default", "ecryptfs" or "enc32"; MASTER is "user:NAME", a
//! "user" key found in the caller's keyrings, or "trusted:NAME", which is
//! EOPNOTSUPP since there are no trusted keys. The master key is only
//! needed to read or load the key.

use alloc::vec::Vec;

use crate::crypto::aes::{self, Aes256};
use crate::crypto::{parse_hex, push_hex, sha256};
use crate::keys::copy;
use crate::{no_memory, Error};

const LENGTH_MINIMUM: usize = 20;
const LENGTH_MAXIMUM: usize = 4096;
/// The largest payload add_key(2) or KEYCTL_UPDATE may give.
const COMMAND_LIMIT: usize = 32_767;
const USER_PREFIX: &[u8] = b"user:";
const TRUSTED_PREFIX: &[u8] = b"trusted:";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    Default,
    /// For eCryptfs: a description of 16 hex digits and 64 bytes of data.
    Ecryptfs,
    /// Exactly 32 bytes of data.
    Enc32,
}

impl Format {
    fn from_name(name: &[u8]) -> Option<Self> {
        match name {
            b"default" => Some(Self::Default),
            b"ecryptfs" => Some(Self::Ecryptfs),
            b"enc32" => Some(Self::Enc32),
            _ => None,
        }
    }

    const fn name(self) -> &'static [u8] {
        match self {
            Self::Default => b"default",
            Self::Ecryptfs => b"ecryptfs",
            Self::Enc32 => b"enc32",
        }
    }
}

/// An encrypted key's payload.
pub(crate) struct Encrypted {
    format: Format,
    /// "user:NAME" or "trusted:NAME".
    master: Vec<u8>,
    /// The data length as the command spelled it.
    length_text: Vec<u8>,
    iv: [u8; aes::BLOCK_BYTES],
    data: Vec<u8>,
}

/// A command's words, split as strsep(" \t") splits them: each separator
/// ends a word, so two in a row give an empty one.
struct Words<'a>(Option<&'a [u8]>);

impl<'a> Words<'a> {
    fn new(command: &'a [u8]) -> Self {
        // Linux copies the payload as a C string.
        let end = command
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(command.len());
        Self(Some(&command[..end]))
    }
}

impl<'a> Iterator for Words<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        let rest = self.0?;
        match rest.iter().position(|&byte| byte == b' ' || byte == b'\t') {
            Some(index) => {
                self.0 = Some(&rest[index + 1..]);
                Some(&rest[..index])
            }
            None => {
                self.0 = None;
                Some(rest)
            }
        }
    }
}

/// What a command says, as Linux's datablob_parse reads it.
struct Command<'a> {
    keyword: &'a [u8],
    format: Option<Format>,
    master: &'a [u8],
    length: Option<&'a [u8]>,
    /// The hex data of "new" or the blob of "load".
    argument: Option<&'a [u8]>,
}

/// `update` says whether the command came from KEYCTL_UPDATE, which takes
/// no length; anything malformed is EINVAL.
fn parse_command(command: &[u8], update: bool) -> Result<Command<'_>, Error> {
    if command.is_empty() || command.len() > COMMAND_LIMIT {
        return Err(Error::Invalid);
    }
    let mut words = Words::new(command);
    let keyword = words.next().ok_or(Error::Invalid)?;
    let second = words.next().ok_or(Error::Invalid)?;
    let format = Format::from_name(second);
    let master = if format.is_some() {
        words.next().ok_or(Error::Invalid)?
    } else {
        second
    };
    check_master(master, None)?;
    let length = if update {
        None
    } else {
        Some(words.next().ok_or(Error::Invalid)?)
    };
    let argument = match (keyword, update) {
        (b"new", false) => words.next(),
        (b"load", false) => Some(words.next().ok_or(Error::Invalid)?),
        (b"update", true) => None,
        _ => return Err(Error::Invalid),
    };
    Ok(Command {
        keyword,
        format,
        master,
        length,
        argument,
    })
}

/// A master key name needs a "user:" or "trusted:" prefix and a name; an
/// update must keep the prefix of `old`.
fn check_master(master: &[u8], old: Option<&[u8]>) -> Result<(), Error> {
    let prefix = [USER_PREFIX, TRUSTED_PREFIX]
        .into_iter()
        .find(|prefix| master.starts_with(prefix))
        .ok_or(Error::Invalid)?;
    if master.len() == prefix.len() || old.is_some_and(|old| !old.starts_with(prefix)) {
        return Err(Error::Invalid);
    }
    Ok(())
}

/// kstrtol in base 10: an optional sign, digits and an optional newline.
fn parse_length(text: &[u8]) -> Option<usize> {
    let text = text.strip_suffix(b"\n").unwrap_or(text);
    let digits = text.strip_prefix(b"+").unwrap_or(text);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    digits.iter().try_fold(0_usize, |value, &digit| {
        value
            .checked_mul(10)?
            .checked_add(usize::from(digit - b'0'))
    })
}

/// The key derived from the master key for encryption or authentication:
/// SHA-256 over the label, its NUL and the master key, in a buffer sized
/// for the longer label and at least one digest long.
fn derive(label: &[u8], master_key: &[u8]) -> Result<[u8; aes::KEY_BYTES], Error> {
    let length = (b"AUTH_KEY".len() + 1 + master_key.len()).max(sha256::DIGEST_BYTES);
    let mut buffer = Vec::new();
    buffer.try_reserve_exact(length).map_err(no_memory)?;
    buffer.resize(length, 0);
    buffer[..label.len()].copy_from_slice(label);
    buffer[label.len() + 1..][..master_key.len()].copy_from_slice(master_key);
    Ok(sha256::digest(&[&buffer]))
}

impl Encrypted {
    /// encrypted_instantiate: runs a "new" or "load" command for a key
    /// described `description`. `random` fills the IV and any random data;
    /// `master_key` finds the master key's data for a "load".
    pub(crate) fn instantiate(
        description: &[u8],
        command: &[u8],
        random: impl FnOnce(&mut [u8]) -> Result<(), Error>,
        master_key: impl FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
    ) -> Result<Self, Error> {
        let command = parse_command(command, false)?;
        let length_text = command.length.ok_or(Error::Invalid)?;
        let length = parse_length(length_text)
            .filter(|length| (LENGTH_MINIMUM..=LENGTH_MAXIMUM).contains(length))
            .ok_or(Error::Invalid)?;
        let format = command.format.unwrap_or(Format::Default);
        let data = match (command.keyword, command.argument) {
            (b"new", Some(hex)) => {
                if hex.len() != length * 2 {
                    return Err(Error::Invalid);
                }
                Some(parse_hex(hex)?)
            }
            _ => None,
        };
        let valid_length = match format {
            Format::Ecryptfs => length == 64,
            Format::Enc32 => length == 32,
            Format::Default => true,
        };
        if !valid_length {
            return Err(Error::Invalid);
        }
        if format == Format::Ecryptfs
            && !(description.len() == 16 && description.iter().all(u8::is_ascii_hexdigit))
        {
            return Err(Error::Invalid);
        }
        let mut key = Self {
            format,
            master: copy(command.master)?,
            length_text: copy(length_text)?,
            iv: [0; aes::BLOCK_BYTES],
            data: Vec::new(),
        };
        if command.keyword == b"load" {
            let blob = command.argument.ok_or(Error::Invalid)?;
            key.load(blob, command.format.is_some(), master_key)?;
            return Ok(key);
        }
        let mut random_bytes = Vec::new();
        random_bytes
            .try_reserve_exact(aes::BLOCK_BYTES + length)
            .map_err(no_memory)?;
        random_bytes.resize(
            aes::BLOCK_BYTES + if data.is_some() { 0 } else { length },
            0,
        );
        random(&mut random_bytes)?;
        key.iv.copy_from_slice(&random_bytes[..aes::BLOCK_BYTES]);
        key.data = match data {
            Some(data) => data,
            None => copy(&random_bytes[aes::BLOCK_BYTES..])?,
        };
        Ok(key)
    }

    /// encrypted_update: KEYCTL_UPDATE's "update MASTER" gives the key a
    /// new master key of the same kind.
    pub(crate) fn update(&self, command: &[u8]) -> Result<Self, Error> {
        let command = parse_command(command, true)?;
        check_master(command.master, Some(&self.master))?;
        Ok(Self {
            format: self.format,
            master: copy(command.master)?,
            length_text: copy(&self.length_text)?,
            iv: self.iv,
            data: copy(&self.data)?,
        })
    }

    fn encrypted_length(&self) -> usize {
        self.data.len().next_multiple_of(aes::BLOCK_BYTES)
    }

    /// The format, master key name, length text, IV and encrypted data,
    /// each followed by a NUL but the last: what the HMAC covers.
    fn blob_length(&self) -> usize {
        self.format.name().len()
            + 1
            + self.master.len()
            + 1
            + self.length_text.len()
            + 1
            + aes::BLOCK_BYTES
            + 1
            + self.encrypted_length()
    }

    pub(crate) fn quota_bytes(&self) -> usize {
        self.data.len() + self.blob_length() + sha256::DIGEST_BYTES + 1
    }

    /// The master key name, which KEYCTL_READ and "load" look up.
    pub(crate) fn master(&self) -> &[u8] {
        &self.master
    }

    /// How long KEYCTL_READ's text is.
    pub(crate) fn read_length(&self) -> usize {
        self.blob_length()
            + aes::BLOCK_BYTES
            + 1
            + self.encrypted_length()
            + 2 * sha256::DIGEST_BYTES
    }

    fn blob(&self, encrypted: &[u8]) -> Result<Vec<u8>, Error> {
        let mut blob = Vec::new();
        blob.try_reserve_exact(self.blob_length())
            .map_err(no_memory)?;
        for part in [
            self.format.name(),
            &self.master,
            &self.length_text,
            &self.iv[..],
        ] {
            blob.extend_from_slice(part);
            blob.push(0);
        }
        blob.extend_from_slice(encrypted);
        Ok(blob)
    }

    /// KEYCTL_READ's text: "FORMAT MASTER LENGTH " and the hex of the IV,
    /// a zero byte, the encrypted data and the HMAC, under `master_key`.
    pub(crate) fn read(&self, master_key: &[u8]) -> Result<Vec<u8>, Error> {
        let cipher = Aes256::new(&derive(b"ENC_KEY", master_key)?);
        let mut encrypted = Vec::new();
        encrypted
            .try_reserve_exact(self.encrypted_length())
            .map_err(no_memory)?;
        encrypted.extend_from_slice(&self.data);
        encrypted.resize(self.encrypted_length(), 0);
        cipher.encrypt_cbc(&self.iv, &mut encrypted);
        let blob = self.blob(&encrypted)?;
        let mac = sha256::hmac(&derive(b"AUTH_KEY", master_key)?, &[&blob]);
        let mut text = Vec::new();
        text.try_reserve_exact(self.read_length())
            .map_err(no_memory)?;
        for part in [self.format.name(), &self.master, &self.length_text] {
            text.extend_from_slice(part);
            text.push(b' ');
        }
        push_hex(&mut text, &self.iv)?;
        push_hex(&mut text, &[0])?;
        push_hex(&mut text, &encrypted)?;
        push_hex(&mut text, &mac)?;
        Ok(text)
    }

    /// encrypted_key_decrypt: takes the IV and data from a blob that
    /// KEYCTL_READ gave, once its HMAC checks out. Without an explicit
    /// format the HMAC starts at the master key name, as for blobs from
    /// before formats existed. A blob of the wrong length, bad hex or a
    /// wrong HMAC is EINVAL.
    fn load(
        &mut self,
        blob: &[u8],
        format_given: bool,
        master_key: impl FnOnce(&[u8]) -> Result<Vec<u8>, Error>,
    ) -> Result<(), Error> {
        let length = parse_length(&self.length_text).ok_or(Error::Invalid)?;
        let encrypted_length = length.next_multiple_of(aes::BLOCK_BYTES);
        if blob.len() != (aes::BLOCK_BYTES + 1 + encrypted_length + sha256::DIGEST_BYTES) * 2 {
            return Err(Error::Invalid);
        }
        let iv_hex = 2 * aes::BLOCK_BYTES;
        let data_hex = iv_hex + 2;
        let mac_hex = data_hex + 2 * encrypted_length;
        let iv = parse_hex(&blob[..iv_hex])?;
        let mut encrypted = parse_hex(&blob[data_hex..mac_hex])?;
        let mac = parse_hex(&blob[mac_hex..])?;
        self.iv.copy_from_slice(&iv);
        let master_key = master_key(&self.master)?;
        let blob = self.blob(&encrypted)?;
        let covered = if format_given {
            &blob[..]
        } else {
            &blob[self.format.name().len() + 1..]
        };
        if sha256::hmac(&derive(b"AUTH_KEY", &master_key)?, &[covered])[..] != mac[..] {
            return Err(Error::Invalid);
        }
        Aes256::new(&derive(b"ENC_KEY", &master_key)?).decrypt_cbc(&self.iv, &mut encrypted);
        encrypted.truncate(length);
        self.data = encrypted;
        Ok(())
    }
}
