//! The text of /proc/keys and /proc/key-users, and the fallible buffer
//! that text and KEYCTL_DESCRIBE are formatted into.

use alloc::vec::Vec;
use core::fmt;

use crate::keys::State;
use crate::permission::{possessor, VIEW};
use crate::{no_memory, Caller, Error, KeyType, Keyrings, NANOSECONDS_PER_SECOND, OVERFLOW_ID};

/// Bytes formatted with `format_args!`, growing only by `try_reserve`.
pub(crate) struct Text(Vec<u8>);

impl Text {
    pub(crate) const fn new() -> Self {
        Self(Vec::new())
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.0.try_reserve(bytes.len()).map_err(no_memory)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    /// Formatting can only fail here by running out of memory.
    pub(crate) fn format(&mut self, arguments: fmt::Arguments<'_>) -> Result<(), Error> {
        fmt::Write::write_fmt(self, arguments).map_err(no_memory)
    }
}

impl fmt::Write for Text {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        self.push(text.as_bytes()).map_err(|_| fmt::Error)
    }
}

impl Keyrings {
    /// /proc/keys as `caller` reads it: one line per key it may view
    /// (possessing it counts), with the serial, state flags, references,
    /// time left, permissions, owner, group, type and description, and the
    /// payload size or link count of an instantiated key.
    pub fn proc_keys(&self, caller: &Caller, now: u64) -> Result<Vec<u8>, Error> {
        let mut text = Text::new();
        for key in &self.keys {
            // Searching for possession is only worth it if it could matter.
            let possessed =
                key.permissions & possessor(VIEW) != 0 && self.possesses(caller, key.serial);
            if !key.permits(caller, possessed, VIEW) {
                continue;
            }
            let flag = |set: bool, letter: char| if set { letter } else { '-' };
            text.format(format_args!(
                "{:08x} I{}-Q-{}{} {:5} ",
                key.serial,
                flag(key.state == State::Revoked, 'R'),
                flag(matches!(key.state, State::Negative(_)), 'N'),
                flag(key.state == State::Invalidated, 'i'),
                key.references,
            ))?;
            write_timeout(&mut text, key.expiry, now)?;
            text.format(format_args!(
                " {:08x} {:5} {:5} {:<9.9} ",
                key.permissions,
                key.uid,
                key.gid.unwrap_or(OVERFLOW_ID),
                key.kind.name(),
            ))?;
            text.push(&key.description)?;
            if !matches!(key.state, State::Negative(_)) {
                match key.kind {
                    KeyType::Keyring if key.links.is_empty() => text.push(b": empty")?,
                    KeyType::Keyring => text.format(format_args!(": {}", key.links.len()))?,
                    KeyType::User | KeyType::Logon => {
                        text.format(format_args!(": {}", key.payload.len()))?;
                    }
                }
            }
            text.push(b"\n")?;
        }
        Ok(text.into_bytes())
    }

    /// /proc/key-users: for each user owning keys, "uid: usage
    /// keys/instantiated keys/max keys bytes/max bytes". Every key here is
    /// instantiated and counts against the quota, so the key count appears
    /// in each of those places.
    pub fn proc_key_users(&self) -> Result<Vec<u8>, Error> {
        let mut text = Text::new();
        for user in self.users.iter().filter(|user| user.keys != 0) {
            let (max_keys, max_bytes) = self.limits.of(user.uid);
            text.format(format_args!(
                "{:5}: {:5} {}/{} {}/{} {}/{}\n",
                user.uid,
                user.keys,
                user.keys,
                user.keys,
                user.keys,
                max_keys,
                user.bytes,
                max_bytes,
            ))?;
        }
        Ok(text.into_bytes())
    }
}

/// The four-column time left: "perm" without a timeout, "expd" once it
/// has passed, else whole seconds, minutes, hours, days or weeks.
fn write_timeout(text: &mut Text, expiry: Option<u64>, now: u64) -> Result<(), Error> {
    let Some(expiry) = expiry else {
        return text.push(b"perm");
    };
    if now >= expiry {
        return text.push(b"expd");
    }
    let seconds = (expiry - now).div_ceil(NANOSECONDS_PER_SECOND);
    let (amount, unit) = match seconds {
        0..60 => (seconds, 's'),
        60..3_600 => (seconds / 60, 'm'),
        3_600..86_400 => (seconds / 3_600, 'h'),
        86_400..604_800 => (seconds / 86_400, 'd'),
        _ => (seconds / 604_800, 'w'),
    };
    text.format(format_args!("{amount:>3}{unit}"))
}
