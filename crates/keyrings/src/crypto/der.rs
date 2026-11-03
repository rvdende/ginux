//! A reader for the DER encoding of ASN.1 that certificates and private
//! keys use. Anything malformed is EBADMSG, as Linux's ASN.1 decoder
//! reports it.

use crate::Error;

pub(crate) const BOOLEAN: u8 = 0x01;
pub(crate) const INTEGER: u8 = 0x02;
pub(crate) const BIT_STRING: u8 = 0x03;
pub(crate) const OCTET_STRING: u8 = 0x04;
pub(crate) const OBJECT_IDENTIFIER: u8 = 0x06;
pub(crate) const UTC_TIME: u8 = 0x17;
pub(crate) const GENERALIZED_TIME: u8 = 0x18;
pub(crate) const SEQUENCE: u8 = 0x30;
pub(crate) const SET: u8 = 0x31;

/// The tag of context-specific element `number`, constructed or not.
pub(crate) const fn context(number: u8, constructed: bool) -> u8 {
    0x80 | if constructed { 0x20 } else { 0 } | number
}

/// One element: its tag, its whole encoding and its contents.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Element<'a> {
    pub(crate) tag: u8,
    pub(crate) encoding: &'a [u8],
    pub(crate) contents: &'a [u8],
}

impl<'a> Element<'a> {
    /// A reader over a constructed element's contents.
    pub(crate) fn reader(&self) -> Reader<'a> {
        Reader::new(self.contents)
    }

    /// A BIT STRING's bits, which must fill whole bytes.
    pub(crate) fn bit_string(&self) -> Result<&'a [u8], Error> {
        match self.contents.split_first() {
            Some((0, bits)) if self.tag == BIT_STRING => Ok(bits),
            _ => Err(Error::BadMessage),
        }
    }
}

/// Elements one after another.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) const fn new(data: &'a [u8]) -> Self {
        Self { rest: data }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    pub(crate) fn next(&mut self) -> Result<Element<'a>, Error> {
        let (&tag, after) = self.rest.split_first().ok_or(Error::BadMessage)?;
        // Tag numbers above 30 need more bytes; nothing here uses them.
        if tag & 0x1f == 0x1f {
            return Err(Error::BadMessage);
        }
        let (&first, after) = after.split_first().ok_or(Error::BadMessage)?;
        let (length, after) = if first < 0x80 {
            (usize::from(first), after)
        } else {
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 4 || after.len() < count {
                return Err(Error::BadMessage);
            }
            let length = after[..count]
                .iter()
                .fold(0_usize, |length, &byte| length << 8 | usize::from(byte));
            (length, &after[count..])
        };
        if after.len() < length {
            return Err(Error::BadMessage);
        }
        let header = self.rest.len() - after.len();
        let encoding = &self.rest[..header + length];
        self.rest = &after[length..];
        Ok(Element {
            tag,
            encoding,
            contents: &encoding[header..],
        })
    }

    /// The next element, which must have `tag`.
    pub(crate) fn expect(&mut self, tag: u8) -> Result<Element<'a>, Error> {
        let element = self.next()?;
        if element.tag == tag {
            Ok(element)
        } else {
            Err(Error::BadMessage)
        }
    }

    /// The next element if it has `tag`.
    pub(crate) fn optional(&mut self, tag: u8) -> Result<Option<Element<'a>>, Error> {
        if self.peek_tag() == Some(tag) {
            self.next().map(Some)
        } else {
            Ok(None)
        }
    }
}
