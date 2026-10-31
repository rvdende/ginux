//! The virtio-gpu 2D command protocol (virtio 1.2, section 5.7), as bytes.
//!
//! The kernel driver owns the device, its queues and their DMA memory; this
//! crate only turns commands into the little-endian structures the device
//! reads and checks the replies it writes, so that layout and validation can
//! be tested on the host. It also holds the display-side arithmetic the
//! driver needs: choosing a mode from the host's display information and
//! accumulating damaged rectangles in a single word that can be updated
//! atomically from any context.
//!
//! Only the 2D subset is described: display information, 2D resources with
//! guest-memory backing, scanouts, transfers and flushes. The 3D commands
//! (virgl contexts, blob resources, Venus) come later; [`FEATURE_VIRGL`] and
//! the other feature bits are listed so the driver can report what the host
//! offers.

#![no_std]

/// The modern (virtio 1.x) PCI device ID of a GPU (0x1040 + device type 16).
pub const DEVICE_ID: u16 = 0x1050;

/// The host supports 3D (virgl) contexts.
pub const FEATURE_VIRGL: u64 = 1 << 0;
/// The host supports `GET_EDID`.
pub const FEATURE_EDID: u64 = 1 << 1;
/// The host supports `RESOURCE_ASSIGN_UUID`.
pub const FEATURE_RESOURCE_UUID: u64 = 1 << 2;
/// The host supports blob resources (host-visible memory, needed by Venus).
pub const FEATURE_RESOURCE_BLOB: u64 = 1 << 3;
/// The host supports `CTX_CREATE` with a capset, e.g. Venus or gfxstream.
pub const FEATURE_CONTEXT_INIT: u64 = 1 << 4;

/// The queue that carries every command but cursor updates.
pub const CONTROL_QUEUE: u16 = 0;

/// Byte offset of `num_scanouts` in the device configuration structure.
pub const CONFIG_NUM_SCANOUTS: usize = 8;

/// The most scanouts a device reports in `GET_DISPLAY_INFO`.
pub const MAX_SCANOUTS: usize = 16;

/// Bytes of the header that starts every request and response.
pub const HEADER_SIZE: usize = 24;
/// Bytes of the largest request [`Command::encode`] produces.
pub const MAX_REQUEST: usize = 56;
/// Bytes of the largest response a [`Command`] expects.
pub const MAX_RESPONSE: usize = HEADER_SIZE + MAX_SCANOUTS * 24;

const CMD_GET_DISPLAY_INFO: u32 = 0x0100;
const CMD_RESOURCE_CREATE_2D: u32 = 0x0101;
const CMD_SET_SCANOUT: u32 = 0x0103;
const CMD_RESOURCE_FLUSH: u32 = 0x0104;
const CMD_TRANSFER_TO_HOST_2D: u32 = 0x0105;
const CMD_RESOURCE_ATTACH_BACKING: u32 = 0x0106;

const RESP_OK_NODATA: u32 = 0x1100;
const RESP_OK_DISPLAY_INFO: u32 = 0x1101;
const RESP_ERR_UNSPEC: u32 = 0x1200;
const RESP_ERR_OUT_OF_MEMORY: u32 = 0x1201;
const RESP_ERR_INVALID_SCANOUT_ID: u32 = 0x1202;
const RESP_ERR_INVALID_RESOURCE_ID: u32 = 0x1203;
const RESP_ERR_INVALID_CONTEXT_ID: u32 = 0x1204;
const RESP_ERR_INVALID_PARAMETER: u32 = 0x1205;

/// Bytes per pixel of every format this crate creates resources in.
pub const BYTES_PER_PIXEL: u32 = 4;

/// A pixel format of a 2D resource, named by its bytes in memory order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Format {
    /// Blue, green, red, unused: a little-endian `0x00RRGGBB` word, the
    /// layout of UEFI's `PixelBlueGreenRedReserved8BitPerColor`.
    B8G8R8X8 = 2,
}

/// A rectangle in pixels, as `struct virtio_gpu_rect`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    /// The rectangle covering a whole `width` by `height` surface.
    pub const fn full(width: u32, height: u32) -> Self {
        Self {
            x: 0,
            y: 0,
            width,
            height,
        }
    }

    pub const fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    /// The part of the rectangle inside a `width` by `height` surface.
    pub fn clamp(&self, width: u32, height: u32) -> Self {
        let x = self.x.min(width);
        let y = self.y.min(height);
        Self {
            x,
            y,
            width: self.x.saturating_add(self.width).min(width) - x,
            height: self.y.saturating_add(self.height).min(height) - y,
        }
    }

    fn encode(&self, bytes: &mut [u8]) {
        put_u32(bytes, 0, self.x);
        put_u32(bytes, 4, self.y);
        put_u32(bytes, 8, self.width);
        put_u32(bytes, 12, self.height);
    }

    fn decode(bytes: &[u8]) -> Self {
        Self {
            x: get_u32(bytes, 0),
            y: get_u32(bytes, 4),
            width: get_u32(bytes, 8),
            height: get_u32(bytes, 12),
        }
    }
}

/// The bounding box of damaged pixels, packed into one word so that it can
/// live in an atomic and be extended from any context without a lock.
///
/// Each edge is 16 bits, so surfaces up to 65535 pixels on a side are
/// covered; larger coordinates saturate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Damage(u64);

impl Damage {
    /// No damage.
    pub const EMPTY: Self = Self(0);

    /// Damage covering `rect`.
    pub fn of(rect: Rect) -> Self {
        if rect.is_empty() {
            return Self::EMPTY;
        }
        let edge = |value: u32| u64::from(value.min(u32::from(u16::MAX)));
        let left = edge(rect.x);
        let top = edge(rect.y);
        let right = edge(rect.x.saturating_add(rect.width));
        let bottom = edge(rect.y.saturating_add(rect.height));
        if left == right || top == bottom {
            return Self::EMPTY;
        }
        Self(left | top << 16 | right << 32 | bottom << 48)
    }

    /// The packed word, for storing in an atomic.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Damage from a word that [`Damage::bits`] produced.
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The smallest damage covering both.
    pub fn union(self, other: Self) -> Self {
        match (self.rect(), other.rect()) {
            (None, _) => other,
            (_, None) => self,
            (Some(first), Some(second)) => {
                let left = first.x.min(second.x);
                let top = first.y.min(second.y);
                let right = (first.x + first.width).max(second.x + second.width);
                let bottom = (first.y + first.height).max(second.y + second.height);
                Self::of(Rect {
                    x: left,
                    y: top,
                    width: right - left,
                    height: bottom - top,
                })
            }
        }
    }

    /// The damaged rectangle, if any.
    pub fn rect(self) -> Option<Rect> {
        if self.is_empty() {
            return None;
        }
        let edge = |shift: u32| (self.0 >> shift) as u16 as u32;
        let (left, top, right, bottom) = (edge(0), edge(16), edge(32), edge(48));
        Some(Rect {
            x: left,
            y: top,
            width: right.saturating_sub(left),
            height: bottom.saturating_sub(top),
        })
        .filter(|rect| !rect.is_empty())
    }
}

/// A display mode: the size of a scanout in pixels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mode {
    pub width: u32,
    pub height: u32,
}

impl Mode {
    /// Bytes per row of a tightly packed 32-bit surface in this mode.
    pub fn stride(&self) -> Option<u32> {
        self.width.checked_mul(BYTES_PER_PIXEL)
    }

    /// Bytes of a tightly packed 32-bit surface in this mode.
    pub fn bytes(&self) -> Option<usize> {
        usize::try_from(self.stride()?)
            .ok()?
            .checked_mul(usize::try_from(self.height).ok()?)
    }
}

/// One scanout as `GET_DISPLAY_INFO` describes it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scanout {
    pub rect: Rect,
    pub enabled: bool,
}

/// The reply to `GET_DISPLAY_INFO`: the host's preferred size for each
/// scanout, which follows the host window or the `xres`/`yres` settings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DisplayInfo {
    pub scanouts: [Scanout; MAX_SCANOUTS],
}

impl DisplayInfo {
    /// Parses a `virtio_gpu_resp_display_info`, header included.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        match Response::parse(bytes)? {
            Response::DisplayInfo => {}
            Response::Error(code) => return Err(Error::Device(code)),
            other => return Err(Error::Unexpected(other)),
        }
        if bytes.len() < MAX_RESPONSE {
            return Err(Error::Truncated);
        }
        let mut scanouts = [Scanout {
            rect: Rect::default(),
            enabled: false,
        }; MAX_SCANOUTS];
        for (index, scanout) in scanouts.iter_mut().enumerate() {
            let entry = &bytes[HEADER_SIZE + index * 24..HEADER_SIZE + (index + 1) * 24];
            *scanout = Scanout {
                rect: Rect::decode(&entry[..16]),
                enabled: get_u32(entry, 16) != 0,
            };
        }
        Ok(Self { scanouts })
    }

    /// Picks the scanout to drive and its mode: the first enabled scanout
    /// among the first `count` whose surface fits in `max_bytes`, or else
    /// scanout 0 at `fallback`.
    pub fn choose(&self, count: usize, max_bytes: usize, fallback: Mode) -> (u32, Mode) {
        self.scanouts
            .iter()
            .take(count.min(MAX_SCANOUTS))
            .enumerate()
            .filter(|(_, scanout)| scanout.enabled)
            .map(|(index, scanout)| {
                (
                    index as u32,
                    Mode {
                        width: scanout.rect.width,
                        height: scanout.rect.height,
                    },
                )
            })
            .find(|(_, mode)| {
                mode.width != 0
                    && mode.height != 0
                    && mode.bytes().is_some_and(|bytes| bytes <= max_bytes)
            })
            .unwrap_or((0, fallback))
    }
}

/// A command for the control queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    /// Asks for the host's preferred mode of every scanout.
    GetDisplayInfo,
    /// Creates a host-side 2D resource with no backing yet.
    ResourceCreate2d {
        resource: u32,
        format: Format,
        width: u32,
        height: u32,
    },
    /// Backs a resource with one guest-physical (device-address) range.
    /// A contiguous range needs a single entry.
    AttachBacking {
        resource: u32,
        address: u64,
        length: u32,
    },
    /// Shows `rect` of a resource on a scanout; resource 0 disables it.
    SetScanout {
        scanout: u32,
        resource: u32,
        rect: Rect,
    },
    /// Copies `rect` from the backing into the host resource, reading the
    /// backing from byte `offset` (the rectangle's first pixel) onwards.
    TransferToHost2d {
        resource: u32,
        rect: Rect,
        offset: u64,
    },
    /// Updates every scanout showing `rect` of the resource.
    ResourceFlush { resource: u32, rect: Rect },
}

/// An encoded request: the first `len` bytes of `bytes`.
#[derive(Clone, Copy, Debug)]
pub struct Request {
    bytes: [u8; MAX_REQUEST],
    len: usize,
}

impl Request {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl Command {
    /// The request structure the device reads, header first.
    pub fn encode(&self) -> Request {
        let mut bytes = [0_u8; MAX_REQUEST];
        let (kind, len) = match *self {
            Self::GetDisplayInfo => (CMD_GET_DISPLAY_INFO, HEADER_SIZE),
            Self::ResourceCreate2d {
                resource,
                format,
                width,
                height,
            } => {
                put_u32(&mut bytes, 24, resource);
                put_u32(&mut bytes, 28, format as u32);
                put_u32(&mut bytes, 32, width);
                put_u32(&mut bytes, 36, height);
                (CMD_RESOURCE_CREATE_2D, 40)
            }
            Self::AttachBacking {
                resource,
                address,
                length,
            } => {
                put_u32(&mut bytes, 24, resource);
                // nr_entries, then the single virtio_gpu_mem_entry.
                put_u32(&mut bytes, 28, 1);
                put_u64(&mut bytes, 32, address);
                put_u32(&mut bytes, 40, length);
                (CMD_RESOURCE_ATTACH_BACKING, 48)
            }
            Self::SetScanout {
                scanout,
                resource,
                rect,
            } => {
                rect.encode(&mut bytes[24..40]);
                put_u32(&mut bytes, 40, scanout);
                put_u32(&mut bytes, 44, resource);
                (CMD_SET_SCANOUT, 48)
            }
            Self::TransferToHost2d {
                resource,
                rect,
                offset,
            } => {
                rect.encode(&mut bytes[24..40]);
                put_u64(&mut bytes, 40, offset);
                put_u32(&mut bytes, 48, resource);
                (CMD_TRANSFER_TO_HOST_2D, 56)
            }
            Self::ResourceFlush { resource, rect } => {
                rect.encode(&mut bytes[24..40]);
                put_u32(&mut bytes, 40, resource);
                (CMD_RESOURCE_FLUSH, 48)
            }
        };
        // flags, fence_id, ctx_id and ring_idx stay zero: no fences, no 3D
        // context.
        put_u32(&mut bytes, 0, kind);
        Request { bytes, len }
    }

    /// Bytes the device writes in reply.
    pub fn response_len(&self) -> usize {
        match self {
            Self::GetDisplayInfo => MAX_RESPONSE,
            _ => HEADER_SIZE,
        }
    }

    /// Checks the reply to this command, whose header starts `response`.
    pub fn check(&self, response: &[u8]) -> Result<(), Error> {
        let expected = match self {
            Self::GetDisplayInfo => Response::DisplayInfo,
            _ => Response::NoData,
        };
        match Response::parse(response)? {
            Response::Error(code) => Err(Error::Device(code)),
            reply if reply == expected => Ok(()),
            reply => Err(Error::Unexpected(reply)),
        }
    }
}

/// What a response header says.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response {
    NoData,
    DisplayInfo,
    Error(ErrorCode),
    /// A type this crate does not know, including zero: the device never
    /// wrote the header.
    Other(u32),
}

impl Response {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_SIZE {
            return Err(Error::Truncated);
        }
        Ok(match get_u32(bytes, 0) {
            RESP_OK_NODATA => Self::NoData,
            RESP_OK_DISPLAY_INFO => Self::DisplayInfo,
            RESP_ERR_UNSPEC => Self::Error(ErrorCode::Unspecified),
            RESP_ERR_OUT_OF_MEMORY => Self::Error(ErrorCode::OutOfMemory),
            RESP_ERR_INVALID_SCANOUT_ID => Self::Error(ErrorCode::InvalidScanout),
            RESP_ERR_INVALID_RESOURCE_ID => Self::Error(ErrorCode::InvalidResource),
            RESP_ERR_INVALID_CONTEXT_ID => Self::Error(ErrorCode::InvalidContext),
            RESP_ERR_INVALID_PARAMETER => Self::Error(ErrorCode::InvalidParameter),
            other => Self::Other(other),
        })
    }
}

/// The error responses of section 5.7.6.7.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorCode {
    Unspecified,
    OutOfMemory,
    InvalidScanout,
    InvalidResource,
    InvalidContext,
    InvalidParameter,
}

/// Why a reply was not the success the command expected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The device reported an error.
    Device(ErrorCode),
    /// The device replied with another type, or not at all.
    Unexpected(Response),
    /// The reply was shorter than its structure.
    Truncated,
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut word = [0; 4];
    word.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(word)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], offset: usize) -> u32 {
        get_u32(bytes, offset)
    }

    #[test]
    fn get_display_info_is_a_bare_header() {
        let request = Command::GetDisplayInfo.encode();
        assert_eq!(request.as_bytes().len(), HEADER_SIZE);
        assert_eq!(word(request.as_bytes(), 0), 0x0100);
        assert!(request.as_bytes()[4..].iter().all(|byte| *byte == 0));
        assert_eq!(Command::GetDisplayInfo.response_len(), 408);
    }

    #[test]
    fn create_2d_layout() {
        let request = Command::ResourceCreate2d {
            resource: 1,
            format: Format::B8G8R8X8,
            width: 1280,
            height: 800,
        }
        .encode();
        let bytes = request.as_bytes();
        assert_eq!(bytes.len(), 40);
        assert_eq!(word(bytes, 0), 0x0101);
        assert_eq!(
            [
                word(bytes, 24),
                word(bytes, 28),
                word(bytes, 32),
                word(bytes, 36)
            ],
            [1, 2, 1280, 800]
        );
    }

    #[test]
    fn attach_backing_has_one_entry() {
        let request = Command::AttachBacking {
            resource: 7,
            address: 0x1_2345_6000,
            length: 4_096_000,
        }
        .encode();
        let bytes = request.as_bytes();
        assert_eq!(bytes.len(), 48);
        assert_eq!(word(bytes, 0), 0x0106);
        assert_eq!([word(bytes, 24), word(bytes, 28)], [7, 1]);
        assert_eq!(&bytes[32..40], &0x1_2345_6000_u64.to_le_bytes());
        assert_eq!([word(bytes, 40), word(bytes, 44)], [4_096_000, 0]);
    }

    #[test]
    fn scanout_transfer_and_flush_layouts() {
        let rect = Rect {
            x: 8,
            y: 16,
            width: 32,
            height: 64,
        };
        let scanout = Command::SetScanout {
            scanout: 0,
            resource: 1,
            rect,
        }
        .encode();
        let bytes = scanout.as_bytes();
        assert_eq!((bytes.len(), word(bytes, 0)), (48, 0x0103));
        assert_eq!(
            [
                word(bytes, 24),
                word(bytes, 28),
                word(bytes, 32),
                word(bytes, 36)
            ],
            [8, 16, 32, 64]
        );
        assert_eq!([word(bytes, 40), word(bytes, 44)], [0, 1]);

        let transfer = Command::TransferToHost2d {
            resource: 1,
            rect,
            offset: 16 * 5120 + 8 * 4,
        }
        .encode();
        let bytes = transfer.as_bytes();
        assert_eq!((bytes.len(), word(bytes, 0)), (56, 0x0105));
        assert_eq!(&bytes[40..48], &(16_u64 * 5120 + 32).to_le_bytes());
        assert_eq!(word(bytes, 48), 1);

        let flush = Command::ResourceFlush { resource: 1, rect }.encode();
        let bytes = flush.as_bytes();
        assert_eq!((bytes.len(), word(bytes, 0)), (48, 0x0104));
        assert_eq!(word(bytes, 40), 1);
    }

    #[test]
    fn replies_are_checked() {
        let mut reply = [0_u8; HEADER_SIZE];
        let flush = Command::ResourceFlush {
            resource: 1,
            rect: Rect::full(1, 1),
        };
        assert_eq!(
            flush.check(&reply),
            Err(Error::Unexpected(Response::Other(0)))
        );
        put_u32(&mut reply, 0, RESP_OK_NODATA);
        assert_eq!(flush.check(&reply), Ok(()));
        put_u32(&mut reply, 0, RESP_ERR_INVALID_RESOURCE_ID);
        assert_eq!(
            flush.check(&reply),
            Err(Error::Device(ErrorCode::InvalidResource))
        );
        assert_eq!(flush.check(&reply[..8]), Err(Error::Truncated));
        put_u32(&mut reply, 0, RESP_OK_NODATA);
        assert_eq!(
            Command::GetDisplayInfo.check(&reply),
            Err(Error::Unexpected(Response::NoData))
        );
    }

    fn display_info(modes: &[(u32, u32, bool)]) -> [u8; MAX_RESPONSE] {
        let mut bytes = [0_u8; MAX_RESPONSE];
        put_u32(&mut bytes, 0, RESP_OK_DISPLAY_INFO);
        for (index, (width, height, enabled)) in modes.iter().enumerate() {
            let entry = HEADER_SIZE + index * 24;
            put_u32(&mut bytes, entry + 8, *width);
            put_u32(&mut bytes, entry + 12, *height);
            put_u32(&mut bytes, entry + 16, u32::from(*enabled));
        }
        bytes
    }

    #[test]
    fn display_info_picks_the_first_enabled_scanout_that_fits() {
        let fallback = Mode {
            width: 1024,
            height: 768,
        };
        let info = DisplayInfo::parse(&display_info(&[
            (0, 0, false),
            (1920, 1080, true),
            (800, 600, true),
        ]))
        .unwrap();
        assert!(info.scanouts[1].enabled);
        assert_eq!(
            info.choose(16, 16 << 20, fallback),
            (
                1,
                Mode {
                    width: 1920,
                    height: 1080
                }
            )
        );
        // Too large for the limit: the next enabled scanout.
        assert_eq!(
            info.choose(16, 4 << 20, fallback),
            (
                2,
                Mode {
                    width: 800,
                    height: 600
                }
            )
        );
        // Only the first scanout exists: nothing enabled there.
        assert_eq!(info.choose(1, 16 << 20, fallback), (0, fallback));
        assert_eq!(
            DisplayInfo::parse(&display_info(&[])[..100]),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn damage_unions_into_a_bounding_box() {
        let first = Damage::of(Rect {
            x: 10,
            y: 20,
            width: 30,
            height: 40,
        });
        let second = Damage::of(Rect {
            x: 100,
            y: 5,
            width: 1,
            height: 1,
        });
        assert_eq!(
            first.union(second).rect(),
            Some(Rect {
                x: 10,
                y: 5,
                width: 91,
                height: 55
            })
        );
        assert_eq!(Damage::EMPTY.union(first), first);
        assert_eq!(first.union(Damage::EMPTY), first);
        assert_eq!(Damage::of(Rect::full(0, 10)), Damage::EMPTY);
        assert_eq!(Damage::from_bits(first.bits()), first);
        // Coordinates saturate at 16 bits.
        assert_eq!(
            Damage::of(Rect::full(70_000, 2)).rect(),
            Some(Rect::full(65_535, 2))
        );
    }

    #[test]
    fn rects_clamp_to_the_surface() {
        let rect = Rect {
            x: 1000,
            y: 700,
            width: 500,
            height: 500,
        };
        assert_eq!(
            rect.clamp(1280, 800),
            Rect {
                x: 1000,
                y: 700,
                width: 280,
                height: 100
            }
        );
        assert!(Rect { x: 2000, ..rect }.clamp(1280, 800).is_empty());
    }

    #[test]
    fn modes_know_their_size() {
        let mode = Mode {
            width: 1280,
            height: 800,
        };
        assert_eq!(mode.stride(), Some(5120));
        assert_eq!(mode.bytes(), Some(4_096_000));
        assert_eq!(
            Mode {
                width: u32::MAX,
                height: 2
            }
            .stride(),
            None
        );
    }
}
