#![forbid(unsafe_code)]
//! USB Audio Class 1 and 2 playback descriptors: which streaming interface
//! settings carry PCM to a device, the clock that sets their rate, what they
//! are wired to, and how 48 kHz samples split into isochronous packets.
//!
//! This is pure descriptor logic so the xHCI driver stays thin and the
//! parsing can be tested on the host against real devices' descriptors.

#![no_std]

#[cfg(test)]
extern crate std;

/// Outputs reported for one device.
pub const MAX_OUTPUTS: usize = 4;
/// The only rate the driver plays at.
pub const SAMPLE_RATE: u32 = 48_000;
/// One period of the 500 Hz test tone at 48 kHz.
pub const TONE_FRAMES: usize = 96;

const DESCRIPTOR_INTERFACE: u8 = 4;
const DESCRIPTOR_ENDPOINT: u8 = 5;
const DESCRIPTOR_CS_INTERFACE: u8 = 0x24;
const CLASS_AUDIO: u8 = 1;
const SUBCLASS_CONTROL: u8 = 1;
const SUBCLASS_STREAMING: u8 = 2;
/// bInterfaceProtocol of Audio Class 2 interfaces.
const PROTOCOL_VERSION_2: u8 = 0x20;
const MAX_ENTITIES: usize = 64;
/// Longest chain of entities followed between a terminal and its clock or
/// its other terminal.
const MAX_CHAIN: usize = 16;

// Class-specific AudioControl descriptor subtypes.
const INPUT_TERMINAL: u8 = 2;
const OUTPUT_TERMINAL: u8 = 3;
const MIXER_UNIT: u8 = 4;
const SELECTOR_UNIT: u8 = 5;
const FEATURE_UNIT: u8 = 6;
/// A processing unit in class 1 and an effect unit in class 2.
const UNIT_7: u8 = 7;
/// An extension unit in class 1 and a processing unit in class 2.
const UNIT_8: u8 = 8;
const EXTENSION_UNIT_2: u8 = 9;
const CLOCK_SOURCE: u8 = 0x0a;
const CLOCK_SELECTOR: u8 = 0x0b;
const CLOCK_MULTIPLIER: u8 = 0x0c;

// Class-specific AudioStreaming descriptor subtypes.
const STREAMING_GENERAL: u8 = 1;
const FORMAT_TYPE: u8 = 2;
const FORMAT_TYPE_I: u8 = 1;
const FORMAT_PCM: u16 = 1;

/// The USB Audio Class revision a function follows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Version {
    /// Audio 1.0: a request to the endpoint sets the sampling frequency.
    One,
    /// Audio 2.0: a request to a clock source entity sets it.
    Two,
}

/// The Audio Class 2 clock that times an output.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Clock {
    /// The clock source entity that generates the sampling frequency.
    pub source: u8,
    /// Whether the host may set the frequency.
    pub programmable: bool,
    /// A clock selector between the terminal and the source; it must select
    /// its first input, which leads to `source`.
    pub selector: Option<u8>,
}

/// A playback path: an isochronous OUT endpoint on an audio streaming
/// interface setting that carries PCM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Output {
    pub version: Version,
    /// The AudioControl interface that owns the clock and unit entities.
    pub control_interface: u8,
    pub interface: u8,
    pub alternate: u8,
    /// Endpoint number, without the direction bit.
    pub endpoint: u8,
    /// wMaxPacketSize: the packet size in bits 10:0 and, at high speed,
    /// extra transactions per microframe in bits 12:11.
    pub max_packet: u16,
    pub interval: u8,
    pub channels: u8,
    /// Bytes per sample.
    pub subslot: u8,
    pub bits: u8,
    /// The type of the output terminal the stream reaches, such as 0x0301
    /// for a speaker, or 0 when the path could not be followed.
    pub terminal: u16,
    pub clock: Option<Clock>,
}

impl Output {
    /// Bytes in one frame: a sample for every channel.
    pub fn frame_bytes(&self) -> usize {
        usize::from(self.channels) * usize::from(self.subslot)
    }

    /// Microseconds between packets. bInterval is an exponent of 1 ms frames
    /// at full speed and of 125 us microframes at high speed and above.
    pub fn period_us(&self, high_speed: bool) -> u32 {
        let unit = if high_speed { 125 } else { 1000 };
        unit << (self.interval.clamp(1, 16) - 1)
    }

    /// Frames per packet at 48 kHz, if every packet holds whole frames and
    /// whole packets tile one test-tone period.
    pub fn packet_frames(&self, high_speed: bool) -> Option<usize> {
        let samples = u64::from(SAMPLE_RATE) * u64::from(self.period_us(high_speed));
        if !samples.is_multiple_of(1_000_000) {
            return None;
        }
        let frames = usize::try_from(samples / 1_000_000).ok()?;
        (frames != 0 && TONE_FRAMES.is_multiple_of(frames)).then_some(frames)
    }

    /// Bytes per packet at 48 kHz, if they fit the endpoint.
    pub fn packet_bytes(&self, high_speed: bool) -> Option<usize> {
        let bytes = self.packet_frames(high_speed)? * self.frame_bytes();
        let size = usize::from(self.max_packet & 0x7ff);
        let transactions = if high_speed {
            1 + usize::from((self.max_packet >> 11) & 3)
        } else {
            1
        };
        (bytes <= size * transactions).then_some(bytes)
    }

    /// A short name for what the output is wired to.
    pub fn terminal_name(&self) -> &'static str {
        terminal_name(self.terminal)
    }
}

/// A short name for an output terminal type.
pub fn terminal_name(kind: u16) -> &'static str {
    match kind {
        0x0301 => "speaker",
        0x0302 => "headphones",
        0x0304 => "desktop speaker",
        0x0305 => "room speaker",
        0x0601 => "analog output",
        0x0603 => "line output",
        0x0605 => "S/PDIF output",
        _ => "audio output",
    }
}

/// The playback outputs of one configuration: for each streaming interface,
/// its first setting the driver can play.
#[derive(Clone, Copy, Debug, Default)]
pub struct Outputs {
    list: [Option<Output>; MAX_OUTPUTS],
}

impl Outputs {
    pub fn iter(&self) -> impl Iterator<Item = &Output> {
        self.list.iter().flatten()
    }

    fn push(&mut self, output: Output) {
        if let Some(free) = self.list.iter_mut().find(|entry| entry.is_none()) {
            *free = Some(output);
        }
    }
}

/// A unit, terminal or clock of the AudioControl interface.
#[derive(Clone, Copy, Default)]
struct Entity {
    id: u8,
    subtype: u8,
    /// The first entity feeding this one, or 0.
    source: u8,
    /// The clock entity of a class 2 terminal.
    clock: u8,
    /// The terminal type of a terminal.
    kind: u16,
    /// bmControls of a clock source.
    controls: u8,
}

/// One streaming interface setting as its descriptors are read.
#[derive(Clone, Copy, Default)]
struct Setting {
    interface: u8,
    alternate: u8,
    version_two: bool,
    link: u8,
    pcm: bool,
    channels: u8,
    subslot: u8,
    bits: u8,
    /// Class 1 lists its rates; class 2 rates come from the clock.
    rate_supported: bool,
    /// Number, wMaxPacketSize and bInterval of an isochronous OUT data
    /// endpoint.
    endpoint: Option<(u8, u16, u8)>,
}

/// Finds the playback outputs among a configuration's descriptors. The
/// input may start with the device descriptor.
pub fn outputs(configuration: &[u8]) -> Outputs {
    let mut entities = [Entity::default(); MAX_ENTITIES];
    let mut entity_count = 0;
    let mut control_interface = None;
    let mut subclass = 0;
    let mut version = Version::One;
    for descriptor in descriptors(configuration) {
        match descriptor[1] {
            DESCRIPTOR_INTERFACE if descriptor.len() >= 9 => {
                subclass = if descriptor[5] == CLASS_AUDIO {
                    descriptor[6]
                } else {
                    0
                };
                version = if descriptor[7] == PROTOCOL_VERSION_2 {
                    Version::Two
                } else {
                    Version::One
                };
                if subclass == SUBCLASS_CONTROL && control_interface.is_none() {
                    control_interface = Some(descriptor[2]);
                }
            }
            DESCRIPTOR_CS_INTERFACE if subclass == SUBCLASS_CONTROL => {
                if let Some(entity) = entity(descriptor, version) {
                    if let Some(slot) = entities.get_mut(entity_count) {
                        *slot = entity;
                        entity_count += 1;
                    }
                }
            }
            _ => {}
        }
    }
    let mut found = Outputs::default();
    let Some(control_interface) = control_interface else {
        return found;
    };
    let entities = &entities[..entity_count];
    let mut setting: Option<Setting> = None;
    for descriptor in descriptors(configuration) {
        match descriptor[1] {
            DESCRIPTOR_INTERFACE if descriptor.len() >= 9 => {
                if let Some(setting) = setting.take() {
                    finish(&setting, control_interface, entities, &mut found);
                }
                setting = (descriptor[5] == CLASS_AUDIO
                    && descriptor[6] == SUBCLASS_STREAMING
                    && descriptor[3] != 0)
                    .then(|| Setting {
                        interface: descriptor[2],
                        alternate: descriptor[3],
                        version_two: descriptor[7] == PROTOCOL_VERSION_2,
                        rate_supported: descriptor[7] == PROTOCOL_VERSION_2,
                        ..Setting::default()
                    });
            }
            DESCRIPTOR_CS_INTERFACE => {
                if let Some(setting) = setting.as_mut() {
                    read_streaming(descriptor, setting);
                }
            }
            DESCRIPTOR_ENDPOINT if descriptor.len() >= 7 => {
                let [_, _, address, attributes, low, high, interval, ..] = *descriptor else {
                    continue;
                };
                let isochronous_out_data =
                    address & 0x80 == 0 && attributes & 3 == 1 && (attributes >> 4) & 3 == 0;
                if let Some(setting) = setting
                    .as_mut()
                    .filter(|setting| setting.endpoint.is_none() && isochronous_out_data)
                {
                    setting.endpoint =
                        Some((address & 0x0f, u16::from_le_bytes([low, high]), interval));
                }
            }
            _ => {}
        }
    }
    if let Some(setting) = setting {
        finish(&setting, control_interface, entities, &mut found);
    }
    found
}

/// Splits a configuration into its descriptors, stopping at a malformed one.
fn descriptors(configuration: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut rest = configuration;
    core::iter::from_fn(move || {
        let length = usize::from(*rest.first()?);
        if length < 2 || length > rest.len() {
            return None;
        }
        let (descriptor, tail) = rest.split_at(length);
        rest = tail;
        Some(descriptor)
    })
}

/// Reads an AudioControl terminal, unit or clock descriptor.
fn entity(descriptor: &[u8], version: Version) -> Option<Entity> {
    let byte = |index: usize| descriptor.get(index).copied();
    let word = |index: usize| Some(u16::from_le_bytes([byte(index)?, byte(index + 1)?]));
    // Units with several inputs give their pin count, then the pins.
    let first_pin = |count: usize| {
        Some(if byte(count)? == 0 {
            0
        } else {
            byte(count + 1)?
        })
    };
    let two = version == Version::Two;
    let mut entity = Entity {
        id: byte(3)?,
        subtype: byte(2)?,
        ..Entity::default()
    };
    match entity.subtype {
        INPUT_TERMINAL => {
            entity.kind = word(4)?;
            entity.clock = if two { byte(7)? } else { 0 };
        }
        OUTPUT_TERMINAL => {
            entity.kind = word(4)?;
            entity.source = byte(7)?;
            entity.clock = if two { byte(8)? } else { 0 };
        }
        FEATURE_UNIT => entity.source = byte(4)?,
        MIXER_UNIT | SELECTOR_UNIT => entity.source = first_pin(4)?,
        // A class 2 effect unit has one source after its effect type.
        UNIT_7 if two => entity.source = byte(6)?,
        UNIT_7 | UNIT_8 => entity.source = first_pin(6)?,
        EXTENSION_UNIT_2 if two => entity.source = first_pin(6)?,
        CLOCK_SOURCE if two => entity.controls = byte(5)?,
        CLOCK_SELECTOR if two => entity.source = first_pin(4)?,
        CLOCK_MULTIPLIER if two => entity.source = byte(4)?,
        _ => return None,
    }
    Some(entity)
}

/// Reads a class-specific AudioStreaming descriptor into `setting`.
fn read_streaming(descriptor: &[u8], setting: &mut Setting) {
    let byte = |index: usize| descriptor.get(index).copied().unwrap_or(0);
    match (byte(2), setting.version_two) {
        (STREAMING_GENERAL, false) => {
            setting.link = byte(3);
            setting.pcm = u16::from_le_bytes([byte(5), byte(6)]) == FORMAT_PCM;
        }
        (STREAMING_GENERAL, true) => {
            setting.link = byte(3);
            setting.pcm = byte(5) == FORMAT_TYPE_I && byte(6) & 1 != 0;
            setting.channels = byte(10);
        }
        (FORMAT_TYPE, false) if byte(3) == FORMAT_TYPE_I => {
            setting.channels = byte(4);
            setting.subslot = byte(5);
            setting.bits = byte(6);
            setting.rate_supported = lists_rate(descriptor, SAMPLE_RATE);
        }
        (FORMAT_TYPE, true) if byte(3) == FORMAT_TYPE_I => {
            setting.subslot = byte(4);
            setting.bits = byte(5);
        }
        _ => {}
    }
}

/// Whether a class 1 Type I format descriptor offers `rate`, as a continuous
/// range or in its list of discrete rates.
fn lists_rate(descriptor: &[u8], rate: u32) -> bool {
    let Some(&count) = descriptor.get(7) else {
        return false;
    };
    let rates = descriptor[8..]
        .as_chunks::<3>()
        .0
        .iter()
        .map(|&[low, middle, high]| u32::from_le_bytes([low, middle, high, 0]));
    if count == 0 {
        let mut range = rates.take(2);
        matches!((range.next(), range.next()), (Some(low), Some(high)) if (low..=high).contains(&rate))
    } else {
        rates
            .take(usize::from(count))
            .any(|offered| offered == rate)
    }
}

/// Records a finished setting as its interface's output if the driver can
/// play it and the interface has none yet.
fn finish(setting: &Setting, control_interface: u8, entities: &[Entity], found: &mut Outputs) {
    let Some((endpoint, max_packet, interval)) = setting.endpoint else {
        return;
    };
    if !setting.pcm
        || !setting.rate_supported
        || !(1..=8).contains(&setting.channels)
        || !(2..=4).contains(&setting.subslot)
        || found
            .iter()
            .any(|output| output.interface == setting.interface)
    {
        return;
    }
    let version = if setting.version_two {
        Version::Two
    } else {
        Version::One
    };
    let clock = match version {
        Version::One => None,
        Version::Two => find(entities, setting.link).and_then(|input| clock(entities, input.clock)),
    };
    found.push(Output {
        version,
        control_interface,
        interface: setting.interface,
        alternate: setting.alternate,
        endpoint,
        max_packet,
        interval,
        channels: setting.channels,
        subslot: setting.subslot,
        bits: setting.bits,
        terminal: output_terminal(entities, setting.link),
        clock,
    });
}

fn find(entities: &[Entity], id: u8) -> Option<&Entity> {
    (id != 0)
        .then(|| entities.iter().find(|entity| entity.id == id))
        .flatten()
}

/// The type of the output terminal that `input` feeds, found by following
/// each output terminal's chain of units back through their first source.
fn output_terminal(entities: &[Entity], input: u8) -> u16 {
    let reaches_input = |terminal: &&Entity| {
        let mut id = terminal.source;
        for _ in 0..MAX_CHAIN {
            if id == input {
                return true;
            }
            match find(entities, id) {
                Some(unit) if !matches!(unit.subtype, INPUT_TERMINAL | OUTPUT_TERMINAL) => {
                    id = unit.source;
                }
                _ => return false,
            }
        }
        false
    };
    entities
        .iter()
        .filter(|entity| entity.subtype == OUTPUT_TERMINAL)
        .find(reaches_input)
        .map_or(0, |terminal| terminal.kind)
}

/// The clock source behind clock entity `id`, through selectors and
/// multipliers.
fn clock(entities: &[Entity], mut id: u8) -> Option<Clock> {
    let mut selector = None;
    for _ in 0..MAX_CHAIN {
        let entity = find(entities, id)?;
        match entity.subtype {
            CLOCK_SOURCE => {
                return Some(Clock {
                    source: id,
                    programmable: entity.controls & 3 == 3,
                    selector,
                })
            }
            CLOCK_SELECTOR => {
                selector = selector.or(Some(id));
                id = entity.source;
            }
            CLOCK_MULTIPLIER => id = entity.source,
            _ => return None,
        }
    }
    None
}

/// Writes one period of the 500 Hz test tone, a square wave at 48 kHz, as
/// little-endian samples of `subslot` bytes with the amplitude in their top
/// 16 bits. Returns the bytes written, or `None` if `buffer` is too small or
/// the format is not 2- to 4-byte samples.
pub fn square_wave(buffer: &mut [u8], channels: u8, subslot: u8, amplitude: i16) -> Option<usize> {
    let subslot = usize::from(subslot);
    if !(2..=4).contains(&subslot) || channels == 0 {
        return None;
    }
    let frame = usize::from(channels) * subslot;
    let period = buffer.get_mut(..TONE_FRAMES * frame)?;
    for (index, samples) in period.chunks_exact_mut(frame).enumerate() {
        let value = if index < TONE_FRAMES / 2 {
            amplitude
        } else {
            amplitude.saturating_neg()
        };
        for sample in samples.chunks_exact_mut(subslot) {
            let (low, high) = sample.split_at_mut(subslot - 2);
            low.fill(0);
            high.copy_from_slice(&value.to_le_bytes());
        }
    }
    Some(TONE_FRAMES * frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// The device and configuration descriptors of the MSI "USB Audio"
    /// (0db0:3130) on an MSI B650 board: a high-speed Audio Class 2 device
    /// with rear speaker, front headphone and S/PDIF outputs.
    const MSI_USB_AUDIO: &[u8] = include_bytes!("../tests/data/msi-0db0-3130.bin");

    #[test]
    fn finds_every_output_of_an_audio_class_2_device() {
        let outputs: Vec<Output> = outputs(MSI_USB_AUDIO).iter().copied().collect();
        let summary: Vec<_> = outputs
            .iter()
            .map(|output| {
                (
                    output.interface,
                    output.alternate,
                    output.endpoint,
                    output.terminal_name(),
                    output.clock.map(|clock| clock.source),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                (4, 1, 5, "speaker", Some(5)),
                (5, 1, 6, "headphones", Some(6)),
                (6, 1, 8, "S/PDIF output", Some(8)),
            ]
        );
        for output in &outputs {
            assert_eq!(output.version, Version::Two);
            assert_eq!(output.control_interface, 0);
            assert_eq!((output.channels, output.subslot, output.bits), (2, 2, 16));
            let clock = output.clock.unwrap();
            assert!(clock.programmable);
            assert_eq!(clock.selector, None);
            // Six frames every 125 us microframe.
            assert_eq!(output.period_us(true), 125);
            assert_eq!(output.packet_bytes(true), Some(24));
        }
    }

    /// A full-speed Audio Class 1 speaker laid out like QEMU's usb-audio,
    /// with a second streaming interface that cannot play 48 kHz.
    fn class_1_speaker() -> Vec<u8> {
        let mut descriptors = Vec::new();
        let mut add = |bytes: &[u8]| {
            descriptors.push(bytes.len() as u8 + 1);
            descriptors.extend_from_slice(bytes);
        };
        add(&[2, 0, 0, 3, 1, 0, 0xc0, 50]);
        add(&[4, 0, 0, 0, 1, 1, 0, 0]);
        add(&[0x24, 1, 0, 1, 0, 0, 2, 1, 2]);
        add(&[0x24, 2, 1, 0x01, 0x01, 0, 2, 3, 0, 0, 0]);
        add(&[0x24, 6, 2, 1, 1, 1, 0, 0]);
        add(&[0x24, 3, 3, 0x01, 0x03, 0, 2, 0]);
        add(&[4, 1, 0, 0, 1, 2, 0, 0]);
        add(&[4, 1, 1, 1, 1, 2, 0, 0]);
        add(&[0x24, 1, 1, 1, 1, 0]);
        add(&[0x24, 2, 1, 2, 2, 16, 1, 0x80, 0xbb, 0x00]);
        add(&[5, 0x01, 0x09, 0xc0, 0x00, 1, 0, 0]);
        add(&[0x25, 1, 1, 0, 0, 0]);
        add(&[4, 2, 1, 1, 1, 2, 0, 0]);
        add(&[0x24, 1, 1, 1, 1, 0]);
        add(&[0x24, 2, 1, 2, 2, 16, 1, 0x44, 0xac, 0x00]);
        add(&[5, 0x02, 0x09, 0xc0, 0x00, 1, 0, 0]);
        descriptors
    }

    #[test]
    fn finds_a_class_1_speaker_that_plays_48_khz() {
        let descriptors = class_1_speaker();
        let outputs: Vec<Output> = outputs(&descriptors).iter().copied().collect();
        assert_eq!(
            outputs,
            [Output {
                version: Version::One,
                control_interface: 0,
                interface: 1,
                alternate: 1,
                endpoint: 1,
                max_packet: 192,
                interval: 1,
                channels: 2,
                subslot: 2,
                bits: 16,
                terminal: 0x0301,
                clock: None,
            }]
        );
        // 48 frames every 1 ms frame.
        assert_eq!(outputs[0].packet_bytes(false), Some(192));
    }

    #[test]
    fn splits_48_khz_into_packets_that_tile_a_tone_period() {
        let output = |interval, max_packet| Output {
            version: Version::Two,
            control_interface: 0,
            interface: 1,
            alternate: 1,
            endpoint: 1,
            max_packet,
            interval,
            channels: 2,
            subslot: 2,
            bits: 16,
            terminal: 0,
            clock: None,
        };
        assert_eq!(output(1, 1024).packet_frames(true), Some(6));
        assert_eq!(output(4, 1024).packet_frames(true), Some(48));
        assert_eq!(output(2, 1024).packet_frames(false), Some(96));
        // 192 frames every 4 ms do not tile a 96-frame period.
        assert_eq!(output(3, 1024).packet_frames(false), None);
        // A packet must fit the endpoint, counting extra transactions.
        assert_eq!(output(4, 100).packet_bytes(true), None);
        assert_eq!(output(4, 100 | 1 << 11).packet_bytes(true), Some(192));
    }

    #[test]
    fn writes_a_square_wave_in_the_top_bits_of_each_sample() {
        let mut buffer = [0xff_u8; 4096];
        assert_eq!(square_wave(&mut buffer, 2, 2, 6000), Some(384));
        assert_eq!(buffer[..4], [0x70, 0x17, 0x70, 0x17]);
        assert_eq!(buffer[48 * 4..48 * 4 + 2], (-6000_i16).to_le_bytes());
        assert_eq!(buffer[384], 0xff);

        assert_eq!(square_wave(&mut buffer, 1, 3, 6000), Some(288));
        assert_eq!(buffer[..3], [0, 0x70, 0x17]);
        assert_eq!(square_wave(&mut buffer, 8, 4, 6000), Some(3072));
        assert_eq!(square_wave(&mut buffer[..100], 2, 2, 6000), None);
        assert_eq!(square_wave(&mut buffer, 2, 1, 6000), None);
    }
}
