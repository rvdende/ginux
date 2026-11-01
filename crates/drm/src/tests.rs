extern crate std;

use std::collections::BTreeMap;
use std::vec;
use std::vec::Vec;

use super::*;

/// User memory: a sparse byte map, faulting outside written ranges unless
/// `open` is set.
#[derive(Default)]
struct User {
    bytes: BTreeMap<u64, u8>,
}

impl User {
    fn put(&mut self, address: u64, bytes: &[u8]) {
        for (index, byte) in bytes.iter().enumerate() {
            self.bytes.insert(address + index as u64, *byte);
        }
    }

    fn get(&self, address: u64, length: usize) -> Vec<u8> {
        (0..length as u64)
            .map(|index| *self.bytes.get(&(address + index)).unwrap_or(&0))
            .collect()
    }
}

impl UserMemory for User {
    fn read(&self, address: u64, output: &mut [u8]) -> bool {
        if address < 0x1000 {
            return false;
        }
        output.copy_from_slice(&self.get(address, output.len()));
        true
    }

    fn write(&mut self, address: u64, input: &[u8]) -> bool {
        if address < 0x1000 {
            return false;
        }
        self.put(address, input);
        true
    }
}

#[derive(Default)]
struct FakeGpu {
    contexts: Vec<u32>,
    blobs: Vec<Blob>,
    references: BTreeMap<u32, u32>,
    destroyed: Vec<u32>,
    submitted: Vec<(u32, Option<u8>, Vec<u8>, bool)>,
}

impl Gpu for FakeGpu {
    fn features(&self) -> Features {
        Features {
            three_d: true,
            blob: true,
            host_visible: true,
            context_init: true,
            capsets: 1 << 4,
        }
    }

    fn capset(&mut self, id: u32, version: u32, output: &mut [u8]) -> Result<usize, Errno> {
        if id != 4 || version != 0 {
            return Err(Errno::Inval);
        }
        let data = [7_u8; 160];
        let length = output.len().min(data.len());
        output[..length].copy_from_slice(&data[..length]);
        Ok(data.len())
    }

    fn create_context(&mut self, capset: u32) -> Result<u32, Errno> {
        assert_eq!(capset, 4);
        let id = self.contexts.last().map_or(1, |id| id + 1);
        self.contexts.push(id);
        Ok(id)
    }

    fn destroy_context(&mut self, context: u32) {
        self.contexts.retain(|id| *id != context);
    }

    fn create_blob(&mut self, blob: Blob) -> Result<u32, Errno> {
        self.blobs.push(blob);
        let resource = self.blobs.len() as u32 + 100;
        self.references.insert(resource, 1);
        Ok(resource)
    }

    fn map(&mut self, resource: u32, size: u64) -> Result<Mapping, Errno> {
        assert!(size.is_multiple_of(4096));
        Ok(Mapping {
            physical: 0x80_0000_0000 + u64::from(resource) * 0x10_0000,
            cache: Cache::Cached,
        })
    }

    fn submit(
        &mut self,
        context: u32,
        ring: Option<u8>,
        commands: &[u8],
        fenced: bool,
    ) -> Result<Option<u64>, Errno> {
        self.submitted
            .push((context, ring, commands.to_vec(), fenced));
        Ok(fenced.then_some(self.submitted.len() as u64))
    }

    fn wait(&mut self, _resource: u32, _nowait: bool) -> Result<(), Errno> {
        Ok(())
    }

    fn retain(&mut self, resource: u32) {
        *self.references.entry(resource).or_default() += 1;
    }

    fn release(&mut self, resource: u32) {
        let count = self
            .references
            .get_mut(&resource)
            .expect("released a dead resource");
        *count -= 1;
        if *count == 0 {
            self.references.remove(&resource);
            self.destroyed.push(resource);
        }
    }
}

fn command(number: u8, size: usize) -> u32 {
    (3 << 30) | ((size as u32) << 16) | (u32::from(b'd') << 8) | u32::from(number)
}

fn run(
    file: &mut File,
    gpu: &mut FakeGpu,
    user: &mut User,
    number: u8,
    argument: &mut [u8],
) -> Result<Outcome, Errno> {
    let (request, _) = Request::decode(command(number, argument.len()))?;
    file.ioctl(gpu, user, request, argument)
}

fn init_venus(file: &mut File, gpu: &mut FakeGpu, user: &mut User, rings: u64) {
    let mut parameters = Vec::new();
    for (name, value) in [(1_u64, 4_u64), (2, rings), (3, 0)] {
        parameters.extend_from_slice(&name.to_le_bytes());
        parameters.extend_from_slice(&value.to_le_bytes());
    }
    user.put(0x5000, &parameters);
    let mut argument = [0_u8; 16];
    argument[..4].copy_from_slice(&3_u32.to_le_bytes());
    argument[8..].copy_from_slice(&0x5000_u64.to_le_bytes());
    assert_eq!(run(file, gpu, user, 0x4b, &mut argument), Ok(Outcome::Done));
}

fn create_shmem(file: &mut File, gpu: &mut FakeGpu, user: &mut User, size: u64) -> (u32, u32) {
    let mut argument = [0_u8; 48];
    argument[..4].copy_from_slice(&2_u32.to_le_bytes());
    argument[4..8].copy_from_slice(&1_u32.to_le_bytes());
    argument[16..24].copy_from_slice(&size.to_le_bytes());
    assert_eq!(run(file, gpu, user, 0x4a, &mut argument), Ok(Outcome::Done));
    (get_u32(&argument, 8), get_u32(&argument, 12))
}

#[test]
fn decode_takes_the_number_and_the_callers_size() {
    assert_eq!(Request::decode(0xc040_6400), Ok((Request::Version, 64)));
    assert_eq!(
        Request::decode(0xc030_644a),
        Ok((Request::ResourceCreateBlob, 48))
    );
    assert_eq!(Request::decode(0xc018_6449), Ok((Request::GetCaps, 24)));
    assert_eq!(Request::decode(0xc020_6449), Ok((Request::GetCaps, 32)));
    assert_eq!(Request::decode(0x4008_6409), Ok((Request::GemClose, 8)));
    assert_eq!(Request::decode(0x5401), Err(Errno::NoTty));
    assert_eq!(Request::decode(0xc008_6477), Err(Errno::Inval));
}

#[test]
fn version_reports_virtio_gpu_in_two_calls() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    // drmGetVersion first asks for the lengths, then the strings.
    let mut argument = [0_u8; 64];
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x00, &mut argument),
        Ok(Outcome::Done)
    );
    assert_eq!(get_u64(&argument, 16), 10);
    argument[24..32].copy_from_slice(&0x9000_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x00, &mut argument),
        Ok(Outcome::Done)
    );
    assert_eq!(user.get(0x9000, 10), b"virtio_gpu");
    assert_eq!([get_u32(&argument, 0), get_u32(&argument, 4)], [0, 1]);
}

#[test]
fn getparam_writes_an_int_where_value_points() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    for (param, expected) in [(1_u64, 1_u32), (3, 1), (4, 1), (5, 0), (6, 1), (7, 16)] {
        let mut argument = [0_u8; 16];
        argument[..8].copy_from_slice(&param.to_le_bytes());
        argument[8..].copy_from_slice(&0x6000_u64.to_le_bytes());
        assert_eq!(
            run(&mut file, &mut gpu, &mut user, 0x43, &mut argument),
            Ok(Outcome::Done)
        );
        assert_eq!(user.get(0x6000, 4), expected.to_le_bytes());
    }
    let mut argument = [0_u8; 16];
    argument[..8].copy_from_slice(&99_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x43, &mut argument),
        Err(Errno::Inval)
    );
}

#[test]
fn get_caps_copies_the_capset() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    let mut argument = [0_u8; 24];
    argument[..4].copy_from_slice(&4_u32.to_le_bytes());
    argument[8..16].copy_from_slice(&0x7000_u64.to_le_bytes());
    argument[16..20].copy_from_slice(&64_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x49, &mut argument),
        Ok(Outcome::Done)
    );
    assert_eq!(user.get(0x7000, 65), [vec![7; 64], vec![0]].concat());
}

#[test]
fn context_init_once_with_a_known_capset() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    init_venus(&mut file, &mut gpu, &mut user, 64);
    assert_eq!(gpu.contexts, vec![1]);
    let mut argument = [0_u8; 16];
    argument[..4].copy_from_slice(&1_u32.to_le_bytes());
    argument[8..].copy_from_slice(&0x5000_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x4b, &mut argument),
        Err(Errno::Exist)
    );
    // An unknown capset is refused.
    let mut other = File::new();
    user.put(0x5100, &[1_u64.to_le_bytes(), 9_u64.to_le_bytes()].concat());
    argument[8..].copy_from_slice(&0x5100_u64.to_le_bytes());
    assert_eq!(
        run(&mut other, &mut gpu, &mut user, 0x4b, &mut argument),
        Err(Errno::Inval)
    );
}

#[test]
fn blobs_map_at_fake_offsets_and_close_releases() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    // No context yet: no blob.
    let mut argument = [0_u8; 48];
    argument[..4].copy_from_slice(&2_u32.to_le_bytes());
    argument[16..24].copy_from_slice(&4096_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x4a, &mut argument),
        Err(Errno::Inval)
    );
    init_venus(&mut file, &mut gpu, &mut user, 64);
    let (handle, resource) = create_shmem(&mut file, &mut gpu, &mut user, 5000);
    assert_eq!((handle, resource), (1, 101));
    assert_eq!(gpu.blobs[0].size, 8192);
    // RESOURCE_INFO reports it.
    let mut info = [0_u8; 16];
    info[..4].copy_from_slice(&handle.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x45, &mut info),
        Ok(Outcome::Done)
    );
    assert_eq!(
        [get_u32(&info, 4), get_u32(&info, 8), get_u32(&info, 12)],
        [101, 8192, 2]
    );
    // Unmapped, mmap fails; MAP gives the fake offset; mmap then works.
    let offset = u64::from(handle) << 32;
    assert_eq!(file.mmap(offset, 8192), Err(Errno::Inval));
    let mut map = [0_u8; 16];
    map[8..12].copy_from_slice(&handle.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x41, &mut map),
        Ok(Outcome::Done)
    );
    assert_eq!(get_u64(&map, 0), offset);
    assert_eq!(
        file.mmap(offset, 8192),
        Ok(Mapping {
            physical: 0x80_0000_0000 + 101 * 0x10_0000,
            cache: Cache::Cached
        })
    );
    assert_eq!(file.mmap(offset, 12288), Err(Errno::Inval));
    assert_eq!(file.mmap(offset + 4096, 4096), Err(Errno::Inval));
    // GEM_CLOSE drops the only reference; the handle is reused.
    let mut close = [0_u8; 8];
    close[..4].copy_from_slice(&handle.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x09, &mut close),
        Ok(Outcome::Done)
    );
    assert_eq!(gpu.destroyed, vec![101]);
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x09, &mut close),
        Err(Errno::NoEnt)
    );
    let (again, _) = create_shmem(&mut file, &mut gpu, &mut user, 4096);
    assert_eq!(again, 1);
    file.close(&mut gpu);
    assert_eq!(gpu.destroyed, vec![101, 102]);
    assert!(gpu.contexts.is_empty());
}

#[test]
fn execbuffer_submits_on_a_ring_and_asks_for_a_fence_descriptor() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    init_venus(&mut file, &mut gpu, &mut user, 2);
    user.put(0x8000, &[1, 2, 3, 4]);
    let mut argument = [0_u8; 64];
    argument[..4].copy_from_slice(&(2_u32 | 4).to_le_bytes());
    argument[4..8].copy_from_slice(&4_u32.to_le_bytes());
    argument[8..16].copy_from_slice(&0x8000_u64.to_le_bytes());
    argument[32..36].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x42, &mut argument),
        Ok(Outcome::FenceDescriptor {
            fence: 1,
            offset: 28
        })
    );
    assert_eq!(gpu.submitted, vec![(1, Some(1), vec![1, 2, 3, 4], true)]);
    // Ring 2 of 2 does not exist; nor does a bo handle 5.
    argument[32..36].copy_from_slice(&2_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x42, &mut argument),
        Err(Errno::Inval)
    );
    argument[32..36].copy_from_slice(&0_u32.to_le_bytes());
    user.put(0x8100, &5_u32.to_le_bytes());
    argument[16..24].copy_from_slice(&0x8100_u64.to_le_bytes());
    argument[24..28].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x42, &mut argument),
        Err(Errno::NoEnt)
    );
    // Without FENCE_FD_OUT there is no fence descriptor.
    argument[..4].copy_from_slice(&0_u32.to_le_bytes());
    argument[24..28].copy_from_slice(&0_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x42, &mut argument),
        Ok(Outcome::Done)
    );
    assert_eq!(gpu.submitted.last().map(|submit| submit.3), Some(false));
}

#[test]
fn prime_export_and_import_share_one_resource() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    init_venus(&mut file, &mut gpu, &mut user, 1);
    let (handle, resource) = create_shmem(&mut file, &mut gpu, &mut user, 4096);
    let mut argument = [0_u8; 12];
    argument[..4].copy_from_slice(&handle.to_le_bytes());
    argument[4..8].copy_from_slice(&0o2_000_002_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x2d, &mut argument),
        Ok(Outcome::Export {
            resource,
            size: 4096,
            flags: 0o2_000_002,
            offset: 8
        })
    );
    // Importing into the same file finds the existing handle.
    let mut import = [0_u8; 12];
    import[8..12].copy_from_slice(&9_i32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x2e, &mut import),
        Ok(Outcome::Import { descriptor: 9 })
    );
    file.import(&mut gpu, resource, 4096, 2, &mut import)
        .unwrap();
    assert_eq!(get_u32(&import, 4), handle);
    // Another file gets its own handle and reference.
    let mut other = File::new();
    other
        .import(&mut gpu, resource, 4096, 2, &mut import)
        .unwrap();
    assert_eq!(get_u32(&import, 4), 1);
    assert_eq!(gpu.references.get(&resource), Some(&2));
    other.close(&mut gpu);
    file.close(&mut gpu);
    assert_eq!(gpu.destroyed, vec![resource]);
}

#[test]
fn faults_and_unknown_flags_are_reported() {
    let (mut file, mut gpu, mut user) = (File::new(), FakeGpu::default(), User::default());
    let mut argument = [0_u8; 16];
    argument[..8].copy_from_slice(&1_u64.to_le_bytes());
    argument[8..].copy_from_slice(&0x10_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x43, &mut argument),
        Err(Errno::Fault)
    );
    init_venus(&mut file, &mut gpu, &mut user, 1);
    let mut blob = [0_u8; 48];
    blob[..4].copy_from_slice(&2_u32.to_le_bytes());
    blob[4..8].copy_from_slice(&8_u32.to_le_bytes());
    blob[16..24].copy_from_slice(&4096_u64.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x4a, &mut blob),
        Err(Errno::Inval)
    );
    let mut prime = [0_u8; 12];
    prime[4..8].copy_from_slice(&0x40_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x2d, &mut prime),
        Err(Errno::Inval)
    );
    let mut execbuffer = [0_u8; 64];
    execbuffer[44..48].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        run(&mut file, &mut gpu, &mut user, 0x42, &mut execbuffer),
        Err(Errno::Inval)
    );
    assert_eq!(execbuffer_in_fence(&execbuffer), None);
    execbuffer[..4].copy_from_slice(&1_u32.to_le_bytes());
    execbuffer[28..32].copy_from_slice(&7_i32.to_le_bytes());
    assert_eq!(execbuffer_in_fence(&execbuffer), Some(7));
}
