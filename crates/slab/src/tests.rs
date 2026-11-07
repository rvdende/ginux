use super::*;
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::collections::BTreeSet;
use std::vec::Vec;

/// Frames from the host's allocator, with the ones still out counted.
#[derive(Default)]
struct HostFrames {
    out: BTreeSet<usize>,
    allocated: usize,
    released: usize,
    limit: Option<usize>,
}

fn layout() -> Layout {
    Layout::from_size_align(FRAME_SIZE, FRAME_SIZE).unwrap()
}

impl Frames for HostFrames {
    fn allocate(&mut self) -> Option<usize> {
        if self.limit.is_some_and(|limit| self.out.len() >= limit) {
            return None;
        }
        // SAFETY: a non-zero layout.
        let frame = unsafe { alloc_zeroed(layout()) } as usize;
        assert_ne!(frame, 0);
        self.out.insert(frame);
        self.allocated += 1;
        Some(frame)
    }

    fn release(&mut self, frame: usize) {
        assert!(self.out.remove(&frame), "released a frame never given");
        self.released += 1;
        // SAFETY: allocated above with the same layout.
        unsafe { dealloc(frame as *mut u8, layout()) };
    }
}

impl Drop for HostFrames {
    fn drop(&mut self) {
        for frame in core::mem::take(&mut self.out) {
            // SAFETY: as in release.
            unsafe { dealloc(frame as *mut u8, layout()) };
        }
    }
}

#[test]
fn classes_fill_the_area_and_align() {
    for (class, &size) in CLASS_SIZES.iter().enumerate() {
        assert!(class_capacity(class) * size <= AREA);
        assert!(class_capacity(class) >= 2, "class {size} holds one object");
        assert_eq!(size % class_alignment(class), 0);
    }
    assert_eq!(class_for(0, 1), Some(0));
    assert_eq!(class_for(16, 16), Some(0));
    assert_eq!(class_for(17, 8), Some(1));
    assert_eq!(class_for(300, 8), Some(5));
    // 448 is only 64-aligned: a 128-aligned request moves to a page run.
    assert_eq!(class_for(300, 128), None);
    assert_eq!(class_for(2016, 16), Some(8));
    assert_eq!(class_for(2017, 8), None);
}

#[test]
fn objects_are_distinct_aligned_and_keep_their_data() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    for (class, &size) in CLASS_SIZES.iter().enumerate() {
        let mut objects = Vec::new();
        for index in 0..(class_capacity(class) * 3 + 1) {
            // SAFETY: host frames are aligned, writable and ours.
            let object = unsafe { slabs.allocate(class, &mut frames) }.unwrap();
            assert_eq!(object as usize % class_alignment(class), 0);
            // SAFETY: the object is `size` bytes of ours.
            unsafe { object.write_bytes(index as u8, size) };
            objects.push((object, index as u8));
        }
        let mut seen = BTreeSet::new();
        for (object, value) in &objects {
            assert!(seen.insert(*object as usize));
            // SAFETY: still live.
            let bytes = unsafe { core::slice::from_raw_parts(*object, size) };
            assert!(bytes.iter().all(|byte| byte == value));
        }
        for (object, _) in objects {
            // SAFETY: given above, of this class.
            unsafe { slabs.free(class, object, &mut frames) }.unwrap();
        }
    }
    assert_eq!(slabs.held_frames(), slabs.empty_frames());
    assert!(slabs.empty_frames() <= SPARE_EMPTY);
    assert_eq!(frames.out.len(), slabs.held_frames());
}

#[test]
fn a_burst_gives_its_frames_back_but_the_spares() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    let class = class_for(64, 8).unwrap();
    let count = class_capacity(class) * 1000;
    let objects: Vec<*mut u8> = (0..count)
        // SAFETY: host frames.
        .map(|_| unsafe { slabs.allocate(class, &mut frames) }.unwrap())
        .collect();
    assert_eq!(frames.out.len(), 1000);
    for object in objects {
        // SAFETY: given above.
        unsafe { slabs.free(class, object, &mut frames) }.unwrap();
    }
    assert_eq!(frames.out.len(), SPARE_EMPTY);
    assert_eq!(slabs.held_frames(), SPARE_EMPTY);
    assert_eq!(frames.released, 1000 - SPARE_EMPTY);
    // The spares serve the next burst, of any class, before new frames.
    let other = class_for(1000, 8).unwrap();
    let again: Vec<*mut u8> = (0..class_capacity(other) * SPARE_EMPTY)
        // SAFETY: host frames.
        .map(|_| unsafe { slabs.allocate(other, &mut frames) }.unwrap())
        .collect();
    assert_eq!(frames.allocated, 1000);
    assert_eq!(slabs.empty_frames(), 0);
    for object in again {
        // SAFETY: given above.
        unsafe { slabs.free(other, object, &mut frames) }.unwrap();
    }
    assert_eq!(slabs.empty_frames(), SPARE_EMPTY);
}

#[test]
fn a_size_that_comes_and_goes_does_not_thrash() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    for _ in 0..1000 {
        // SAFETY: host frames.
        let object = unsafe { slabs.allocate(3, &mut frames) }.unwrap();
        // SAFETY: given above.
        unsafe { slabs.free(3, object, &mut frames) }.unwrap();
    }
    assert_eq!(frames.allocated, 1);
    assert_eq!(frames.released, 0);
}

#[test]
fn partial_slabs_are_reused_before_new_frames() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    let class = 2;
    let capacity = class_capacity(class);
    let objects: Vec<*mut u8> = (0..capacity * 4)
        // SAFETY: host frames.
        .map(|_| unsafe { slabs.allocate(class, &mut frames) }.unwrap())
        .collect();
    // One object freed in each slab: four partial slabs.
    for slab in 0..4 {
        // SAFETY: given above.
        unsafe { slabs.free(class, objects[slab * capacity], &mut frames) }.unwrap();
    }
    for _ in 0..4 {
        // SAFETY: host frames.
        unsafe { slabs.allocate(class, &mut frames) }.unwrap();
    }
    assert_eq!(frames.allocated, 4);
}

#[test]
fn bad_frees_are_refused() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    // SAFETY: host frames.
    let object = unsafe { slabs.allocate(4, &mut frames) }.unwrap();
    // SAFETY: the pointers lie in a slab of ours; the frees are refused
    // before anything is written.
    unsafe {
        assert_eq!(
            slabs.free(3, object, &mut frames),
            Err(FreeError::WrongClass)
        );
        assert_eq!(
            slabs.free(4, object.add(8), &mut frames),
            Err(FreeError::Misaligned)
        );
        assert_eq!(
            slabs.free(4, object.add(AREA), &mut frames),
            Err(FreeError::NotASlab)
        );
        slabs.free(4, object, &mut frames).unwrap();
    }
    // The slab went empty and is kept: freeing again is no live object.
    // SAFETY: as above.
    let error = unsafe { slabs.free(4, object, &mut frames) };
    assert_eq!(error, Err(FreeError::NotASlab));
}

#[test]
fn no_frame_no_object() {
    let mut frames = HostFrames::default();
    frames.limit = Some(1);
    let mut slabs = Slabs::new();
    let capacity = class_capacity(8);
    let objects: Vec<*mut u8> = (0..capacity)
        // SAFETY: host frames.
        .map(|_| unsafe { slabs.allocate(8, &mut frames) }.unwrap())
        .collect();
    // SAFETY: host frames.
    assert!(unsafe { slabs.allocate(8, &mut frames) }.is_none());
    for object in objects {
        // SAFETY: given above.
        unsafe { slabs.free(8, object, &mut frames) }.unwrap();
    }
}

#[test]
fn mixed_churn_keeps_every_live_object_intact() {
    let mut frames = HostFrames::default();
    let mut slabs = Slabs::new();
    let mut live: Vec<(usize, *mut u8, u8)> = Vec::new();
    let mut seed = 0x1234_5678_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for step in 0..200_000_u32 {
        if live.is_empty() || next() % 3 != 0 {
            let class = (next() % CLASS_COUNT as u64) as usize;
            // SAFETY: host frames.
            let object = unsafe { slabs.allocate(class, &mut frames) }.unwrap();
            let value = step as u8;
            // SAFETY: a live object of `CLASS_SIZES[class]` bytes.
            unsafe { object.write_bytes(value, CLASS_SIZES[class]) };
            live.push((class, object, value));
        } else {
            let index = (next() % live.len() as u64) as usize;
            let (class, object, value) = live.swap_remove(index);
            // SAFETY: still live.
            let bytes = unsafe { core::slice::from_raw_parts(object, CLASS_SIZES[class]) };
            assert!(bytes.iter().all(|byte| *byte == value), "object clobbered");
            // SAFETY: given above, of this class.
            unsafe { slabs.free(class, object, &mut frames) }.unwrap();
        }
    }
    for (class, object, _) in live {
        // SAFETY: given above.
        unsafe { slabs.free(class, object, &mut frames) }.unwrap();
    }
    assert_eq!(slabs.held_frames(), slabs.empty_frames());
    assert_eq!(frames.out.len(), slabs.held_frames());
}
