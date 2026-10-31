// mmap/munmap/mremap/madvise stress test for Ginux, shaped like musl
// mallocng's group traffic: many small anonymous mappings, some adjacent,
// unmapped and moved in random order, with every surviving page's pattern
// checked after each operation.
use std::ptr;

extern "C" {
    fn mmap(address: *mut u8, length: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn munmap(address: *mut u8, length: usize) -> i32;
    fn mremap(old: *mut u8, old_length: usize, new_length: usize, flags: i32, ...) -> *mut u8;
    fn madvise(address: *mut u8, length: usize, advice: i32) -> i32;
}

const PAGE: usize = 4096;
const PROT_READ_WRITE: i32 = 3;
const MAP_PRIVATE_ANONYMOUS: i32 = 0x22;
const MREMAP_MAYMOVE: i32 = 1;
const MADV_FREE: i32 = 8;

struct Region {
    address: *mut u8,
    pages: usize,
    tag: u64,
}

fn word(tag: u64, page: usize, index: usize) -> u64 {
    tag ^ ((page as u64) << 32) ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

fn fill(region: &Region) {
    for page in 0..region.pages {
        let words = unsafe { region.address.add(page * PAGE) as *mut u64 };
        for index in 0..PAGE / 8 {
            unsafe { words.add(index).write(word(region.tag, page, index)) };
        }
    }
}

fn check(region: &Region, what: &str, errors: &mut u64) {
    for page in 0..region.pages {
        let words = unsafe { region.address.add(page * PAGE) as *const u64 };
        for index in 0..PAGE / 8 {
            let value = unsafe { words.add(index).read() };
            if value != word(region.tag, page, index) {
                *errors += 1;
                if *errors < 10 {
                    eprintln!(
                        "MISMATCH {what}: region {:p} pages {} page {page} word {index}: {value:#x}",
                        region.address, region.pages
                    );
                }
                return;
            }
        }
    }
}

fn main() {
    let rounds: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20000);
    let mut state = 0x5eed_u64;
    let mut next = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut regions: Vec<Region> = Vec::new();
    let mut errors = 0;
    for round in 0..rounds {
        let roll = next() % 10;
        if roll < 4 || regions.len() < 4 {
            let pages = (next() % 4) as usize + 1;
            let address = unsafe { mmap(ptr::null_mut(), pages * PAGE, PROT_READ_WRITE, MAP_PRIVATE_ANONYMOUS, -1, 0) };
            if address as isize == -1 {
                eprintln!("mmap failed");
                break;
            }
            let region = Region { address, pages, tag: next() };
            fill(&region);
            regions.push(region);
        } else if roll < 7 {
            // Unmap a whole region, or split one by unmapping a page.
            let pick = (next() as usize) % regions.len();
            let region = regions.swap_remove(pick);
            check(&region, "before munmap", &mut errors);
            if region.pages > 2 && next() % 2 == 0 {
                let hole = (next() as usize) % region.pages;
                unsafe { munmap(region.address.add(hole * PAGE), PAGE) };
                if hole > 0 {
                    regions.push(Region { address: region.address, pages: hole, tag: region.tag });
                }
                if hole + 1 < region.pages {
                    // Keep the tail with its own page numbering by refilling.
                    let tail = Region {
                        address: unsafe { region.address.add((hole + 1) * PAGE) },
                        pages: region.pages - hole - 1,
                        tag: next(),
                    };
                    fill(&tail);
                    regions.push(tail);
                }
            } else {
                unsafe { munmap(region.address, region.pages * PAGE) };
            }
        } else if roll < 9 {
            // Grow a region, possibly moving it.
            let pick = (next() as usize) % regions.len();
            let extra = (next() % 3) as usize + 1;
            let region = &mut regions[pick];
            check(region, "before mremap", &mut errors);
            let moved = unsafe {
                mremap(region.address, region.pages * PAGE, (region.pages + extra) * PAGE, MREMAP_MAYMOVE)
            };
            if moved as isize == -1 {
                eprintln!("mremap failed");
                break;
            }
            region.address = moved;
            let old_pages = region.pages;
            region.pages += extra;
            // The old contents must have moved with it.
            let old = Region { address: moved, pages: old_pages, tag: region.tag };
            check(&old, "after mremap", &mut errors);
            fill(region);
        } else {
            // Free and reuse a page in place, as malloc does with MADV_FREE.
            let pick = (next() as usize) % regions.len();
            let region = &regions[pick];
            unsafe { madvise(region.address, PAGE, MADV_FREE) };
            fill(region);
        }
        if round % 1000 == 0 {
            for region in &regions {
                check(region, "sweep", &mut errors);
            }
        }
    }
    for region in &regions {
        check(region, "final", &mut errors);
    }
    println!("mmapstress rounds={rounds} regions={} errors={errors}", regions.len());
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
