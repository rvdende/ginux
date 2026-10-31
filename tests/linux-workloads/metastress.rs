// Forces musl mallocng past its brk meta areas: hundreds of thousands of
// live small allocations across size classes need thousands of groups, so
// later metadata comes from PROT_NONE mappings enabled page by page with
// mprotect. Also checks mprotect on a reserved PROT_NONE range directly.
use std::ptr;

extern "C" {
    fn mmap(address: *mut u8, length: usize, protection: i32, flags: i32, fd: i32, offset: i64) -> *mut u8;
    fn mprotect(address: *mut u8, length: usize, protection: i32) -> i32;
}

fn direct_mprotect(errors: &mut u64) {
    const PAGES: usize = 64;
    let base = unsafe { mmap(ptr::null_mut(), PAGES * 4096, 0, 0x22, -1, 0) };
    assert!(base as isize != -1, "mmap PROT_NONE failed");
    for page in 0..PAGES {
        if unsafe { mprotect(base.add(page * 4096), 4096, 3) } != 0 {
            eprintln!("mprotect page {page} failed");
            *errors += 1;
            return;
        }
        let words = unsafe { base.add(page * 4096) as *mut u64 };
        for index in 0..512 {
            unsafe { words.add(index).write((page * 512 + index) as u64 ^ 0xdead_beef) };
        }
        // Every page enabled so far must still hold its pattern.
        for earlier in 0..=page {
            let words = unsafe { base.add(earlier * 4096) as *const u64 };
            for index in 0..512 {
                if unsafe { words.add(index).read() } != (earlier * 512 + index) as u64 ^ 0xdead_beef {
                    *errors += 1;
                    eprintln!("MISMATCH mprotect page {earlier} word {index} after enabling page {page}");
                    return;
                }
            }
        }
    }
}

fn main() {
    let count: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(300_000);
    let mut errors = 0;
    direct_mprotect(&mut errors);
    let mut live: Vec<Box<[u32]>> = Vec::with_capacity(count);
    for index in 0..count {
        let words = [3, 7, 12, 28, 60, 124, 252, 500][index % 8];
        live.push((0..words as u32).map(|word| word ^ index as u32).collect());
    }
    let check = |live: &Vec<Box<[u32]>>, errors: &mut u64, what: &str| {
        for (index, block) in live.iter().enumerate() {
            if block.is_empty() {
                continue;
            }
            if block.iter().enumerate().any(|(word, value)| *value != word as u32 ^ index as u32) {
                *errors += 1;
                if *errors < 10 {
                    eprintln!("MISMATCH {what} block {index}");
                }
            }
        }
    };
    check(&live, &mut errors, "after allocation");
    // Free every other block, then refill, so groups empty and refill.
    for index in (0..count).step_by(2) {
        live[index] = Box::new([]);
    }
    for index in (0..count).step_by(2) {
        let words = [5, 9, 30, 100][index % 4];
        live[index] = (0..words as u32).map(|word| word ^ index as u32).collect();
    }
    check(&live, &mut errors, "after refill");
    drop(live);
    println!("metastress count={count} errors={errors}");
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
