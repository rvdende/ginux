// Allocator and threading stress test for Ginux: threads allocate, grow,
// verify and free patterned buffers of many sizes, so malloc's mmap, munmap,
// mremap and madvise traffic and timer preemption all run concurrently.
// Any lost or zeroed page shows up as a pattern mismatch.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

fn fill(buffer: &mut [u64], tag: u64) {
    for (index, word) in buffer.iter_mut().enumerate() {
        *word = tag ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
}

fn check(buffer: &[u64], tag: u64, what: &str, errors: &AtomicU64) {
    for (index, word) in buffer.iter().enumerate() {
        let expected = tag ^ (index as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        if *word != expected {
            if errors.fetch_add(1, Ordering::SeqCst) < 8 {
                eprintln!(
                    "MISMATCH {what}: len {} index {index} addr {:p} got {word:#x} want {expected:#x}",
                    buffer.len(),
                    &buffer[index]
                );
            }
            return;
        }
    }
}

fn main() {
    let threads: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let rounds: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(20000);
    let errors = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..threads)
        .map(|worker| {
            let errors = Arc::clone(&errors);
            thread::spawn(move || {
                let mut rng = Rng(0x1234_5678 + worker);
                let mut live: Vec<(Vec<u64>, u64)> = Vec::new();
                for round in 0..rounds {
                    let roll = rng.next() % 16;
                    if roll < 8 || live.is_empty() {
                        // Mostly small, sometimes large enough for mmap.
                        let words = if rng.next() % 8 == 0 {
                            (rng.next() % 200_000) as usize + 1
                        } else {
                            (rng.next() % 2_000) as usize + 1
                        };
                        let tag = rng.next();
                        let mut buffer = vec![0_u64; words];
                        fill(&mut buffer, tag);
                        live.push((buffer, tag));
                    } else if roll < 11 {
                        // Grow one in place or by moving it (realloc, mremap).
                        let pick = (rng.next() as usize) % live.len();
                        let (buffer, tag) = &mut live[pick];
                        check(buffer, *tag, "before grow", &errors);
                        let extra = (rng.next() % 100_000) as usize + 1;
                        let old = buffer.len();
                        buffer.resize(old + extra, 0);
                        fill(buffer, *tag);
                    } else {
                        let pick = (rng.next() as usize) % live.len();
                        let (buffer, tag) = live.swap_remove(pick);
                        check(&buffer, tag, "free", &errors);
                    }
                    if live.len() > 48 {
                        let (buffer, tag) = live.remove(0);
                        check(&buffer, tag, "evict", &errors);
                    }
                    if round % 5000 == 0 {
                        for (buffer, tag) in &live {
                            check(buffer, *tag, "sweep", &errors);
                        }
                    }
                }
                for (buffer, tag) in &live {
                    check(buffer, *tag, "final", &errors);
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let errors = errors.load(Ordering::SeqCst);
    println!("memstress threads={threads} rounds={rounds} errors={errors}");
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
