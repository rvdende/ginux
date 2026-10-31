// Thread churn stress test for Ginux: generations of short-lived threads,
// joined and detached, allocate and verify memory while long-lived threads
// do the same, so thread creation, exit, join and stack reuse run under load.
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

fn work(seed: u64, rounds: u64, errors: &AtomicU64) {
    let mut state = seed | 1;
    let mut live: Vec<(Vec<u64>, u64)> = Vec::new();
    for _ in 0..rounds {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let words = (state % 3000) as usize + 1;
        live.push(((0..words as u64).map(|index| index ^ state).collect(), state));
        if live.len() > 16 {
            let (buffer, tag) = live.swap_remove((state as usize) % live.len());
            if buffer.iter().enumerate().any(|(index, word)| *word != index as u64 ^ tag) {
                if errors.fetch_add(1, Ordering::SeqCst) < 8 {
                    eprintln!("MISMATCH in thread {:?}", thread::current().id());
                }
            }
        }
    }
}

fn main() {
    let generations: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(200);
    let errors = Arc::new(AtomicU64::new(0));
    let background: Vec<_> = (0..2)
        .map(|index| {
            let errors = Arc::clone(&errors);
            thread::spawn(move || work(0xabc + index, 20_000, &errors))
        })
        .collect();
    let (done, finished) = mpsc::channel();
    let mut detached = 0;
    for generation in 0..generations {
        let joined: Vec<_> = (0..4)
            .map(|index| {
                let errors = Arc::clone(&errors);
                thread::spawn(move || work(generation * 8 + index, 200, &errors))
            })
            .collect();
        // A detached thread that reports back through a channel.
        let errors_detached = Arc::clone(&errors);
        let done = done.clone();
        drop(thread::spawn(move || {
            work(generation * 8 + 7, 100, &errors_detached);
            let _ = done.send(());
        }));
        detached += 1;
        for handle in joined {
            handle.join().unwrap();
        }
    }
    for _ in 0..detached {
        finished.recv().unwrap();
    }
    for handle in background {
        handle.join().unwrap();
    }
    let errors = errors.load(Ordering::SeqCst);
    println!("threadstress generations={generations} errors={errors}");
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
