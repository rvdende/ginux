//! ginux-threadtest: threads for Ginux tests (tests/smp/tests/multithread.rs).
//!
//! - `spin N`: N threads each do the same fixed amount of arithmetic; prints
//!   `SPIN n=N ms=T`. On N CPUs they take about as long as one.
//! - `pingpong N`: two threads pass a counter back and forth N times through
//!   a mutex and condition variable (futex waits and wakes between CPUs).
//! - `sleep`: threads sleep and wait with timeouts, which must end on time.
//! - `queue`: a channel feeds work to a pool of threads.
//! - `spawn N`: a thread other than the main one runs `true` N times.
//! - `exit`: busy threads are running when the main thread exits with
//!   status 7, which must end them all.
//! - `segv`: a thread other than the main one writes through a null pointer
//!   while others spin: the process dies (status 139).
//!
//! Each prints `THREADTEST OK <mode>` when it is done and exits 0.

use std::hint::black_box;
use std::process::{Command, ExitCode};
use std::sync::mpsc;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Enough work for a few hundred milliseconds per thread.
const SPIN_ROUNDS: u64 = 150_000_000;

fn spin_work(seed: u64) -> u64 {
    let mut state = seed | 1;
    for _ in 0..SPIN_ROUNDS {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
    }
    black_box(state)
}

fn spin(threads: usize) -> ExitCode {
    let started = Instant::now();
    let workers: Vec<_> = (0..threads)
        .map(|index| thread::spawn(move || spin_work(index as u64 + 1)))
        .collect();
    let mut sum = 0_u64;
    for worker in workers {
        sum = sum.wrapping_add(worker.join().unwrap());
    }
    let elapsed = started.elapsed().as_millis();
    println!("SPIN n={threads} ms={elapsed} sum={sum}");
    println!("THREADTEST OK spin");
    ExitCode::SUCCESS
}

fn pingpong(rounds: u64) -> ExitCode {
    let started = Instant::now();
    let shared = Arc::new((Mutex::new(0_u64), Condvar::new()));
    let pair = shared.clone();
    let other = thread::spawn(move || {
        let (counter, ready) = &*pair;
        let mut count = counter.lock().unwrap();
        while *count < rounds {
            if *count % 2 == 1 {
                *count += 1;
                ready.notify_one();
            } else {
                count = ready.wait(count).unwrap();
            }
        }
    });
    {
        let (counter, ready) = &*shared;
        let mut count = counter.lock().unwrap();
        while *count < rounds {
            if *count % 2 == 0 {
                *count += 1;
                ready.notify_one();
            } else {
                count = ready.wait(count).unwrap();
            }
        }
    }
    other.join().unwrap();
    println!("PINGPONG rounds={rounds} ms={}", started.elapsed().as_millis());
    println!("THREADTEST OK pingpong");
    ExitCode::SUCCESS
}

fn sleep() -> ExitCode {
    let started = Instant::now();
    let workers: Vec<_> = (0..3)
        .map(|index| {
            thread::spawn(move || {
                let waited = Arc::new((Mutex::new(false), Condvar::new()));
                for round in 0..10 {
                    thread::sleep(Duration::from_millis(5 + index));
                    let (flag, ready) = &*waited;
                    let guard = flag.lock().unwrap();
                    // Nothing signals: the wait must end by its timeout.
                    let (_guard, result) = ready
                        .wait_timeout(guard, Duration::from_millis(5))
                        .unwrap();
                    assert!(result.timed_out(), "round {round}: woke without a timeout");
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let elapsed = started.elapsed();
    // 10 rounds of at least 10 ms each; well under a second even on a busy
    // machine.
    if elapsed < Duration::from_millis(100) || elapsed > Duration::from_secs(5) {
        eprintln!("threadtest: sleeps took {elapsed:?}");
        return ExitCode::FAILURE;
    }
    println!("SLEEP ms={}", elapsed.as_millis());
    println!("THREADTEST OK sleep");
    ExitCode::SUCCESS
}

fn queue() -> ExitCode {
    let started = Instant::now();
    let (sender, receiver) = mpsc::channel::<u64>();
    let receiver = Arc::new(Mutex::new(receiver));
    let (done_sender, done_receiver) = mpsc::channel::<u64>();
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let receiver = receiver.clone();
            let done = done_sender.clone();
            thread::spawn(move || loop {
                let job = receiver.lock().unwrap().recv();
                let Ok(job) = job else {
                    break;
                };
                let mut state = job | 1;
                for _ in 0..200_000 {
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                }
                done.send(black_box(state)).unwrap();
            })
        })
        .collect();
    drop(done_sender);
    for job in 0..400 {
        sender.send(job).unwrap();
    }
    drop(sender);
    let mut results = 0;
    while done_receiver.recv().is_ok() {
        results += 1;
    }
    for worker in workers {
        worker.join().unwrap();
    }
    if results != 400 {
        eprintln!("threadtest: {results} results of 400");
        return ExitCode::FAILURE;
    }
    println!("QUEUE jobs=400 ms={}", started.elapsed().as_millis());
    println!("THREADTEST OK queue");
    ExitCode::SUCCESS
}

fn spawn(count: usize) -> ExitCode {
    let started = Instant::now();
    let worker = thread::spawn(move || {
        for _ in 0..count {
            let status = Command::new("true").status()?;
            if !status.success() {
                return Err(std::io::Error::other(format!("true exited {status}")));
            }
        }
        Ok::<(), std::io::Error>(())
    });
    if let Err(error) = worker.join().unwrap() {
        eprintln!("threadtest: spawn: {error}");
        return ExitCode::FAILURE;
    }
    println!("SPAWN count={count} ms={}", started.elapsed().as_millis());
    println!("THREADTEST OK spawn");
    ExitCode::SUCCESS
}

fn busy_threads(count: usize) {
    for index in 0..count {
        thread::spawn(move || loop {
            black_box(spin_work(index as u64));
        });
    }
}

fn exit() -> ExitCode {
    busy_threads(3);
    thread::sleep(Duration::from_millis(50));
    println!("THREADTEST OK exit");
    std::process::exit(7)
}

fn segv() -> ExitCode {
    busy_threads(2);
    let faulting = thread::spawn(|| {
        thread::sleep(Duration::from_millis(50));
        let pointer: *mut u32 = std::ptr::null_mut();
        // SAFETY: not safe at all; the write faults, which is the point.
        unsafe { pointer.write_volatile(1) };
    });
    let _ = faulting.join();
    eprintln!("threadtest: the fault did not end the process");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let number = |index: usize, default: u64| {
        arguments
            .get(index)
            .and_then(|value| value.parse().ok())
            .unwrap_or(default)
    };
    match arguments.first().map(String::as_str) {
        Some("spin") => spin(number(1, 1) as usize),
        Some("pingpong") => pingpong(number(1, 10_000)),
        Some("sleep") => sleep(),
        Some("queue") => queue(),
        Some("spawn") => spawn(number(1, 10) as usize),
        Some("exit") => exit(),
        Some("segv") => segv(),
        _ => {
            eprintln!("usage: ginux-threadtest spin N | pingpong N | sleep | queue | spawn N | exit | segv");
            ExitCode::FAILURE
        }
    }
}
