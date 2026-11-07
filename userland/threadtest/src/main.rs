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
//! - `pin`: a child pinned to each CPU with sched_setaffinity runs there at
//!   once and keeps running there across 1 ms sleeps; then the process
//!   itself moves to the last CPU the same way.
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

extern "C" {
    fn fork() -> i32;
    fn _exit(status: i32) -> !;
    fn alarm(seconds: u32) -> u32;
    fn sched_setaffinity(pid: i32, size: usize, mask: *const u64) -> i32;
    fn sched_getcpu() -> i32;
    fn usleep(microseconds: u32) -> i32;
    fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
}

/// A child pinned to `cpu` runs there at once and keeps running there
/// across sleeps; its exit status says what went wrong (0: nothing).
fn pinned_child(cpu: usize) -> i32 {
    // musl's cpu_set_t: 1024 bits.
    let mut mask = [0_u64; 16];
    mask[cpu / 64] |= 1 << (cpu % 64);
    // SAFETY: the mask is a live cpu_set_t-sized buffer.
    if unsafe { sched_setaffinity(0, size_of_val(&mask), mask.as_ptr()) } != 0 {
        return 2;
    }
    // SAFETY: a plain query.
    if unsafe { sched_getcpu() } != cpu as i32 {
        return 3;
    }
    for _ in 0..3 {
        // SAFETY: a plain sleep.
        unsafe { usleep(1000) };
        // SAFETY: a plain query.
        if unsafe { sched_getcpu() } != cpu as i32 {
            return 4;
        }
    }
    0
}

/// `pin`: on each CPU (up to four), a forked child pinned to it with
/// sched_setaffinity reports that CPU at once and again after each of three
/// 1 ms sleeps, and exits; SIGALRM after 10 s ends one that never runs again.
fn pin() -> ExitCode {
    let cpus = thread::available_parallelism()
        .map_or(1, usize::from)
        .min(4);
    let mut failures = 0;
    for cpu in 0..cpus {
        // SAFETY: the process is single-threaded here, so the child may run
        // any code.
        let child = unsafe { fork() };
        if child == 0 {
            // SAFETY: arms this child's own alarm, then ends it without the
            // parent's exit code.
            unsafe {
                alarm(10);
                _exit(pinned_child(cpu))
            }
        }
        if child < 0 {
            eprintln!("threadtest: fork failed");
            return ExitCode::FAILURE;
        }
        let mut status = 0;
        // SAFETY: waits for the child just made.
        if unsafe { waitpid(child, &mut status, 0) } != child {
            eprintln!("threadtest: waitpid failed");
            return ExitCode::FAILURE;
        }
        println!("PIN cpu={cpu} status={status}");
        failures += usize::from(status != 0);
    }
    // The process itself, not a fresh child, moves to the last CPU at once
    // and stays there across a sleep, then may run anywhere again.
    let last = cpus - 1;
    let status = pinned_child(last);
    println!("PIN self cpu={last} status={status}");
    failures += usize::from(status != 0);
    let all = [u64::MAX; 16];
    // SAFETY: the mask is a live cpu_set_t-sized buffer.
    if unsafe { sched_setaffinity(0, size_of_val(&all), all.as_ptr()) } != 0 {
        eprintln!("threadtest: restoring the affinity failed");
        failures += 1;
    }
    if failures != 0 {
        return ExitCode::FAILURE;
    }
    println!("THREADTEST OK pin");
    ExitCode::SUCCESS
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
        Some("pin") => pin(),
        _ => {
            eprintln!(
                "usage: ginux-threadtest spin N | pingpong N | sleep | queue | spawn N | exit | segv | pin"
            );
            ExitCode::FAILURE
        }
    }
}
