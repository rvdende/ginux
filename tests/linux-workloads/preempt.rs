// A process spinning in user mode, making no system calls, must not keep
// others off the CPU: the parent spawns such a child, sleeps, then kills and
// reaps it, which only works if the kernel preempts the child. Run with no
// argument; the child is this program run with "spin".
use std::process::Command;
use std::time::{Duration, Instant};

fn main() {
    if std::env::args().nth(1).as_deref() == Some("spin") {
        loop {
            std::hint::spin_loop();
        }
    }
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new(exe).arg("spin").spawn().expect("spawn spinner");
    let started = Instant::now();
    std::thread::sleep(Duration::from_millis(500));
    let slept = started.elapsed();
    child.kill().expect("kill spinner");
    let status = child.wait().expect("wait for spinner");
    assert!(!status.success(), "spinner exited normally: {status}");
    assert!(
        slept < Duration::from_secs(10),
        "parent slept {slept:?} for a 500 ms sleep"
    );
    println!("parent woke after {slept:?} while its child spun");
}
