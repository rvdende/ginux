//! ginux-init: process 1 of a Rust-only Ginux domain. It sets up the
//! environment, runs an interactive shell on the console, reaps orphaned
//! processes, and exits with the shell's status so the domain stops when the
//! shell does.
//!
//! The shell command line comes from `/etc/ginux/shell` (program and
//! arguments separated by spaces), else the first of `/bin/brush` and
//! `/bin/sh` that exists; `/etc/ginux/motd` is printed first if present.
//! The same command line is exported as `SHELL`, which ginux-term runs.

use std::{
    os::unix::process::CommandExt,
    path::Path,
    process::{Command, ExitCode},
};

use rustix::process::{wait, Pid, WaitOptions};

const PATH: &str = "/bin:/sbin";

fn shell() -> String {
    std::fs::read_to_string("/etc/ginux/shell")
        .ok()
        .map(|text| text.trim().to_string())
        .filter(|command| {
            command
                .split_whitespace()
                .next()
                .is_some_and(|program| Path::new(program).exists())
        })
        .or_else(|| {
            ["/bin/brush", "/bin/sh"]
                .into_iter()
                .find(|path| Path::new(path).exists())
                .map(String::from)
        })
        .unwrap_or_else(|| "/bin/sh".into())
}

fn main() -> ExitCode {
    if let Ok(motd) = std::fs::read_to_string("/etc/ginux/motd") {
        print!("{motd}");
    }
    let shell = shell();
    let mut words = shell.split_whitespace();
    let program = words.next().unwrap_or("/bin/sh");
    let spawned = Command::new(program)
        .args(words)
        .env_clear()
        .env("PATH", PATH)
        .env("HOME", "/root")
        .env("USER", "root")
        .env("SHELL", &shell)
        .env("TERM", "linux")
        .env("XDG_RUNTIME_DIR", "/tmp")
        .current_dir("/root")
        .arg0(program)
        .spawn();
    let shell_pid = match spawned {
        Ok(child) => Pid::from_child(&child),
        Err(error) => {
            eprintln!("ginux-init: cannot start {shell}: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Reap every child, including orphans reparented to init, until the
    // shell itself exits.
    loop {
        match wait(WaitOptions::empty()) {
            Ok(Some((pid, status))) if pid == shell_pid => {
                let code = status.exit_status().unwrap_or(1);
                return ExitCode::from(code as u8);
            }
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => {}
            Err(error) => {
                eprintln!("ginux-init: wait: {error}");
                return ExitCode::FAILURE;
            }
        }
    }
}
