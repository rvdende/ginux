//! ginux-fetch: prints the system summary neofetch-style tools show — OS,
//! kernel, CPU, memory, uptime, display and input devices — from uname(2),
//! /etc/os-release, /proc and the fbdev and evdev interfaces.

use std::{fs, os::fd::AsRawFd};

const LOGO: [&str; 8] = [
    r"   ____ _                  ",
    r"  / ___(_)_ __  _   ___  __",
    r" | |  _| | '_ \| | | \ \/ /",
    r" | |_| | | | | | |_| |>  < ",
    r"  \____|_|_| |_|\__,_/_/\_\",
    r"                           ",
    r"   a Rust kernel           ",
    r"                           ",
];

extern "C" {
    fn ioctl(fd: i32, request: u64, ...) -> i32;
}

/// The value of `key` in a `key: value` or `key=value` text file.
fn field(text: &str, key: &str, separator: char) -> Option<String> {
    text.lines().find_map(|line| {
        let (name, value) = line.split_once(separator)?;
        (name.trim() == key).then(|| value.trim().trim_matches('"').to_string())
    })
}

fn os_name() -> Option<String> {
    let release = fs::read_to_string("/etc/os-release").ok()?;
    field(&release, "PRETTY_NAME", '=').or_else(|| field(&release, "NAME", '='))
}

fn memory() -> Option<String> {
    let info = fs::read_to_string("/proc/meminfo").ok()?;
    let kib = |key| {
        field(&info, key, ':')?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()
    };
    let total = kib("MemTotal")?;
    let available = kib("MemAvailable").or_else(|| kib("MemFree"))?;
    Some(format!(
        "{} MiB / {} MiB",
        (total - available) / 1024,
        total / 1024
    ))
}

fn uptime() -> Option<String> {
    let text = fs::read_to_string("/proc/uptime").ok()?;
    let seconds = text.split_whitespace().next()?.parse::<f64>().ok()? as u64;
    Some(match seconds {
        0..=59 => format!("{seconds} s"),
        60..=3599 => format!("{} min", seconds / 60),
        _ => format!("{} h {} min", seconds / 3600, seconds % 3600 / 60),
    })
}

/// The framebuffer mode from FBIOGET_VSCREENINFO.
fn display() -> Option<String> {
    let file = fs::File::open("/dev/fb0").ok()?;
    let mut info = [0_u32; 40];
    // SAFETY: FBIOGET_VSCREENINFO fills a 160-byte fb_var_screeninfo.
    (unsafe { ioctl(file.as_raw_fd(), 0x4600, info.as_mut_ptr()) } == 0)
        .then(|| format!("{}x{} {} bpp (/dev/fb0)", info[0], info[1], info[6]))
}

/// Names of the evdev devices, from EVIOCGNAME.
fn input_devices() -> Option<String> {
    let names: Vec<String> = (0..8)
        .filter_map(|index| {
            let file = fs::File::open(format!("/dev/input/event{index}")).ok()?;
            let mut name = [0_u8; 64];
            let request = 0x8000_4506 | ((name.len() as u64) << 16);
            // SAFETY: EVIOCGNAME writes at most name.len() bytes.
            let length = unsafe { ioctl(file.as_raw_fd(), request, name.as_mut_ptr()) };
            let length = usize::try_from(length).ok()?.min(name.len());
            let text = String::from_utf8_lossy(&name[..length]);
            Some(text.trim_end_matches('\0').to_string())
        })
        .collect();
    (!names.is_empty()).then(|| names.join(", "))
}

fn main() {
    let uname = rustix::system::uname();
    let text = |value: &std::ffi::CStr| value.to_string_lossy().into_owned();
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu = field(&cpuinfo, "model name", ':');
    let cores = cpuinfo
        .lines()
        .filter(|line| line.starts_with("processor"))
        .count();
    let user = std::env::var("USER").unwrap_or_else(|_| "root".into());
    let rows: Vec<(&str, Option<String>)> = vec![
        ("OS", os_name()),
        (
            "Kernel",
            Some(format!(
                "{} {}",
                text(uname.sysname()),
                text(uname.release())
            )),
        ),
        ("Host", Some(text(uname.nodename()))),
        ("Arch", Some(text(uname.machine()))),
        ("CPU", cpu.map(|cpu| format!("{cpu} ({cores})"))),
        ("Memory", memory()),
        ("Uptime", uptime()),
        ("Display", display()),
        ("Input", input_devices()),
        (
            "Shell",
            std::env::var("SHELL")
                .ok()
                .or_else(|| Some("/bin/sh".into())),
        ),
    ];
    let rows: Vec<String> = std::iter::once(format!("{user}@{}", text(uname.nodename())))
        .chain(std::iter::once("-".repeat(24)))
        .chain(
            rows.into_iter()
                .filter_map(|(label, value)| Some(format!("{label}: {}", value?))),
        )
        .collect();
    for index in 0..rows.len().max(LOGO.len()) {
        let logo = LOGO
            .get(index)
            .copied()
            .unwrap_or("                           ");
        println!("{logo}  {}", rows.get(index).map_or("", String::as_str));
    }
}

#[cfg(test)]
mod tests {
    use super::field;

    #[test]
    fn reads_both_file_formats() {
        assert_eq!(
            field("NAME=\"Alpine Linux\"\nID=alpine", "NAME", '='),
            Some("Alpine Linux".into())
        );
        assert_eq!(
            field("model name\t: Ginux CPU", "model name", ':'),
            Some("Ginux CPU".into())
        );
        assert_eq!(field("ID=x", "NAME", '='), None);
    }
}
