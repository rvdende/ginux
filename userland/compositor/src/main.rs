//! ginux-wm: a Wayland compositor and stacking window manager for Ginux,
//! written in Rust on the pure-Rust wayland-server backend. It composes
//! client windows in software onto the Linux framebuffer (/dev/fb0) and
//! reads keyboards and pointers from evdev devices.

mod backend;
mod input;
mod protocol;
mod wm;

use std::{
    os::{
        fd::{AsRawFd, BorrowedFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant},
};

use backend::Output;
use rustix::event::{poll, PollFd, PollFlags, Timespec};
use wayland_server::Display;

const USAGE: &str = "usage: ginux-wm [--headless WIDTHxHEIGHT] [--framebuffer PATH] \
[--input DIR] [--socket NAME] [--terminal COMMAND] [--keymap FILE] [--spawn COMMAND]... \
[--screenshot SECONDS PATH]";

struct Options {
    headless: Option<(i32, i32)>,
    framebuffer: PathBuf,
    input: PathBuf,
    socket: String,
    terminal: String,
    keymap: Option<PathBuf>,
    spawn: Vec<String>,
    screenshot: Option<(Duration, PathBuf)>,
}

fn parse_options() -> Result<Options, String> {
    let mut options = Options {
        headless: None,
        framebuffer: PathBuf::from("/dev/fb0"),
        input: PathBuf::from("/dev/input"),
        socket: "wayland-0".into(),
        terminal: "ginux-term".into(),
        keymap: None,
        spawn: Vec::new(),
        screenshot: None,
    };
    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        let mut value = || {
            arguments
                .next()
                .ok_or_else(|| format!("{argument} needs a value"))
        };
        match argument.as_str() {
            "--headless" => {
                let size = value()?;
                let (width, height) = size.split_once('x').ok_or("size must be WIDTHxHEIGHT")?;
                let parse = |text: &str| text.parse::<i32>().map_err(|error| error.to_string());
                options.headless = Some((parse(width)?, parse(height)?));
            }
            "--framebuffer" => options.framebuffer = value()?.into(),
            "--input" => options.input = value()?.into(),
            "--socket" => options.socket = value()?,
            "--terminal" => options.terminal = value()?,
            "--keymap" => options.keymap = Some(value()?.into()),
            "--spawn" => options.spawn.push(value()?),
            "--screenshot" => {
                let seconds: f64 = value()?.parse().map_err(|_| "seconds must be a number")?;
                options.screenshot = Some((Duration::from_secs_f64(seconds), value()?.into()));
            }
            "--help" | "-h" => return Err(USAGE.into()),
            _ => return Err(format!("unknown argument {argument}\n{USAGE}")),
        }
    }
    Ok(options)
}

fn main() -> ExitCode {
    let options = match parse_options() {
        Ok(options) => options,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };
    match run(options) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ginux-wm: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Binds the Wayland socket in XDG_RUNTIME_DIR, replacing a stale one.
/// Unlike wayland-server's ListeningSocket this takes no flock()ed lock
/// file, since one compositor runs per domain.
fn listen(name: &str) -> Result<UnixListener, String> {
    let directory = std::env::var_os("XDG_RUNTIME_DIR").unwrap_or_default();
    let path = std::path::Path::new(&directory).join(name);
    let _ = std::fs::remove_file(&path);
    let listener =
        UnixListener::bind(&path).map_err(|error| format!("bind {}: {error}", path.display()))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(listener)
}

fn accept(listener: &UnixListener) -> Result<Option<UnixStream>, String> {
    match listener.accept() {
        Ok((stream, _)) => Ok(Some(stream)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(format!("accept: {error}")),
    }
}

fn run(options: Options) -> Result<(), String> {
    if std::env::var_os("XDG_RUNTIME_DIR").is_none() {
        let directory = "/tmp/ginux-wayland";
        std::fs::create_dir_all(directory).map_err(|error| format!("{directory}: {error}"))?;
        std::env::set_var("XDG_RUNTIME_DIR", directory);
    }
    let mut output: Box<dyn Output> = match options.headless {
        Some((width, height)) => Box::new(backend::Headless { width, height }),
        None => Box::new(
            backend::Framebuffer::open(&options.framebuffer)
                .map_err(|error| format!("{}: {error}", options.framebuffer.display()))?,
        ),
    };
    let (width, height) = output.size();
    let mut devices = input::Devices::open(&options.input);

    let mut display: Display<wm::State> = Display::new().map_err(|error| error.to_string())?;
    protocol::create_globals(&display.handle());
    let mut state = wm::State::new(width, height, options.terminal.clone());
    if let Some(path) = &options.keymap {
        let mut keymap =
            std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
        keymap.push(0);
        state.keymap = Some(keymap);
    }
    let listener = listen(&options.socket)?;
    std::env::set_var("WAYLAND_DISPLAY", &options.socket);
    eprintln!("ginux-wm: {width}x{height} on {}", options.socket);
    println!("GINUX_WM_READY {width}x{height}");
    for command in &options.spawn {
        state.spawn(command);
    }

    let display_fd = display.backend().poll_fd().as_raw_fd();
    let started = Instant::now();
    while !state.quit {
        let now = Instant::now();
        let timeout = state.frame_due(now).unwrap_or(Duration::from_millis(500));
        {
            // SAFETY: the display outlives this loop iteration.
            let display_fd = unsafe { BorrowedFd::borrow_raw(display_fd) };
            let mut fds = vec![
                PollFd::new(&listener, PollFlags::IN),
                PollFd::new(&display_fd, PollFlags::IN),
            ];
            fds.extend(
                devices
                    .fds()
                    .map(|fd| PollFd::from_borrowed_fd(fd, PollFlags::IN)),
            );
            let timeout = Timespec {
                tv_sec: timeout.as_secs() as _,
                tv_nsec: timeout.subsec_nanos() as _,
            };
            match poll(&mut fds, Some(&timeout)) {
                Ok(_) | Err(rustix::io::Errno::INTR) => {}
                Err(error) => return Err(format!("poll: {error}")),
            }
        }
        while let Some(stream) = accept(&listener)? {
            if let Err(error) = display
                .handle()
                .insert_client(stream, Arc::new(protocol::ClientState))
            {
                eprintln!("ginux-wm: cannot add client: {error}");
            }
        }
        display
            .dispatch_clients(&mut state)
            .map_err(|error| error.to_string())?;
        devices.read(|event| state.input(event));
        if state.render_if_due(Instant::now()) {
            output.present(&state.frame);
        }
        display.flush_clients().map_err(|error| error.to_string())?;
        state.reap();
        if let Some((delay, path)) = &options.screenshot {
            if started.elapsed() >= *delay {
                state.dirty = true;
                state.render_if_due(Instant::now() + Duration::from_secs(1));
                backend::save_ppm(path, &state.frame, width, height)
                    .map_err(|error| format!("{}: {error}", path.display()))?;
                println!("GINUX_WM_SCREENSHOT {}", path.display());
                break;
            }
        }
    }
    Ok(())
}
