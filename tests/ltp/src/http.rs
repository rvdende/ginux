//! A minimal HTTP/1.0 file server for the guest: the LTP tree, the runner,
//! setup.sh and the run list, all from one directory.

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

/// Serves the files in `directory` (by bare name, symlinks followed) on a
/// free port of 127.0.0.1, which the guest reaches as 10.0.2.2. Returns the
/// port; the server runs until the process exits.
pub fn serve(directory: PathBuf) -> io::Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    let directory = Arc::new(directory);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let directory = Arc::clone(&directory);
            thread::spawn(move || {
                let _ = respond(stream, &directory);
            });
        }
    });
    Ok(port)
}

/// The served file's name in a request target, if it names one.
fn file_name(target: &str) -> Option<&str> {
    let path = target.split(['?', '#']).next()?;
    let name = path.strip_prefix('/')?;
    let plain = !name.is_empty() && !name.contains('/') && name != "." && name != "..";
    plain.then_some(name)
}

fn respond(mut stream: TcpStream, directory: &Path) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(60)))?;
    stream.set_write_timeout(Some(Duration::from_secs(60)))?;
    let mut head = Vec::new();
    let mut buffer = [0; 4096];
    while memchr::memmem::find(&head, b"\r\n\r\n").is_none()
        && memchr::memmem::find(&head, b"\n\n").is_none()
    {
        let count = stream.read(&mut buffer)?;
        if count == 0 || head.len() > 65536 {
            return Ok(());
        }
        head.extend_from_slice(&buffer[..count]);
    }
    let head = String::from_utf8_lossy(&head);
    let mut request = head.lines().next().unwrap_or_default().split_whitespace();
    let method = request.next().unwrap_or_default();
    let target = request.next().unwrap_or_default();
    if method != "GET" && method != "HEAD" {
        return stream.write_all(
            b"HTTP/1.0 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    }
    let file = file_name(target).and_then(|name| File::open(directory.join(name)).ok());
    let Some(mut file) = file.filter(|file| file.metadata().is_ok_and(|m| m.is_file())) else {
        return stream.write_all(
            b"HTTP/1.0 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
    };
    let length = file.metadata()?.len();
    write!(
        stream,
        "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
    )?;
    if method == "GET" {
        io::copy(&mut file, &mut stream)?;
    }
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get(port: u16, target: &str) -> String {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).unwrap();
        response
    }

    #[test]
    fn names_only_files_in_the_directory() {
        assert_eq!(file_name("/setup.sh"), Some("setup.sh"));
        assert_eq!(file_name("/runlist.txt?x=1"), Some("runlist.txt"));
        assert_eq!(file_name("/"), None);
        assert_eq!(file_name("/../etc/passwd"), None);
        assert_eq!(file_name("/.."), None);
        assert_eq!(file_name("setup.sh"), None);
    }

    #[test]
    fn serves_a_file_and_refuses_the_rest() {
        let directory = std::env::temp_dir().join(format!("ginux-ltp-http-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("runlist.txt"), "0\ta\t60\ta\n").unwrap();
        let port = serve(directory.clone()).unwrap();
        let response = get(port, "/runlist.txt");
        assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
        assert!(response.contains("Content-Length: 9\r\n"), "{response}");
        assert!(response.ends_with("\r\n\r\n0\ta\t60\ta\n"), "{response}");
        assert!(get(port, "/missing").starts_with("HTTP/1.0 404"));
        assert!(get(port, "/").starts_with("HTTP/1.0 404"));
        std::fs::remove_dir_all(&directory).unwrap();
    }
}
