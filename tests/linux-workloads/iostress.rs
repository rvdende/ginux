// File I/O stress test for Ginux: threads write, read back, rename, copy,
// append to and positionally rewrite files of many sizes in a directory,
// checking every byte and that no read writes past the buffer it was given
// (guard bytes on both sides of each read buffer).
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::FileExt;
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

const GUARD: usize = 64;

fn pattern(tag: u64, length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (tag.wrapping_add(index as u64).wrapping_mul(0x9e37_79b9) >> 7) as u8)
        .collect()
}

fn report(errors: &AtomicU64, message: String) {
    if errors.fetch_add(1, Ordering::SeqCst) < 12 {
        eprintln!("ERROR {message}");
    }
}

/// Reads `path` with reads of `chunk` bytes into a guarded buffer and
/// returns the contents.
fn guarded_read(path: &str, chunk: usize, errors: &AtomicU64) -> Option<Vec<u8>> {
    let mut file = File::open(path).ok()?;
    let mut contents = Vec::new();
    let mut buffer = vec![0xa5_u8; chunk + 2 * GUARD];
    loop {
        let read = match file.read(&mut buffer[GUARD..GUARD + chunk]) {
            Ok(read) => read,
            Err(error) => {
                report(errors, format!("read {path}: {error}"));
                return None;
            }
        };
        if read > chunk {
            report(errors, format!("read {path} returned {read} > {chunk}"));
        }
        if buffer[..GUARD].iter().chain(&buffer[GUARD + chunk..]).any(|byte| *byte != 0xa5) {
            report(errors, format!("read {path} wrote outside its {chunk}-byte buffer"));
            buffer[..GUARD].fill(0xa5);
            buffer[GUARD + chunk..].fill(0xa5);
        }
        if read == 0 {
            return Some(contents);
        }
        contents.extend_from_slice(&buffer[GUARD..GUARD + read]);
    }
}

fn main() {
    let threads: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(4);
    let rounds: u64 = std::env::args().nth(2).and_then(|s| s.parse().ok()).unwrap_or(2000);
    let root = std::env::args().nth(3).unwrap_or_else(|| "/tmp/iostress".into());
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let errors = Arc::new(AtomicU64::new(0));
    let workers: Vec<_> = (0..threads)
        .map(|worker| {
            let errors = Arc::clone(&errors);
            let root = root.clone();
            thread::spawn(move || {
                let mut rng = Rng(0xfeed + worker);
                let directory = format!("{root}/w{worker}/a/b");
                fs::create_dir_all(&directory).unwrap();
                for round in 0..rounds {
                    let length = match rng.next() % 4 {
                        0 => (rng.next() % 64) as usize,
                        1 => (rng.next() % 5000) as usize,
                        2 => (rng.next() % 70_000) as usize,
                        _ => (rng.next() % 400_000) as usize,
                    };
                    let tag = rng.next();
                    let data = pattern(tag, length);
                    let temporary = format!("{directory}/.tmp{round}");
                    let path = format!("{directory}/f{}", round % 37);
                    if fs::write(&temporary, &data).is_err() || fs::rename(&temporary, &path).is_err() {
                        report(&errors, format!("write/rename {path}"));
                        continue;
                    }
                    let chunk = [1, 7, 512, 4096, 8192, 65536][(rng.next() % 6) as usize];
                    match guarded_read(&path, chunk, &errors) {
                        Some(read) if read == data => {}
                        Some(read) => report(
                            &errors,
                            format!("{path}: read {} bytes, wrote {}", read.len(), data.len()),
                        ),
                        None => {}
                    }
                    match fs::read(&path) {
                        Ok(read) if read == data => {}
                        _ => report(&errors, format!("fs::read {path} mismatch")),
                    }
                    if rng.next() % 4 == 0 && length > 16 {
                        // Rewrite a range in place and append, as databases do.
                        let file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
                        let offset = (rng.next() as usize) % length;
                        let patch = pattern(tag ^ 0x55, (rng.next() % 9000) as usize);
                        file.write_all_at(&patch, offset as u64).unwrap();
                        let mut expected = data.clone();
                        let end = offset + patch.len();
                        if end > expected.len() {
                            expected.resize(end, 0);
                        }
                        expected[offset..end].copy_from_slice(&patch);
                        let mut appended = OpenOptions::new().append(true).open(&path).unwrap();
                        appended.write_all(b"tail").unwrap();
                        expected.extend_from_slice(b"tail");
                        let mut positioned = vec![0_u8; expected.len()];
                        file.read_exact_at(&mut positioned, 0).unwrap();
                        if positioned != expected {
                            report(&errors, format!("{path}: positioned rewrite mismatch"));
                        }
                        let mut seeked = File::open(&path).unwrap();
                        seeked.seek(SeekFrom::Start(offset as u64)).unwrap();
                        let mut rest = Vec::new();
                        seeked.read_to_end(&mut rest).unwrap();
                        if rest != expected[offset..] {
                            report(&errors, format!("{path}: seek read mismatch"));
                        }
                    }
                    if rng.next() % 8 == 0 {
                        let copy = format!("{directory}/copy");
                        if fs::copy(&path, &copy).is_err() || fs::read(&copy).ok() != fs::read(&path).ok() {
                            report(&errors, format!("{path}: copy mismatch"));
                        }
                    }
                    if rng.next() % 5 == 0 {
                        let _ = fs::remove_file(&path);
                    }
                }
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    let errors = errors.load(Ordering::SeqCst);
    println!("iostress threads={threads} rounds={rounds} errors={errors}");
    std::process::exit(if errors == 0 { 0 } else { 1 });
}
