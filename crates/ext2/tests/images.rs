//! The driver against images the host's e2fsprogs makes: each test formats
//! an image with `mke2fs`, works on it in memory, writes it back and has
//! `e2fsck -fn` check it and `debugfs` read it. Without e2fsprogs on the
//! host the tests have nothing to compare with and pass vacuously.

use std::path::{Path, PathBuf};
use std::process::Command;

use ginux_ext2::{
    BlockDevice, Change, Error, Filesystem, Kind, Options, RenameMode, Result, Timestamp,
    XattrMode, ROOT_INODE,
};

struct Memory(Vec<u8>);

impl BlockDevice for Memory {
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> Result<()> {
        let start = offset as usize;
        let source = self.0.get(start..start + buffer.len()).ok_or(Error::Io)?;
        buffer.copy_from_slice(source);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let start = offset as usize;
        let target = self.0.get_mut(start..start + data.len()).ok_or(Error::Io)?;
        target.copy_from_slice(data);
        Ok(())
    }

    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

const NOW: Timestamp = Timestamp::new(1_700_000_000, 250_000_000);

fn tool(name: &str) -> Option<PathBuf> {
    ["/usr/sbin", "/sbin", "/usr/bin", "/bin"]
        .iter()
        .map(|directory| Path::new(directory).join(name))
        .find(|path| path.exists())
}

struct Image {
    path: PathBuf,
}

impl Image {
    /// A fresh image of `megabytes` made with `mke2fs -t ext2` and `options`,
    /// or `None` without e2fsprogs.
    fn new(name: &str, megabytes: u64, options: &[&str]) -> Option<Self> {
        let mke2fs = tool("mke2fs")?;
        tool("e2fsck")?;
        tool("debugfs")?;
        let directory = std::env::temp_dir().join(format!("ginux-ext2-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{name}.img"));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(megabytes << 20).unwrap();
        let status = Command::new(mke2fs)
            .args(["-q", "-F", "-t", "ext2"])
            .args(options)
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "mke2fs failed");
        Some(Self { path })
    }

    fn mount(&self) -> Filesystem<Memory> {
        let bytes = std::fs::read(&self.path).unwrap();
        Filesystem::mount(
            Memory(bytes),
            Options {
                read_only: false,
                now: NOW,
            },
        )
        .unwrap()
    }

    /// Unmounts `filesystem` into the image and checks it with e2fsck.
    fn store(&self, filesystem: Filesystem<Memory>) {
        let device = filesystem.unmount(NOW).unwrap();
        std::fs::write(&self.path, device.0).unwrap();
        let output = Command::new(tool("e2fsck").unwrap())
            .args(["-fn"])
            .arg(&self.path)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "e2fsck found problems:\n{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn debugfs(&self, request: &str) -> String {
        let output = Command::new(tool("debugfs").unwrap())
            .args(["-R", request])
            .arg(&self.path)
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout).into_owned()
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn names(filesystem: &mut Filesystem<Memory>, directory: u32) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;
    while let Some((entry, next)) = filesystem.read_dir(directory, offset).unwrap() {
        names.push(String::from_utf8_lossy(entry.name()).into_owned());
        offset = next;
    }
    names.sort();
    names
}

fn create_file(filesystem: &mut Filesystem<Memory>, parent: u32, name: &str) -> u32 {
    filesystem
        .create(
            parent,
            name.as_bytes(),
            Kind::File,
            0o644,
            1000,
            100,
            0,
            NOW,
        )
        .unwrap()
}

/// A pattern that differs at every position, so a misplaced block shows.
fn pattern(offset: u64, length: usize) -> Vec<u8> {
    (0..length as u64)
        .map(|index| ((offset + index) * 7 % 251) as u8)
        .collect()
}

#[test]
fn a_fresh_image_mounts_and_lists() {
    let Some(image) = Image::new("fresh", 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let root = filesystem.stat(ROOT_INODE).unwrap();
    assert_eq!(root.kind, Kind::Directory);
    assert_eq!(root.mode, 0o755);
    assert_eq!(
        names(&mut filesystem, ROOT_INODE),
        [".", "..", "lost+found"]
    );
    let found = filesystem.lookup(ROOT_INODE, b"lost+found").unwrap();
    assert_eq!(filesystem.stat(found).unwrap().kind, Kind::Directory);
    assert_eq!(
        filesystem.lookup(ROOT_INODE, b"missing"),
        Err(Error::NotFound)
    );
    let statfs = filesystem.statfs();
    assert!(statfs.free_blocks > 0 && statfs.free_blocks < statfs.blocks);
    image.store(filesystem);
}

#[test]
fn file_data_survives_every_level_of_the_block_map() {
    // 1 KiB blocks: the triple indirect blocks start past 64 MiB.
    let Some(image) = Image::new("data", 96, &["-b", "1024"]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "data");
    let offsets = [0_u64, 11 * 1024 + 100, 300 * 1024, 70 << 20];
    for offset in offsets {
        let data = pattern(offset, 5000);
        assert_eq!(filesystem.write(file, offset, &data).unwrap(), data.len());
    }
    for offset in offsets {
        let mut buffer = vec![0; 5000];
        assert_eq!(filesystem.read(file, offset, &mut buffer).unwrap(), 5000);
        assert_eq!(buffer, pattern(offset, 5000));
    }
    // A hole reads as zeros.
    let mut hole = vec![1; 100];
    filesystem.read(file, 1 << 20, &mut hole).unwrap();
    assert!(hole.iter().all(|byte| *byte == 0));
    let stat = filesystem.stat(file).unwrap();
    assert_eq!(stat.size, (70 << 20) + 5000);
    image.store(filesystem);
    let listing = image.debugfs("stat /data");
    assert!(
        listing.contains("TIND"),
        "no triple indirect block:\n{listing}"
    );

    // Shrinking frees the far blocks and zeroes the rest of the last one.
    let mut filesystem = image.mount();
    let before = filesystem.statfs().free_blocks;
    filesystem.truncate(file, 300 * 1024 + 10).unwrap();
    assert!(filesystem.statfs().free_blocks > before);
    filesystem.truncate(file, 300 * 1024 + 4000).unwrap();
    let mut tail = vec![1; 3990];
    filesystem.read(file, 300 * 1024 + 10, &mut tail).unwrap();
    assert!(tail.iter().all(|byte| *byte == 0));
    image.store(filesystem);

    let mut filesystem = image.mount();
    filesystem.truncate(file, 0).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().blocks, 0);
    image.store(filesystem);
}

#[test]
fn debugfs_reads_what_was_written() {
    let Some(image) = Image::new("contents", 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let directory = filesystem
        .create(ROOT_INODE, b"dir", Kind::Directory, 0o750, 0, 0, 0, NOW)
        .unwrap();
    let file = create_file(&mut filesystem, directory, "hello");
    filesystem.write(file, 0, b"hello, ext2\n").unwrap();
    image.store(filesystem);
    assert_eq!(image.debugfs("cat /dir/hello"), "hello, ext2\n");
    let stat = image.debugfs("stat /dir/hello");
    assert!(
        stat.contains("User:  1000") && stat.contains("Group:   100"),
        "{stat}"
    );
}

#[test]
fn directories_grow_and_shrink() {
    let Some(image) = Image::new("directories", 16, &["-b", "1024"]) else {
        return;
    };
    let mut filesystem = image.mount();
    let parent = filesystem
        .create(ROOT_INODE, b"many", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let root_links = filesystem.stat(ROOT_INODE).unwrap().links;
    for index in 0..300 {
        create_file(
            &mut filesystem,
            parent,
            &format!("file-with-a-long-name-{index:04}"),
        );
    }
    assert!(filesystem.stat(parent).unwrap().size > 1024);
    assert_eq!(names(&mut filesystem, parent).len(), 302);
    for index in (0..300).step_by(2) {
        let name = format!("file-with-a-long-name-{index:04}");
        let inode = filesystem.unlink(parent, name.as_bytes(), NOW).unwrap();
        assert!(filesystem.release(inode, NOW).unwrap());
    }
    assert_eq!(names(&mut filesystem, parent).len(), 152);
    assert_eq!(
        filesystem.rmdir(ROOT_INODE, b"many", NOW),
        Err(Error::NotEmpty)
    );
    let sub = filesystem
        .create(parent, b"sub", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    assert_eq!(filesystem.stat(parent).unwrap().links, 3);
    let gone = filesystem.rmdir(parent, b"sub", NOW).unwrap();
    assert_eq!(gone, sub);
    assert_eq!(filesystem.stat(parent).unwrap().links, 2);
    assert!(filesystem.release(sub, NOW).unwrap());
    assert_eq!(filesystem.stat(ROOT_INODE).unwrap().links, root_links);
    image.store(filesystem);
}

#[test]
fn links_symlinks_and_devices() {
    let Some(image) = Image::new("links", 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    filesystem.link(ROOT_INODE, b"other", file, NOW).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().links, 2);
    assert_eq!(
        filesystem.link(ROOT_INODE, b"other", file, NOW),
        Err(Error::Exists)
    );
    filesystem.unlink(ROOT_INODE, b"file", NOW).unwrap();
    assert!(!filesystem.release(file, NOW).unwrap());
    assert_eq!(filesystem.stat(file).unwrap().links, 1);

    let short = filesystem
        .symlink(ROOT_INODE, b"short", b"other", 0, 0, NOW)
        .unwrap();
    let long_target = "x/".repeat(100);
    let long = filesystem
        .symlink(ROOT_INODE, b"long", long_target.as_bytes(), 0, 0, NOW)
        .unwrap();
    let mut buffer = [0; 4096];
    let length = filesystem.read_link(short, &mut buffer).unwrap();
    assert_eq!(&buffer[..length], b"other");
    let length = filesystem.read_link(long, &mut buffer).unwrap();
    assert_eq!(&buffer[..length], long_target.as_bytes());

    let device = filesystem
        .create(
            ROOT_INODE,
            b"null",
            Kind::CharacterDevice,
            0o666,
            0,
            0,
            (1 << 8) | 3,
            NOW,
        )
        .unwrap();
    assert_eq!(filesystem.stat(device).unwrap().device, (1 << 8) | 3);
    filesystem
        .create(ROOT_INODE, b"fifo", Kind::Fifo, 0o600, 0, 0, 0, NOW)
        .unwrap();
    image.store(filesystem);
    assert_eq!(image.debugfs("cat /other"), "");
    assert!(image.debugfs("stat /long").contains("Type: symlink"));

    // Removing them frees everything again: e2fsck counts the bitmaps.
    let mut filesystem = image.mount();
    for name in ["short", "long", "null", "fifo", "other"] {
        let inode = filesystem.unlink(ROOT_INODE, name.as_bytes(), NOW).unwrap();
        assert!(filesystem.release(inode, NOW).unwrap());
    }
    image.store(filesystem);
}

#[test]
fn renames_move_names_and_directories() {
    let Some(image) = Image::new("rename", 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let a = filesystem
        .create(ROOT_INODE, b"a", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let b = filesystem
        .create(ROOT_INODE, b"b", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let inner = filesystem
        .create(a, b"inner", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let file = create_file(&mut filesystem, a, "file");
    let target = create_file(&mut filesystem, b, "target");

    // A directory into itself is EINVAL.
    assert_eq!(
        filesystem.rename(ROOT_INODE, b"a", inner, b"x", RenameMode::Replace, NOW),
        Err(Error::Invalid)
    );
    // A file replaces another, which loses its only name.
    let replaced = filesystem
        .rename(a, b"file", b, b"target", RenameMode::Replace, NOW)
        .unwrap();
    assert_eq!(replaced, Some(target));
    assert!(filesystem.release(target, NOW).unwrap());
    assert_eq!(filesystem.lookup(b, b"target").unwrap(), file);
    // A directory moves, and the link counts follow its "..".
    filesystem
        .rename(a, b"inner", b, b"moved", RenameMode::NoReplace, NOW)
        .unwrap();
    assert_eq!(filesystem.lookup(inner, b"..").unwrap(), b);
    assert_eq!(filesystem.stat(a).unwrap().links, 2);
    assert_eq!(filesystem.stat(b).unwrap().links, 3);
    assert_eq!(
        filesystem.rename(ROOT_INODE, b"a", b, b"moved", RenameMode::NoReplace, NOW),
        Err(Error::Exists)
    );
    // Exchanging a file and a directory across directories.
    filesystem
        .rename(b, b"target", ROOT_INODE, b"a", RenameMode::Exchange, NOW)
        .unwrap();
    assert_eq!(filesystem.lookup(ROOT_INODE, b"a").unwrap(), file);
    assert_eq!(filesystem.lookup(b, b"target").unwrap(), a);
    assert_eq!(filesystem.lookup(a, b"..").unwrap(), b);
    image.store(filesystem);
}

#[test]
fn attributes_and_extended_attributes() {
    let Some(image) = Image::new("xattr", 16, &["-I", "256"]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    let later = Timestamp::new(1_800_000_000, 123_456_789);
    filesystem
        .change(
            file,
            &Change {
                mode: Some(0o4711),
                owner: Some(70000),
                group: Some(70001),
                mtime: Some(later),
                ..Change::default()
            },
        )
        .unwrap();
    let stat = filesystem.stat(file).unwrap();
    assert_eq!(
        (stat.mode, stat.owner, stat.group, stat.mtime),
        (0o4711, 70000, 70001, later)
    );
    assert_eq!(stat.crtime, Some(NOW));

    filesystem
        .set_xattr(file, b"user.first", b"one", XattrMode::Create)
        .unwrap();
    filesystem
        .set_xattr(file, b"trusted.second", &[7; 300], XattrMode::Any)
        .unwrap();
    filesystem
        .set_xattr(file, b"user.empty", b"", XattrMode::Any)
        .unwrap();
    assert_eq!(
        filesystem.set_xattr(file, b"user.first", b"x", XattrMode::Create),
        Err(Error::Exists)
    );
    assert_eq!(
        filesystem.set_xattr(file, b"user.none", b"x", XattrMode::Replace),
        Err(Error::NoData)
    );
    filesystem
        .set_xattr(file, b"user.first", b"uno", XattrMode::Replace)
        .unwrap();
    assert_eq!(filesystem.get_xattr(file, b"user.first").unwrap(), b"uno");
    assert_eq!(
        filesystem.list_xattrs(file).unwrap(),
        b"user.empty\0user.first\0trusted.second\0"
    );
    assert_eq!(
        filesystem.set_xattr(file, b"user.big", &[1; 8000], XattrMode::Any),
        Err(Error::NoSpace)
    );
    image.store(filesystem);
    let listing = image.debugfs("ea_list /file");
    assert!(
        listing.contains("user.first") && listing.contains("uno"),
        "{listing}"
    );

    let mut filesystem = image.mount();
    for name in ["user.first", "trusted.second", "user.empty"] {
        filesystem.remove_xattr(file, name.as_bytes()).unwrap();
    }
    assert_eq!(
        filesystem.remove_xattr(file, b"user.first"),
        Err(Error::NoData)
    );
    assert_eq!(filesystem.stat(file).unwrap().blocks, 0);
    image.store(filesystem);
}

#[test]
fn a_full_disk_writes_short_then_fails() {
    let Some(image) = Image::new("full", 4, &["-b", "1024"]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "fill");
    let chunk = vec![0x5a; 1 << 20];
    let mut written = 0;
    loop {
        match filesystem.write(file, written, &chunk) {
            Ok(0) => panic!("no progress"),
            Ok(count) if count < chunk.len() => {
                written += count as u64;
                break;
            }
            Ok(count) => written += count as u64,
            Err(error) => {
                assert_eq!(error, Error::NoSpace);
                break;
            }
        }
    }
    assert_eq!(filesystem.statfs().free_blocks, 0);
    assert_eq!(
        filesystem.write(file, written, b"more"),
        Err(Error::NoSpace)
    );
    assert_eq!(filesystem.stat(file).unwrap().size, written);
    image.store(filesystem);
    let mut filesystem = image.mount();
    let inode = filesystem.unlink(ROOT_INODE, b"fill", NOW).unwrap();
    assert!(filesystem.release(inode, NOW).unwrap());
    image.store(filesystem);
}

#[test]
fn files_mke2fs_made_read_back() {
    let directory = std::env::temp_dir().join(format!("ginux-ext2-src-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("sub")).unwrap();
    std::fs::write(directory.join("sub/text"), pattern(0, 100_000)).unwrap();
    let _ = std::os::unix::fs::symlink("sub/text", directory.join("link"));
    let source = directory.to_string_lossy().into_owned();
    let Some(image) = Image::new("populated", 16, &["-d", &source]) else {
        return;
    };
    let mut filesystem = image.mount();
    let sub = filesystem.lookup(ROOT_INODE, b"sub").unwrap();
    let text = filesystem.lookup(sub, b"text").unwrap();
    let mut buffer = vec![0; 100_000];
    assert_eq!(filesystem.read(text, 0, &mut buffer).unwrap(), 100_000);
    assert_eq!(buffer, pattern(0, 100_000));
    let link = filesystem.lookup(ROOT_INODE, b"link").unwrap();
    let length = filesystem.read_link(link, &mut buffer).unwrap();
    assert_eq!(&buffer[..length], b"sub/text");
    image.store(filesystem);
    let _ = std::fs::remove_dir_all(directory);
}
