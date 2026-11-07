//! The driver against images the host's e2fsprogs makes: each test formats
//! an image with `mke2fs` (as ext2, and as ext4 with mke2fs's default
//! ext4 features: extents, 64-bit, flex_bg, metadata_csum, a journal),
//! works on it in memory, writes it back and has `e2fsck -fn` check it and
//! `debugfs` read it. Without e2fsprogs on the host the tests have nothing
//! to compare with and pass vacuously.

use std::path::{Path, PathBuf};
use std::process::Command;

use ginux_ext2::{
    BlockDevice, Change, Damage, DquotChange, Error, ErrorPolicy, Failure, Filesystem, FsType,
    Kind, Options, QuotaKind, QuotaOptions, RenameMode, Result, Timestamp, XattrMode, ROOT_INODE,
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

/// What an image is made as.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Format {
    Ext2,
    Ext4,
}

impl Format {
    fn name(self) -> &'static str {
        match self {
            Self::Ext2 => "ext2",
            Self::Ext4 => "ext4",
        }
    }

    fn fs_type(self) -> FsType {
        match self {
            Self::Ext2 => FsType::Ext2,
            Self::Ext4 => FsType::Ext4,
        }
    }
}

struct Image {
    path: PathBuf,
    format: Format,
}

impl Image {
    /// A fresh image of `megabytes` made with `mke2fs -t FORMAT` and
    /// `options`, or `None` without e2fsprogs.
    fn new(name: &str, format: Format, megabytes: u64, options: &[&str]) -> Option<Self> {
        let mke2fs = tool("mke2fs")?;
        tool("e2fsck")?;
        tool("debugfs")?;
        let directory = std::env::temp_dir().join(format!("ginux-ext2-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(format!("{name}-{}.img", format.name()));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(megabytes << 20).unwrap();
        let status = Command::new(mke2fs)
            .args(["-q", "-F", "-t", format.name()])
            .args(options)
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success(), "mke2fs failed");
        Some(Self { path, format })
    }

    fn mount(&self) -> Filesystem<Memory> {
        self.mount_as(self.format.fs_type(), false).unwrap()
    }

    fn mount_as(&self, fs_type: FsType, read_only: bool) -> Result<Filesystem<Memory>> {
        self.mount_with(fs_type, read_only, QuotaOptions::default())
    }

    fn mount_with(
        &self,
        fs_type: FsType,
        read_only: bool,
        quota: QuotaOptions,
    ) -> Result<Filesystem<Memory>> {
        let bytes = std::fs::read(&self.path).unwrap();
        Filesystem::mount(
            Memory(bytes),
            Options {
                read_only,
                now: NOW,
                fs_type,
                quota,
                errors: None,
            },
        )
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

fn a_fresh_image_mounts_and_lists(format: Format) {
    let Some(image) = Image::new("fresh", format, 16, &[]) else {
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

fn file_data_survives_every_level_of_the_block_map(format: Format) {
    // 1 KiB blocks: the triple indirect blocks start past 64 MiB.
    let Some(image) = Image::new("data", format, 96, &["-b", "1024"]) else {
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
    // The written runs, and nothing for the holes between them.
    let extents = filesystem.extents(file, 0, u64::MAX).unwrap();
    assert_eq!(extents.first().unwrap().logical, 0);
    assert_eq!(
        extents.last().unwrap().logical + extents.last().unwrap().length,
        (70 << 20) + 5 * 1024
    );
    assert!(extents
        .iter()
        .all(|extent| extent.logical < 1 << 20 || extent.logical >= 70 << 20));
    image.store(filesystem);
    let listing = image.debugfs("stat /data");
    let mapping = match format {
        Format::Ext2 => "TIND",
        Format::Ext4 => "EXTENTS",
    };
    assert!(listing.contains(mapping), "no {mapping}:\n{listing}");

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

fn debugfs_reads_what_was_written(format: Format) {
    let Some(image) = Image::new("contents", format, 16, &[]) else {
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
    let _ = format;
    let stat = image.debugfs("stat /dir/hello");
    assert!(
        stat.contains("User:  1000") && stat.contains("Group:   100"),
        "{stat}"
    );
}

fn directories_grow_and_shrink(format: Format) {
    let Some(image) = Image::new("directories", format, 16, &["-b", "1024"]) else {
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

fn links_symlinks_and_devices(format: Format) {
    let Some(image) = Image::new("links", format, 16, &[]) else {
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

fn renames_move_names_and_directories(format: Format) {
    let Some(image) = Image::new("rename", format, 16, &[]) else {
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

fn attributes_and_extended_attributes(format: Format) {
    let Some(image) = Image::new("xattr", format, 16, &["-I", "256"]) else {
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

fn a_full_disk_writes_short_then_fails(format: Format) {
    let Some(image) = Image::new("full", format, 4, &["-b", "1024"]) else {
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

fn files_mke2fs_made_read_back(format: Format) {
    let directory = std::env::temp_dir().join(format!(
        "ginux-ext2-src-{}-{}",
        std::process::id(),
        format.name()
    ));
    std::fs::create_dir_all(directory.join("sub")).unwrap();
    std::fs::write(directory.join("sub/text"), pattern(0, 100_000)).unwrap();
    let _ = std::os::unix::fs::symlink("sub/text", directory.join("link"));
    let source = directory.to_string_lossy().into_owned();
    let Some(image) = Image::new("populated", format, 16, &["-d", &source]) else {
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

/// An inode with no file type and an entry naming a reserved inode, as
/// debugfs makes them (fanotify22): lookups see the damage ext4 reports.
fn damaged_references_are_found(format: Format) {
    let Some(image) = Image::new("damaged", format, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let base = filesystem
        .create(ROOT_INODE, b"base", Kind::Directory, 0o777, 0, 0, 0, NOW)
        .unwrap();
    let bad = filesystem
        .create(base, b"bad_dir", Kind::Directory, 0o777, 0, 0, 0, NOW)
        .unwrap();
    assert_eq!(filesystem.damaged_reference(bad), None);
    assert_eq!(filesystem.damaged_reference(ROOT_INODE), None);
    image.store(filesystem);
    for request in ["sif base/bad_dir mode 0xff", "ln <1> base/bad_link"] {
        let status = Command::new(tool("debugfs").unwrap())
            .args(["-w", "-R", request])
            .arg(&image.path)
            .output()
            .unwrap()
            .status;
        assert!(status.success(), "debugfs {request} failed");
    }
    let mut filesystem = image.mount();
    assert_eq!(filesystem.lookup(ROOT_INODE, b"base"), Ok(base));
    assert_eq!(filesystem.lookup(base, b"bad_dir"), Ok(bad));
    assert_eq!(filesystem.damaged_reference(bad), Some(Damage::Inode));
    let link = filesystem.lookup(base, b"bad_link").unwrap();
    assert_eq!(link, 1);
    assert_eq!(filesystem.damaged_reference(link), Some(Damage::Number));
    assert_eq!(filesystem.damaged_reference(base), None);
}

macro_rules! in_every_format {
    ($($test:ident),* $(,)?) => {
        mod ext2 {
            $(
                #[test]
                fn $test() {
                    super::$test(super::Format::Ext2);
                }
            )*
        }
        mod ext4 {
            $(
                #[test]
                fn $test() {
                    super::$test(super::Format::Ext4);
                }
            )*
        }
    };
}

in_every_format!(
    a_fresh_image_mounts_and_lists,
    file_data_survives_every_level_of_the_block_map,
    debugfs_reads_what_was_written,
    directories_grow_and_shrink,
    links_symlinks_and_devices,
    renames_move_names_and_directories,
    attributes_and_extended_attributes,
    a_full_disk_writes_short_then_fails,
    files_mke2fs_made_read_back,
    damaged_references_are_found
);

#[test]
fn ext4_images_have_the_features_mke2fs_gives_ext4() {
    let Some(image) = Image::new("features", Format::Ext4, 16, &[]) else {
        return;
    };
    let features = image.debugfs("features");
    for feature in ["extent", "64bit", "flex_bg", "metadata_csum", "has_journal"] {
        assert!(features.contains(feature), "{features}");
    }
}

#[test]
fn mount_types_take_the_features_linux_does() {
    let Some(ext4) = Image::new("types", Format::Ext4, 16, &[]) else {
        return;
    };
    for fs_type in [FsType::Ext2, FsType::Ext3] {
        assert_eq!(ext4.mount_as(fs_type, false).err(), Some(Error::Invalid));
        assert_eq!(ext4.mount_as(fs_type, true).err(), Some(Error::Invalid));
    }
    let Some(ext2) = Image::new("types", Format::Ext2, 16, &[]) else {
        return;
    };
    // ext3 needs a journal; the ext4 driver takes an ext2 filesystem.
    assert_eq!(
        ext2.mount_as(FsType::Ext3, false).err(),
        Some(Error::Invalid)
    );
    let filesystem = ext2.mount_as(FsType::Ext4, false).unwrap();
    ext2.store(filesystem);
    let mke2fs = tool("mke2fs").unwrap();
    let status = Command::new(mke2fs)
        .args(["-q", "-F", "-t", "ext3"])
        .arg(&ext2.path)
        .status()
        .unwrap();
    assert!(status.success());
    for fs_type in [FsType::Ext2, FsType::Ext3, FsType::Ext4] {
        let mut filesystem = ext2.mount_as(fs_type, false).unwrap();
        create_file(&mut filesystem, ROOT_INODE, &format!("{fs_type:?}"));
        ext2.store(filesystem);
    }
}

#[test]
fn fragmented_files_grow_deep_extent_trees() {
    // 1 KiB blocks: a tree block holds 84 extents, so 400 runs need two
    // levels below the inode.
    let Some(image) = Image::new("fragments", Format::Ext4, 32, &["-b", "1024"]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "fragments");
    for index in (0..800_u64).step_by(2) {
        let data = pattern(index * 1024, 1024);
        filesystem.write(file, index * 1024, &data).unwrap();
    }
    assert_eq!(filesystem.extents(file, 0, u64::MAX).unwrap().len(), 400);
    image.store(filesystem);
    let listing = image.debugfs("stat /fragments");
    assert!(listing.contains("EXTENTS"), "{listing}");

    // Filling the holes (elsewhere on the disk) and reading it all back.
    let mut filesystem = image.mount();
    for index in (1..800_u64).step_by(2) {
        let data = pattern(index * 1024, 1024);
        filesystem.write(file, index * 1024, &data).unwrap();
    }
    let mut buffer = vec![0; 800 * 1024];
    assert_eq!(filesystem.read(file, 0, &mut buffer).unwrap(), buffer.len());
    assert_eq!(buffer, pattern(0, 800 * 1024));
    image.store(filesystem);

    // Shrinking it a run at a time frees the tree as it goes.
    let mut filesystem = image.mount();
    let free = filesystem.statfs().free_blocks;
    for size in [700_u64, 333, 5, 0] {
        filesystem.truncate(file, size * 1024 + 10).unwrap();
        image.store(filesystem);
        filesystem = image.mount();
    }
    filesystem.truncate(file, 0).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().blocks, 0);
    assert!(filesystem.statfs().free_blocks > free);
    image.store(filesystem);
}

#[test]
fn preallocated_blocks_read_as_zeros_until_written() {
    let Some(image) = Image::new("fallocate", Format::Ext4, 32, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    filesystem.write(file, 0, &[1; 100]).unwrap();
    filesystem.allocate(file, 0, 1 << 20, false).unwrap();
    let stat = filesystem.stat(file).unwrap();
    assert_eq!(stat.size, 1 << 20);
    assert_eq!(stat.blocks, (1 << 20) / 512);
    let mut buffer = vec![9; 8192];
    filesystem.read(file, 4096, &mut buffer).unwrap();
    assert!(buffer.iter().all(|byte| *byte == 0));
    // Past the size with KEEP_SIZE: allocated, the size stays.
    filesystem.allocate(file, 1 << 20, 1 << 20, true).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().size, 1 << 20);
    assert_eq!(filesystem.stat(file).unwrap().blocks, (2 << 20) / 512);
    // A write in the middle of an unwritten block zeroes the rest of it.
    filesystem.write(file, 10_000, b"middle").unwrap();
    let mut block = vec![9; 4096];
    filesystem.read(file, 8192, &mut block).unwrap();
    assert_eq!(&block[10_000 - 8192..10_006 - 8192], b"middle");
    assert_eq!(block.iter().filter(|byte| **byte != 0).count(), 6);
    image.store(filesystem);
    let listing = image.debugfs("stat /file");
    assert!(listing.contains("[u]"), "{listing}");

    // Punching frees the whole blocks and zeroes the edges.
    let mut filesystem = image.mount();
    filesystem.write(file, 0, &pattern(0, 1 << 20)).unwrap();
    let before = filesystem.stat(file).unwrap().blocks;
    filesystem.punch_hole(file, 1000, 3 * 4096).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().blocks, before - 2 * 8);
    let mut buffer = vec![9; 5 * 4096];
    filesystem.read(file, 0, &mut buffer).unwrap();
    let mut expected = pattern(0, 5 * 4096);
    expected[1000..1000 + 3 * 4096].fill(0);
    assert_eq!(buffer, expected);
    // Truncating drops what was preallocated past the end.
    filesystem.truncate(file, 4096).unwrap();
    assert_eq!(filesystem.stat(file).unwrap().blocks, 8);
    image.store(filesystem);
}

/// What LTP's fallocate04 does: punch, zero, collapse and insert ranges of
/// a file of lettered blocks, checking the data and the space after each.
#[test]
fn ranges_punch_zero_collapse_and_insert() {
    for block_size in [1024_u64, 4096] {
        let size = block_size.to_string();
        let Some(image) = Image::new(
            &format!("ranges-{block_size}"),
            Format::Ext4,
            32,
            &["-b", &size],
        ) else {
            return;
        };
        let mut filesystem = image.mount();
        let file = create_file(&mut filesystem, ROOT_INODE, "file");
        let blocks = 16_u64;
        let length = blocks * block_size;
        let mut expected: Vec<u8> = (0..blocks)
            .flat_map(|index| vec![b'a' + index as u8; block_size as usize])
            .collect();
        filesystem.allocate(file, 0, length, false).unwrap();
        filesystem.write(file, 0, &expected).unwrap();
        let used =
            |filesystem: &mut Filesystem<Memory>| filesystem.stat(file).unwrap().blocks * 512;
        let check = |filesystem: &mut Filesystem<Memory>, expected: &[u8]| {
            let mut buffer = vec![0; expected.len()];
            filesystem.read(file, 0, &mut buffer).unwrap();
            assert_eq!(buffer, expected);
        };

        let before = used(&mut filesystem);
        filesystem.punch_hole(file, block_size, block_size).unwrap();
        assert_eq!(filesystem.seek(file, 0, false).unwrap(), Some(block_size));
        assert_eq!(
            filesystem.seek(file, block_size, true).unwrap(),
            Some(2 * block_size)
        );
        assert_eq!(used(&mut filesystem), before - block_size);
        expected[block_size as usize..2 * block_size as usize].fill(0);
        check(&mut filesystem, &expected);

        let before = used(&mut filesystem);
        filesystem
            .zero_range(file, block_size - 1, block_size + 2, false)
            .unwrap();
        assert_eq!(used(&mut filesystem), before + block_size);
        expected[block_size as usize - 1..2 * block_size as usize + 1].fill(0);
        check(&mut filesystem, &expected);

        let before = used(&mut filesystem);
        filesystem
            .collapse_range(file, block_size, block_size)
            .unwrap();
        assert_eq!(used(&mut filesystem), before - block_size);
        expected.drain(block_size as usize..2 * block_size as usize);
        check(&mut filesystem, &expected);
        assert_eq!(filesystem.stat(file).unwrap().size, length - block_size);

        filesystem
            .insert_range(file, block_size, block_size)
            .unwrap();
        filesystem
            .zero_range(file, block_size, block_size, false)
            .unwrap();
        let zeros = vec![0; block_size as usize];
        expected.splice(block_size as usize..block_size as usize, zeros);
        check(&mut filesystem, &expected);
        assert_eq!(filesystem.stat(file).unwrap().size, length);
        assert_eq!(
            filesystem.collapse_range(file, 0, length),
            Err(Error::Invalid)
        );
        assert_eq!(
            filesystem.insert_range(file, 1, block_size),
            Err(Error::Invalid)
        );
        assert_eq!(filesystem.seek(file, length, true).unwrap(), None);
        assert_eq!(filesystem.seek(file, 0, true).unwrap(), Some(0));
        image.store(filesystem);
    }
}

#[test]
fn indexed_directories_change_as_linear_ones() {
    let directory = std::env::temp_dir().join(format!("ginux-ext4-index-{}", std::process::id()));
    std::fs::create_dir_all(directory.join("big")).unwrap();
    for index in 0..400 {
        std::fs::write(
            directory.join(format!("big/entry-with-a-long-name-{index:04}")),
            b"x",
        )
        .unwrap();
    }
    let source = directory.to_string_lossy().into_owned();
    for format in [Format::Ext2, Format::Ext4] {
        let Some(image) = Image::new("indexed", format, 16, &["-b", "1024", "-d", &source]) else {
            return;
        };
        // e2fsck -D indexes every directory of more than a block.
        let status = Command::new(tool("e2fsck").unwrap())
            .args(["-fyD"])
            .arg(&image.path)
            .output()
            .unwrap()
            .status;
        assert!(
            status.code().is_some_and(|code| code <= 1),
            "e2fsck -D: {status}"
        );
        assert!(image.debugfs("htree /big").contains("Root node dump"));
        let mut filesystem = image.mount();
        let big = filesystem.lookup(ROOT_INODE, b"big").unwrap();
        assert_eq!(names(&mut filesystem, big).len(), 402);
        for index in (0..400).step_by(3) {
            let name = format!("entry-with-a-long-name-{index:04}");
            let inode = filesystem.unlink(big, name.as_bytes(), NOW).unwrap();
            assert!(filesystem.release(inode, NOW).unwrap());
        }
        create_file(&mut filesystem, big, "new");
        assert_eq!(names(&mut filesystem, big).len(), 402 - 134 + 1);
        image.store(filesystem);
    }
    let _ = std::fs::remove_dir_all(directory);
}

/// What LTP's fallocate05 and fallocate06 do on a full filesystem: writes
/// into preallocated blocks need no space, and punching frees some.
#[test]
fn preallocated_blocks_take_writes_on_a_full_disk() {
    for block_size in [1024_u64, 4096] {
        let size = block_size.to_string();
        let Some(image) = Image::new(
            &format!("full-prealloc-{block_size}"),
            Format::Ext4,
            16,
            &["-b", &size],
        ) else {
            return;
        };
        let mut filesystem = image.mount();
        let file = create_file(&mut filesystem, ROOT_INODE, "file");
        let written = 16 * block_size;
        filesystem
            .write(file, 0, &pattern(0, written as usize))
            .unwrap();
        // Misaligned, as fallocate06 has it.
        let offset = written + block_size / 2;
        let length = 256 * block_size;
        filesystem.allocate(file, offset, length, false).unwrap();
        // Fill the disk.
        let filler = create_file(&mut filesystem, ROOT_INODE, "filler");
        let chunk = vec![7; 1 << 20];
        let mut at = 0;
        loop {
            match filesystem.write(filler, at, &chunk) {
                Ok(count) if count == chunk.len() => at += count as u64,
                Ok(count) => {
                    at += count as u64;
                }
                Err(error) => {
                    assert_eq!(error, Error::NoSpace);
                    break;
                }
            }
        }
        let data = pattern(offset, length as usize);
        assert_eq!(filesystem.write(file, offset, &data).unwrap(), data.len());
        // Preallocate past the end until the disk is full.
        let mut extra = 0;
        while filesystem
            .allocate(file, offset + length + extra, block_size, false)
            .is_ok()
        {
            extra += block_size;
        }
        let end = offset + length + extra;
        if extra > 0 {
            let more = pattern(offset + length, extra as usize);
            assert_eq!(
                filesystem.write(file, offset + length, &more).unwrap(),
                more.len()
            );
        }
        let hole = 8 * block_size;
        filesystem.punch_hole(file, 0, hole).unwrap();
        assert_eq!(filesystem.write(file, end, b"0123456789").unwrap(), 10);
        assert_eq!(filesystem.seek(file, 0, false).unwrap(), Some(0));
        assert_eq!(filesystem.seek(file, 0, true).unwrap(), Some(hole));
        let mut back = vec![0; data.len()];
        filesystem.read(file, offset, &mut back).unwrap();
        assert_eq!(back, data);
        image.store(filesystem);
    }
}

/// ext4's quota feature: usage kept in the hidden quota inodes through
/// writes, chown and deletion (e2fsck checks it against the files), limits
/// that persist, and EDQUOT past a hard limit once enforced.
#[test]
fn system_quota_files_count_and_enforce() {
    let Some(image) = Image::new(
        "quota",
        Format::Ext4,
        32,
        &["-O", "quota,project", "-I", "256"],
    ) else {
        return;
    };
    let mut filesystem = image.mount();
    assert!(filesystem.quota_system_files());
    let user = 1000;
    let file = create_file(&mut filesystem, ROOT_INODE, "owned");
    filesystem.write(file, 0, &vec![1; 100_000]).unwrap();
    let directory = filesystem
        .create(
            ROOT_INODE,
            b"dir",
            Kind::Directory,
            0o755,
            user,
            100,
            0,
            NOW,
        )
        .unwrap();
    let inner = create_file(&mut filesystem, directory, "inner");
    filesystem.write(inner, 0, &vec![2; 5000]).unwrap();
    let usage = filesystem.get_quota(QuotaKind::User, user).unwrap();
    assert_eq!(usage.inodes, 3);
    assert!(usage.space >= 100_000 + 5000);
    // Ids get entries in the tree as they appear (new tree and data
    // blocks), and e2fsck finds them right.
    for id in [2000_u32, 70_000, 0x0102_0304] {
        let name = format!("file-{id}");
        let number = create_file(&mut filesystem, ROOT_INODE, &name);
        filesystem
            .change(
                number,
                &Change {
                    owner: Some(id),
                    ..Change::default()
                },
            )
            .unwrap();
        filesystem.write(number, 0, b"data").unwrap();
    }
    filesystem
        .set_quota(
            QuotaKind::User,
            user,
            &DquotChange {
                space_soft: Some(100 << 10),
                ..DquotChange::default()
            },
        )
        .unwrap();
    filesystem
        .set_quota_info(QuotaKind::User, Some(80), None)
        .unwrap();
    image.store(filesystem);

    let mut filesystem = image.mount();
    assert_eq!(
        filesystem
            .get_quota(QuotaKind::User, user)
            .unwrap()
            .space_soft,
        100 << 10
    );
    assert_eq!(
        filesystem.quota_info(QuotaKind::User).unwrap().space_grace,
        80
    );
    assert_eq!(filesystem.next_quota_id(QuotaKind::User, 1).unwrap(), 1000);
    assert_eq!(
        filesystem.next_quota_id(QuotaKind::User, 70_001).unwrap(),
        0x0102_0304
    );
    assert_eq!(
        filesystem.next_quota_id(QuotaKind::User, 0x0102_0305),
        Err(Error::NoQuota)
    );
    // Deleting gives the usage back.
    let gone = filesystem.unlink(directory, b"inner", NOW).unwrap();
    assert!(filesystem.release(gone, NOW).unwrap());
    assert_eq!(
        filesystem.get_quota(QuotaKind::User, user).unwrap().inodes,
        2
    );
    // Enforced: a write past the hard limit stops short, then EDQUOT.
    filesystem
        .set_quota(
            QuotaKind::User,
            user,
            &DquotChange {
                space_hard: Some(160 << 10),
                ..DquotChange::default()
            },
        )
        .unwrap();
    assert_eq!(filesystem.quota_enable(QuotaKind::User), Ok(()));
    assert_eq!(filesystem.quota_enable(QuotaKind::User), Err(Error::Exists));
    filesystem.set_caller(NOW, false);
    let written = filesystem.write(file, 100_000, &vec![3; 200_000]).unwrap();
    assert!(written < 200_000, "{written}");
    assert_eq!(
        filesystem.write(file, 100_000 + written as u64, &vec![3; 8192]),
        Err(Error::QuotaExceeded)
    );
    // Root may go past it.
    filesystem.set_caller(NOW, true);
    filesystem.write(file, 400_000, &vec![4; 8192]).unwrap();
    assert_eq!(filesystem.quota_disable(QuotaKind::User), Ok(()));
    assert_eq!(
        filesystem.quota_disable(QuotaKind::User),
        Err(Error::Exists)
    );
    image.store(filesystem);
}

/// A quota file quotaon(2) names (what quotacheck makes): an empty vfsv1
/// file of the format turns on, takes limits, and keeps them.
#[test]
fn quota_files_turn_on_and_keep_limits() {
    let Some(image) = Image::new("quotafile", Format::Ext4, 16, &[]) else {
        return;
    };
    let quota = QuotaOptions {
        user: true,
        ..QuotaOptions::default()
    };
    let mut filesystem = image.mount_with(FsType::Ext4, false, quota).unwrap();
    let file = create_file(&mut filesystem, ROOT_INODE, "aquota.user");
    // Header (magic, version 1), information (grace times, two blocks),
    // and an empty tree root.
    let mut contents = vec![0_u8; 2048];
    contents[0..4].copy_from_slice(&0xd9c0_1f11_u32.to_le_bytes());
    contents[4..8].copy_from_slice(&1_u32.to_le_bytes());
    contents[8..12].copy_from_slice(&604_800_u32.to_le_bytes());
    contents[12..16].copy_from_slice(&604_800_u32.to_le_bytes());
    contents[20..24].copy_from_slice(&2_u32.to_le_bytes());
    filesystem.write(file, 0, &contents).unwrap();
    assert_eq!(
        filesystem.get_quota(QuotaKind::User, 0),
        Err(Error::NoQuota)
    );
    assert_eq!(
        filesystem.quota_on(QuotaKind::User, file, 999),
        Err(Error::NoQuota)
    );
    assert_eq!(
        filesystem.quota_on(QuotaKind::User, ROOT_INODE, 4),
        Err(Error::Access)
    );
    assert_eq!(
        filesystem.quota_on(QuotaKind::User, file, 2),
        Err(Error::Invalid)
    );
    filesystem.quota_on(QuotaKind::User, file, 4).unwrap();
    assert_eq!(
        filesystem.quota_on(QuotaKind::User, file, 4),
        Err(Error::Busy)
    );
    assert_eq!(
        filesystem.quota_info(QuotaKind::User).unwrap().space_grace,
        604_800
    );
    let range = DquotChange {
        space_soft: Some(u64::MAX),
        ..DquotChange::default()
    };
    assert_eq!(
        filesystem.set_quota(QuotaKind::User, 5, &range),
        Err(Error::Range)
    );
    for id in [0_u32, 5, 300, 70_000] {
        filesystem
            .set_quota(
                QuotaKind::User,
                id,
                &DquotChange {
                    space_soft: Some(u64::from(id + 1) << 10),
                    inode_hard: Some(u64::from(id) + 7),
                    ..DquotChange::default()
                },
            )
            .unwrap();
    }
    filesystem.quota_off(QuotaKind::User, NOW).unwrap();
    filesystem.quota_on(QuotaKind::User, file, 4).unwrap();
    for id in [0_u32, 5, 300, 70_000] {
        let dquot = filesystem.get_quota(QuotaKind::User, id).unwrap();
        assert_eq!(dquot.space_soft, u64::from(id + 1) << 10);
        assert_eq!(dquot.inode_hard, u64::from(id) + 7);
    }
    assert_eq!(filesystem.next_quota_id(QuotaKind::User, 6).unwrap(), 300);
    filesystem.quota_off(QuotaKind::User, NOW).unwrap();
    image.store(filesystem);
}

// ---- metadata checksums ----
//
// Each test damages one kind of metadata of an ext4 image (metadata_csum
// on, as mke2fs -t ext4 makes it) by flipping bits where it lies, then
// checks the error the driver gives, what it records, and that e2fsck
// finds the damage too.

impl Image {
    fn mount_options(&self, options: Options) -> Result<Filesystem<Memory>> {
        let bytes = std::fs::read(&self.path).unwrap();
        Filesystem::mount(Memory(bytes), options)
    }

    fn mount_errors(&self, errors: Option<ErrorPolicy>) -> Filesystem<Memory> {
        self.mount_options(Options {
            read_only: false,
            now: NOW,
            fs_type: FsType::Ext4,
            quota: QuotaOptions::default(),
            errors,
        })
        .unwrap()
    }

    /// Unmounts `filesystem` into the image, unchecked.
    fn save(&self, filesystem: Filesystem<Memory>) {
        let device = filesystem.unmount(NOW).unwrap();
        std::fs::write(&self.path, device.0).unwrap();
    }

    /// Flips the bits of `mask` in the image's byte `offset`.
    fn flip(&self, offset: u64, mask: u8) {
        let mut bytes = std::fs::read(&self.path).unwrap();
        bytes[offset as usize] ^= mask;
        std::fs::write(&self.path, bytes).unwrap();
    }

    /// The number `debugfs -R request` prints after `key` (hexadecimal
    /// after "0x").
    fn number_after(&self, request: &str, key: &str) -> u64 {
        let output = self.debugfs(request);
        let at = output
            .find(key)
            .unwrap_or_else(|| panic!("{key}?\n{output}"))
            + key.len();
        let rest = output[at..].trim_start();
        let (rest, radix) = match rest.strip_prefix("0x") {
            Some(hex) => (hex, 16),
            None => (rest, 10),
        };
        let digits: String = rest.chars().take_while(|c| c.is_digit(radix)).collect();
        u64::from_str_radix(&digits, radix).unwrap()
    }

    fn block_size(&self) -> u64 {
        self.number_after("stats", "Block size:")
    }

    /// The image's byte `offset` of block `block`.
    fn byte_of_block(&self, block: u64, offset: u64) -> u64 {
        block * self.block_size() + offset
    }

    /// Asserts that `e2fsck -fn` finds the image damaged.
    fn assert_damaged(&self) {
        let output = Command::new(tool("e2fsck").unwrap())
            .args(["-fn"])
            .arg(&self.path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "e2fsck found nothing wrong:\n{}",
            String::from_utf8_lossy(&output.stdout)
        );
    }

    /// The superblock's state, error count and last error inode.
    fn error_record(&self) -> (u16, u32, u32) {
        let bytes = std::fs::read(&self.path).unwrap();
        let superblock = &bytes[1024..2048];
        let u32_at = |at: usize| u32::from_le_bytes(superblock[at..at + 4].try_into().unwrap());
        (
            u16::from_le_bytes([superblock[58], superblock[59]]),
            u32_at(0x194),
            u32_at(0x1d0),
        )
    }
}

fn bad_checksum(inode: u32, block: u64) -> Failure {
    Failure {
        inode,
        block,
        error: Error::BadChecksum,
    }
}

/// `filesystem.stat` of `number` fails as Linux's iget does on a bad
/// inode checksum.
fn assert_bad_checksum<T: std::fmt::Debug>(result: Result<T>) {
    let error = result.unwrap_err();
    assert_eq!(error, Error::BadChecksum);
    assert_eq!(error.errno(), 74);
}

#[test]
fn a_superblock_that_fails_its_checksum_is_not_mounted() {
    let Some(image) = Image::new("csum-super", Format::Ext4, 16, &[]) else {
        return;
    };
    // s_wtime: a field nothing else checks.
    image.flip(1024 + 0x30, 0x01);
    assert_eq!(
        image.mount_as(FsType::Ext4, false).err(),
        Some(Error::BadChecksum)
    );
    assert_eq!(
        image.mount_as(FsType::Ext4, true).err(),
        Some(Error::BadChecksum)
    );
    assert_eq!(
        image.mount_as(FsType::Ext3, true).err(),
        Some(Error::BadChecksum)
    );
    image.assert_damaged();
}

#[test]
fn a_bad_group_descriptor_fails_a_writable_mount_only() {
    let Some(image) = Image::new("csum-group", Format::Ext4, 16, &[]) else {
        return;
    };
    // Group 0's free inode count, in the table after the superblock.
    let table = image.byte_of_block(1, 0);
    image.flip(table + 0x0e, 0x01);
    assert_eq!(
        image.mount_as(FsType::Ext4, false).err(),
        Some(Error::Corrupt)
    );
    let mut filesystem = image.mount_as(FsType::Ext4, true).unwrap();
    assert_eq!(
        names(&mut filesystem, ROOT_INODE),
        [".", "..", "lost+found"]
    );
    assert_eq!(
        filesystem.set_read_only(false, NOW),
        Err(Error::BadChecksum)
    );
    assert!(filesystem.read_only());
    drop(filesystem);
    image.assert_damaged();
}

#[test]
fn sound_descriptors_remount_writable_after_changes() {
    // quotacheck's remount: read-only, then writable again, after the
    // descriptors changed.
    let Some(image) = Image::new("csum-remount", Format::Ext4, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    create_file(&mut filesystem, ROOT_INODE, "file");
    filesystem.set_read_only(true, NOW).unwrap();
    filesystem.set_read_only(false, NOW).unwrap();
    create_file(&mut filesystem, ROOT_INODE, "other");
    image.store(filesystem);
    let mut filesystem = image.mount_as(FsType::Ext4, true).unwrap();
    filesystem.set_read_only(false, NOW).unwrap();
    image.store(filesystem);
}

#[test]
fn a_bad_block_bitmap_leaves_its_group_alone() {
    // 1 KiB blocks: two groups, so the allocator has another to go to.
    let Some(image) = Image::new("csum-bbitmap", Format::Ext4, 16, &["-b", "1024"]) else {
        return;
    };
    let bitmap = image.number_after("stats", "block bitmap at ");
    let blocks_per_group = image.number_after("stats", "Blocks per group:");
    // A bit for a block near the end of group 0, free on a fresh image.
    image.flip(image.byte_of_block(bitmap, blocks_per_group / 8 - 2), 0x10);
    let mut filesystem = image.mount();
    let before = filesystem.statfs().free_blocks;
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    let data = pattern(0, 4096);
    assert_eq!(filesystem.write(file, 0, &data).unwrap(), 4096);
    assert_eq!(filesystem.take_failures(), [bad_checksum(0, bitmap)]);
    // The data went to group 1; the damaged group is not read again.
    let extents = filesystem.extents(file, 0, 4096).unwrap();
    assert!(extents[0].physical / 1024 >= blocks_per_group);
    filesystem.write(file, 4096, &data).unwrap();
    assert!(!filesystem.has_failures());
    assert!(filesystem.statfs().free_blocks < before - 8);
    let mut back = vec![0; 4096];
    filesystem.read(file, 0, &mut back).unwrap();
    assert_eq!(back, data);
    image.save(filesystem);
    assert_eq!(image.error_record().0 & 2, 2);
    image.assert_damaged();
}

#[test]
fn a_bad_inode_bitmap_leaves_its_group_alone() {
    let Some(image) = Image::new("csum-ibitmap", Format::Ext4, 16, &["-b", "1024"]) else {
        return;
    };
    let bitmap = image.number_after("stats", "inode bitmap at ");
    let per_group = image.number_after("stats", "Inodes per group:");
    image.flip(image.byte_of_block(bitmap, per_group / 8 - 1), 0x20);
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    assert!(u64::from(file) > per_group, "inode {file} is in group 0");
    assert_eq!(filesystem.take_failures(), [bad_checksum(0, bitmap)]);
    let other = create_file(&mut filesystem, ROOT_INODE, "other");
    assert!(u64::from(other) > per_group);
    assert!(!filesystem.has_failures());
    image.save(filesystem);
    image.assert_damaged();
}

/// A file whose inode is damaged, its number and its inode table block.
fn damaged_inode(name: &str) -> Option<(Image, u32, u64)> {
    let image = Image::new(name, Format::Ext4, 16, &[])?;
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    filesystem.write(file, 0, b"data").unwrap();
    image.store(filesystem);
    let block = image.number_after("imap /file", "located at block ");
    let offset = image.number_after("imap /file", "offset ");
    // i_mtime.
    image.flip(image.byte_of_block(block, offset + 0x10), 0x01);
    Some((image, file, block))
}

#[test]
fn an_inode_that_fails_its_checksum_is_not_read() {
    let Some((image, file, block)) = damaged_inode("csum-inode") else {
        return;
    };
    let mut filesystem = image.mount();
    // The directory is sound: the name is found, the inode is not read.
    assert_eq!(filesystem.lookup(ROOT_INODE, b"file"), Ok(file));
    assert_bad_checksum(filesystem.stat(file));
    assert_bad_checksum(filesystem.read(file, 0, &mut [0; 4]));
    assert_eq!(filesystem.damaged_reference(file), Some(Damage::Checksum));
    assert_eq!(filesystem.take_failures(), [bad_checksum(file, block); 3]);
    // errors=continue (mke2fs's default) goes on.
    assert_eq!(filesystem.error_policy(), ErrorPolicy::Continue);
    create_file(&mut filesystem, ROOT_INODE, "after");
    image.save(filesystem);
    let (state, count, inode) = image.error_record();
    assert_eq!(state, 3, "clean, with errors");
    assert_eq!((count, inode), (3, file));
    image.assert_damaged();
}

#[test]
fn errors_remount_ro_stops_changes() {
    for policy in [ErrorPolicy::ReadOnly, ErrorPolicy::Panic] {
        let Some((image, file, _)) = damaged_inode("csum-policy") else {
            return;
        };
        let mut filesystem = image.mount_errors(Some(policy));
        assert_eq!(filesystem.shown_error_policy(), Some(policy));
        let other = create_file(&mut filesystem, ROOT_INODE, "other");
        assert_bad_checksum(filesystem.stat(file));
        assert!(filesystem.is_shut_down());
        // As Linux 6.12's ext4 shut down: changes and file reads fail.
        let made = filesystem.create(ROOT_INODE, b"x", Kind::File, 0o644, 0, 0, 0, NOW);
        assert_eq!(made, Err(Error::Io));
        assert_eq!(filesystem.write(other, 0, b"x"), Err(Error::Io));
        assert_eq!(filesystem.read(other, 0, &mut [0; 1]), Err(Error::Io));
        assert_eq!(
            filesystem.set_xattr(other, b"user.a", b"b", XattrMode::Any),
            Err(Error::Io)
        );
        assert!(filesystem.stat(other).is_ok());
        assert_eq!(filesystem.set_read_only(true, NOW), Err(Error::ReadOnly));
        image.save(filesystem);
        assert_eq!(image.error_record().0 & 2, 2);
    }
}

#[test]
fn the_superblock_names_the_default_error_policy() {
    let Some(image) = Image::new("csum-default", Format::Ext4, 16, &[]) else {
        return;
    };
    let filesystem = image.mount_errors(None);
    assert_eq!(filesystem.error_policy(), ErrorPolicy::Continue);
    assert_eq!(filesystem.shown_error_policy(), None);
    image.store(filesystem);
    let status = Command::new(tool("tune2fs").unwrap())
        .args(["-e", "remount-ro"])
        .arg(&image.path)
        .output()
        .unwrap()
        .status;
    assert!(status.success());
    let filesystem = image.mount_errors(None);
    assert_eq!(filesystem.error_policy(), ErrorPolicy::ReadOnly);
    assert_eq!(filesystem.shown_error_policy(), None);
    image.store(filesystem);
    let filesystem = image.mount_errors(Some(ErrorPolicy::Continue));
    assert_eq!(filesystem.shown_error_policy(), Some(ErrorPolicy::Continue));
    image.store(filesystem);
}

#[test]
fn ext2_shows_and_applies_its_error_policy() {
    let Some(image) = Image::new("csum-ext2", Format::Ext2, 16, &[]) else {
        return;
    };
    let options = |errors| Options {
        read_only: false,
        now: NOW,
        fs_type: FsType::Ext2,
        quota: QuotaOptions::default(),
        errors,
    };
    // Linux's ext2 shows errors=continue though the superblock says it.
    let filesystem = image.mount_options(options(None)).unwrap();
    assert_eq!(filesystem.shown_error_policy(), Some(ErrorPolicy::Continue));
    image.store(filesystem);
    let mut filesystem = image
        .mount_options(options(Some(ErrorPolicy::ReadOnly)))
        .unwrap();
    assert_eq!(filesystem.shown_error_policy(), Some(ErrorPolicy::ReadOnly));
    assert_eq!(
        filesystem.report(ROOT_INODE, 0, Error::Corrupt),
        Error::Corrupt
    );
    // ext2 becomes read-only rather than shutting down.
    assert!(filesystem.read_only() && !filesystem.is_shut_down());
    let made = filesystem.create(ROOT_INODE, b"x", Kind::File, 0o644, 0, 0, 0, NOW);
    assert_eq!(made, Err(Error::ReadOnly));
    image.save(filesystem);
    assert_eq!(image.error_record().0 & 2, 2);
}

#[test]
fn a_bad_extent_block_fails_the_read() {
    let Some(image) = Image::new("csum-extent", Format::Ext4, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    // Six runs with holes between: more than the inode's root holds.
    for index in (0..12_u64).step_by(2) {
        filesystem
            .write(file, index * 4096, &pattern(index, 4096))
            .unwrap();
    }
    image.store(filesystem);
    let tree = image.number_after("stat /file", "(ETB0):");
    // The first entry's first file block.
    image.flip(image.byte_of_block(tree, 12), 0x01);
    let mut filesystem = image.mount();
    assert!(filesystem.stat(file).is_ok());
    assert_bad_checksum(filesystem.read(file, 0, &mut [0; 16]));
    assert_bad_checksum(filesystem.extents(file, 0, u64::MAX));
    assert_eq!(filesystem.take_failures()[0], bad_checksum(file, tree));
    image.save(filesystem);
    image.assert_damaged();
}

/// A directory of two blocks or more: the names, in the order made.
fn fill_directory(filesystem: &mut Filesystem<Memory>, directory: u32) -> Vec<String> {
    let names: Vec<String> = (0..60)
        .map(|index| format!("{index:03}{}", "n".repeat(150)))
        .collect();
    for name in &names {
        create_file(filesystem, directory, name);
    }
    names
}

#[test]
fn a_bad_directory_block_fails_lookups_and_readdir_passes_it() {
    let Some(image) = Image::new("csum-dir", Format::Ext4, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let directory = filesystem
        .create(ROOT_INODE, b"dir", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let names = fill_directory(&mut filesystem, directory);
    image.store(filesystem);
    let blocks = image.debugfs("blocks /dir");
    let blocks: Vec<u64> = blocks
        .split_whitespace()
        .map(|b| b.parse().unwrap())
        .collect();
    assert!(blocks.len() >= 3, "{blocks:?}");
    // The first name of the second block.
    image.flip(image.byte_of_block(blocks[1], 8), 0x01);
    let mut filesystem = image.mount();
    assert!(filesystem.lookup(directory, names[0].as_bytes()).is_ok());
    assert_bad_checksum(filesystem.lookup(directory, names[59].as_bytes()));
    assert_eq!(
        filesystem.take_failures(),
        [bad_checksum(directory, blocks[1])]
    );
    // readdir lists the other blocks, passing over the damaged one.
    let listed = names_of(&mut filesystem, directory);
    assert!(listed.contains(&names[0]) && listed.contains(&names[59]));
    assert!(listed.len() < names.len() + 2);
    assert_eq!(
        filesystem.take_failures(),
        [bad_checksum(directory, blocks[1])]
    );
    assert_bad_checksum(filesystem.create(directory, b"new", Kind::File, 0o644, 0, 0, 0, NOW));
    image.save(filesystem);
    image.assert_damaged();
}

fn names_of(filesystem: &mut Filesystem<Memory>, directory: u32) -> Vec<String> {
    let mut names = Vec::new();
    let mut offset = 0;
    while let Some((entry, next)) = filesystem.read_dir(directory, offset).unwrap() {
        names.push(String::from_utf8_lossy(entry.name()).into_owned());
        offset = next;
    }
    names
}

#[test]
fn hash_indexed_directories_are_checked_by_their_index() {
    let Some(image) = Image::new("csum-htree", Format::Ext4, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let directory = filesystem
        .create(ROOT_INODE, b"dir", Kind::Directory, 0o755, 0, 0, 0, NOW)
        .unwrap();
    let names = fill_directory(&mut filesystem, directory);
    image.store(filesystem);
    // e2fsck -D indexes the directory, with the index's checksums.
    let status = Command::new(tool("e2fsck").unwrap())
        .args(["-fyD"])
        .arg(&image.path)
        .output()
        .unwrap()
        .status;
    assert!(status.code().is_some_and(|code| code <= 1));
    let flags = image.number_after("stat /dir", "Flags: ");
    assert_ne!(flags & 0x1000, 0, "not indexed");
    let mut filesystem = image.mount();
    for name in &names {
        assert!(filesystem.lookup(directory, name.as_bytes()).is_ok());
    }
    assert_eq!(names_of(&mut filesystem, directory).len(), names.len() + 2);
    assert!(!filesystem.has_failures());
    drop(filesystem);
    // The root's first index entry.
    let root = image
        .debugfs("blocks /dir")
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    image.flip(image.byte_of_block(root, 0x28), 0x01);
    let mut filesystem = image.mount();
    assert_bad_checksum(filesystem.lookup(directory, names[0].as_bytes()));
    assert_bad_checksum(filesystem.read_dir(directory, 0).map(|_| ()));
    assert_eq!(filesystem.take_failures()[0], bad_checksum(directory, root));
    image.save(filesystem);
    image.assert_damaged();
}

#[test]
fn a_bad_attribute_block_fails_the_attribute_calls() {
    let Some(image) = Image::new("csum-xattr", Format::Ext4, 16, &[]) else {
        return;
    };
    let mut filesystem = image.mount();
    let file = create_file(&mut filesystem, ROOT_INODE, "file");
    filesystem
        .set_xattr(file, b"user.name", &[7; 100], XattrMode::Any)
        .unwrap();
    image.store(filesystem);
    let block = image.number_after("stat /file", "File ACL: ");
    // The value, at the end of the block.
    image.flip(image.byte_of_block(block, image.block_size() - 50), 0x01);
    let mut filesystem = image.mount();
    assert_bad_checksum(filesystem.get_xattr(file, b"user.name"));
    assert_bad_checksum(filesystem.list_xattrs(file));
    assert_eq!(filesystem.take_failures()[0], bad_checksum(file, block));
    image.save(filesystem);
    image.assert_damaged();
}
