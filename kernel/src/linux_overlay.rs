use crate::{
    arch::x86_64::cpu,
    control_abi,
    memory::{self, FrameLease, FrameOwner},
};
use alloc::collections::BTreeMap;
use core::cell::UnsafeCell;

const PAGE_SIZE: usize = 4096;
pub(crate) const PATH_CAPACITY: usize = 256;
const NODE_COUNT: usize = 9;
const MAPPING_COUNT: usize = 100;
const DATA_CAPACITY: usize = PAGE_SIZE - core::mem::size_of::<FrameLease>();
const FRAME_INDEX_CAPACITY: usize = PAGE_SIZE / core::mem::size_of::<FrameLease>() - 1;
const XATTR_NAME_CAPACITY: usize = 255;
const HOST_INSTANCE: usize = control_abi::DOMAIN_LIMIT;
const INSTANCE_LIMIT: usize = control_abi::DOMAIN_LIMIT + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NodeKind {
    File,
    Directory,
    Symlink,
    Fifo,
    /// A UNIX socket's name in the filesystem (bind(2) on a pathname).
    Socket,
    /// A device file (mknod S_IFCHR or S_IFBLK); `Metadata::device` says
    /// which device.
    CharacterDevice,
    BlockDevice,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Handle {
    generation: u32,
    inode: u64,
}

impl Handle {
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Metadata {
    pub(crate) handle: Handle,
    pub(crate) kind: NodeKind,
    pub(crate) mode: u32,
    pub(crate) owner: u32,
    pub(crate) group: u32,
    /// How many names the file has (its hard links).
    pub(crate) links: u32,
    /// A device file's device number, as mknod(2) and stat(2) encode it.
    pub(crate) device: u32,
    /// FS_*_FL attributes (see [`set_attributes`]).
    pub(crate) attributes: u32,
    pub(crate) size: usize,
    pub(crate) atime: (i64, i64),
    pub(crate) mtime: (i64, i64),
    pub(crate) ctime: (i64, i64),
}

pub(crate) struct Child {
    pub(crate) next_cursor: usize,
    pub(crate) metadata: Metadata,
    name_length: usize,
    name: [u8; PATH_CAPACITY],
}

impl Child {
    pub(crate) fn name(&self) -> &[u8] {
        &self.name[..self.name_length]
    }
}

#[repr(C)]
struct DataPage {
    next: FrameLease,
    bytes: [u8; DATA_CAPACITY],
}

// memfd contents are kept one file page per frame, listed in a chain of
// index pages that starts at the node's first_page, so MAP_SHARED can map
// the frames themselves into every process instead of copying them in at
// mmap time.
#[repr(C)]
struct FrameIndexPage {
    next: FrameLease,
    frames: [FrameLease; FRAME_INDEX_CAPACITY],
}

#[repr(C)]
struct XattrPage {
    previous: FrameLease,
    value_first: FrameLease,
    value_size: u32,
    name_length: u16,
    removed: bool,
    name: [u8; XATTR_NAME_CAPACITY],
}

#[derive(Clone, Copy)]
struct SharedMapping {
    active: bool,
    pid: u32,
    address: u64,
    handle: Handle,
    offset: usize,
}

impl SharedMapping {
    const EMPTY: Self = Self {
        active: false,
        pid: 0,
        address: 0,
        handle: Handle {
            generation: 0,
            inode: 0,
        },
        offset: 0,
    };
}

#[repr(C)]
struct MappingPage {
    next: FrameLease,
    mappings: [SharedMapping; MAPPING_COUNT],
}

/// How a file holds its data.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Data {
    /// A chain of data pages.
    Chain,
    /// Whole frames indexed by page (`first_page` roots the index), which
    /// shared mappings map directly: a file becomes paged when it is first
    /// mapped shared.
    Paged,
    /// A memfd, always paged.
    Memfd,
    /// Anonymous shared memory (MAP_SHARED | MAP_ANONYMOUS), paged and
    /// unnamed, as Linux backs it with a shmem file. Each process mapping
    /// it registers its pages, and it is freed once none maps it.
    Shmem,
}

/// Where a file came from, which decides its link count once it has no
/// name and whether it may be given one.
#[derive(Clone, Copy, Eq, PartialEq)]
enum Origin {
    /// Created by name: once unlinked (deleted while open) it has no links.
    Named,
    /// A memfd, secret memory or anonymous shared memory: a file of an
    /// internal filesystem with one link, which no directory can name
    /// (EXDEV).
    Pseudo,
    /// An O_TMPFILE file: no links until linkat(2) names it, which O_EXCL
    /// forbids (`linkable` false).
    Temporary { linkable: bool },
}

#[derive(Clone, Copy)]
struct Node {
    active: bool,
    linked: bool,
    whiteout: bool,
    origin: Origin,
    data: Data,
    kind: NodeKind,
    path_length: u16,
    mode: u32,
    owner: u32,
    group: u32,
    /// A hard link: this node is only a name for the file `alias_of`
    /// holds, and has no data of its own.
    alias_of: Option<Handle>,
    /// How many names the file has: this node's and its aliases'.
    links: u16,
    /// A device file's device number.
    device: u32,
    /// A memfd's seals (F_SEAL_*, which all fit a byte).
    seals: u8,
    /// The file's attributes (FS_IOC_GETFLAGS: FS_IMMUTABLE_FL,
    /// FS_APPEND_FL, FS_NODUMP_FL and FS_NOATIME_FL, which fit a byte).
    attributes: u8,
    /// The pipe socket behind a FIFO, plus one; 0 before one opens it.
    fifo_socket: u16,
    handle: Handle,
    size: usize,
    first_page: FrameLease,
    last_page: FrameLease,
    page_count: usize,
    cached_page: FrameLease,
    cached_page_index: usize,
    xattr_first: FrameLease,
    atime: (i64, i64),
    mtime: (i64, i64),
    ctime: (i64, i64),
    path: [u8; PATH_CAPACITY],
}

impl Node {
    fn paged(&self) -> bool {
        self.data != Data::Chain
    }

    const EMPTY: Self = Self {
        active: false,
        linked: false,
        whiteout: false,
        origin: Origin::Named,
        data: Data::Chain,
        kind: NodeKind::File,
        path_length: 0,
        mode: 0,
        owner: 0,
        group: 0,
        alias_of: None,
        links: 0,
        device: 0,
        seals: 0,
        attributes: 0,
        fifo_socket: 0,
        handle: Handle {
            generation: 0,
            inode: 0,
        },
        size: 0,
        first_page: FrameLease::EMPTY,
        last_page: FrameLease::EMPTY,
        page_count: 0,
        cached_page: FrameLease::EMPTY,
        cached_page_index: 0,
        xattr_first: FrameLease::EMPTY,
        atime: (0, 0),
        mtime: (0, 0),
        ctime: (0, 0),
        path: [0; PATH_CAPACITY],
    };

    fn path(&self) -> &[u8] {
        &self.path[..usize::from(self.path_length)]
    }

    fn metadata(&self) -> Metadata {
        Metadata {
            handle: self.handle,
            kind: self.kind,
            mode: self.mode,
            owner: self.owner,
            group: self.group,
            // Linux counts the names a file has: none for a deleted or
            // O_TMPFILE file still open, one for a memfd.
            links: if self.linked || self.origin == Origin::Pseudo {
                u32::from(self.links.max(1))
            } else {
                u32::from(self.links.saturating_sub(1))
            },
            device: self.device,
            attributes: u32::from(self.attributes),
            size: self.size,
            atime: self.atime,
            mtime: self.mtime,
            ctime: self.ctime,
        }
    }
}

#[repr(C)]
struct NodePage {
    next: FrameLease,
    nodes: [Node; NODE_COUNT],
}

const _: () = assert!(core::mem::size_of::<DataPage>() == PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<FrameIndexPage>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<XattrPage>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<NodePage>() <= PAGE_SIZE);
const _: () = assert!(core::mem::size_of::<MappingPage>() <= PAGE_SIZE);

#[derive(Clone, Copy)]
struct Overlay {
    first_node_page: FrameLease,
    first_mapping_page: FrameLease,
    next_generation: u32,
    next_inode: u64,
    /// Linked symlinks, so path walks skip looking for them when there are
    /// none.
    symlinks: usize,
}

impl Overlay {
    const EMPTY: Self = Self {
        first_node_page: FrameLease::EMPTY,
        first_mapping_page: FrameLease::EMPTY,
        next_generation: 0x8000_0000,
        next_inode: 0x10_000,
        symlinks: 0,
    };
}

/// The overlay has a symlink a path walk may need to follow.
pub(crate) fn has_symlinks() -> bool {
    live().is_some_and(|overlay| overlay.symlinks != 0)
}

pub(crate) fn register_shared_mapping(
    pid: u32,
    address: u64,
    handle: Handle,
    offset: usize,
) -> bool {
    if pid == 0 || !address.is_multiple_of(PAGE_SIZE as u64) || metadata(handle).is_none() {
        return false;
    }
    let overlay = live_mut();
    let mut page = overlay.first_mapping_page;
    let mut last = FrameLease::EMPTY;
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page_mut(page) else {
            return false;
        };
        if mappings
            .mappings
            .iter()
            .any(|mapping| mapping.active && mapping.pid == pid && mapping.address == address)
        {
            return false;
        }
        if let Some(mapping) = mappings.mappings.iter_mut().find(|mapping| !mapping.active) {
            *mapping = SharedMapping {
                active: true,
                pid,
                address,
                handle,
                offset,
            };
            return true;
        }
        last = page;
        page = mappings.next;
    }
    let Some(page) = allocate_mapping_page() else {
        return false;
    };
    if last == FrameLease::EMPTY {
        overlay.first_mapping_page = page;
    } else {
        let Some(previous) = mapping_page_mut(last) else {
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
            return false;
        };
        previous.next = page;
    }
    let Some(mapping) = mapping_page_mut(page).and_then(|page| page.mappings.first_mut()) else {
        return false;
    };
    *mapping = SharedMapping {
        active: true,
        pid,
        address,
        handle,
        offset,
    };
    true
}

pub(crate) fn shared_mapping(pid: u32, address: u64) -> Option<(Handle, usize)> {
    let overlay = live()?;
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let mappings = mapping_page(page)?;
        if let Some(mapping) = mappings
            .mappings
            .iter()
            .find(|mapping| mapping.active && mapping.pid == pid && mapping.address == address)
        {
            return Some((mapping.handle, mapping.offset));
        }
        page = mappings.next;
    }
    None
}

pub(crate) fn next_shared_mapping(pid: u32, after: Option<u64>) -> Option<(u64, Handle, usize)> {
    let overlay = live()?;
    let mut selected: Option<(u64, Handle, usize)> = None;
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let mappings = mapping_page(page)?;
        for mapping in &mappings.mappings {
            if mapping.active
                && mapping.pid == pid
                && after.is_none_or(|after| mapping.address > after)
                && selected.is_none_or(|selected| mapping.address < selected.0)
            {
                selected = Some((mapping.address, mapping.handle, mapping.offset));
            }
        }
        page = mappings.next;
    }
    selected
}

pub(crate) fn remove_shared_mapping(pid: u32, address: u64) -> bool {
    let overlay = live_mut();
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page_mut(page) else {
            return false;
        };
        if let Some(mapping) = mappings
            .mappings
            .iter_mut()
            .find(|mapping| mapping.active && mapping.pid == pid && mapping.address == address)
        {
            *mapping = SharedMapping::EMPTY;
            return true;
        }
        page = mappings.next;
    }
    false
}

pub(crate) fn clone_shared_mappings(parent: u32, child: u32) -> bool {
    let mut count = 0;
    let Some(overlay) = live() else {
        return false;
    };
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page(page) else {
            return false;
        };
        count += mappings
            .mappings
            .iter()
            .filter(|mapping| mapping.active && mapping.pid == parent)
            .count();
        page = mappings.next;
    }
    for wanted in 0..count {
        let mut found = 0;
        let mut selected = None;
        let Some(overlay) = live() else {
            return false;
        };
        let mut page = overlay.first_mapping_page;
        while page != FrameLease::EMPTY && selected.is_none() {
            let Some(mappings) = mapping_page(page) else {
                return false;
            };
            for mapping in &mappings.mappings {
                if mapping.active && mapping.pid == parent {
                    if found == wanted {
                        selected = Some(*mapping);
                        break;
                    }
                    found += 1;
                }
            }
            page = mappings.next;
        }
        let Some(mapping) = selected else {
            return false;
        };
        if !register_shared_mapping(child, mapping.address, mapping.handle, mapping.offset) {
            remove_process_shared_mappings(child);
            return false;
        }
    }
    true
}

pub(crate) fn remove_process_shared_mappings(pid: u32) {
    let overlay = live_mut();
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page_mut(page) else {
            return;
        };
        for mapping in &mut mappings.mappings {
            if mapping.active && mapping.pid == pid {
                *mapping = SharedMapping::EMPTY;
            }
        }
        page = mappings.next;
    }
}

struct OverlayRuntimeOwner(UnsafeCell<[Overlay; INSTANCE_LIMIT]>);

unsafe impl Sync for OverlayRuntimeOwner {}

static OVERLAY_RUNTIME: OverlayRuntimeOwner =
    OverlayRuntimeOwner(UnsafeCell::new([Overlay::EMPTY; INSTANCE_LIMIT]));

pub(crate) fn lookup(path: &[u8]) -> Option<Metadata> {
    valid_path(path)?;
    let named = linked_node(path, false)?;
    match named.alias_of {
        Some(file) => metadata(file),
        None => Some(named.metadata()),
    }
}

/// The node linked at `path` (a whiteout too when `whiteouts`), found by
/// the path hints first.
fn linked_node(path: &[u8], whiteouts: bool) -> Option<&'static mut Node> {
    let wanted = |node: &Node| {
        node.active && node.linked && (whiteouts || !node.whiteout) && node.path() == path
    };
    let hints = path_hints();
    let hint = *hints.get(&path_key(path))?;
    // SAFETY: as in `node_mut`: hints point into live node pages.
    if let Some(node) = (hint != 0).then(|| unsafe { &mut *(hint as *mut Node) }) {
        if wanted(node) {
            return Some(node);
        }
    }
    let overlay = live_mut();
    let mut page = overlay.first_node_page;
    while page != FrameLease::EMPTY {
        let nodes = node_page_mut(page)?;
        if let Some(index) = nodes.nodes.iter().position(&wanted) {
            let node = nodes.nodes.get_mut(index)?;
            hints.insert(path_key(path), core::ptr::from_mut(node) as usize);
            return Some(node);
        }
        page = nodes.next;
    }
    None
}

pub(crate) fn hidden(path: &[u8]) -> bool {
    // Only a path or ancestor some node was ever given can be hidden.
    let hints = path_hints();
    let named = (0..=path.len())
        .filter(|end| *end == path.len() || path.get(*end) == Some(&b'/'))
        .any(|end| hints.contains_key(&path_key(&path[..end])));
    named
        && valid_path(path).is_some()
        && live().is_some_and(|overlay| {
            for_each_node(overlay, |node| {
                (node.linked
                    && node.whiteout
                    && (node.path() == path
                        || path.starts_with(node.path())
                            && path.get(node.path().len()) == Some(&b'/')))
                .then_some(())
            })
            .is_some()
        })
}

pub(crate) fn from_generation(generation: u32) -> Option<Handle> {
    let overlay = live()?;
    for_each_node(overlay, |node| {
        (node.handle.generation == generation).then_some(node.handle)
    })
}

pub(crate) fn generation(handle: Handle) -> u32 {
    handle.generation
}

pub(crate) fn metadata(handle: Handle) -> Option<Metadata> {
    node(handle).map(Node::metadata)
}

pub(crate) fn configure_memfd(handle: Handle, allow_sealing: bool) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    if node.kind != NodeKind::File {
        return false;
    }
    if !make_node_paged(node) {
        return false;
    }
    node.data = Data::Memfd;
    node.origin = Origin::Pseudo;
    node.seals = if allow_sealing { 0 } else { 1 };
    true
}

/// Marks `handle` a file of an internal filesystem (secret memory): one
/// link, and no directory can name it.
pub(crate) fn mark_pseudo(handle: Handle) -> bool {
    node_mut(handle).is_some_and(|node| {
        node.origin = Origin::Pseudo;
        true
    })
}

/// The name an O_TMPFILE file is created under in its directory, for the
/// moment before it is unlinked.
const TEMPORARY_NAME: &[u8] = b".ginux-o-tmpfile";

/// Creates an O_TMPFILE file: a regular file with no name, made as if in
/// `directory` (owner, group and set-group-ID inheritance from it), that
/// linkat(2) may later name unless `linkable` is false (O_EXCL).
pub(crate) fn create_temporary(directory: &[u8], mode: u32, linkable: bool) -> Option<Handle> {
    let mut path = [0_u8; PATH_CAPACITY];
    let separator = usize::from(!directory.is_empty());
    let length = directory.len() + separator + TEMPORARY_NAME.len();
    let path = path.get_mut(..length)?;
    path[..directory.len()].copy_from_slice(directory);
    if separator == 1 {
        path[directory.len()] = b'/';
    }
    path[directory.len() + separator..].copy_from_slice(TEMPORARY_NAME);
    let handle = create_file(path, mode, &[])?;
    if !unlink(handle) {
        return None;
    }
    node_mut(handle)?.origin = Origin::Temporary { linkable };
    Some(handle)
}

/// Why [`link_unnamed`] could not name a file.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinkError {
    /// The file was deleted, or is an O_TMPFILE file opened with O_EXCL
    /// (ENOENT).
    Gone,
    /// The file belongs to an internal filesystem (EXDEV).
    CrossDevice,
    /// Something already has that name (EEXIST).
    Exists,
    /// The name is invalid or the node table is full.
    Failed,
}

/// Gives the file `handle`, which has no name, the name `path`: the
/// linkat(2) of an O_TMPFILE file. A named file gets a hard link from
/// [`create_link`] instead.
pub(crate) fn link_unnamed(path: &[u8], handle: Handle) -> Result<(), LinkError> {
    valid_path(path).ok_or(LinkError::Failed)?;
    if lookup(path).is_some() {
        return Err(LinkError::Exists);
    }
    let node = node(handle).ok_or(LinkError::Gone)?;
    match node.origin {
        Origin::Pseudo => return Err(LinkError::CrossDevice),
        Origin::Temporary { linkable: true } if !node.linked => {}
        _ => return Err(LinkError::Gone),
    }
    // A whiteout of the same name hides the image's entry; the file takes
    // its place by taking over the name.
    if hidden(path) {
        let overlay = live_mut();
        let whiteout = node_by_path_mut(overlay, path).ok_or(LinkError::Failed)?;
        *whiteout = Node::EMPTY;
    }
    let node = node_mut(handle).ok_or(LinkError::Gone)?;
    note_path(path);
    node.path = [0; PATH_CAPACITY];
    node.path[..path.len()].copy_from_slice(path);
    node.path_length = path.len() as u16;
    node.linked = true;
    node.links = 1;
    // Named once, it is an ordinary file (Linux clears I_LINKABLE).
    node.origin = Origin::Named;
    Ok(())
}

/// Whether the file `handle` still has a name.
pub(crate) fn linked(handle: Handle) -> bool {
    node(handle).is_some_and(|node| node.linked)
}

/// Returns the frame that holds page `index` of a paged file (a memfd, or a
/// file mapped shared), allocating a zeroed one if the page has never been
/// written. Shared mappings map this frame directly; it lives until the
/// overlay is torn down with its domain.
pub(crate) fn memfd_frame(handle: Handle, index: usize) -> Option<FrameLease> {
    let node = node_mut(handle)?;
    node.paged().then_some(())?;
    memfd_page(node, index, true)
}

/// The frame holding page `index` of a paged file, if the page has one:
/// what a shared mapping of that page maps. Nothing is allocated.
pub(crate) fn paged_frame(handle: Handle, index: usize) -> Option<FrameLease> {
    let node = node_mut(handle)?;
    node.paged().then_some(())?;
    memfd_page(node, index, false)
}

/// The paged file whose inode is `inode` (not a hard link's name for it):
/// the file a shared mapping recorded by inode maps.
pub(crate) fn paged_file(inode: u64) -> Option<Handle> {
    let overlay = live()?;
    for_each_node(overlay, |node| {
        (node.handle.inode == inode
            && node.alias_of.is_none()
            && node.kind == NodeKind::File
            && node.paged())
        .then_some(node.handle)
    })
}

/// Makes the unnamed node behind an anonymous shared mapping. Its pages are
/// allocated zeroed as they are first mapped (`memfd_frame`).
pub(crate) fn create_shmem() -> Option<Handle> {
    let handle = create_file(b"tmp/.ginux-shmem", 0o600, &[])?;
    let made = node_mut(handle).is_some_and(|node| {
        let paged = make_node_paged(node);
        if paged {
            node.data = Data::Shmem;
            node.origin = Origin::Pseudo;
        }
        paged
    });
    (unlink(handle) && made).then_some(handle)
}

/// Frees the anonymous shared memory that no process maps any more. Call
/// it once the pages of the mappings just unregistered are out of every
/// page table.
pub(crate) fn release_unmapped_shmem() {
    let Some(overlay) = live() else {
        return;
    };
    let mut page = overlay.first_node_page;
    while page != FrameLease::EMPTY {
        let Some(nodes) = node_page_mut(page) else {
            return;
        };
        for node in nodes.nodes.iter_mut() {
            if node.active
                && node.data == Data::Shmem
                && !handle_mapped(overlay, node.handle)
                && release_node_data(node)
            {
                *node = Node::EMPTY;
            }
        }
        page = nodes.next;
    }
}

/// Whether a process has a shared mapping of `handle` registered.
fn handle_mapped(overlay: &Overlay, handle: Handle) -> bool {
    let mut page = overlay.first_mapping_page;
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page(page) else {
            return true;
        };
        if mappings
            .mappings
            .iter()
            .any(|mapping| mapping.active && mapping.handle == handle)
        {
            return true;
        }
        page = mappings.next;
    }
    false
}

/// Moves a file's data into whole frames, so every process that maps it
/// shared maps the same pages (as Linux maps the page cache), instead of a
/// copy written back at munmap. Already paged files stay as they are.
pub(crate) fn make_paged(handle: Handle) -> bool {
    node_mut(handle).is_some_and(|node| node.kind == NodeKind::File && make_node_paged(node))
}

fn make_node_paged(node: &mut Node) -> bool {
    if node.paged() {
        return true;
    }
    // Build the frame index beside the data chain, then swap them.
    let mut paged = Node {
        first_page: FrameLease::EMPTY,
        data: Data::Paged,
        ..*node
    };
    let mut buffer = [0_u8; PAGE_SIZE];
    for index in 0..node.size.div_ceil(PAGE_SIZE) {
        let Some(length) = read_node(node, index * PAGE_SIZE, &mut buffer) else {
            let _ = release_frame_index(paged.first_page);
            return false;
        };
        let Some(address) =
            memfd_page(&mut paged, index, true).and_then(FrameLease::direct_map_address)
        else {
            let _ = release_frame_index(paged.first_page);
            return false;
        };
        unsafe { core::slice::from_raw_parts_mut(address as *mut u8, length) }
            .copy_from_slice(&buffer[..length]);
    }
    if !release_data_pages(node.first_page) {
        let _ = release_frame_index(paged.first_page);
        return false;
    }
    node.first_page = paged.first_page;
    node.last_page = FrameLease::EMPTY;
    node.page_count = 0;
    node.cached_page = FrameLease::EMPTY;
    node.cached_page_index = 0;
    node.data = Data::Paged;
    true
}

pub(crate) fn file_seals(handle: Handle) -> Option<u32> {
    let node = node(handle)?;
    (node.data == Data::Memfd).then_some(u32::from(node.seals))
}

pub(crate) fn add_file_seals(handle: Handle, seals: u32) -> Option<bool> {
    let node = node_mut(handle)?;
    let seals = u8::try_from(seals).ok()?;
    if node.data != Data::Memfd {
        return None;
    }
    // F_SEAL_SEAL forbids any further F_ADD_SEALS, even of nothing.
    if node.seals & 1 != 0 {
        return Some(false);
    }
    node.seals |= seals;
    Some(true)
}

pub(crate) fn copy_path(handle: Handle, output: &mut [u8]) -> Option<usize> {
    let overlay = live()?;
    for_each_node(overlay, |node| {
        if node.handle != handle {
            return None;
        }
        output
            .get_mut(..node.path().len())?
            .copy_from_slice(node.path());
        Some(node.path().len())
    })
}

/// The overlay's entry after `cursor` directly below the canonical
/// directory path `directory` ("" for the root), whether or not the overlay
/// has a node for the directory itself: files created in a directory of the
/// image are overlay nodes below the image's directory.
pub(crate) fn next_child_at(directory: &[u8], cursor: usize) -> Option<Option<Child>> {
    let mut parent = [0_u8; PATH_CAPACITY + 1];
    parent
        .get_mut(..directory.len())?
        .copy_from_slice(directory);
    let mut prefix_length = directory.len();
    if prefix_length != 0 {
        parent[prefix_length] = b'/';
        prefix_length += 1;
    }
    // The cursor is a node slot's place among all slots, which stays put
    // while nodes come and go (pages are only appended): unlinking the
    // entries already read, as `rm -r` does between reads, moves none of
    // the rest past the cursor.
    let overlay = live()?;
    let mut page = overlay.first_node_page;
    let mut ordinal = 0_usize;
    while page != FrameLease::EMPTY {
        let nodes = node_page(page)?;
        if ordinal + nodes.nodes.len() <= cursor {
            ordinal += nodes.nodes.len();
            page = nodes.next;
            continue;
        }
        for (index, node) in nodes.nodes.iter().enumerate() {
            let place = ordinal + index;
            if place < cursor || !node.active || !node.linked || node.whiteout {
                continue;
            }
            let Some(remainder) = node.path().strip_prefix(&parent[..prefix_length]) else {
                continue;
            };
            if remainder.is_empty() || remainder.contains(&b'/') {
                continue;
            }
            let mut name = [0_u8; PATH_CAPACITY];
            name[..remainder.len()].copy_from_slice(remainder);
            let metadata = match node.alias_of {
                Some(file) => metadata(file)?,
                None => node.metadata(),
            };
            return Some(Some(Child {
                next_cursor: place + 1,
                metadata,
                name_length: remainder.len(),
                name,
            }));
        }
        ordinal += nodes.nodes.len();
        page = nodes.next;
    }
    Some(None)
}

pub(crate) fn create_file(path: &[u8], mode: u32, initial: &[u8]) -> Option<Handle> {
    create(path, NodeKind::File, mode, initial)
}

pub(crate) fn create_directory(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Directory, mode, &[])
}

pub(crate) fn create_symlink(path: &[u8], target: &[u8]) -> Option<Handle> {
    create(path, NodeKind::Symlink, 0o777, target)
}

pub(crate) fn create_fifo(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Fifo, mode, &[])
}

/// Creates the socket file a UNIX socket is bound to at `path`.
pub(crate) fn create_socket(path: &[u8], mode: u32) -> Option<Handle> {
    create(path, NodeKind::Socket, mode, &[])
}

/// Creates a device file at `path` for `device` (mknod S_IFCHR or S_IFBLK).
pub(crate) fn create_device(path: &[u8], kind: NodeKind, mode: u32, device: u32) -> Option<Handle> {
    if !matches!(kind, NodeKind::CharacterDevice | NodeKind::BlockDevice) {
        return None;
    }
    let handle = create(path, kind, mode, &[])?;
    node_mut(handle)?.device = device;
    Some(handle)
}

pub(crate) fn fifo_socket(handle: Handle) -> Option<crate::linux_socket::SlotId> {
    let node = node(handle)?;
    (node.kind == NodeKind::Fifo && node.fifo_socket != 0).then_some(node.fifo_socket - 1)
}

pub(crate) fn set_fifo_socket(handle: Handle, slot: crate::linux_socket::SlotId) -> bool {
    let Some(node) = node_mut(handle).filter(|node| node.kind == NodeKind::Fifo) else {
        return false;
    };
    let Some(encoded) = slot.checked_add(1) else {
        return false;
    };
    node.fifo_socket = encoded;
    true
}

fn create(path: &[u8], kind: NodeKind, mode: u32, initial: &[u8]) -> Option<Handle> {
    // A new file's times are when it was made.
    let created = crate::arch::x86_64::cpu::linux_realtime_now();
    valid_path(path)?;
    if lookup(path).is_some() {
        return None;
    }
    let replace_whiteout = hidden(path);
    let overlay = live_mut();
    let generation = overlay.next_generation.checked_add(1)?;
    let inode = overlay.next_inode.checked_add(1)?;
    let node = if replace_whiteout {
        node_by_path_mut(overlay, path)?
    } else {
        empty_node_slot(overlay)?
    };
    let mut stored_path = [0_u8; PATH_CAPACITY];
    stored_path[..path.len()].copy_from_slice(path);
    let handle = Handle { generation, inode };
    // A new file belongs to its creator, or to a set-group-ID directory's
    // group.
    let (owner, group, mode) =
        cpu::linux_new_file_identity(path, kind == NodeKind::Directory, mode);
    *node = Node {
        active: true,
        linked: true,
        whiteout: false,
        origin: Origin::Named,
        data: Data::Chain,
        kind,
        path_length: path.len() as u16,
        mode: mode & 0o7777,
        owner,
        group,
        alias_of: None,
        links: 1,
        device: 0,
        seals: 0,
        attributes: 0,
        fifo_socket: 0,
        handle,
        size: 0,
        first_page: FrameLease::EMPTY,
        last_page: FrameLease::EMPTY,
        page_count: 0,
        cached_page: FrameLease::EMPTY,
        cached_page_index: 0,
        xattr_first: FrameLease::EMPTY,
        atime: created,
        mtime: created,
        ctime: created,
        path: stored_path,
    };
    note_path(path);
    overlay.next_generation = generation;
    overlay.next_inode = inode;
    if kind == NodeKind::Symlink {
        overlay.symlinks += 1;
    }
    if !initial.is_empty() && write(handle, 0, initial) != Some(initial.len()) {
        let _ = unlink(handle);
        return None;
    }
    Some(handle)
}

pub(crate) fn whiteout(path: &[u8]) -> bool {
    if valid_path(path).is_none() {
        return false;
    }
    let has_node = lookup(path).is_some() || hidden(path);
    let overlay = live_mut();
    if has_node {
        let Some(node) = node_by_path_mut(overlay, path) else {
            return false;
        };
        if !release_data_pages(node.first_page) || !release_xattr_pages(node.xattr_first) {
            return false;
        }
        node.first_page = FrameLease::EMPTY;
        node.last_page = FrameLease::EMPTY;
        node.page_count = 0;
        node.cached_page = FrameLease::EMPTY;
        node.xattr_first = FrameLease::EMPTY;
        node.size = 0;
        node.linked = true;
        node.whiteout = true;
        return true;
    }
    let generation = match overlay.next_generation.checked_add(1) {
        Some(generation) => generation,
        None => return false,
    };
    let inode = match overlay.next_inode.checked_add(1) {
        Some(inode) => inode,
        None => return false,
    };
    let Some(node) = empty_node_slot(overlay) else {
        return false;
    };
    let mut stored_path = [0_u8; PATH_CAPACITY];
    stored_path[..path.len()].copy_from_slice(path);
    *node = Node {
        active: true,
        linked: true,
        whiteout: true,
        origin: Origin::Named,
        data: Data::Chain,
        kind: NodeKind::File,
        path_length: path.len() as u16,
        mode: 0,
        owner: 0,
        group: 0,
        alias_of: None,
        links: 0,
        device: 0,
        seals: 0,
        attributes: 0,
        fifo_socket: 0,
        handle: Handle { generation, inode },
        size: 0,
        first_page: FrameLease::EMPTY,
        last_page: FrameLease::EMPTY,
        page_count: 0,
        cached_page: FrameLease::EMPTY,
        cached_page_index: 0,
        xattr_first: FrameLease::EMPTY,
        atime: (0, 0),
        mtime: (0, 0),
        ctime: (0, 0),
        path: stored_path,
    };
    note_path(path);
    overlay.next_generation = generation;
    overlay.next_inode = inode;
    true
}

pub(crate) fn read(handle: Handle, offset: usize, output: &mut [u8]) -> Option<usize> {
    let node = node_mut(handle)?;
    if matches!(
        node.kind,
        NodeKind::Directory
            | NodeKind::Fifo
            | NodeKind::Socket
            | NodeKind::CharacterDevice
            | NodeKind::BlockDevice
    ) {
        return None;
    }
    read_node(node, offset, output)
}

fn read_node(node: &mut Node, offset: usize, output: &mut [u8]) -> Option<usize> {
    let start = offset.min(node.size);
    let end = start.saturating_add(output.len()).min(node.size);
    if node.paged() {
        let mut position = start;
        while position < end {
            let within = position % PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - within);
            let target = &mut output[position - start..position - start + length];
            match memfd_page(node, position / PAGE_SIZE, false)
                .and_then(FrameLease::direct_map_address)
            {
                Some(address) => target.copy_from_slice(unsafe {
                    core::slice::from_raw_parts((address + within) as *const u8, length)
                }),
                None => target.fill(0),
            }
            position += length;
        }
        return Some(end - start);
    }
    let target_page = start / DATA_CAPACITY;
    let (mut page, mut page_index) =
        if node.cached_page != FrameLease::EMPTY && node.cached_page_index <= target_page {
            (node.cached_page, node.cached_page_index)
        } else {
            (node.first_page, 0)
        };
    while page_index < target_page {
        page = data_page(page)?.next;
        page_index += 1;
    }
    node.cached_page = page;
    node.cached_page_index = page_index;
    let mut skipped = page_index * DATA_CAPACITY;
    let mut copied = 0;
    while start + copied < end {
        let data = data_page(page)?;
        let page_offset = start + copied - skipped;
        let length = (end - start - copied).min(DATA_CAPACITY - page_offset);
        output[copied..copied + length]
            .copy_from_slice(&data.bytes[page_offset..page_offset + length]);
        copied += length;
        skipped += DATA_CAPACITY;
        page = data.next;
    }
    Some(copied)
}

/// Writes `input` at `offset` of the file at `handle`, which marks it
/// modified now (its mtime and ctime), as a Linux write does.
pub(crate) fn write(handle: Handle, offset: usize, input: &[u8]) -> Option<usize> {
    let written = write_data(handle, offset, input)?;
    if written != 0 {
        let _ = touch_modified(handle, crate::arch::x86_64::cpu::linux_realtime_now());
    }
    Some(written)
}

fn write_data(handle: Handle, offset: usize, input: &[u8]) -> Option<usize> {
    let end = offset.checked_add(input.len())?;
    if input.is_empty() {
        return Some(0);
    }
    let node = node_mut(handle)?;
    if matches!(
        node.kind,
        NodeKind::Directory
            | NodeKind::Fifo
            | NodeKind::Socket
            | NodeKind::CharacterDevice
            | NodeKind::BlockDevice
    ) {
        return None;
    }
    if node.paged() {
        let mut position = offset;
        while position < end {
            let within = position % PAGE_SIZE;
            let length = (end - position).min(PAGE_SIZE - within);
            let address = memfd_page(node, position / PAGE_SIZE, true)?.direct_map_address()?;
            unsafe { core::slice::from_raw_parts_mut((address + within) as *mut u8, length) }
                .copy_from_slice(&input[position - offset..position - offset + length]);
            position += length;
        }
        node.size = node.size.max(end);
        return Some(input.len());
    }
    ensure_data_pages(node, end.div_ceil(DATA_CAPACITY))?;
    let target_page = offset / DATA_CAPACITY;
    let (mut page, mut page_index) =
        if node.cached_page != FrameLease::EMPTY && node.cached_page_index <= target_page {
            (node.cached_page, node.cached_page_index)
        } else {
            (node.first_page, 0)
        };
    while page_index < target_page {
        page = data_page(page)?.next;
        page_index += 1;
    }
    node.cached_page = page;
    node.cached_page_index = page_index;
    let mut skipped = page_index * DATA_CAPACITY;
    let mut copied = 0;
    while copied < input.len() {
        let data = data_page_mut(page)?;
        let page_offset = offset + copied - skipped;
        let length = (input.len() - copied).min(DATA_CAPACITY - page_offset);
        data.bytes[page_offset..page_offset + length]
            .copy_from_slice(&input[copied..copied + length]);
        copied += length;
        skipped += DATA_CAPACITY;
        page = data.next;
    }
    node.size = node.size.max(end);
    Some(input.len())
}

pub(crate) fn truncate(handle: Handle, size: usize) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    if node.kind != NodeKind::File {
        return false;
    }
    if node.paged() {
        // Frames stay allocated when a paged file shrinks, since processes
        // may still map them; the cut-off bytes are zeroed so the file reads
        // back as zeros if it grows again.
        let mut position = size;
        while position < node.size {
            let within = position % PAGE_SIZE;
            let length = (node.size - position).min(PAGE_SIZE - within);
            if let Some(address) = memfd_page(node, position / PAGE_SIZE, false)
                .and_then(FrameLease::direct_map_address)
            {
                unsafe { core::ptr::write_bytes((address + within) as *mut u8, 0, length) };
            }
            position += length;
        }
        node.size = size;
        return true;
    }
    if size > node.size {
        if ensure_data_pages(node, size.div_ceil(DATA_CAPACITY)).is_none() {
            return false;
        }
    } else if size == 0 {
        let first = core::mem::replace(&mut node.first_page, FrameLease::EMPTY);
        if !release_data_pages(first) {
            node.first_page = first;
            return false;
        }
        node.last_page = FrameLease::EMPTY;
        node.page_count = 0;
        node.cached_page = FrameLease::EMPTY;
        node.cached_page_index = 0;
    } else if size < node.size {
        // The cut-off bytes are zeroed so the file reads back as zeros if
        // it grows again (ftruncate01).
        let mut page = node.first_page;
        let mut page_index = 0;
        let mut position = size;
        while position < node.size {
            while page_index < position / DATA_CAPACITY {
                let Some(data) = data_page(page) else {
                    return false;
                };
                page = data.next;
                page_index += 1;
            }
            let Some(data) = data_page_mut(page) else {
                return false;
            };
            let within = position % DATA_CAPACITY;
            let length = (node.size - position).min(DATA_CAPACITY - within);
            data.bytes[within..within + length].fill(0);
            position += length;
        }
    }
    node.size = size;
    true
}

pub(crate) fn set_mode(handle: Handle, mode: u32) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.mode = mode & 0o7777;
    true
}

/// Sets a file's attributes (FS_IOC_SETFLAGS): FS_*_FL bits, of which
/// the file keeps those that fit a byte.
pub(crate) fn set_attributes(handle: Handle, attributes: u32) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.attributes = attributes as u8;
    true
}

pub(crate) fn set_owner(handle: Handle, owner: u32, group: u32) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.owner = owner;
    node.group = group;
    true
}

/// Marks the file at `handle` modified at `time` (its mtime and ctime).
pub(crate) fn touch_modified(handle: Handle, time: (i64, i64)) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.mtime = time;
    node.ctime = time;
    true
}

pub(crate) fn set_times(handle: Handle, atime: (i64, i64), mtime: (i64, i64)) -> bool {
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.atime = atime;
    node.mtime = mtime;
    node.ctime = mtime;
    true
}

pub(crate) fn set_xattr_from<F>(
    handle: Handle,
    name: &[u8],
    value_size: usize,
    create_only: bool,
    replace_only: bool,
    mut fill: F,
) -> bool
where
    F: FnMut(usize, &mut [u8]) -> bool,
{
    if name.is_empty()
        || name.len() > XATTR_NAME_CAPACITY
        || name.contains(&0)
        || u32::try_from(value_size).is_err()
    {
        return false;
    }
    let exists = xattr_metadata(handle, name).is_some_and(|(_, removed)| !removed);
    if create_only && exists || replace_only && !exists {
        return false;
    }
    let mut offset = 0;
    let value_first = match allocate_data_pages_with(value_size, |bytes| {
        let accepted = fill(offset, bytes);
        offset += bytes.len();
        accepted
    }) {
        Some(first) => first,
        None => return false,
    };
    append_xattr_pages(handle, name, value_first, value_size, false)
}

pub(crate) fn get_xattr_chunk(
    handle: Handle,
    name: &[u8],
    offset: usize,
    output: &mut [u8],
) -> Option<(usize, usize)> {
    let (page, removed) = xattr_metadata(handle, name)?;
    if removed {
        return None;
    }
    let record = xattr_page(page)?;
    let size = record.value_size as usize;
    if offset >= size || output.is_empty() {
        return Some((size, 0));
    }
    let mut value_page = record.value_first;
    let mut page_index = offset / DATA_CAPACITY;
    while page_index != 0 {
        value_page = data_page(value_page)?.next;
        page_index -= 1;
    }
    let mut within_page = offset % DATA_CAPACITY;
    let mut copied = 0;
    let wanted = output.len().min(size - offset);
    while copied < wanted {
        let data = data_page(value_page)?;
        let length = (wanted - copied).min(DATA_CAPACITY - within_page);
        output[copied..copied + length]
            .copy_from_slice(&data.bytes[within_page..within_page + length]);
        copied += length;
        within_page = 0;
        value_page = data.next;
    }
    Some((size, copied))
}

pub(crate) fn list_xattrs_chunk(
    handle: Handle,
    offset: usize,
    output: &mut [u8],
) -> Option<(usize, usize)> {
    let node = node(handle)?;
    let mut current = node.xattr_first;
    let mut used: usize = 0;
    let mut copied: usize = 0;
    while current != FrameLease::EMPTY {
        let record = xattr_page(current)?;
        if !record.removed && !xattr_superseded(node.xattr_first, current, record.name())? {
            let length = usize::from(record.name_length).checked_add(1)?;
            let end = used.checked_add(length)?;
            let copy_start = offset.max(used);
            let copy_end = end.min(offset.saturating_add(output.len()));
            if copy_start < copy_end {
                for source_index in copy_start - used..copy_end - used {
                    output[copied] = if source_index < record.name().len() {
                        record.name()[source_index]
                    } else {
                        0
                    };
                    copied += 1;
                }
            }
            used = end;
        }
        current = record.previous;
    }
    Some((used, copied))
}

pub(crate) fn remove_xattr(handle: Handle, name: &[u8]) -> bool {
    if !xattr_metadata(handle, name).is_some_and(|(_, removed)| !removed) {
        return false;
    }
    append_xattr(handle, name, &[], true)
}

pub(crate) fn rename(handle: Handle, path: &[u8]) -> bool {
    if valid_path(path).is_none() || lookup(path).is_some() {
        return false;
    }
    let Some(source) = node(handle) else {
        return false;
    };
    if !source.linked {
        return false;
    }
    let mut old_path = [0_u8; PATH_CAPACITY];
    let old_length = source.path().len();
    old_path[..old_length].copy_from_slice(source.path());
    let directory = source.kind == NodeKind::Directory;
    let Some(overlay) = live() else {
        return false;
    };
    let valid = for_each_node(overlay, |candidate| {
        if !candidate.linked
            || candidate.handle == handle
            || !directory
            || !candidate.path().starts_with(&old_path[..old_length])
            || candidate.path().get(old_length) != Some(&b'/')
        {
            return None;
        }
        let suffix = &candidate.path()[old_length..];
        let Some(new_length) = path.len().checked_add(suffix.len()) else {
            return Some(false);
        };
        if new_length >= PATH_CAPACITY {
            return Some(false);
        }
        let mut destination = [0_u8; PATH_CAPACITY];
        destination[..path.len()].copy_from_slice(path);
        destination[path.len()..new_length].copy_from_slice(suffix);
        if lookup(&destination[..new_length]).is_some() {
            return Some(false);
        }
        None
    });
    if valid == Some(false) {
        return false;
    }
    let overlay = live_mut();
    let mut page = overlay.first_node_page;
    while page != FrameLease::EMPTY {
        let Some(nodes) = node_page_mut(page) else {
            return false;
        };
        for candidate in &mut nodes.nodes {
            if !candidate.active || !candidate.linked {
                continue;
            }
            let suffix = if candidate.handle == handle {
                &[][..]
            } else if directory
                && candidate.path().starts_with(&old_path[..old_length])
                && candidate.path().get(old_length) == Some(&b'/')
            {
                &candidate.path()[old_length..]
            } else {
                continue;
            };
            let new_length = path.len() + suffix.len();
            let mut destination = [0_u8; PATH_CAPACITY];
            destination[..path.len()].copy_from_slice(path);
            destination[path.len()..new_length].copy_from_slice(suffix);
            note_path(&destination[..new_length]);
            candidate.path = destination;
            candidate.path_length = new_length as u16;
        }
        page = nodes.next;
    }
    true
}

/// Gives the file `target` (not a directory) another name, `path`: a hard
/// link. Both names then reach the same data, owner and mode.
pub(crate) fn create_link(path: &[u8], target: Handle) -> bool {
    if valid_path(path).is_none() || lookup(path).is_some() {
        return false;
    }
    let Some(file) = node(target) else {
        return false;
    };
    if file.kind == NodeKind::Directory || !file.linked || file.alias_of.is_some() {
        return false;
    }
    let kind = file.kind;
    let replace_whiteout = hidden(path);
    let overlay = live_mut();
    let Some(generation) = overlay.next_generation.checked_add(1) else {
        return false;
    };
    let Some(slot) = (if replace_whiteout {
        node_by_path_mut(overlay, path)
    } else {
        empty_node_slot(overlay)
    }) else {
        return false;
    };
    let mut stored_path = [0_u8; PATH_CAPACITY];
    stored_path[..path.len()].copy_from_slice(path);
    *slot = Node {
        active: true,
        linked: true,
        kind,
        path_length: path.len() as u16,
        alias_of: Some(target),
        handle: Handle {
            generation,
            inode: target.inode,
        },
        path: stored_path,
        ..Node::EMPTY
    };
    note_path(path);
    overlay.next_generation = generation;
    let Some(file) = node_mut(target) else {
        return false;
    };
    file.links = file.links.saturating_add(1);
    true
}

/// Removes the name `path`. A file with other names keeps its data under
/// them: removing an alias drops just that name, and removing the file's
/// own node moves one alias's name onto it. Directories and files with one
/// name go as `unlink` does.
pub(crate) fn unlink_path(path: &[u8]) -> bool {
    let Some(overlay) = live() else {
        return false;
    };
    let Some(named) = for_each_node(overlay, |node| {
        (node.linked && !node.whiteout && node.path() == path)
            .then_some((node.handle, node.alias_of))
    }) else {
        return false;
    };
    match named {
        (alias, Some(file)) => drop_alias(alias, file),
        (file, None) => {
            let alias = for_each_node(overlay, |node| {
                (node.linked && node.alias_of == Some(file)).then_some((
                    node.handle,
                    node.path,
                    node.path_length,
                ))
            });
            match alias {
                Some((alias, alias_path, alias_length)) => {
                    let Some(node) = node_mut(file) else {
                        return false;
                    };
                    note_path(&alias_path[..usize::from(alias_length)]);
                    node.path = alias_path;
                    node.path_length = alias_length;
                    drop_alias(alias, file)
                }
                None => unlink(file),
            }
        }
    }
}

/// Frees the alias node `alias` of `file` and takes one name off the file.
fn drop_alias(alias: Handle, file: Handle) -> bool {
    let Some(node) = node_mut(alias) else {
        return false;
    };
    *node = Node::EMPTY;
    if let Some(node) = node_mut(file) {
        node.links = node.links.saturating_sub(1).max(1);
    }
    true
}

/// Renames the name `from` to `to`: an alias moves alone; a file's own node
/// (or a directory, with everything under it) as `rename` does.
pub(crate) fn rename_path(from: &[u8], to: &[u8]) -> bool {
    if valid_path(to).is_none() || lookup(to).is_some() {
        return false;
    }
    let Some(overlay) = live() else {
        return false;
    };
    let Some((handle, alias_of)) = for_each_node(overlay, |node| {
        (node.linked && !node.whiteout && node.path() == from)
            .then_some((node.handle, node.alias_of))
    }) else {
        return false;
    };
    if alias_of.is_none() {
        return rename(handle, to);
    }
    let Some(node) = node_mut(handle) else {
        return false;
    };
    let mut stored_path = [0_u8; PATH_CAPACITY];
    stored_path[..to.len()].copy_from_slice(to);
    note_path(to);
    node.path = stored_path;
    node.path_length = to.len() as u16;
    true
}

/// Removes everything below the directory `path`, as unmounting a tmpfs
/// from it drops what was created there. Open files stay readable until
/// closed, as after unlink.
pub(crate) fn unlink_below(path: &[u8]) {
    let overlay = live_mut();
    let mut page = overlay.first_node_page;
    let mut symlinks_removed = 0;
    while page != FrameLease::EMPTY {
        let Some(nodes) = node_page_mut(page) else {
            return;
        };
        for node in &mut nodes.nodes {
            let below = node.active
                && node.linked
                && node
                    .path()
                    .strip_prefix(path)
                    .is_some_and(|rest| rest.starts_with(b"/"));
            if !below {
                continue;
            }
            if node.alias_of.is_some() {
                *node = Node::EMPTY;
            } else {
                if node.kind == NodeKind::Symlink && !node.whiteout {
                    symlinks_removed += 1;
                }
                node.linked = false;
            }
        }
        page = nodes.next;
    }
    let overlay = live_mut();
    overlay.symlinks = overlay.symlinks.saturating_sub(symlinks_removed);
}

pub(crate) fn unlink(handle: Handle) -> bool {
    let Some(metadata) = metadata(handle) else {
        return false;
    };
    if metadata.kind == NodeKind::Directory {
        let mut prefix = [0_u8; PATH_CAPACITY];
        let Some(length) = copy_path(handle, &mut prefix) else {
            return false;
        };
        prefix[length] = b'/';
        if for_each_node(live().unwrap_or(&Overlay::EMPTY), |candidate| {
            (candidate.linked
                && !candidate.whiteout
                && candidate.path().starts_with(&prefix[..length + 1]))
            .then_some(())
        })
        .is_some()
        {
            return false;
        }
    }
    let Some(node) = node_mut(handle) else {
        return false;
    };
    node.linked = false;
    if node.kind == NodeKind::Symlink {
        let overlay = live_mut();
        overlay.symlinks = overlay.symlinks.saturating_sub(1);
    }
    true
}

pub(crate) fn teardown() -> bool {
    // The domain's loop devices are backed by its files, and its RAM disks
    // go with them.
    crate::linux_loop::forget_domain();
    crate::linux_ramdisk::forget_domain();
    let overlay = live_mut();
    *node_hints() = BTreeMap::new();
    *path_hints() = BTreeMap::new();
    let mut page = core::mem::replace(&mut overlay.first_node_page, FrameLease::EMPTY);
    while page != FrameLease::EMPTY {
        let Some(nodes) = node_page_mut(page) else {
            return false;
        };
        let next = nodes.next;
        for node in &mut nodes.nodes {
            if node.active && (!release_node_data(node) || !release_xattr_pages(node.xattr_first)) {
                return false;
            }
            *node = Node::EMPTY;
        }
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    let mut page = core::mem::replace(&mut overlay.first_mapping_page, FrameLease::EMPTY);
    while page != FrameLease::EMPTY {
        let Some(mappings) = mapping_page(page) else {
            return false;
        };
        let next = mappings.next;
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    overlay.next_generation = 0x8000_0000;
    overlay.next_inode = 0x10_000;
    true
}

fn valid_path(path: &[u8]) -> Option<()> {
    (!path.is_empty()
        && path.len() < PATH_CAPACITY
        && !path.starts_with(b"/")
        && !path.ends_with(b"/")
        && path.split(|byte| *byte == b'/').all(|component| {
            !component.is_empty()
                && component != b"."
                && component != b".."
                && !component.contains(&0)
        }))
    .then_some(())
}

fn node_by_path_mut<'a>(_overlay: &'a mut Overlay, path: &[u8]) -> Option<&'a mut Node> {
    linked_node(path, true)
}

fn empty_node_slot(overlay: &mut Overlay) -> Option<&mut Node> {
    let mut page = overlay.first_node_page;
    let mut last = FrameLease::EMPTY;
    while page != FrameLease::EMPTY {
        let nodes = node_page_mut(page)?;
        if let Some(index) = nodes.nodes.iter().position(|node| !node.active) {
            return nodes.nodes.get_mut(index);
        }
        last = page;
        page = nodes.next;
    }
    let page = allocate_node_page()?;
    if last == FrameLease::EMPTY {
        overlay.first_node_page = page;
    } else {
        node_page_mut(last)?.next = page;
    }
    node_page_mut(page)?.nodes.first_mut()
}

fn allocate_node_page() -> Option<FrameLease> {
    let [page] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    let address = page.direct_map_address()?;
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE);
        core::ptr::write(
            address as *mut NodePage,
            NodePage {
                next: FrameLease::EMPTY,
                nodes: [Node::EMPTY; NODE_COUNT],
            },
        );
    }
    Some(page)
}

fn allocate_mapping_page() -> Option<FrameLease> {
    let [page] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    let address = page.direct_map_address()?;
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE);
        core::ptr::write(
            address as *mut MappingPage,
            MappingPage {
                next: FrameLease::EMPTY,
                mappings: [SharedMapping::EMPTY; MAPPING_COUNT],
            },
        );
    }
    Some(page)
}

fn allocate_zeroed_frame() -> Option<FrameLease> {
    let [page] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    let address = page.direct_map_address()?;
    unsafe { core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE) };
    Some(page)
}

fn frame_index_page_mut(page: FrameLease) -> Option<&'static mut FrameIndexPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &mut *(address as *mut FrameIndexPage) })
}

// A zeroed frame is an index page whose entries are all FrameLease::EMPTY.
fn memfd_page(node: &mut Node, index: usize, allocate: bool) -> Option<FrameLease> {
    if node.first_page == FrameLease::EMPTY {
        allocate.then_some(())?;
        node.first_page = allocate_zeroed_frame()?;
    }
    let mut page = node.first_page;
    for _ in 0..index / FRAME_INDEX_CAPACITY {
        let entries = frame_index_page_mut(page)?;
        if entries.next == FrameLease::EMPTY {
            allocate.then_some(())?;
            entries.next = allocate_zeroed_frame()?;
        }
        page = entries.next;
    }
    let entry = &mut frame_index_page_mut(page)?.frames[index % FRAME_INDEX_CAPACITY];
    if *entry == FrameLease::EMPTY {
        allocate.then_some(())?;
        *entry = allocate_zeroed_frame()?;
    }
    Some(*entry)
}

fn release_node_data(node: &Node) -> bool {
    if node.paged() {
        release_frame_index(node.first_page)
    } else {
        release_data_pages(node.first_page)
    }
}

fn release_frame_index(mut page: FrameLease) -> bool {
    while page != FrameLease::EMPTY {
        let Some(entries) = frame_index_page_mut(page) else {
            return false;
        };
        let next = entries.next;
        for frame in entries
            .frames
            .iter()
            .filter(|frame| **frame != FrameLease::EMPTY)
        {
            if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(frame)) {
                return false;
            }
        }
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    true
}

fn allocate_data_page() -> Option<FrameLease> {
    let [page] = memory::allocate_frames::<1>(FrameOwner::KERNEL)?;
    let address = page.direct_map_address()?;
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE);
        core::ptr::write(
            address as *mut DataPage,
            DataPage {
                next: FrameLease::EMPTY,
                bytes: [0; DATA_CAPACITY],
            },
        );
    }
    Some(page)
}

impl XattrPage {
    fn name(&self) -> &[u8] {
        &self.name[..usize::from(self.name_length)]
    }
}

fn append_xattr(handle: Handle, name: &[u8], value: &[u8], removed: bool) -> bool {
    let value_first = if value.is_empty() {
        FrameLease::EMPTY
    } else {
        let Some(first) = allocate_data_pages(value) else {
            return false;
        };
        first
    };
    append_xattr_pages(handle, name, value_first, value.len(), removed)
}

fn append_xattr_pages(
    handle: Handle,
    name: &[u8],
    value_first: FrameLease,
    value_size: usize,
    removed: bool,
) -> bool {
    let Some([page]) = memory::allocate_frames::<1>(FrameOwner::KERNEL) else {
        let _ = release_data_pages(value_first);
        return false;
    };
    let Some(address) = page.direct_map_address() else {
        let _ = release_data_pages(value_first);
        let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
        return false;
    };
    let Some(node) = node_mut(handle) else {
        let _ = release_data_pages(value_first);
        let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
        return false;
    };
    let mut stored_name = [0_u8; XATTR_NAME_CAPACITY];
    stored_name[..name.len()].copy_from_slice(name);
    unsafe {
        core::ptr::write_bytes(address as *mut u8, 0, PAGE_SIZE);
        core::ptr::write(
            address as *mut XattrPage,
            XattrPage {
                previous: node.xattr_first,
                value_first,
                value_size: value_size as u32,
                name_length: name.len() as u16,
                removed,
                name: stored_name,
            },
        );
    }
    node.xattr_first = page;
    true
}

fn allocate_data_pages(input: &[u8]) -> Option<FrameLease> {
    let mut offset = 0;
    allocate_data_pages_with(input.len(), |output| {
        output.copy_from_slice(&input[offset..offset + output.len()]);
        offset += output.len();
        true
    })
}

fn allocate_data_pages_with<F>(size: usize, mut fill: F) -> Option<FrameLease>
where
    F: FnMut(&mut [u8]) -> bool,
{
    let mut first = FrameLease::EMPTY;
    let mut last = FrameLease::EMPTY;
    let mut remaining = size;
    while remaining != 0 {
        let Some(page) = allocate_data_page() else {
            let _ = release_data_pages(first);
            return None;
        };
        let Some(data) = data_page_mut(page) else {
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
            let _ = release_data_pages(first);
            return None;
        };
        let length = remaining.min(DATA_CAPACITY);
        if !fill(&mut data.bytes[..length]) {
            let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
            let _ = release_data_pages(first);
            return None;
        }
        if first == FrameLease::EMPTY {
            first = page;
        } else {
            let Some(tail) = data_page_mut(last) else {
                let _ = memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page]);
                let _ = release_data_pages(first);
                return None;
            };
            tail.next = page;
        }
        last = page;
        remaining -= length;
    }
    Some(first)
}

fn xattr_metadata(handle: Handle, name: &[u8]) -> Option<(FrameLease, bool)> {
    let node = node(handle)?;
    let mut page = node.xattr_first;
    while page != FrameLease::EMPTY {
        let record = xattr_page(page)?;
        if record.name() == name {
            return Some((page, record.removed));
        }
        page = record.previous;
    }
    None
}

fn xattr_superseded(first: FrameLease, target: FrameLease, name: &[u8]) -> Option<bool> {
    let mut page = first;
    while page != target {
        let record = xattr_page(page)?;
        if record.name() == name {
            return Some(true);
        }
        page = record.previous;
    }
    Some(false)
}

fn release_xattr_pages(mut page: FrameLease) -> bool {
    while page != FrameLease::EMPTY {
        let Some(record) = xattr_page(page) else {
            return false;
        };
        let previous = record.previous;
        if !release_data_pages(record.value_first)
            || !memory::scrub_and_release_frames(FrameOwner::KERNEL, &[page])
        {
            return false;
        }
        page = previous;
    }
    true
}

fn ensure_data_pages(node: &mut Node, required: usize) -> Option<()> {
    while node.page_count < required {
        let next = allocate_data_page()?;
        if node.first_page == FrameLease::EMPTY {
            node.first_page = next;
            node.cached_page = next;
            node.cached_page_index = 0;
        } else {
            data_page_mut(node.last_page)?.next = next;
        }
        node.last_page = next;
        node.page_count += 1;
    }
    Some(())
}

fn release_data_pages(mut page: FrameLease) -> bool {
    while page != FrameLease::EMPTY {
        let Some(data) = data_page(page) else {
            return false;
        };
        let next = data.next;
        if !memory::scrub_and_release_frames(FrameOwner::KERNEL, core::slice::from_ref(&page)) {
            return false;
        }
        page = next;
    }
    true
}

fn node(handle: Handle) -> Option<&'static Node> {
    node_mut(handle).map(|node| &*node)
}

/// Where each instance's nodes were last found, by inode: a hint checked on
/// every use (the slot must still hold that handle), so a stale entry only
/// costs the scan it would have saved. Node pages are freed only in
/// `teardown`, which clears the instance's hints, so a hint always points
/// into a live node page. Without it every read, write and page fault of a
/// file scanned all nodes: rustc mapping its 150 MB driver library from a
/// domain with tens of thousands of files took minutes.
struct NodeHints(UnsafeCell<[BTreeMap<u64, usize>; INSTANCE_LIMIT]>);

unsafe impl Sync for NodeHints {}

static NODE_HINTS: NodeHints =
    NodeHints(UnsafeCell::new([const { BTreeMap::new() }; INSTANCE_LIMIT]));

/// The current instance's node hints. The overlay's own state has the same
/// owner: whoever runs the instance's file system calls.
fn node_hints() -> &'static mut BTreeMap<u64, usize> {
    let index = current_instance();
    // SAFETY: as for `live_mut`: one instance's overlay is used by one
    // caller at a time.
    unsafe { &mut *NODE_HINTS.0.get().cast::<BTreeMap<u64, usize>>().add(index) }
}

/// Every path an instance's nodes were ever given, by `path_key`, with
/// where that node was last found (0 when not yet looked up). A path
/// missing here names no node, which spares path lookups of files that do
/// not exist (the dynamic loader's, cargo's while it unpacks crates) a scan
/// of every node; a present one is checked like a node hint. Every place
/// that gives a node a path notes it (`note_path`); teardown clears them.
static PATH_HINTS: NodeHints =
    NodeHints(UnsafeCell::new([const { BTreeMap::new() }; INSTANCE_LIMIT]));

fn path_hints() -> &'static mut BTreeMap<u64, usize> {
    let index = current_instance();
    // SAFETY: as for `node_hints`.
    unsafe { &mut *PATH_HINTS.0.get().cast::<BTreeMap<u64, usize>>().add(index) }
}

/// FNV-1a of `path`; two paths may share a key, which costs a scan.
fn path_key(path: &[u8]) -> u64 {
    path.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Records that a node now has the name `path`.
fn note_path(path: &[u8]) {
    path_hints().entry(path_key(path)).or_insert(0);
}

fn node_mut(handle: Handle) -> Option<&'static mut Node> {
    let overlay = live_mut();
    let hints = node_hints();
    if let Some(address) = hints.get(&handle.inode).copied() {
        // SAFETY: hints point at node slots in this instance's node pages,
        // which stay allocated until `teardown` clears the hints.
        let node = unsafe { &mut *(address as *mut Node) };
        if node.active && node.handle == handle {
            return Some(node);
        }
    }
    let mut page = overlay.first_node_page;
    while page != FrameLease::EMPTY {
        let nodes = node_page_mut(page)?;
        if let Some(index) = nodes
            .nodes
            .iter()
            .position(|node| node.active && node.handle == handle)
        {
            let node = nodes.nodes.get_mut(index)?;
            hints.insert(handle.inode, core::ptr::from_mut(node) as usize);
            return Some(node);
        }
        page = nodes.next;
    }
    None
}

fn for_each_node<T>(
    overlay: &Overlay,
    mut select: impl FnMut(&'static Node) -> Option<T>,
) -> Option<T> {
    let mut page = overlay.first_node_page;
    while page != FrameLease::EMPTY {
        let nodes = node_page(page)?;
        for node in &nodes.nodes {
            if node.active {
                if let Some(value) = select(node) {
                    return Some(value);
                }
            }
        }
        page = nodes.next;
    }
    None
}

fn node_page(page: FrameLease) -> Option<&'static NodePage> {
    let address = page.direct_map_address()?;
    Some(unsafe { &*(address as *const NodePage) })
}

fn node_page_mut(page: FrameLease) -> Option<&'static mut NodePage> {
    let address = page.direct_map_address()?;
    Some(unsafe { &mut *(address as *mut NodePage) })
}

fn mapping_page(page: FrameLease) -> Option<&'static MappingPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &*(address as *const MappingPage) })
}

fn mapping_page_mut(page: FrameLease) -> Option<&'static mut MappingPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &mut *(address as *mut MappingPage) })
}

fn data_page(page: FrameLease) -> Option<&'static DataPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &*(address as *const DataPage) })
}

fn data_page_mut(page: FrameLease) -> Option<&'static mut DataPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &mut *(address as *mut DataPage) })
}

fn xattr_page(page: FrameLease) -> Option<&'static XattrPage> {
    (page != FrameLease::EMPTY).then_some(())?;
    let address = page.direct_map_address()?;
    Some(unsafe { &*(address as *const XattrPage) })
}

fn live() -> Option<&'static Overlay> {
    let index = current_instance();
    Some(unsafe { &*OVERLAY_RUNTIME.0.get().cast::<Overlay>().add(index) })
}

fn live_mut() -> &'static mut Overlay {
    let index = current_instance();
    unsafe { &mut *OVERLAY_RUNTIME.0.get().cast::<Overlay>().add(index) }
}

fn current_instance() -> usize {
    cpu::current_container_slot().unwrap_or(HOST_INSTANCE)
}
