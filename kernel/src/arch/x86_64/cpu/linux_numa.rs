//! NUMA, as a Linux machine with one memory node shows it: node 0 holds
//! every CPU and all memory (`/sys/devices/system/node/node0`), and the
//! memory policy calls (mm/mempolicy.c, mm/migrate.c) take and report
//! policies with Linux's checks and errors in Linux's order. A process's
//! policy (set_mempolicy) is inherited across fork and kept across exec;
//! an area's (mbind) lives in its memory area, so it splits, moves and is
//! copied with it. With one node every page is on node 0 whatever the
//! policy says, so moving pages has nothing to do, and a test that needs
//! two nodes finds one, as on a one-node Linux machine.
//!
//! Linux keeps a policy per thread; here a process's threads share one.
//! Mappings the kernel makes itself (the program image, its stack and
//! heap) have no memory area yet, so mbind accepts them but records no
//! policy for them.

use super::*;
use crate::linux_areas::Policy;

/// The nodes Linux was built for (NODES_SHIFT 6, x86-64's default):
/// node masks are one 64-bit word.
const LINUX_MAX_NUMNODES: u64 = 64;
/// The nodes that exist, have memory and CPUs, and every task may use
/// (cpuset_current_mems_allowed): node 0.
const LINUX_NODES_ONLINE: u64 = 1;

const MPOL_DEFAULT: u8 = 0;
const MPOL_PREFERRED: u8 = 1;
const MPOL_BIND: u8 = 2;
const MPOL_INTERLEAVE: u8 = 3;
const MPOL_LOCAL: u8 = 4;
const MPOL_PREFERRED_MANY: u8 = 5;
const MPOL_WEIGHTED_INTERLEAVE: u8 = 6;
const MPOL_MAX: u32 = 7;

const MPOL_F_STATIC_NODES: u16 = 1 << 15;
const MPOL_F_RELATIVE_NODES: u16 = 1 << 14;
const MPOL_F_NUMA_BALANCING: u16 = 1 << 13;
const MPOL_MODE_FLAGS: u16 = MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES | MPOL_F_NUMA_BALANCING;

/// get_mempolicy's flags.
const MPOL_F_NODE: u64 = 1;
const MPOL_F_ADDR: u64 = 2;
const MPOL_F_MEMS_ALLOWED: u64 = 4;

/// mbind's and move_pages's flags.
const MPOL_MF_STRICT: u32 = 1;
const MPOL_MF_MOVE: u32 = 2;
const MPOL_MF_MOVE_ALL: u32 = 4;
const MPOL_MF_VALID: u32 = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_MOVE_ALL;

/// mbind's and set_mempolicy's `mode`: the mode and its flags
/// (sanitize_mpol_flags). EINVAL for an unknown mode, both node-numbering
/// flags, or MPOL_F_NUMA_BALANCING on a mode it does not apply to.
fn linux_policy_mode(mode: u64) -> Result<(u8, u16), u64> {
    let mode = mode as i32 as u32;
    let flags = (mode & u32::from(MPOL_MODE_FLAGS)) as u16;
    let mode = mode & !u32::from(MPOL_MODE_FLAGS);
    if mode >= MPOL_MAX {
        return Err(LINUX_EINVAL);
    }
    let mode = mode as u8;
    if flags & MPOL_F_STATIC_NODES != 0 && flags & MPOL_F_RELATIVE_NODES != 0 {
        return Err(LINUX_EINVAL);
    }
    if flags & MPOL_F_NUMA_BALANCING != 0 && !matches!(mode, MPOL_BIND | MPOL_PREFERRED_MANY) {
        return Err(LINUX_EINVAL);
    }
    Ok((mode, flags))
}

/// Reads `count` bits of a user node mask (get_bitmap): whole words, the
/// last one cut to `count`.
fn linux_read_node_word(address: u64, word: u64, count: u64) -> Result<u64, u64> {
    let mut bytes = [0_u8; 8];
    let source = word
        .checked_mul(8)
        .and_then(|offset| address.checked_add(offset))
        .ok_or(LINUX_EFAULT)?;
    if !copy_from_linux_user(source, &mut bytes) {
        return Err(LINUX_EFAULT);
    }
    let value = u64::from_ne_bytes(bytes);
    Ok(if count.is_multiple_of(64) {
        value
    } else {
        value & ((1 << (count % 64)) - 1)
    })
}

/// The node mask at `address`, `maximum` + 1 bits long, as Linux's
/// get_nodes reads it: none for a null mask or `maximum` of 0 or 1, EINVAL
/// past a page of bits, and bits past the nodes Linux has must be clear
/// (EINVAL), read a word at a time from the end.
fn linux_read_nodes(address: u64, maximum: u64) -> Result<u64, u64> {
    let mut bits = maximum.wrapping_sub(1);
    if bits == 0 || address == 0 {
        return Ok(0);
    }
    if bits > (PAGE_SIZE * 8) as u64 {
        return Err(LINUX_EINVAL);
    }
    while bits > LINUX_MAX_NUMNODES {
        let count = bits.min(64);
        let word = linux_read_node_word(address, (bits - 1) / 64, count)?;
        if bits - count >= LINUX_MAX_NUMNODES {
            bits -= count;
        } else {
            bits = LINUX_MAX_NUMNODES;
        }
        if word != 0 {
            return Err(LINUX_EINVAL);
        }
    }
    linux_read_node_word(address, 0, bits)
}

/// Writes `nodes` to the user mask at `address`, `maximum` - 1 bits long
/// rounded up to words (copy_nodes_to_user): words past the nodes Linux
/// has are cleared first, up to a page (EINVAL beyond).
fn linux_write_nodes(address: u64, maximum: u64, nodes: u64) -> Result<(), u64> {
    let mut copy = maximum.wrapping_sub(1).wrapping_add(63) & !63;
    copy /= 8;
    if copy > 8 {
        if copy > PAGE_SIZE as u64 {
            return Err(LINUX_EINVAL);
        }
        let zeros = [0_u8; 64];
        let mut offset = 8;
        while offset < copy {
            let length = (copy - offset).min(zeros.len() as u64) as usize;
            let target = address.checked_add(offset).ok_or(LINUX_EFAULT)?;
            if !copy_to_linux_user(target, &zeros[..length]) {
                return Err(LINUX_EFAULT);
            }
            offset += length as u64;
        }
        copy = 8;
    }
    let bytes = nodes.to_ne_bytes();
    if copy != 0 && !copy_to_linux_user(address, &bytes[..copy as usize]) {
        return Err(LINUX_EFAULT);
    }
    Ok(())
}

/// The policy `mode` with `flags` makes of the caller's `nodes` (mpol_new
/// and mpol_set_nodemask): MPOL_DEFAULT takes no nodes and is no policy,
/// MPOL_PREFERRED without nodes is MPOL_LOCAL, MPOL_LOCAL takes none, and
/// the others need some. The nodes are cut to those allowed (folded onto
/// them for MPOL_F_RELATIVE_NODES); none left is EINVAL.
fn linux_new_policy(mode: u8, flags: u16, nodes: u64) -> Result<Policy, u64> {
    let numbering = flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0;
    let mode = match mode {
        MPOL_DEFAULT if nodes != 0 => return Err(LINUX_EINVAL),
        MPOL_DEFAULT => return Ok(Policy::DEFAULT),
        MPOL_PREFERRED if nodes == 0 && numbering => return Err(LINUX_EINVAL),
        MPOL_PREFERRED if nodes == 0 => MPOL_LOCAL,
        MPOL_LOCAL if nodes != 0 || numbering => return Err(LINUX_EINVAL),
        MPOL_LOCAL => MPOL_LOCAL,
        _ if nodes == 0 => return Err(LINUX_EINVAL),
        mode => mode,
    };
    let mut policy = Policy {
        mode,
        flags,
        user_nodes: if numbering { nodes } else { 0 },
        ..Policy::DEFAULT
    };
    if mode == MPOL_LOCAL {
        return Ok(policy);
    }
    let allowed = LINUX_NODES_ONLINE;
    let usable = if flags & MPOL_F_RELATIVE_NODES != 0 {
        linux_relative_nodes(nodes, allowed)
    } else {
        nodes & allowed
    };
    if usable == 0 {
        return Err(LINUX_EINVAL);
    }
    policy.nodes = if mode == MPOL_PREFERRED {
        usable.isolate_lowest_one()
    } else {
        usable
    };
    Ok(policy)
}

/// `nodes` read relative to `allowed` (mpol_relative_nodemask): node n is
/// the (n mod |allowed|)th allowed node.
fn linux_relative_nodes(nodes: u64, allowed: u64) -> u64 {
    let weight = allowed.count_ones();
    if weight == 0 {
        return 0;
    }
    let mut relative = 0_u64;
    for node in (0..64).filter(|node| nodes & (1 << node) != 0) {
        let place = node % weight;
        let mut remaining = allowed;
        for _ in 0..place {
            remaining &= remaining - 1;
        }
        relative |= remaining.isolate_lowest_one();
    }
    relative
}

/// What the current process maps at `address` (Linux's vma_lookup): its
/// memory area if it has one, and the area's end, or a mapping the kernel
/// made (which has no area) one page long; None when nothing is mapped.
fn linux_numa_mapping(address: u64) -> Option<(Policy, u64)> {
    if address >= 1 << 47 {
        return None;
    }
    let page = address & !(PAGE_SIZE as u64 - 1);
    if let Some(area) = crate::linux_areas::area_at(
        linux_execution_instance(),
        current_linux_process_pid(),
        page,
    ) {
        return Some((area.policy, area.end));
    }
    address_space::current_linux_runtime_page(page)
        .occupied
        .then_some((Policy::DEFAULT, page + PAGE_SIZE as u64))
}

/// Whether the current process's page at `page` holds memory (as mincore
/// counts it), which is on node 0.
fn linux_numa_page_present(page: u64) -> bool {
    let state = address_space::current_linux_runtime_page(page);
    state.frame.is_some()
        && (!state.shared
            || !linux_anonymous_shared_area(page)
            || address_space::current_linux_page_accessed(page))
}

pub(super) fn linux_set_mempolicy(mode: u64, nodes: u64, maximum_node: u64) -> u64 {
    let result = linux_policy_mode(mode).and_then(|(mode, flags)| {
        let nodes = linux_read_nodes(nodes, maximum_node)?;
        linux_new_policy(mode, flags, nodes)
    });
    match result {
        Ok(policy) => {
            let _ =
                linux_process::set_live_process_memory_policy(current_linux_process_pid(), policy);
            0
        }
        Err(error) => error,
    }
}

pub(super) fn linux_get_mempolicy(
    mode_address: u64,
    nodes_address: u64,
    maximum_node: u64,
    address: u64,
    flags: u64,
) -> u64 {
    match linux_query_mempolicy(nodes_address, maximum_node, address, flags) {
        Ok((mode, nodes)) => {
            if mode_address != 0 && !copy_to_linux_user(mode_address, &mode.to_ne_bytes()) {
                return LINUX_EFAULT;
            }
            if nodes_address != 0 {
                if let Err(error) = linux_write_nodes(nodes_address, maximum_node, nodes) {
                    return error;
                }
            }
            0
        }
        Err(error) => error,
    }
}

/// get_mempolicy's answer (do_get_mempolicy): the mode word and the nodes.
fn linux_query_mempolicy(
    nodes_address: u64,
    maximum_node: u64,
    address: u64,
    flags: u64,
) -> Result<(i32, u64), u64> {
    // A mask must hold every node there is (nr_node_ids, 1).
    if nodes_address != 0 && maximum_node < 1 {
        return Err(LINUX_EINVAL);
    }
    if flags & !(MPOL_F_NODE | MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED) != 0 {
        return Err(LINUX_EINVAL);
    }
    if flags & MPOL_F_MEMS_ALLOWED != 0 {
        if flags & (MPOL_F_NODE | MPOL_F_ADDR) != 0 {
            return Err(LINUX_EINVAL);
        }
        return Ok((0, LINUX_NODES_ONLINE));
    }
    let process_policy = flags & MPOL_F_ADDR == 0;
    let policy = if process_policy {
        if address != 0 {
            return Err(LINUX_EINVAL);
        }
        linux_process::live_process_memory_policy(current_linux_process_pid())
            .unwrap_or(Policy::DEFAULT)
    } else {
        // An area without a policy of its own reports MPOL_DEFAULT, not
        // its process's.
        linux_numa_mapping(address).ok_or(LINUX_EFAULT)?.0
    };
    let mode = if flags & MPOL_F_NODE != 0 {
        if !process_policy {
            // The node of the page there, which a read brings in: node 0,
            // unless the page cannot be read.
            let page = address & !(PAGE_SIZE as u64 - 1);
            if address_space::current_linux_runtime_page(page).protection == 0 {
                return Err(LINUX_EFAULT);
            }
            0
        } else if matches!(policy.mode, MPOL_INTERLEAVE | MPOL_WEIGHTED_INTERLEAVE) {
            // The next node interleaving allocates from.
            policy.nodes.trailing_zeros() as i32
        } else {
            return Err(LINUX_EINVAL);
        }
    } else {
        i32::from(policy.mode) | i32::from(policy.flags & MPOL_MODE_FLAGS)
    };
    let nodes = if policy.flags & (MPOL_F_STATIC_NODES | MPOL_F_RELATIVE_NODES) != 0 {
        policy.user_nodes
    } else {
        policy.nodes
    };
    Ok((mode, nodes))
}

pub(super) fn linux_mbind(
    start: u64,
    length: u64,
    mode: u64,
    nodes: u64,
    maximum_node: u64,
    flags: u64,
) -> u64 {
    match linux_bind_memory(start, length, mode, nodes, maximum_node, flags as u32) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

/// mbind (kernel_mbind, do_mbind): the policy for `[start, start +
/// length)`, every page of which must be mapped unless the policy is
/// MPOL_DEFAULT (which some page must be; EFAULT). MPOL_MF_STRICT without
/// a move asks that no page be on a node outside `nodes` (EIO, and the
/// policy is not set); moving such pages has nothing to do with one node.
fn linux_bind_memory(
    start: u64,
    length: u64,
    mode: u64,
    nodes: u64,
    maximum_node: u64,
    mut flags: u32,
) -> Result<(), u64> {
    let (mode, mode_flags) = linux_policy_mode(mode)?;
    let nodes = linux_read_nodes(nodes, maximum_node)?;
    if flags & !MPOL_MF_VALID != 0 {
        return Err(LINUX_EINVAL);
    }
    if flags & MPOL_MF_MOVE_ALL != 0
        && !linux_has_capability(ginux_credentials::capability::SYS_NICE)
    {
        return Err(LINUX_EPERM);
    }
    if !start.is_multiple_of(PAGE_SIZE as u64) {
        return Err(LINUX_EINVAL);
    }
    if mode == MPOL_DEFAULT {
        flags &= !MPOL_MF_STRICT;
    }
    let length = length.wrapping_add(PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let end = start.wrapping_add(length);
    if end < start {
        return Err(LINUX_EINVAL);
    }
    if end == start {
        return Ok(());
    }
    let policy = linux_new_policy(mode, mode_flags, nodes)?;
    // The default policy may skip holes in the range; others may not.
    let holes_allowed = policy.is_default();
    let strict = flags & MPOL_MF_STRICT != 0;
    let moving = flags & (MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0;
    let mut mapped_any = false;
    let mut address = start;
    // Each mapping in turn (queue_pages_range): a hole before it or after
    // it, then a misplaced page in it, ends the walk.
    while address < end {
        let Some((_, mapping_end)) = linux_numa_mapping(address) else {
            if !holes_allowed {
                return Err(LINUX_EFAULT);
            }
            address += PAGE_SIZE as u64;
            continue;
        };
        mapped_any = true;
        let mapping_end = mapping_end.min(end);
        if !holes_allowed && mapping_end < end && linux_numa_mapping(mapping_end).is_none() {
            return Err(LINUX_EFAULT);
        }
        // A page on node 0 is misplaced when the caller's nodes leave
        // node 0 out.
        if strict
            && !moving
            && nodes & 1 == 0
            && (address..mapping_end)
                .step_by(PAGE_SIZE)
                .any(linux_numa_page_present)
        {
            return Err(LINUX_EIO);
        }
        address = mapping_end;
    }
    if !mapped_any {
        return Err(LINUX_EFAULT);
    }
    crate::linux_areas::set_policy(
        linux_execution_instance(),
        current_linux_process_pid(),
        start,
        end,
        policy,
    );
    Ok(())
}

pub(super) fn linux_set_mempolicy_home_node(
    start: u64,
    length: u64,
    home_node: u64,
    flags: u64,
) -> u64 {
    match linux_set_home_node(start, length, home_node, flags) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

/// set_mempolicy_home_node: the home node of the MPOL_BIND and
/// MPOL_PREFERRED_MANY policies of the areas in the range. ENOENT when no
/// area there has a policy, EOPNOTSUPP at one with another mode (areas
/// before it keep their new home node, as in Linux).
fn linux_set_home_node(start: u64, length: u64, home_node: u64, flags: u64) -> Result<(), u64> {
    if !start.is_multiple_of(PAGE_SIZE as u64) || flags != 0 {
        return Err(LINUX_EINVAL);
    }
    if home_node >= LINUX_MAX_NUMNODES || LINUX_NODES_ONLINE & (1 << home_node) == 0 {
        return Err(LINUX_EINVAL);
    }
    let length = length.wrapping_add(PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let end = start.wrapping_add(length);
    if end < start {
        return Err(LINUX_EINVAL);
    }
    if end == start {
        return Ok(());
    }
    let (instance, pid) = (linux_execution_instance(), current_linux_process_pid());
    let mut result = Err(LINUX_ENOENT);
    for (piece_start, piece_end, policy) in
        crate::linux_areas::policies_in(instance, pid, start, end)
    {
        if policy.is_default() {
            continue;
        }
        if !matches!(policy.mode, MPOL_BIND | MPOL_PREFERRED_MANY) {
            return Err(LINUX_EOPNOTSUPP);
        }
        let policy = Policy {
            home_node: Some(home_node as u8),
            ..policy
        };
        crate::linux_areas::set_policy(instance, pid, piece_start, piece_end, policy);
        result = Ok(());
    }
    result
}

/// The process `pid` names for migrate_pages and move_pages (0: the
/// caller): ESRCH for none, EPERM when the caller may not look into it
/// (ptrace_may_access), EINVAL when it has no memory (a zombie).
fn linux_numa_target(pid: u64) -> Result<u32, u64> {
    let pid = pid as i32;
    let caller = current_linux_process_pid();
    if pid == 0 {
        return Ok(caller);
    }
    let pid = u32::try_from(pid).map_err(|_| LINUX_ESRCH)?;
    let status = linux_process::live_process_status(pid).ok_or(LINUX_ESRCH)?;
    if !linux_ptrace_access_permitted(pid) {
        return Err(LINUX_EPERM);
    }
    if !status.state.is_running() {
        return Err(LINUX_EINVAL);
    }
    Ok(pid)
}

pub(super) fn linux_migrate_pages(
    pid: u64,
    maximum_node: u64,
    old_nodes: u64,
    new_nodes: u64,
) -> u64 {
    match linux_migrate_process_pages(pid, maximum_node, old_nodes, new_nodes) {
        Ok(()) => 0,
        Err(error) => error,
    }
}

/// migrate_pages (kernel_migrate_pages): moving a process's pages from
/// `old_nodes` to `new_nodes`, which must hold a node it may use. Without
/// CAP_SYS_NICE the new nodes must all be ones the process may use
/// (EPERM). Every page is already on node 0, so none is left behind.
fn linux_migrate_process_pages(
    pid: u64,
    maximum_node: u64,
    old_nodes: u64,
    new_nodes: u64,
) -> Result<(), u64> {
    let _old = linux_read_nodes(old_nodes, maximum_node)?;
    let new = linux_read_nodes(new_nodes, maximum_node)?;
    let pid = pid as i32;
    if pid != 0 {
        let target = u32::try_from(pid).map_err(|_| LINUX_ESRCH)?;
        linux_process::live_process_status(target).ok_or(LINUX_ESRCH)?;
        if !linux_ptrace_access_permitted(target) {
            return Err(LINUX_EPERM);
        }
    }
    if new & !LINUX_NODES_ONLINE != 0
        && !linux_has_capability(ginux_credentials::capability::SYS_NICE)
    {
        return Err(LINUX_EPERM);
    }
    if new & LINUX_NODES_ONLINE == 0 {
        return Err(LINUX_EINVAL);
    }
    linux_numa_target(u64::from(pid as u32)).map(|_| ())
}

pub(super) fn linux_move_pages(
    pid: u64,
    count: u64,
    pages: u64,
    nodes: u64,
    status: u64,
    flags: u64,
) -> u64 {
    match linux_move_process_pages(pid, count, pages, nodes, status, flags as i32) {
        Ok(left) => left,
        Err(error) => error,
    }
}

/// Whether `page` of process `pid` is mapped, and then whether it holds
/// memory: None for no mapping (EFAULT in a status), Some(false) for a
/// page not brought in yet (ENOENT).
fn linux_process_page(pid: u32, page: u64) -> Option<bool> {
    if page >= 1 << 47 {
        return None;
    }
    if pid == current_linux_process_pid() {
        return linux_numa_mapping(page).map(|_| linux_numa_page_present(page));
    }
    let present = linux_process::live_process_range_mapped(pid, page, PAGE_SIZE, false);
    (present || crate::linux_areas::area_at(linux_execution_instance(), pid, page).is_some())
        .then_some(present)
}

/// move_pages (kernel_move_pages): where the `count` pages listed at
/// `pages` are, or, with `nodes`, moving each to its node. A page's status
/// is its node (0), -ENOENT for one not brought in, or -EFAULT for one not
/// mapped; a node other than 0 ends the call with ENODEV.
fn linux_move_process_pages(
    pid: u64,
    count: u64,
    pages: u64,
    nodes: u64,
    status: u64,
    flags: i32,
) -> Result<u64, u64> {
    let flags = flags as u32;
    if flags & !(MPOL_MF_MOVE | MPOL_MF_MOVE_ALL) != 0 {
        return Err(LINUX_EINVAL);
    }
    if flags & MPOL_MF_MOVE_ALL != 0
        && !linux_has_capability(ginux_credentials::capability::SYS_NICE)
    {
        return Err(LINUX_EPERM);
    }
    let pid = linux_numa_target(pid)?;
    let read_word = |address: u64, index: u64, size: u64| -> Result<u64, u64> {
        let mut bytes = [0_u8; 8];
        let source = index
            .checked_mul(size)
            .and_then(|offset| address.checked_add(offset))
            .ok_or(LINUX_EFAULT)?;
        if !copy_from_linux_user(source, &mut bytes[..size as usize]) {
            return Err(LINUX_EFAULT);
        }
        Ok(u64::from_ne_bytes(bytes))
    };
    let write_status = |index: u64, value: i32| -> Result<(), u64> {
        let target = index
            .checked_mul(4)
            .and_then(|offset| status.checked_add(offset))
            .ok_or(LINUX_EFAULT)?;
        if copy_to_linux_user(target, &value.to_ne_bytes()) {
            Ok(())
        } else {
            Err(LINUX_EFAULT)
        }
    };
    let page_status = |address: u64| -> i32 {
        match linux_process_page(pid, address & !(PAGE_SIZE as u64 - 1)) {
            Some(true) => 0,
            // The errors are -errno, as a status holds them.
            Some(false) => LINUX_ENOENT as i64 as i32,
            None => LINUX_EFAULT as i64 as i32,
        }
    };
    for index in 0..count {
        let address = read_word(pages, index, 8)?;
        if nodes != 0 {
            let node = read_word(nodes, index, 4)? as u32 as i32;
            // A node that is not, or has no memory: only node 0 is.
            if node < 0
                || node as u64 >= LINUX_MAX_NUMNODES
                || LINUX_NODES_ONLINE & (1 << node) == 0
            {
                return Err(LINUX_ENODEV);
            }
        }
        // Already on its node, or why it could not be looked at.
        write_status(index, page_status(address))?;
    }
    Ok(0)
}

/// The NUMA node directory of sysfs.
const LINUX_NODE_SYSFS: &[u8] = b"sys/devices/system/node";

/// The node files of sysfs, under `LINUX_NODE_SYSFS`, with what they hold
/// until `linux_refresh_numa_sysfs` writes the live ones.
const LINUX_NODE_SYSFS_FILES: [(&[u8], &[u8]); 11] = [
    (b"online", b"0\n"),
    (b"possible", b"0\n"),
    (b"has_memory", b"0\n"),
    (b"has_normal_memory", b"0\n"),
    (b"has_cpu", b"0\n"),
    (b"node0/cpumap", b"1\n"),
    (b"node0/cpulist", b"0\n"),
    // A node's distance to itself, Linux's LOCAL_DISTANCE.
    (b"node0/distance", b"10\n"),
    (b"node0/meminfo", b""),
    (
        b"node0/numastat",
        b"numa_hit 0\nnuma_miss 0\nnuma_foreign 0\ninterleave_hit 0\nlocal_node 0\nother_node 0\n",
    ),
    (b"node0/vmstat", b"nr_free_pages 0\n"),
];

/// `LINUX_NODE_SYSFS`/`name`.
fn linux_node_sysfs_path(name: &[u8]) -> Vec<u8> {
    let mut path = Vec::new();
    path.extend_from_slice(LINUX_NODE_SYSFS);
    path.push(b'/');
    path.extend_from_slice(name);
    path
}

/// A domain starts: `/sys/devices/system/node` shows node 0, online, with
/// the domain's CPUs and memory.
pub(super) fn linux_prepare_numa_sysfs() {
    for directory in [
        &b"sys"[..],
        b"sys/devices",
        b"sys/devices/system",
        LINUX_NODE_SYSFS,
        b"sys/devices/system/node/node0",
    ] {
        if crate::linux_overlay::lookup(directory).is_none()
            && crate::published_rootfs::exact_entry(directory).is_none()
        {
            if let Some(handle) = crate::linux_overlay::create_directory(directory, 0o755) {
                let _ = crate::linux_overlay::set_owner(handle, 0, 0);
            }
        }
    }
    for (name, contents) in LINUX_NODE_SYSFS_FILES {
        let path = linux_node_sysfs_path(name);
        if crate::linux_overlay::lookup(&path).is_none() {
            if let Some(handle) = crate::linux_overlay::create_file(&path, 0o444, contents) {
                let _ = crate::linux_overlay::set_owner(handle, 0, 0);
            }
        }
    }
    linux_refresh_numa_sysfs();
}

/// Replaces the text of the node file `name`.
fn linux_write_node_file(name: &[u8], text: &[u8]) {
    let path = linux_node_sysfs_path(name);
    if let Some(metadata) = crate::linux_overlay::lookup(&path) {
        let _ = crate::linux_overlay::truncate(metadata.handle, 0)
            && crate::linux_overlay::write(metadata.handle, 0, text) == Some(text.len());
    }
}

/// Rewrites node 0's CPU and memory files with what the domain has now; a
/// walk to a path under `LINUX_NODE_SYSFS` does this.
pub(super) fn linux_refresh_numa_sysfs() {
    let cpus = linux_available_cpu_mask();
    let cpu_count = linux_available_cpu_count() as u32;
    let mut cpumap = linux_bitmap_text(cpus, cpu_count);
    cpumap.push(b'\n');
    linux_write_node_file(b"node0/cpumap", &cpumap);
    let mut cpulist = linux_bitmap_list(cpus);
    cpulist.push(b'\n');
    linux_write_node_file(b"node0/cpulist", &cpulist);
    let (total, free) = linux_domain_frame_counts();
    let (total, free) = (total * 4, free * 4);
    let used = total - free;
    let huge = linux_huge_page_counts();
    let mut meminfo = alloc::format!(
        "Node 0 MemTotal:       {total:>8} kB\nNode 0 MemFree:        {free:>8} kB\n\
         Node 0 MemUsed:        {used:>8} kB\nNode 0 SwapCached:     {zero:>8} kB\n\
         Node 0 Active:         {used:>8} kB\nNode 0 Inactive:       {zero:>8} kB\n\
         Node 0 Active(anon):   {used:>8} kB\nNode 0 Inactive(anon): {zero:>8} kB\n\
         Node 0 Active(file):   {zero:>8} kB\nNode 0 Inactive(file): {zero:>8} kB\n\
         Node 0 Unevictable:    {zero:>8} kB\nNode 0 Mlocked:        {zero:>8} kB\n\
         Node 0 Dirty:          {zero:>8} kB\nNode 0 Writeback:      {zero:>8} kB\n\
         Node 0 FilePages:      {zero:>8} kB\nNode 0 Mapped:         {zero:>8} kB\n\
         Node 0 AnonPages:      {used:>8} kB\nNode 0 Shmem:          {zero:>8} kB\n\
         Node 0 KernelStack:    {zero:>8} kB\nNode 0 PageTables:     {zero:>8} kB\n\
         Node 0 SecPageTables:  {zero:>8} kB\nNode 0 NFS_Unstable:   {zero:>8} kB\n\
         Node 0 Bounce:         {zero:>8} kB\nNode 0 WritebackTmp:   {zero:>8} kB\n\
         Node 0 KReclaimable:   {zero:>8} kB\nNode 0 Slab:           {zero:>8} kB\n\
         Node 0 SReclaimable:   {zero:>8} kB\nNode 0 SUnreclaim:     {zero:>8} kB\n\
         Node 0 HugePages_Total: {huge_total:>5}\nNode 0 HugePages_Free:  {huge_free:>5}\n\
         Node 0 HugePages_Surp:  {huge_surplus:>5}\n",
        zero = 0,
        huge_total = huge.total,
        huge_free = huge.free,
        huge_surplus = huge.surplus,
    )
    .into_bytes();
    meminfo.shrink_to_fit();
    linux_write_node_file(b"node0/meminfo", &meminfo);
    let vmstat = alloc::format!("nr_free_pages {}\n", free / 4);
    linux_write_node_file(b"node0/vmstat", vmstat.as_bytes());
}

/// `mask`, `bits` wide, as Linux's `%*pb` prints a bitmap: hex in 32-bit
/// groups separated by commas, the first as wide as its bits need.
pub(super) fn linux_bitmap_text(mask: u64, bits: u32) -> Vec<u8> {
    let bits = bits.clamp(1, 64);
    let mut text = Vec::new();
    let groups = bits.div_ceil(32);
    for group in (0..groups).rev() {
        let width = if group == groups - 1 && !bits.is_multiple_of(32) {
            (bits % 32).div_ceil(4)
        } else {
            8
        };
        let value = (mask >> (group * 32)) & 0xffff_ffff;
        for digit in (0..width).rev() {
            text.push(b"0123456789abcdef"[((value >> (digit * 4)) & 0xf) as usize]);
        }
        if group != 0 {
            text.push(b',');
        }
    }
    text
}

/// `mask` as Linux's `%*pbl` prints a bitmap: ranges such as `0-3,6`.
pub(super) fn linux_bitmap_list(mask: u64) -> Vec<u8> {
    let mut text = Vec::new();
    let mut bit = 0_u32;
    while bit < 64 {
        if mask & (1 << bit) == 0 {
            bit += 1;
            continue;
        }
        let first = bit;
        while bit + 1 < 64 && mask & (1 << (bit + 1)) != 0 {
            bit += 1;
        }
        if !text.is_empty() {
            text.push(b',');
        }
        text.extend_from_slice(alloc::format!("{first}").as_bytes());
        if bit != first {
            text.extend_from_slice(alloc::format!("-{bit}").as_bytes());
        }
        bit += 1;
    }
    text
}

/// The CPU and node lines of `/proc/PID/status` for a process allowed
/// `cpus`: Cpus_allowed, Cpus_allowed_list, Mems_allowed and
/// Mems_allowed_list.
pub(super) fn linux_allowed_status(cpus: u64) -> Vec<u8> {
    let mut text = Vec::new();
    text.extend_from_slice(b"Cpus_allowed:\t");
    text.extend_from_slice(&linux_bitmap_text(cpus, linux_available_cpu_count() as u32));
    text.extend_from_slice(b"\nCpus_allowed_list:\t");
    text.extend_from_slice(&linux_bitmap_list(cpus));
    text.extend_from_slice(b"\nMems_allowed:\t");
    text.extend_from_slice(&linux_bitmap_text(
        LINUX_NODES_ONLINE,
        LINUX_MAX_NUMNODES as u32,
    ));
    text.extend_from_slice(b"\nMems_allowed_list:\t");
    text.extend_from_slice(&linux_bitmap_list(LINUX_NODES_ONLINE));
    text.push(b'\n');
    text
}

/// The boot check of the policy calls: Linux's first errors, and a policy
/// set and read back.
pub(super) fn verify_linux_numa_syscalls() -> bool {
    let saved = linux_process::live_process_memory_policy(current_linux_process_pid());
    let checks = linux_policy_mode(u64::from(MPOL_MAX)) == Err(LINUX_EINVAL)
        && linux_new_policy(MPOL_DEFAULT, 0, 1) == Err(LINUX_EINVAL)
        && linux_new_policy(MPOL_BIND, 0, 0) == Err(LINUX_EINVAL)
        && linux_new_policy(MPOL_BIND, 0, 2) == Err(LINUX_EINVAL)
        && linux_new_policy(MPOL_PREFERRED, 0, 0).map(|policy| policy.mode) == Ok(MPOL_LOCAL)
        && linux_new_policy(MPOL_INTERLEAVE, MPOL_F_RELATIVE_NODES, 6)
            .is_ok_and(|policy| policy.nodes == 1 && policy.user_nodes == 6)
        // Nodes 1 and 3 fold onto the second of nodes 1 and 2.
        && linux_relative_nodes(0b1010, 0b0110) == 0b0100
        && linux_relative_nodes(0b0011, 0b0110) == 0b0110
        && linux_bitmap_text(0xf, 4) == b"f"
        && linux_bitmap_text(1, 64) == b"00000000,00000001"
        && linux_bitmap_list(0b1110_1011) == b"0-1,3,5-7"
        && linux_query_mempolicy(0, 0, 0, MPOL_F_MEMS_ALLOWED) == Ok((0, 1))
        && linux_query_mempolicy(0, 0, 0, MPOL_F_MEMS_ALLOWED | MPOL_F_NODE) == Err(LINUX_EINVAL)
        && linux_query_mempolicy(0, 0, 1, 0) == Err(LINUX_EINVAL)
        && linux_query_mempolicy(0, 0, 0, MPOL_F_ADDR) == Err(LINUX_EFAULT)
        && linux_set_mempolicy(u64::from(MPOL_DEFAULT), 0, 0) == 0
        && linux_query_mempolicy(0, 0, 0, 0) == Ok((0, 0))
        && linux_query_mempolicy(0, 0, 0, MPOL_F_NODE) == Err(LINUX_EINVAL)
        && linux_set_home_node(1, PAGE_SIZE as u64, 0, 0) == Err(LINUX_EINVAL)
        && linux_set_home_node(0, PAGE_SIZE as u64, 1, 0) == Err(LINUX_EINVAL)
        && linux_migrate_process_pages(0, u64::MAX, 0, 0) == Err(LINUX_EINVAL)
        && linux_move_process_pages(0, 0, 0, 0, 0, 1) == Err(LINUX_EINVAL);
    if let Some(policy) = saved {
        let _ = linux_process::set_live_process_memory_policy(current_linux_process_pid(), policy);
    }
    checks
}
