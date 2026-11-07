# Linux x86-64 Userspace Compatibility Matrix

This document is the compatibility ledger for running unmodified Linux x86-64
userspace on Ginux. It records the target contract, the current implementation,
and the remaining work. It is an index, not a substitute for the detailed
behavioral specifications and tests.

## Contract and authorities

There is no single document that defines the complete Linux userspace ABI.
Ginux uses this authority order:

1. The pinned [Linux v6.12 x86-64 syscall table](https://github.com/torvalds/linux/blob/v6.12/arch/x86/entry/syscalls/syscall_64.tbl)
   defines native x86-64 syscall names and numbers.
2. Linux [UAPI headers](https://github.com/torvalds/linux/tree/v6.12/include/uapi)
   define userspace-visible constants, flags, structures, ioctl encodings, and
   filesystem interfaces.
3. The [Linux man-pages project](https://www.kernel.org/doc/man-pages/)
   defines expected syscall behavior, errors, and observable semantics.
4. The [x86-64 psABI](https://gitlab.com/x86-psABIs/x86-64-ABI)
   and System V generic ABI define ELF, relocation, process-entry, calling,
   register, stack, and TLS conventions.
5. Linux's documented [stable ABI](https://www.kernel.org/doc/html/latest/admin-guide/abi-stable.html),
   procfs/sysfs documentation, and behavior verified by Linux selftests define
   the remaining observable kernel/userspace interfaces.

The baseline is native 64-bit x86-64 Linux v6.12. The x32 and i386 compatibility
ABIs are out of scope. Moving the baseline requires an explicit review of the
new syscall table and UAPI changes.

## Status rules

| Status | Meaning |
|---|---|
| Complete | Matches the pinned Linux contract and has positive, negative, and edge-case conformance tests. |
| Partial | Dispatched and useful, but intentionally bounded or not yet proven equivalent to Linux. |
| Policy-denied | Recognized as a privileged operation and rejected by the container authority policy. This is not full syscall support. |
| Missing | Returns `-ENOSYS` through the default dispatcher. |

Detailed bounded behavior for implemented calls lives in
[Linux Syscall Entry v0](../specs/kernel/linux-syscall-v0.md).
The matrix must be updated in the same commit whenever syscall dispatch or its
documented behavior changes.

Current totals: **91 Complete**, **250 Partial**, **34 Policy-denied**, **0 Missing**.

## Current stopping point

The syscall table is fully dispatched: no pinned x86-64 syscall currently
falls through to `ENOSYS`. The current tranche also supports cross-process
signal delivery to saved fork peers and generation-bound pidfds for any live
process, including signal-zero probes, queued user `siginfo`, zombie
readiness, stale-identity rejection, and nonblocking or non-consuming
`waitid(P_PIDFD)` observation of child lifecycle state. Permitted live peers
also support cross-process memory transfer and comparison of fork-distinct
kernel resource tables.

This is a useful implementation checkpoint, not full Linux conformance. The
next work should prioritize behavior inside the existing Partial entries:
general concurrent process/thread dispatch and blocking process waits; complete
signal selection, job control, restart, and permission semantics; the broader
ptrace access model and remote-object operations needed by `process_madvise`
and `process_mrelease`, plus cross-process `pidfd_getfd` for sockets and special
event descriptors; general file-backed
shared mappings; broader procfs, sysfs, and cgroup surfaces; IPv6 and
interruptible network waits; wider ELF,
loader, NSS, and locale coverage; and end-to-end systemd and package-manager
workloads. Each tranche should promote entries to Complete only after its
positive, negative, lifecycle, and cleanup tests pass.

## Non-syscall ABI surfaces

| Surface | Status | Current boundary |
|---|---|---|
| x86-64 `SYSCALL` entry and return | Partial | Native register convention and `-errno` returns; bounded context validation. |
| ELF64 loading | Partial | `ET_EXEC` and dynamically interpreted `ET_DYN` use bounded program-header and relocation profiles. Linux static PIE (`ET_DYN` without `PT_INTERP`, including Rocky's `ldconfig`) remains unsupported and is rejected with `ENOEXEC`; see [Linux ELF64 Profile v0](../specs/kernel/linux-elf-v0.md). |
| Initial stack and auxiliary vector | Partial | Bounded argv/envp, selected `AT_*` entries, kernel-provided `AT_RANDOM` and `AT_SYSINFO_EHDR`, and a one-page initial runtime stack that grows downward on demand. |
| Dynamic loader and shared objects | Partial | Unmodified Alpine/musl and Rocky 10/glibc shells load. Rocky's dynamic coreutils `cat` and `ls` execute from the OCI root. Broader dependency, relocation, locale, and NSS coverage remains incomplete. |
| TLS | Partial | Bounded static TLS and `arch_prctl` FS-base support. |
| Process and thread model | Partial | `waitid` reports exited children only with `WEXITED`, so a `WSTOPPED`-only poll no longer reaps a child another waiter owns. When a domain's init exits, the domain's other processes are killed (as when a PID namespace's init exits) and the domain shuts down cleanly. Repeated fork/exec/exit/wait works for Rocky shells. Fork preserves parent memory, descriptor, nice, and I/O-priority state. Fork shares private pages copy-on-write. The frame allocator keeps a map count per page, as Linux does: fork and vfork count the child's mappings, and a page is freed only when its last mapping goes (munmap, `MADV_DONTNEED`, a copy-on-write copy, an `mprotect` that makes a shared page writable, exec or exit); the last mapping writes a copy-on-write page in place. Exit releases what the process's page tables map, so a process killed by a signal frees its pages too. `MADV_WIPEONFORK` is honored only by eager-copy forks. Process, process-group, session, and pidfd selectors use Linux's 32-bit PID/flag conversions. `wait4` selects an exact PID, any child, the caller's process group, or an explicit process group; `waitid` supports the corresponding `P_ALL`, `P_PID`, and zero/explicit `P_PGID` forms. Stopped and continued child events have Linux status encodings, option filtering, one-shot consumption, and procfs stopped-state reporting. `waitid(P_PIDFD)` selects a generation-bound child, reports `EAGAIN` for a running child through a nonblocking pidfd, supports `WNOHANG` and repeatable `WNOWAIT` observation, and rejects non-child, stale, and non-pidfd selectors. `getpriority`/`setpriority` and `ioprio_get`/`ioprio_set` persist per-process values and implement process, process-group, and real-UID selection; admitted runnable processes feed nice values into priority selection. `process_vm_readv`/`process_vm_writev` transfer between the caller and a live same-domain process when both processes share a user namespace, the caller's real IDs match all target real/effective/saved IDs, and the target is dumpable. Transfers use the target's actual generation-bound page mappings, enforce mapping availability and target write permission, validate complete remote iov elements before mutation, and retain Linux partial progress across vector elements. Cross-domain access and capability-based ptrace overrides remain unavailable. `kcmp` compares VM, descriptor-table, filesystem, signal-handler, I/O, SysV semaphore-undo, and generation-safe open-file-description identity across permitted live processes. Descriptor identities survive `dup` and fork, are cleared on close, and cannot alias after descriptor-number reuse. File positions belong to the open-file description, remain shared across `dup` and fork, and remain distinct for separate opens. Per-thread `rseq` registration supports original and extended lengths, Linux error precedence, CPU/node/mm-CID publication, matching unregister, and lifecycle cleanup; migration and critical-section abort semantics remain pending. Scheduler-backed suspension for a blocking wait on a still-running child, signal-driven job-control transitions, proportional nice weighting, non-root priority permission proofs, I/O-priority influence on physical scheduling, COW runtime re-enable, and general Linux scheduling semantics remain incomplete. |
| Signals | Partial | Handlers registered with `SA_RESTART`, `SA_NOCLDSTOP` or `SA_NOCLDWAIT` are delivered; an interrupted blocking call still returns `EINTR` rather than restarting. Selected standard and real-time signal, mask, alternate-stack, queued delivery with Linux-compatible `si_signo`, `si_code`, `sigval`, sender PID/UID, delivery, and return behavior. Linux's x86-64 default terminate/core, ignore, and running-process `SIGCONT` dispositions are enforced; job-control stop/resume state is pending. `kill` implements exact-PID, caller-process-group, selected-process-group, and all-eligible-process selectors with same-user-namespace UID checks plus same-session `SIGCONT`; `rt_sigqueueinfo` supports permitted process-directed cross-process queuing and rejects userspace attempts to forge kernel-origin `si_code` values. `tgkill`, `tkill`, and `rt_tgsigqueueinfo` resolve a live fork peer's saved main-thread identity and queue into its thread-private pending queue; the ring-3 test verifies `tgkill` delivery, `SI_TKILL`, and sender PID/UID across the process switch. `pidfd_open` creates a generation-bound reference to any live peer; `pidfd_send_signal` supports signal-zero probes and queued user `siginfo`, and pidfd polling reports zombie readiness or a stale-identity hangup. Permitted live peers support `pidfd_getfd` for regular files and console descriptors with close-on-exec and preserved open-file identity; sockets and special event descriptors remain pending until their backing state is independently saved per process. Signal, PID/TID, and mask-operation selectors follow Linux's 32-bit UAPI conversions. Process-shared and thread-private pending queues are distinct, demand-allocated, release empty storage, coalesce standard signals, and preserve multiple real-time instances in FIFO order across `rt_sigpending`, `rt_sigtimedwait`, queued delivery, and `signalfd`. Fork starts with empty pending queues, exec preserves them, and thread/process exit releases them. Arbitrary noncurrent multithreaded-process targeting, `CAP_KILL` and hierarchical user-namespace permission semantics, complete process-directed selection among concurrently scheduled threads, job-control state, restart/nesting semantics, full post-reap pidfd reference semantics, and capability-based ptrace overrides remain incomplete. |
| VFS and path lookup | Partial | Immutable OCI lower root with a demand-allocated, per-domain RAM overlay, directories, symlinks, FIFO metadata, cwd, tmpfs, devfs, procfs subsets, and frame-chained extended attributes. Overlay file and xattr data grow by allocating frames rather than stopping at a fixed aggregate cache ceiling; open-unlinked objects live through their descriptors, directory renames include descendants, and permission/ownership operations cover the package-manager path. Generation-stable OCI and overlay file handles support size discovery, mount IDs, rename-stable reopening, and `O_PATH`; procfs and other virtual filesystems do not export handles. `cachestat` reports RAM-resident pages for regular OCI/overlay files. `memfd_create` provides elastic anonymous files, `MFD_CLOEXEC`, inode-wide `F_GET_SEALS`/`F_ADD_SEALS`, Linux's default `F_SEAL_SEAL`, and write/grow/shrink/future-write/execute seal enforcement across duplicated descriptors. `memfd_secret` provides anonymous shared mappings that reject kernel user-copy and descriptor I/O, but direct-map removal, coherent repeated mappings, demand allocation, locked-memory accounting, and fork inheritance remain pending. `mknod`/`mknodat` create regular files, FIFOs and (for root) device files, which open only the kernel's null, zero and console devices (others are `ENXIO`). Hard links are names sharing one file (data, owner, mode, inode, link count). Path walks follow the overlay's symlinks among directories and, where the call follows links, at the last component, up to 40 links (`ELOOP`); user paths may be up to `PATH_MAX` long, though a resolved path is limited to 255 bytes. `renameat2` supports `RENAME_NOREPLACE` and `RENAME_EXCHANGE`. Named FIFOs support shared nonblocking reader/writer opens, descriptor flags, byte transfer, and lifecycle cleanup; blocking-open, endpoint-count, and complete `SIGPIPE` semantics remain incomplete. `O_TMPFILE` makes an unnamed file in a directory, linkable later with `linkat(AT_EMPTY_PATH)` or `/proc/self/fd/N` unless `O_EXCL`; `openat2` honors its `RESOLVE_*` flags (beneath, in-root, no symlinks, no magic links, no cross-device, cached) through a restricted walk; `fchmodat2` takes `AT_SYMLINK_NOFOLLOW` (`EOPNOTSUPP` on a symlink) and `AT_EMPTY_PATH`; unknown `open` flags are ignored as on Linux. AF_UNIX `bind` makes no socket node: the name lives in the socket table until the socket closes, so `unlink` does not free it (pending). Directories list as lookup sees them: the image's entries the overlay neither hides nor replaces, then the overlay's own (files created in an image directory such as `/tmp` are listed). Removing a name only the image has checks it as Linux does (`ENOTDIR`, `EISDIR`, `ENOTEMPTY` counting overlay entries, `EBUSY` on a mount point) before whiting it out. The kernel's `/dev/null` (1:3), `/dev/zero` (1:5), `/dev/console` (5:1) and `/dev/tty` (5:0) have their own inode and device number (GNU grep takes output that stats like `/dev/null` as discarded). Deleted files keep their memory until the domain stops. This is not yet a complete Linux VFS. |
| Filesystem notifications | Partial | inotify instances keep watches by path and event queues with names, cookies, self and child events, merging, `IN_Q_OVERFLOW`, `IN_ONESHOT`, `IN_MASK_ADD`/`IN_MASK_CREATE`, `IN_EXCL_UNLINK`, blocking reads and fdinfo (`kernel/src/linux_inotify.rs`). dnotify (`F_NOTIFY`, with `F_SETSIG`/`F_GETSIG`) shares its path matching: `DN_ACCESS`, `MODIFY`, `CREATE`, `DELETE`, `ATTRIB` on the directory and its entries, `DN_RENAME` for a rename within it, one-shot unless `DN_MULTISHOT`, signalled before the causing call returns with `si_fd` and `si_band`. fanotify groups (`kernel/src/linux_fanotify.rs`) of every class keep inode marks by path (with `FAN_EVENT_ON_CHILD`, `FAN_ONDIR`, `FAN_MARK_DONT_FOLLOW`/`ONLYDIR`, flush) and mount and filesystem marks by mount, ignore masks (legacy and `FAN_MARK_IGNORE`, cleared on modify unless `SURV_MODIFY`), and queue merged v3 events for open, access, modify, close and exec with a descriptor opened for the listener (whose use raises no events), the process or thread (`FAN_REPORT_TID`), overflow, blocking reads and poll. `FAN_OPEN_PERM` and `FAN_ACCESS_PERM` hold the opening or reading thread until every group answers with a written response or closes. Groups made with `FAN_REPORT_FID`, `FAN_REPORT_DIR_FID`, `FAN_REPORT_NAME` and `FAN_REPORT_TARGET_FID` report identifier records instead of descriptors (the fsid statfs gives and the file handle name_to_handle_at encodes; directory, entry name, a rename's old and new directory and name, and the entry's own identifier, chosen and merged as Linux's fanotify does) and hear the directory entry and inode events (`FAN_CREATE`, `FAN_DELETE`, `FAN_MOVED_FROM`/`TO`, `FAN_RENAME`, `FAN_ATTRIB`, `FAN_DELETE_SELF`, `FAN_MOVE_SELF`, with `FAN_ONDIR`) on inode and filesystem marks (by fsid); `FAN_REPORT_PIDFD` adds a pidfd record (`FAN_NOPIDFD` for a process the reader cannot see). Groups made without `CAP_SYS_ADMIN` get no mount or filesystem marks and see only their own pid; `/proc/PID/fdinfo` lists a group's marks. Inode marks stay on the object they were set on (its file handle, else its path), follow it across renames and go when it is deleted; an event on an overlayfs file is also reported on the layer's file underneath, as Linux does since 6.5; a file deleted while open reports `FAN_DELETE_SELF` at the unlink rather than at its last close, and a file replaced by a rename hears its own deletion only through filesystem marks. Groups and marks count per user in each user namespace up the chain, as Linux's ucounts do, against `/proc/sys/user/max_fanotify_groups` and `max_fanotify_marks` (each namespace's own; `/proc/sys/fs/fanotify/max_user_*` are the initial one's), and `fs/fanotify/max_queued_events` sizes new queues. An exec asks `FAN_OPEN_EXEC_PERM`, then `FAN_OPEN_PERM`. Unmounting a filesystem ends the inotify watches on it with `IN_UNMOUNT` and `IN_IGNORED`. `FAN_REPORT_FD_ERROR` and pre-content events are pending. |
| `/proc` | Partial | Automatically mounted per domain with domain-local PID directories, `status`, `stat`, `statm`, `mountinfo`, namespace maps, `cpuinfo`, `meminfo`, `stat`, `uptime`, `loadavg`, `filesystems`, `cmdline`, a boot-unique UUID at `/proc/sys/kernel/random/boot_id`, and `/proc/sysrq-trigger` (`t` lists every task's threads to the kernel log, `l` profiles the runtime CPU). `/proc/PID` lists `fd`, `exe`, `maps`, `mounts` and `oom_score_adj` too. `/proc/self/fd/N` (and `/proc/thread-self/fd/N`, the caller's `/proc/PID/fd/N`, `/dev/fd/N`, and `N` under a `/proc/self/fd` directory descriptor) is a magic link for `readlink`, `lstat`, `stat`, `statx`, `open`, `execve`, `linkat` and `mount`: it reads as the file's path, `/dev/console`, `pipe:[N]`, `socket:[N]` or `anon_inode:[...]`, and opening it opens the file again, or the same pipe end with the new open's flags (bash's `<(...)`). `/proc/sys` and each of its directories list the values the kernel serves (`ls /proc/sys/kernel/keys`, a working directory there), and every `/proc` file and directory has an inode of its own (a process's and a thread's directory by its id). Broader Linux procfs coverage and unconstrained process enumeration remain incomplete. |
| IPv4 sockets | Partial | Domain descriptors expose repeated client TCP and UDP connections plus TCP bind/listen/accept over the shared host NIC with IOMMU-confined virtio queues. Connections to a listener on the domain's own IPv4 address use a kernel-local TCP path with the same descriptor, peer-name, readiness, and stream-I/O semantics; AF_UNIX stream socket pairs cover local runtime coordination. ICMP sockets: ping sockets (`SOCK_DGRAM`, `IPPROTO_ICMP`) send echo requests with the socket's identifier and checksum filled in and receive their replies, and raw ICMP sockets (`SOCK_RAW`) receive every ICMP packet with its IP header, with `IP_TTL`, `IP_RECVTTL` (the reply's real TTL) and `ICMP_FILTER`; ICMP errors are not queued for `IP_RECVERR` yet. A blocking call on a socket with `SO_RCVTIMEO`/`SO_SNDTIMEO` lets the domain's other processes run until its timeout passes, as untimed ones do. Ancillary data, IPv6, multi-entry listen backlogs, interruptible blocking accepts, and complete option/error semantics remain pending. |
| `/dev` | Partial | The first walk under `/dev` makes, in the domain's overlay, the kernel's devices (`null` 1:3, `zero` 1:5, `full` 1:7, `random` 1:8, `urandom` 1:9, `console` 5:1, `tty` 5:0), Linux's links `fd`, `stdin`, `stdout` and `stderr` into `/proc/self/fd`, and `shm` (mode 1777) for POSIX shared memory, so listing and `lstat` find what `open` and `stat` already do. A device file opens the kernel's device itself, and `O_TRUNC` is ignored on devices and FIFOs as on Linux. The console answers `TCGETS2`/`TCSETS2` (termios2). `random` and `urandom` read the kernel's random bytes (as `getrandom`), `full` fails writes with `ENOSPC`, and reads of `zero` fill any length. `ptmx` 5:2 makes Unix98 pseudo-terminal pairs: each slave appears as `/dev/pts/N` (136:N, mode 0620, group tty) until its master closes, with the terminal line discipline in `crates/tty` (canonical editing, echo, CR/NL translation, signal characters, flow control, VMIN/VTIME, packet mode), termios and window size on both ends, the TIOC*PT* calls, job control on the slave, and EIO on the master once the slave closes. `userfaultfd` 10:126 (mode 0600) makes userfaultfds with `USERFAULTFD_IOC_NEW`. |
| OCI overlay root | Partial | Verified layers are assembled in manifest order with replacements and OCI whiteouts. Broader overlay conformance remains under test. |
| Runtime `mmap` | Partial | Page-table-backed anonymous and OCI file mappings, writable overlay-file `MAP_SHARED` mappings with `msync`/unmap writeback and fork inheritance, memfd `MAP_SHARED` mappings of the file's own page frames (coherent across processes and with `read`/`write` without `msync`; frames stay allocated until domain teardown), fixed placement, in-place growth/shrink and movable anonymous `mremap`, protection changes, unmap, `madvise`, and `mincore` support Alpine and the validated Rocky glibc/coreutils path. SysV shared-memory pages remain shared across process hierarchy cloning. NUMA policy calls expose the current single node, validate node-0 masks, and make node-0 placement/migration operations explicit no-ops. Shared writeback currently occurs at page granularity; `MREMAP_DONTUNMAP`, movable file mappings, multi-node NUMA policy, and full Linux page-cache coherency remain incomplete. |
| `/dev` and terminal ABI | Partial | Selected console/device nodes and bounded termios/winsize ioctls. `/dev/fb0` exposes the firmware framebuffer, or a virtio-gpu surface (docs/GRAPHICS.md), through fbdev (`FBIOGET_VSCREENINFO`/`FBIOPUT_VSCREENINFO`/`FBIOGET_FSCREENINFO`, pan/blank/vsync as no-ops, read/write and `MAP_SHARED` mmap); `/dev/input/event0`-`event3` deliver evdev records from USB keyboards, boot mice and QEMU's tablet with poll readiness and the `EVIOCG*` identity, bit, name and absolute-axis queries. Empty evdev reads return `EAGAIN` instead of blocking, `/dev/input` cannot be listed, and the fbdev mode is fixed at boot (the firmware's, or the one the virtio-gpu host asks for). With a 3D virtio-gpu, `/dev/dri/renderD128` serves Mesa's Venus driver: the virtgpu ioctls, sync-file fences and dma-bufs (docs/GRAPHICS.md). |
| `/sys` | Partial | Only what libdrm reads to find a virtio-gpu render node: `/sys/dev/char/226:128` with its device's `uevent`, PCI ids, `subsystem` link and `drm/renderD128`, and securityfs's `/sys/kernel/security/lsm`. No general sysfs contract. |
| Credentials and user namespaces | Partial | Each process has real, effective, saved and filesystem user and group ids and supplementary groups, inherited across fork and kept across exec (set-user-ID and set-group-ID programs apply); the `set*id`, `setfs*id`, `setgroups` and `getgroups` calls follow Linux's rules (`crates/credentials`). Root in a domain may take other ids only when the domain is set `user-switching=true`, the one flag that grants it: its user namespace then maps ids 0-65535 (`/proc/PID/uid_map` `0 100000 65536`, `setgroups` `allow`); otherwise it maps only 0 and every process stays root. Files have owners and groups (from the image's tar headers, else their creator's filesystem ids); open, create, remove, rename, chmod, chown, utimes, access(2) and exec check the owner, group and other permission bits, root's override, and sticky directories. Processes carry effective, permitted, inheritable and bounding capability sets (`capget`/`capset` versions 1-3, `PR_CAPBSET_READ`/`PR_CAPBSET_DROP`); user-id changes and exec move them as capabilities(7) says, and the time, resource, admin, pipe-size and namespace checks ask for the capability. Ambient sets, file capabilities, path-walk search permission and nested user-namespace id maps remain incomplete. |
| Mount and namespace APIs | Partial | Container roots are kernel-created; `listmount` and `statmount` enumerate and describe the domain root and automatic proc mount. Root in a domain may `mount` filesystems on directories, `MS_REMOUNT` them (read-only mounts make changes below them `EROFS`; `nodev` stops device files) and `umount2` them (a tmpfs's files go with it); bind and move mounts are accepted but do not redirect paths, and `/proc/PID/mountinfo` does not list domain mounts yet. `unshare` creates user and mount namespaces (UTS, IPC, network, PID, cgroup and time namespaces are `EINVAL`); chroot, pivot_root and setns are policy-denied. |
| Socket API | Partial | Linux TCP/UDP sockets use the kernel network stack and survive the connection churn of OCI and DNF downloads; TCP server sockets, deterministic same-domain TCP connections with a requested-backlog pending queue, repeated `accept`/`accept4`, local `socketpair`, stream half-close, `SIGPIPE`/`MSG_NOSIGNAL`, nondestructive `MSG_PEEK`, stream `MSG_WAITALL`, Linux UDP `MSG_TRUNC` reporting, multi-descriptor AF_UNIX `SCM_RIGHTS` for sockets and files (a passed file gets its own descriptor with the sender's open state, such as a memfd), negative `listen` backlogs meaning the maximum, verified AF_UNIX `SCM_CREDENTIALS`/`SO_PASSCRED` and `SO_PEERCRED`, `MSG_CMSG_CLOEXEC`/`MSG_CTRUNC`, stateful `SO_REUSEADDR`, `SO_KEEPALIVE`, `SO_RCVTIMEO`, `SO_SNDTIMEO`, `IP_RECVERR`, and `TCP_NODELAY`, plus live type/protocol/domain/listener queries are supported. AF_UNIX stream connect now creates a queued server endpoint immediately, allowing pre-`accept` writes, and successful local writes provide a cooperative server scheduling point. `AF_NETLINK` sockets receive the kernel's messages as datagrams (mq_notify's `SIGEV_THREAD` cookie) and answer every request with an `NLMSG_ERROR` of `EOPNOTSUPP`, as no netlink family (rtnetlink and the rest) is served yet; `bind` takes a port id and `getsockname` reports it. Connected named-socket peer credentials remain incomplete. IPv6, general ancillary data, interruptible socket waits, multi-entry external-network listen backlogs, and the full option surface remain pending. |
| cgroups | Partial | cgroup v2 at `/sys/fs/cgroup` with the memory controller: `cgroup.procs` moves a process (children start in their parent's cgroup), `cgroup.subtree_control` delegates `memory` under Linux's rules (`ENOENT` for a controller the parent does not offer, `EBUSY` for internal processes or a controller a child still delegates), `cgroup.events`, `cgroup.kill`, `cgroup.stat`, and rmdir refuses a populated cgroup (`EBUSY`). User pages are charged to the faulting process's cgroup and uncharged when freed; `memory.current`, `peak`, `min`, `low`, `high`, `max`, `events`, `events.local`, `stat`, `oom.group` and `reclaim` follow `mm/memcontrol.c`. A charge past `memory.max` reclaims `MAP_DROPPABLE` and clean `MADV_FREE` pages of the cgroup's processes, then OOM-kills its largest process. No other controllers; `memory.swap.*` read zero until swap exists; `/proc/self/cgroup` names the caller's cgroup. |
| seccomp, audit, LSM ABI | Partial | Strict seccomp mode, BPF seccomp filters and the Linux LSM API are implemented. `SECCOMP_SET_MODE_FILTER` (through `seccomp` and `PR_SET_SECCOMP`) checks a classic BPF program as Linux does (`crates/seccomp`, host-tested) and installs it in front of the process's chain, inherited at fork and kept across exec, 32768 instructions per chain; each system call of a filtered process runs through the chain and the strictest answer wins: `ALLOW`/`LOG` run it, `ERRNO` fails it, `TRAP` delivers `SIGSYS` with `SYS_SECCOMP` and the call's address, number and architecture, `KILL_THREAD`/`KILL_PROCESS` end the process with `SIGSYS`. `TRACE` and `USER_NOTIF` answer `ENOSYS` (no tracer or listener); `SECCOMP_FILTER_FLAG_NEW_LISTENER` is `EINVAL`, and filters are per process rather than per thread. The active modules are the capability module and Landlock: `lsm_list_modules` lists their ids (100, 110), securityfs's `/sys/kernel/security/lsm` names them (`capability,landlock`), and `lsm_get_self_attr`/`lsm_set_self_attr` check their arguments in Linux's order and then report `EOPNOTSUPP`, as neither module keeps process attributes (SELinux, AppArmor and Smack are not provided). Landlock (ABI version 6: `crates/landlock`, host-tested, and `kernel/src/linux_landlock.rs`) creates rulesets as descriptors, adds path-beneath and TCP port rules and stacks up to 16 layers, with Linux's errors (`EBADFD` for a descriptor of the wrong kind, `ENOMSG`, `E2BIG`); `landlock_restrict_self` takes no_new_privs or `CAP_SYS_ADMIN`. A domain is copied at fork and kept across exec, and is enforced on open (read, write, read-dir, `O_TRUNC`), creation (`mknod`, `mkdir`, `symlink`, `O_CREAT`), unlink and rmdir, link and rename (`LANDLOCK_ACCESS_FS_REFER`, `EXDEV` when a file would gain rights), exec, `truncate`/`ftruncate` and device ioctls (decided when the file is opened, with Linux's exempt commands), TCP `bind`/`connect` by port, and the signal and abstract Unix socket scopes; `mount`, `umount2` and `pivot_root` are `EPERM` for a domain that handles filesystem rights. Rules name paths, not inodes: a rule covers what lies beneath the path it named, and does not follow a renamed directory. A process's threads share one domain, the ELF interpreter is not checked for `EXECUTE`, and UDP port rules (ABI 10) are not offered. Audit remains missing. |
| vDSO/vvar | Partial | A one-page versioned x86-64 vDSO and adjacent read-only/NX vvar page serve realtime, monotonic, coarse, boottime, alarm, and TAI `clock_gettime` calls without a privilege transition. Each execution image receives an immutable time base, fixed-point TSC conversion, and constant-time nanosecond normalization. CPU-time clocks fall back to the syscall; wider Linux vDSO symbols and live vvar updates remain pending. |
| Linux module userspace ABI | Policy-denied | Module management is owned by the trusted control plane. |
| ioctl families | Partial | Explicitly admitted console, pipe, and device requests. Runtime pipes report descriptor-local queued bytes through `FIONREAD`; duplicated pipe descriptors preserve their shared queue while `F_GETFL` reports Linux-correct directional access and mutable `O_NONBLOCK` state. ioctl remains a family of ABIs rather than one completed interface. |

The current POSIX timer profile provides one monotonic `SIGEV_NONE` timer per
domain, including relative/absolute arm, query, overrun, and
delete operations. Timer selectors, clock IDs, timer IDs, and flag words follow
Linux's 32-bit UAPI conversion rules even when the unused upper register bits
are nonzero. Signal/thread notification, realtime clocks, multiple timer
objects, and overrun accumulation remain pending.

`ITIMER_REAL` is shared by `setitimer`, `getitimer`, and `alarm`, with Linux
`timeval` validation, old-value reporting, rounded remaining seconds from
`alarm`, one-shot and periodic deadlines, and `SIGALRM` publication at syscall
boundaries. The state survives `exec` and is cleared for a fork child. Runtime
verification covers arm/query/disarm, invalid microseconds, periodic deadline
advancement, pending-signal delivery, and upper-register argument garbage.
`ITIMER_VIRTUAL` (`SIGVTALRM`) and `ITIMER_PROF` (`SIGPROF`) run on the
process's CPU clock beside its POSIX timers (none in a new child, kept across
exec), fired at system call boundaries and preemption ticks; user and system
time are not told apart, so both count the same time.

Resource-accounting verification covers `getrusage`, `times`, and `sysinfo`.
`getrusage` follows Linux's signed 32-bit selector conversion for self,
children, and thread queries. `ru_maxrss` is the most a process was seen to
hold resident (at `getrusage`, exit and exec); `RUSAGE_CHILDREN` reports the
most any waited-for child, or its own waited children, held. `times`
uses 100 Hz ticks, while `sysinfo` reports live process and physical-frame
counts. Per-process CPU accounting, child aggregation, page-fault/I/O/context
switch counters, load averages, and resident-memory high-water tracking remain
pending.

Filesystem syscall boundaries convert Linux `int`, `unsigned int`, `mode_t`,
`uid_t`, and `gid_t` arguments from the low 32 register bits before validating
them. Boot verification covers dirty upper register bits for `openat`,
`newfstatat`, `faccessat`, and `statx`; the same conversion is applied across
the implemented `*at`, ownership, permission, truncate, and allocation paths.
SysV shared-memory, semaphore, and message-queue IDs, keys, commands, counts,
and flags likewise follow their declared signed or unsigned 32-bit Linux
types. POSIX message-queue descriptors, open flags, modes, and priorities use
the same conversion rules; their full lifecycle tests include nonzero unused
upper register bits.
Event and notification interfaces apply the same rule to epoll, eventfd,
timerfd, signalfd, inotify, fanotify, and userfaultfd descriptors and flag
words. Boot tests create, configure, and retire these objects with dirty upper
register bits, including epoll registration and descriptor cleanup.
`dup`, `dup2`, `dup3` and `fcntl(F_DUPFD[_CLOEXEC])` of an epoll descriptor give
another descriptor for the same epoll instance, as tokio's I/O driver expects;
closing the original moves the instance's watches to a remaining duplicate.
A userfaultfd (`kernel/src/linux_userfaultfd.rs`) registers ranges of its
process's memory for missing-page, write-protect and minor (shared or overlay
file page) faults. A user-mode fault there queues a `uffd_msg` for read and
poll and the faulting thread waits, trying the access again as it is
rescheduled, until UFFDIO_COPY, ZEROPAGE, MOVE, CONTINUE, POISON,
WRITEPROTECT or WAKE resolves it. The kernel's own accesses are never
reported, the fork, remap, remove and unmap events are not offered, and a
forked child's memory is not registered. Without UFFD_USER_MODE_ONLY the
system call needs CAP_SYS_PTRACE; `/dev/userfaultfd` needs only its mode.
An eventfd or timerfd is one open file (`kernel/src/linux_event_files.rs`):
its counter, timer and `O_NONBLOCK` are shared by every descriptor `dup`,
`F_DUPFD` and fork make from it, and freed with the last, as on Linux.
`select`/`pselect6` convert `nfds` as a signed Linux `int`; epoll wait variants
do the same for the epoll descriptor and `maxevents`. Verification covers a
zero-timeout select and an immediately readable epoll target with dirty upper
register bits.
Memory-management boundary tests cover 32-bit `msync` flags and signed
protection-key IDs, including Linux key `-1`, plus 32-bit pidfd descriptors for
`process_madvise` and `process_mrelease`. Page-table-backed runtime mappings
implement `MADV_DONTFORK` and `MADV_DOFORK` with explicit leaf-PTE inheritance
metadata. `MADV_WIPEONFORK` and `MADV_KEEPONFORK` use independent leaf-PTE
metadata for private anonymous mappings. Both policies survive protection
changes, demand materialization, `MADV_DONTNEED`, and `mremap`; process cloning
omits DONTFORK pages, zeroes WIPEONFORK pages in the child while preserving the
parent, and restores ordinary inheritance after the corresponding reversal
advice. Boot verification covers both advice pairs on dynamic mmap storage and
the pre-seeded process stack, a child hierarchy in which a DONTFORK page is
absent, and an executed child whose WIPEONFORK stack begins zeroed while the
parent stack remains unchanged.
`MADV_POPULATE_READ` and `MADV_POPULATE_WRITE` prefault every page in a mapped
range with the requested access, including demand-backed anonymous pages.
They reject insufficient permissions and secret mappings with `EINVAL`, report
unmapped ranges or allocation failure with `ENOMEM`, and may leave an earlier
part of the range populated when a later page fails, matching Linux's partial
progress contract. Boot verification proves physical backing is installed,
write population rejects a read-only mapping, and unmapped ranges fail.
`MADV_FREE` accepts private anonymous mappings and frees their pages lazily,
as Linux does: a page keeps its contents until memory runs short (a memory
cgroup over `memory.max`, or the machine short of free frames), when reclaim
drops it and a later access reads zeros; a page written after the advice is
kept. File-backed, shared, and secret mappings are rejected with `EINVAL`.
`MAP_DROPPABLE` (Linux 6.11) maps private anonymous memory that reclaim drops
first; it is not inherited by children. Boot verification writes, frees and
confirms the page and its contents stay.
`MADV_DONTNEED_LOCKED` is supported by both `madvise` and `process_madvise`.
Because Ginux currently has no separate `mlock` or reclaim state, it follows
the same immediate discard and zero-fill-on-demand path as `MADV_DONTNEED`.
Boot verification covers direct advice and a multi-vector process operation,
including release of physical backing and the subsequent zero-filled read.
The reversible VMA hints `MADV_MERGEABLE`, `MADV_UNMERGEABLE`,
`MADV_HUGEPAGE`, `MADV_NOHUGEPAGE`, `MADV_DONTDUMP`, and `MADV_DODUMP` are
accepted after validating the complete mapped range. Ginux currently uses
base pages, does not deduplicate memory across domains, and has no core-dump
engine, so these hints do not alter backing or weaken isolation. Mergeability
hints are restricted to private anonymous mappings. Boot verification covers
anonymous mappings, a pre-seeded stack VMA, and a deliberately unmapped range.
`mseal` prevents protection changes, unmapping, remapping, replacement, and
backing discard. In particular, `MADV_DONTNEED`, `MADV_FREE`, and
`MADV_DONTNEED_LOCKED` now return `EPERM` for sealed mappings regardless of
their current write permission. `MADV_DONTFORK` and `MADV_WIPEONFORK` are
likewise denied, while their non-destructive reversal operations remain valid.
Inheritance metadata can be updated on demand-reserved pages without forcing
physical allocation. Boot verification seals a writable anonymous mapping and
exercises each prohibited mutation; sealed mappings remain owned until process
teardown releases them.
`MADV_COLD` and `MADV_PAGEOUT` validate mapped ranges and are accepted through
both `madvise` and `process_madvise`. They are best-effort no-ops while Ginux
has neither swap nor a page-reclaim queue; secret mappings remain rejected and
unmapped ranges report `ENOMEM`.
Anonymous `mmap` accepts `MAP_POPULATE` and prefaults demand-backed pages using
the same access-aware path. As on Linux, inability to prefault does not fail
the mapping, and `MAP_NONBLOCK` suppresses the prefault work. Boot verification
distinguishes physically populated pages from the nonblocking reserved form.
`MAP_EXECUTABLE` is accepted as Linux's ignored compatibility flag.
`MAP_LOCKED` performs best-effort prefaulting; because Ginux has no swap or
page-reclaim path, successfully backed pages remain resident without separate
locking metadata. The verifier covers both flags on an anonymous mapping.
Runtime `mincore` now queries every mapped VMA rather than only the dynamic
`mmap` arena. It reports physical residency independently of page protection,
distinguishes reserved demand pages from backed pages, rejects unaligned input
with `EINVAL`, and reports holes with `ENOMEM`. Boot verification covers a
nonresident anonymous reservation and the pre-seeded process stack.
Snapshot completion imports the inheritance bit from every leaf PTE, including
stack, heap, executable-image, and dynamically allocated mappings.
Descriptor-control verification also covers Linux 32-bit descriptor and
command conversion for `fcntl` and `flock`. `flock` now uses the same explicit,
directly tested syscall handler in both normal execution and conformance tests
instead of inline dispatcher logic.
File-descriptor extended-attribute operations and directory enumeration also
convert descriptors and xattr flags according to their Linux 32-bit types.
The filesystem verifier now performs an overlay xattr set/get/list/remove
lifecycle and root `getdents64` enumeration with dirty upper register bits,
then proves descriptor and overlay cleanup.
Opaque file handles use an eight-byte generation-stable identity, allowing
systemd to derive cgroup IDs without a size-discovery retry while retaining
rename-stable `open_by_handle_at` behavior.
`statfs` and `fstatfs` avoid fabricated fixed capacity values. The writable,
elastic domain root reports current physical frame capacity and availability,
while proc and the other pseudo-filesystems retain Linux-style undefined zero
capacity. The domain root and automatic proc mount report their RAMFS/proc
magic, page block and fragment sizes, stable mount-local filesystem IDs,
255-byte name limit, and appropriate nosuid, nodev, noexec, relatime, and
`ST_VALID` flags. Open pipe, socket, and anonymous-inode descriptors report
their Linux pseudo-filesystem magic. Boot verification covers root and proc
path queries (including systemd's trailing-slash `/proc/` probe), matching
`fstatfs` results for `O_PATH` mount-root descriptors, anonymous descriptors,
Linux 32-bit descriptor conversion, error ordering, and complete cleanup.
Persistent block-filesystem capacity, quota reporting, and additional future
mount types remain outside the current profile.
The deprecated `ustat` view of the root device now derives the same undefined
zero capacity and inode counts instead of exposing a contradictory fixed-size
placeholder. `ustat` device IDs and `sysfs` option selectors follow their
Linux 32-bit UAPI types; the verifier covers dirty upper register bits,
zero-based filesystem indexes, complete output contents, invalid selectors,
bad pointers, and Linux error ordering.
RPM-based images that omit `/etc/rpm/platform` receive the standard
architecture/personality value `x86_64-linux` in their domain-local overlay.
This lets RPM select Linux packages while `uname` continues to identify the
actual kernel as Ginux; an image-provided platform file is never replaced.
Pipe and zero-copy boundaries convert `pipe2`, `splice`, `tee`, `vmsplice`, and
`copy_file_range` descriptors and flag words from their Linux 32-bit types.
Boot verification creates a close-on-exec pipe and exercises zero-length
`tee`/`vmsplice` operations with dirty upper register bits before closing both
ends. `splice` moves data between two pipes, from a pipe into a socket or
regular file, and from a socket or regular file into a pipe, with an
explicit offset on the file side or its file position; `tee` copies between
two different pipes; `vmsplice` writes a pipe opened for writing or reads one
opened only for reading. All three check access before file kinds (EBADF,
then EINVAL or ESPIPE as Linux orders them), and wait as a blocking pipe read
or write does unless `SPLICE_F_NONBLOCK` or `O_NONBLOCK` makes them fail
with EAGAIN; filling a pipe with no reader raises SIGPIPE. Splicing from a
directory or an unconnected Unix socket is EINVAL.
Keys (`add_key`, `request_key`, `keyctl`) live in the host-tested
`ginux-keyrings` crate, one set per domain: "user", "logon" and "keyring"
keys with owners, permission masks, possession, quotas, timeouts,
revocation and invalidation; the thread, process, session, user and
user-session keyrings, shared at fork and thread creation and dropped at
exec; links, moves, restrictions, searches and negative keys from
`request_key` with callout data. There are no upcalls, so instantiation is
EPERM, and Diffie-Hellman, public-key and persistent-keyring operations are
EOPNOTSUPP. `/proc/keys` lists the keys the reader may view and
`/proc/key-users` each user's key count and quota usage; the quotas are
the domain's `/proc/sys/kernel/keys/{maxkeys,maxbytes,root_maxkeys,root_maxbytes}`.
A thread's and a process's keyrings go when they exit, and a revoked or
expired key leaves every keyring `gc_delay` seconds later (300, as
`/proc/sys/kernel/keys/gc_delay` sets it), so keys nothing keeps leave
their owners' quotas.
The domain's `fs.protected_hardlinks` and `fs.protected_symlinks` (off by
default, as Linux boots) restrict links as Linux's: a hard link to a file
the caller neither owns nor may read and write is EPERM, and following a
symlink in a sticky, world-writable directory that neither the follower
nor the directory's owner owns is EACCES.
Socket descriptor lookup and descriptor-local status flags now convert the
Linux `int` descriptor from its low 32 register bits for the complete socket
operation family. The live system-init TCP/AF_UNIX lifecycle includes dirty
upper-bit `getpeername` and `shutdown` calls through that shared lookup path.
`io_uring` (`kernel/src/linux_io_uring.rs`) gives each ring its own
submission and completion rings, mapped as three areas, of up to 32768
entries (`IORING_SETUP_CQSIZE`, `CLAMP`). `io_uring_enter` runs the queued
entries at once and in order (NOP, READV, WRITEV, FSYNC, READ_FIXED,
WRITE_FIXED, SENDMSG, READ, WRITE, at an offset or the file position, with
link chains and `CQE_SKIP_SUCCESS`), so nothing waits in flight; buffers are
registered, unregistered and cloned between rings, `IORING_REGISTER_PROBE`
reports the operations, and `/proc/sys/kernel/io_uring_disabled` decides
who may make rings. Polling threads, registered files and extended enter
arguments are not offered. Setup entry counts, ring descriptors, enter
counts and flags, and register opcodes/counts convert from their Linux
32-bit types; the setup/map/submit/probe/close verifier supplies dirty upper
register bits at each boundary.
`cachestat` likewise converts its descriptor and flags before validation.

`modify_ldt` implements Linux's empty per-process LDT read and the retained
x86-64 function-2 compatibility read, including its 128-byte maximum,
zero-fill behavior, short reads, zero-length handling, bad-pointer errors, and
32-bit function selector conversion. Boot verification covers each boundary.
Functions 1 and `0x11` remain unsupported until Ginux has per-mm LDT storage,
safe descriptor validation, LDTR loading, fork inheritance, and context-switch
integration; segmented 16/32-bit execution is therefore still outside the
current long-mode profile.

`prctl` converts its option from the Linux `int` UAPI type and implements
process-name access, dumpability state, statistical timing, strict-seccomp
entry and mode queries, and irreversible `no_new_privs`. Dumpability is
process-local, inherited across fork, retained across the current
non-credential-changing exec path, and restored when Ginux switches between
live processes. Boot verification covers valid transitions, invalid modes,
unused-argument behavior, userspace faults, dirty upper register bits, and
state restoration. Credential-changing exec resets, core-dump enforcement,
parent-death signals, subreapers, capability controls, securebits, timer
slack, speculation controls, and the remaining Linux option families are not
implemented, so `prctl` remains Partial.

`arch_prctl(ARCH_SET_FS/ARCH_GET_FS)` treats the FS base as opaque architectural
thread state rather than requiring it to identify a mapped kernel-owned TLS
extent. Any address in Ginux's x86-64 userspace range, including zero and an
unmapped address, is accepted; an address at or above the task boundary is
rejected with `EPERM`. Optional owned TLS allocation metadata remains separate
and survives an FS-base change. The option follows its Linux `int` width, and
boot verification covers dirty upper bits, zero, an unmapped base, the highest
valid base, the task boundary, output faults, and state restoration. GS-base,
CPUID-faulting, extended-state permission, LAM, and shadow-stack operations
remain unsupported, so `arch_prctl` remains Partial.

The ring-3 controller directly verifies its Linux PID/TID, parent,
process-group, session, UID/GID, supplementary-group, scheduler-yield, and
`uname` contracts, including invalid PID, count, and userspace-address errors.
The Linux-compatible `uname` syscall identifies the kernel as `Ginux`; it does
not claim that Ginux is Linux. Programs may separately append a compile-time
operating-system label (for example, Alpine BusyBox prints `Linux` for `-o`),
which is userspace output rather than a field supplied by the kernel.
It also directly exercises realtime and monotonic `clock_gettime`,
`clock_getres`, `gettimeofday`, `time`, and `times`, including invalid clock
and userspace-address behavior.

Process-group state tracks whether each process has successfully replaced its
image. A parent can move itself or a non-executed child within its session, but
attempting to change a child after exec now returns Linux `EACCES`; unrelated
processes return `ESRCH`, while session-leader and cross-session changes return
`EPERM`. The process lifecycle verifier covers child group creation, return to
an existing group, the post-exec barrier, session creation, and cross-session
rejection. Controlling terminals, orphaned-group signaling, and a concurrent
ring-3 parent/child mutation proof remain pending, so `setpgid` and `setsid`
remain Partial.

`personality` now stores per-process Linux personality state, returns the
previous value on a successful change, implements the `0xffffffff` query, and
converts the request through Linux's 32-bit interface. `PER_LINUX` and the
`UNAME26` flag are supported; `UNAME26` changes `uname` release reporting from
`6.12.0-ginux.0.1` to `2.6.52.0-ginux.0.1`. State is inherited across fork,
retained across exec, and restored across process switches. Boot verification
covers transitions, dirty upper register bits, invalid personalities,
observable uname output, and state restoration. Flags that require different
memory layouts, executable-read mappings, page-zero mappings, timeout quirks,
or non-Linux execution domains remain unsupported, so `personality` remains
Partial.

The ring-3 controller also exercises `poll` against its live nonblocking pipe
descriptors. The probe covers empty and readable input, writable output,
ignored negative descriptors, `POLLNVAL`, writer-close `POLLHUP`, invalid
userspace addresses, the descriptor-count bound, and zero-descriptor polling.
Blocking poll remains bounded by the controller's single-thread execution
model, so `poll` remains Partial.

The same live controller probe covers immediate `select` and `pselect6` pipe
read/write readiness, exception-set clearing, invalid descriptor `EBADF`, and
invalid-address `EFAULT`, timeval/timespec ranges, and the packed `pselect6`
signal-mask pointer and size. The kernel now snapshots their sets into typed
scheduler waits, wakes them on descriptor changes, expires positive deadlines
from the APIC timer, writes `select` remaining time, and atomically restores a
temporary `pselect6` mask on every completion and interruption path. Their
variable-length descriptor sets cover the domain's full 1,024-descriptor
`RLIMIT_NOFILE`, including blocked-wait snapshots. Blocking still requires
another runnable thread rather than idling the processor, so both calls remain
Partial.

`clock_gettime` and `clock_getres` accept every Linux static clock ID that is
readable without changing system time: realtime, monotonic, process/thread CPU,
monotonic raw, realtime/monotonic coarse, boottime, realtime/boottime alarm,
and TAI. Clock IDs and `clock_nanosleep` flags use Linux's 32-bit UAPI
conversion rules. Coarse clocks use and report the Ginux 100 Hz clock-tick resolution;
boottime equals monotonic because Ginux does not yet suspend, and TAI equals
realtime until a trusted time service supplies a TAI offset. Dynamic clock IDs
and exact multi-process/thread CPU accounting remain pending, so both syscalls
remain Partial.

`sysinfo` reports live uptime, allocator-derived total and currently available
RAM, and the visible process count (domain-local in a domain and host-wide in
the control domain). Swap, high memory, load averages,
and shared/buffer accounting are zero because those facilities do not yet
exist; Linux-compatible structure layout, units, and invalid-address behavior
are exercised from ring 3. The syscall remains Partial until accounting and
process/thread semantics cover the complete Linux contract.

`getrandom` accepts Linux `GRND_NONBLOCK`, `GRND_RANDOM`, and
`GRND_INSECURE`, rejects unknown flags and the invalid
`GRND_RANDOM|GRND_INSECURE` combination, preserves a successful partial copy
when a later user range faults, and is directly exercised by the ring-3
controller. Ginux currently treats hardware RNG availability as its ready
entropy source; a mixed, reseeding kernel CSPRNG and interruptible large reads
remain pending, so the syscall remains Partial.

`getpriority` and `setpriority` implement Linux process, process-group, and
real-UID selectors, raw kernel return encoding, signed 32-bit nice values,
`-20..19` clamping, and dirty-upper-register conversion. Multi-target changes
now match Linux's non-atomic behavior: permitted targets are updated while a
permission error is retained for the call. Permission checks accept the
caller's effective UID matching either target real or effective UID. Boot
verification covers selectors, missing targets, invalid selectors, signed and
clamped updates, and exact state restoration. `RLIMIT_NICE`-authorized
unprivileged raises, distinct per-thread nice values, and proportional scheduler
weighting remain pending; admitted process priorities currently select the
highest-priority ready process first. Both syscalls therefore remain Partial.

`getrlimit` now accepts every Linux resource number from `RLIMIT_CPU` through
`RLIMIT_RTTIME`. Finite limits reflect Ginux's actual process, descriptor,
signal, nice, and realtime-priority boundaries; resources without a present
quota report infinity. The ring-3 controller verifies the full query range,
ordering, and error behavior. Linux programs can lower and restore the soft
resource limits within the existing hard limit; hard-limit raises remain
permission-denied. `RLIMIT_NOFILE` enforcement makes descriptor allocation
fail with `EMFILE`, while `RLIMIT_NPROC` makes fork and thread creation fail
with `EAGAIN`. `RLIMIT_FSIZE` shortens writes at the file-size boundary and
enforces `EFBIG` plus `SIGXFSZ` for writes and file extensions beyond it across
ordinary, positioned, vectored, `sendfile`, `copy_file_range`, `ftruncate`, and
`fallocate` paths. Limits survive fork and exec, and the linked ring-3 probe
exercises mutation, enforcement, and restoration. `RLIMIT_MSGQUEUE` applies
Linux's payload and kernel-object charge formula to each newly created POSIX
message queue, rejects creation with `EMFILE` at the soft limit, and releases
the charge only when an unlinked queue's final descriptor closes.
`prlimit64` can query or lower limits for another live process in the same
domain when Linux real/effective/saved UID and GID permission checks permit it;
the fork-child lifecycle probe verifies mutation, observation, and restoration.
`RLIMIT_AS` accounts the live user page tables and rejects `mmap` and `mremap`
growth that would exceed the soft byte limit while permitting fixed mappings
that only replace already-accounted pages.
Resource-specific enforcement not listed above, privileged hard-limit raises,
and unimplemented resource families remain pending, so the resource-limit
family remains Partial. `RLIMIT_NOFILE` now also accounts for descriptors in
flight over UNIX sockets, returns `ETOOMANYREFS` using Linux's current-count
rule, releases charges on receive/discard/close, and closes received excess
when the destination descriptor table reaches its soft limit.

System V shared memory now uses domain-owned, dynamically allocated frame
objects whose lifetime is independent of any one mapping. `shmget`, `shmat`,
`shmdt`, and `shmctl(IPC_STAT/IPC_RMID)` provide keyed creation, shared page
mapping, attachment reference counts, and deferred destruction after
`IPC_RMID`. `IPC_SET` updates the permission mode; fork preserves shared page
identity and inherits attachment accounting; process/domain teardown releases
the corresponding references and objects. `SHM_REMAP`, timestamps, owner/group
updates, permission enforcement, and Linux's
information commands remain pending, so these calls remain Partial.

System V semaphores use dynamically allocated, per-domain sets and chained
value pages. `semget`, `semop`, `semtimedop`, and the principal `semctl`
commands support keyed creation, atomic multi-operation preflight and commit,
mode/stat queries, individual and whole-set values, and immediate removal.
The Linux default `SEMMSL=32000` and `SEMOPM=500` limits are enforced.
Operations that would sleep currently return `EAGAIN`; waiter scheduling,
`SEM_UNDO`, timestamps, permission enforcement, and information commands are
pending, so the family remains Partial.

System V message queues use dynamically allocated, per-domain queue and
payload objects. `msgget`, `msgsnd`, `msgrcv`, and
`msgctl(IPC_STAT/IPC_SET/IPC_RMID)` support keyed creation, ordered messages,
Linux type selection, `MSG_EXCEPT`, nondestructive `MSG_COPY`, and
`MSG_NOERROR` truncation. Queue byte limits are configurable and payloads are
not constrained to a static aggregate cache. Blocking wait/wakeup, timestamps,
credential enforcement, and Linux's information commands remain pending, so
the family remains Partial.

POSIX message queues use named per-domain objects backed by the same dynamic
page allocator. `mq_open`, `mq_unlink`, `mq_timedsend`, `mq_timedreceive`,
`mq_notify`, and `mq_getsetattr` cover create/exclusive lookup, descriptor
duplication and close, unlink lifetime, priority ordering, attributes,
`O_NONBLOCK`, owners and modes (`EACCES`, owner-only unlink), and the
`/proc/sys/fs/mqueue` limits (`queues_max`, `msg_max`, `msgsize_max`,
`msg_default`, `msgsize_default`). Names are taken as the C library passes
them, without the slash. Sends to a full queue and receives from an empty one
wait until the absolute `CLOCK_REALTIME` timeout (`ETIMEDOUT`) or a signal.
`mq_notify` registers `SIGEV_NONE`, `SIGEV_SIGNAL` (`SI_MESGQ`) or
`SIGEV_THREAD` as the C library makes it (a cookie sent back on a netlink
socket with `NOTIFY_WOKENUP` or `NOTIFY_REMOVED`). Creation also observes the
calling domain's Linux-compatible `RLIMIT_MSGQUEUE` byte charge, including
queue bookkeeping, with the charge retained across unlink until final close.
Timestamps and the mqueue filesystem itself are absent, so this family remains
Partial.

Legacy Linux AIO uses dynamically allocated per-process contexts (freed with
their process) and completion records. `io_setup`, `io_submit`,
`io_getevents`, `io_pgetevents`, `io_cancel`, and `io_destroy` support
synchronous `PREAD`, `PWRITE`, `FSYNC`, and `FDSYNC` submission with Linux
`iocb`/`io_event` layouts and an mmap-backed ring header; requests are checked
as submitted (descriptor, direction, reserved fields), and reads from pipes and
sockets take what is queued (`EAGAIN` when nothing is). True asynchronous execution, blocking waits, cancellation of
in-flight work, vectored requests, poll, and eventfd completion remain pending.

## Syscall index

The table includes every native `common` or `64` entry in Linux v6.12's
x86-64 syscall table. Number gaps reserved by Linux are not syscalls and are
therefore omitted.

| Number | Syscall | Status |
|---:|---|---|
| 0 | read | Partial |
| 1 | write | Partial |
| 2 | open | Partial |
| 3 | close | Partial |
| 4 | stat | Partial |
| 5 | fstat | Partial |
| 6 | lstat | Partial |
| 7 | poll | Partial |
| 8 | lseek | Partial |
| 9 | mmap | Partial |
| 10 | mprotect | Partial |
| 11 | munmap | Partial |
| 12 | brk | Partial |
| 13 | rt_sigaction | Partial |
| 14 | rt_sigprocmask | Partial |
| 15 | rt_sigreturn | Partial |
| 16 | ioctl | Partial |
| 17 | pread64 | Partial |
| 18 | pwrite64 | Partial |
| 19 | readv | Partial |
| 20 | writev | Partial |
| 21 | access | Partial |
| 22 | pipe | Partial |
| 23 | select | Partial |
| 24 | sched_yield | Complete |
| 25 | mremap | Partial |
| 26 | msync | Partial |
| 27 | mincore | Partial |
| 28 | madvise | Partial |
| 29 | shmget | Partial |
| 30 | shmat | Partial |
| 31 | shmctl | Partial |
| 32 | dup | Partial |
| 33 | dup2 | Partial |
| 34 | pause | Partial |
| 35 | nanosleep | Partial |
| 36 | getitimer | Partial |
| 37 | alarm | Partial |
| 38 | setitimer | Partial |
| 39 | getpid | Complete |
| 40 | sendfile | Partial |
| 41 | socket | Complete |
| 42 | connect | Partial |
| 43 | accept | Partial |
| 44 | sendto | Complete |
| 45 | recvfrom | Complete |
| 46 | sendmsg | Complete |
| 47 | recvmsg | Complete |
| 48 | shutdown | Partial |
| 49 | bind | Complete |
| 50 | listen | Complete |
| 51 | getsockname | Complete |
| 52 | getpeername | Complete |
| 53 | socketpair | Complete |
| 54 | setsockopt | Complete |
| 55 | getsockopt | Complete |
| 56 | clone | Partial |
| 57 | fork | Partial |
| 58 | vfork | Partial |
| 59 | execve | Partial |
| 60 | exit | Partial |
| 61 | wait4 | Partial |
| 62 | kill | Partial |
| 63 | uname | Complete |
| 64 | semget | Partial |
| 65 | semop | Partial |
| 66 | semctl | Partial |
| 67 | shmdt | Partial |
| 68 | msgget | Partial |
| 69 | msgsnd | Partial |
| 70 | msgrcv | Partial |
| 71 | msgctl | Partial |
| 72 | fcntl | Partial |
| 73 | flock | Partial |
| 74 | fsync | Complete |
| 75 | fdatasync | Complete |
| 76 | truncate | Partial |
| 77 | ftruncate | Partial |
| 78 | getdents | Partial |
| 79 | getcwd | Partial |
| 80 | chdir | Partial |
| 81 | fchdir | Partial |
| 82 | rename | Partial |
| 83 | mkdir | Partial |
| 84 | rmdir | Partial |
| 85 | creat | Partial |
| 86 | link | Partial |
| 87 | unlink | Partial |
| 88 | symlink | Partial |
| 89 | readlink | Partial |
| 90 | chmod | Partial |
| 91 | fchmod | Partial |
| 92 | chown | Partial |
| 93 | fchown | Partial |
| 94 | lchown | Partial |
| 95 | umask | Complete |
| 96 | gettimeofday | Complete |
| 97 | getrlimit | Complete |
| 98 | getrusage | Partial |
| 99 | sysinfo | Partial |
| 100 | times | Partial |
| 101 | ptrace | Policy-denied |
| 102 | getuid | Complete |
| 103 | syslog | Policy-denied |
| 104 | getgid | Complete |
| 105 | setuid | Complete |
| 106 | setgid | Complete |
| 107 | geteuid | Complete |
| 108 | getegid | Complete |
| 109 | setpgid | Partial |
| 110 | getppid | Complete |
| 111 | getpgrp | Complete |
| 112 | setsid | Partial |
| 113 | setreuid | Complete |
| 114 | setregid | Complete |
| 115 | getgroups | Complete |
| 116 | setgroups | Complete |
| 117 | setresuid | Complete |
| 118 | getresuid | Complete |
| 119 | setresgid | Complete |
| 120 | getresgid | Complete |
| 121 | getpgid | Complete |
| 122 | setfsuid | Complete |
| 123 | setfsgid | Complete |
| 124 | getsid | Complete |
| 125 | capget | Partial |
| 126 | capset | Partial |
| 127 | rt_sigpending | Partial |
| 128 | rt_sigtimedwait | Partial |
| 129 | rt_sigqueueinfo | Partial |
| 130 | rt_sigsuspend | Partial |
| 131 | sigaltstack | Partial |
| 132 | utime | Partial |
| 133 | mknod | Partial |
| 134 | uselib | Complete |
| 135 | personality | Partial |
| 136 | ustat | Complete |
| 137 | statfs | Partial |
| 138 | fstatfs | Partial |
| 139 | sysfs | Complete |
| 140 | getpriority | Partial |
| 141 | setpriority | Partial |
| 142 | sched_setparam | Complete |
| 143 | sched_getparam | Complete |
| 144 | sched_setscheduler | Complete |
| 145 | sched_getscheduler | Complete |
| 146 | sched_get_priority_max | Complete |
| 147 | sched_get_priority_min | Complete |
| 148 | sched_rr_get_interval | Complete |
| 149 | mlock | Complete |
| 150 | munlock | Complete |
| 151 | mlockall | Complete |
| 152 | munlockall | Complete |
| 153 | vhangup | Policy-denied |
| 154 | modify_ldt | Partial |
| 155 | pivot_root | Policy-denied |
| 156 | _sysctl | Complete |
| 157 | prctl | Partial |
| 158 | arch_prctl | Partial |
| 159 | adjtimex | Policy-denied |
| 160 | setrlimit | Partial |
| 161 | chroot | Policy-denied |
| 162 | sync | Complete |
| 163 | acct | Policy-denied |
| 164 | settimeofday | Policy-denied |
| 165 | mount | Partial |
| 166 | umount2 | Partial |
| 167 | swapon | Policy-denied |
| 168 | swapoff | Policy-denied |
| 169 | reboot | Policy-denied |
| 170 | sethostname | Policy-denied |
| 171 | setdomainname | Policy-denied |
| 172 | iopl | Policy-denied |
| 173 | ioperm | Policy-denied |
| 174 | create_module | Complete |
| 175 | init_module | Policy-denied |
| 176 | delete_module | Policy-denied |
| 177 | get_kernel_syms | Complete |
| 178 | query_module | Complete |
| 179 | quotactl | Policy-denied |
| 180 | nfsservctl | Complete |
| 181 | getpmsg | Complete |
| 182 | putpmsg | Complete |
| 183 | afs_syscall | Complete |
| 184 | tuxcall | Complete |
| 185 | security | Complete |
| 186 | gettid | Complete |
| 187 | readahead | Complete |
| 188 | setxattr | Partial |
| 189 | lsetxattr | Partial |
| 190 | fsetxattr | Partial |
| 191 | getxattr | Partial |
| 192 | lgetxattr | Partial |
| 193 | fgetxattr | Partial |
| 194 | listxattr | Partial |
| 195 | llistxattr | Partial |
| 196 | flistxattr | Partial |
| 197 | removexattr | Partial |
| 198 | lremovexattr | Partial |
| 199 | fremovexattr | Partial |
| 200 | tkill | Partial |
| 201 | time | Complete |
| 202 | futex | Partial |
| 203 | sched_setaffinity | Complete |
| 204 | sched_getaffinity | Complete |
| 205 | set_thread_area | Complete |
| 206 | io_setup | Partial |
| 207 | io_destroy | Partial |
| 208 | io_getevents | Partial |
| 209 | io_submit | Partial |
| 210 | io_cancel | Partial |
| 211 | get_thread_area | Complete |
| 212 | lookup_dcookie | Complete |
| 213 | epoll_create | Partial |
| 214 | epoll_ctl_old | Complete |
| 215 | epoll_wait_old | Complete |
| 216 | remap_file_pages | Partial |
| 217 | getdents64 | Partial |
| 218 | set_tid_address | Complete |
| 219 | restart_syscall | Complete |
| 220 | semtimedop | Partial |
| 221 | fadvise64 | Complete |
| 222 | timer_create | Partial |
| 223 | timer_settime | Partial |
| 224 | timer_gettime | Partial |
| 225 | timer_getoverrun | Partial |
| 226 | timer_delete | Partial |
| 227 | clock_settime | Policy-denied |
| 228 | clock_gettime | Partial |
| 229 | clock_getres | Partial |
| 230 | clock_nanosleep | Partial |
| 231 | exit_group | Partial |
| 232 | epoll_wait | Partial |
| 233 | epoll_ctl | Partial |
| 234 | tgkill | Partial |
| 235 | utimes | Partial |
| 236 | vserver | Complete |
| 237 | mbind | Partial |
| 238 | set_mempolicy | Partial |
| 239 | get_mempolicy | Partial |
| 240 | mq_open | Partial |
| 241 | mq_unlink | Partial |
| 242 | mq_timedsend | Partial |
| 243 | mq_timedreceive | Partial |
| 244 | mq_notify | Partial |
| 245 | mq_getsetattr | Partial |
| 246 | kexec_load | Policy-denied |
| 247 | waitid | Partial |
| 248 | add_key | Partial |
| 249 | request_key | Partial |
| 250 | keyctl | Partial |
| 251 | ioprio_set | Partial |
| 252 | ioprio_get | Partial |
| 253 | inotify_init | Partial |
| 254 | inotify_add_watch | Partial |
| 255 | inotify_rm_watch | Partial |
| 256 | migrate_pages | Partial |
| 257 | openat | Partial |
| 258 | mkdirat | Partial |
| 259 | mknodat | Partial |
| 260 | fchownat | Partial |
| 261 | futimesat | Partial |
| 262 | newfstatat | Partial |
| 263 | unlinkat | Partial |
| 264 | renameat | Partial |
| 265 | linkat | Partial |
| 266 | symlinkat | Partial |
| 267 | readlinkat | Partial |
| 268 | fchmodat | Partial |
| 269 | faccessat | Partial |
| 270 | pselect6 | Partial |
| 271 | ppoll | Partial |
| 272 | unshare | Partial |
| 273 | set_robust_list | Partial |
| 274 | get_robust_list | Complete |
| 275 | splice | Partial |
| 276 | tee | Partial |
| 277 | sync_file_range | Complete |
| 278 | vmsplice | Partial |
| 279 | move_pages | Partial |
| 280 | utimensat | Partial |
| 281 | epoll_pwait | Partial |
| 282 | signalfd | Partial |
| 283 | timerfd_create | Partial |
| 284 | eventfd | Partial |
| 285 | fallocate | Partial |
| 286 | timerfd_settime | Partial |
| 287 | timerfd_gettime | Partial |
| 288 | accept4 | Partial |
| 289 | signalfd4 | Partial |
| 290 | eventfd2 | Partial |
| 291 | epoll_create1 | Partial |
| 292 | dup3 | Complete |
| 293 | pipe2 | Partial |
| 294 | inotify_init1 | Partial |
| 295 | preadv | Partial |
| 296 | pwritev | Partial |
| 297 | rt_tgsigqueueinfo | Partial |
| 298 | perf_event_open | Policy-denied |
| 299 | recvmmsg | Complete |
| 300 | fanotify_init | Partial |
| 301 | fanotify_mark | Partial |
| 302 | prlimit64 | Partial |
| 303 | name_to_handle_at | Partial |
| 304 | open_by_handle_at | Partial |
| 305 | clock_adjtime | Policy-denied |
| 306 | syncfs | Complete |
| 307 | sendmmsg | Complete |
| 308 | setns | Policy-denied |
| 309 | getcpu | Complete |
| 310 | process_vm_readv | Partial |
| 311 | process_vm_writev | Partial |
| 312 | kcmp | Partial |
| 313 | finit_module | Policy-denied |
| 314 | sched_setattr | Complete |
| 315 | sched_getattr | Complete |
| 316 | renameat2 | Partial |
| 317 | seccomp | Partial |
| 318 | getrandom | Partial |
| 319 | memfd_create | Partial |
| 320 | kexec_file_load | Policy-denied |
| 321 | bpf | Policy-denied |
| 322 | execveat | Partial |
| 323 | userfaultfd | Partial |
| 324 | membarrier | Complete |
| 325 | mlock2 | Complete |
| 326 | copy_file_range | Partial |
| 327 | preadv2 | Partial |
| 328 | pwritev2 | Partial |
| 329 | pkey_mprotect | Partial |
| 330 | pkey_alloc | Partial |
| 331 | pkey_free | Partial |
| 332 | statx | Partial |
| 333 | io_pgetevents | Partial |
| 334 | rseq | Partial |
| 335 | uretprobe | Partial |
| 424 | pidfd_send_signal | Partial |
| 425 | io_uring_setup | Partial |
| 426 | io_uring_enter | Partial |
| 427 | io_uring_register | Partial |
| 428 | open_tree | Policy-denied |
| 429 | move_mount | Policy-denied |
| 430 | fsopen | Policy-denied |
| 431 | fsconfig | Policy-denied |
| 432 | fsmount | Policy-denied |
| 433 | fspick | Policy-denied |
| 434 | pidfd_open | Partial |
| 435 | clone3 | Partial |
| 436 | close_range | Complete |
| 437 | openat2 | Partial |
| 438 | pidfd_getfd | Partial |
| 439 | faccessat2 | Partial |
| 440 | process_madvise | Partial |
| 441 | epoll_pwait2 | Partial |
| 442 | mount_setattr | Policy-denied |
| 443 | quotactl_fd | Policy-denied |
| 444 | landlock_create_ruleset | Partial |
| 445 | landlock_add_rule | Partial |
| 446 | landlock_restrict_self | Partial |
| 447 | memfd_secret | Partial |
| 448 | process_mrelease | Partial |
| 449 | futex_waitv | Partial |
| 450 | set_mempolicy_home_node | Partial |
| 451 | cachestat | Partial |
| 452 | fchmodat2 | Partial |
| 453 | map_shadow_stack | Partial |
| 454 | futex_wake | Partial |
| 455 | futex_wait | Partial |
| 456 | futex_requeue | Partial |
| 457 | statmount | Partial |
| 458 | listmount | Partial |
| 459 | lsm_get_self_attr | Partial |
| 460 | lsm_set_self_attr | Partial |
| 461 | lsm_list_modules | Partial |
| 462 | mseal | Partial |

## Completion requirements

A syscall may move from Partial to Complete only when its supported flags,
structures, success behavior, Linux error precedence, blocking/interruption
behavior, concurrency, and filesystem or descriptor side effects are covered by
tests. libc startup success alone is not conformance.

The practical compatibility gate remains workload-driven:

1. Trace the next target workload on Linux.
2. Add every observed syscall and non-syscall ABI dependency to this ledger.
3. Implement the behavior against the pinned sources.
4. Add focused kernel tests and a real OCI userspace regression.
5. Change status only after those tests prove the documented boundary.

The controller exposes the complete compiled ledger through `test linux all`;
see [Linux Userspace Interface Test v0](../specs/kernel/linux-abi-test-v0.md).
Boot verification also executes `/bin/linux-conformance` as a separate measured
ring-3 ELF with its own five-page executable profile. New syscall-level
tests belong there instead of expanding the tightly bounded bootstrap probe;
the first suite covers inode-wide memfd seals through real Linux syscalls.
`test linux` prints its summary, while `interfaces`, `syscalls`, and `syscall
NAME|NUMBER` select detailed results. The command name is intentionally
environment-specific so future compatibility profiles, such as BSD, can have
independent tests and contracts.

For grouped interfaces, PASS reports that the current bounded Ginux profile was
verified during boot; it does not upgrade that interface to complete Linux
compatibility. For individual syscalls, only a complete runtime conformance
probe may print PASS. Partial or missing behavior prints FAIL, and deliberate
authority policy prints POLICY-EXEMPT. Lack of verification is therefore an
actionable failure rather than a separate outcome. The runtime catalog is
generated from every syscall row in this file so documentation and the
executable checklist cannot silently diverge.
