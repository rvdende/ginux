# A small trusted core: the framekernel plan

Ginux wants `unsafe` confined to a minimal, audited layer (page tables,
context switch, MMIO, DMA, entry code, the allocators, per-CPU state and
locks) with everything above it in safe Rust that the compiler checks. This
is the "framekernel" architecture of Asterinas. This document measures where
Ginux stands, proposes the boundary and the safe APIs the core must offer,
and lays out an ordered migration with CI enforcement.

Measured at `e321d83d` (2026-10-31). Every number below comes from
`tools/architecture/inventory-unsafe.sh`; rerun it to refresh them.

## 1. Summary

- **1,360 unsafe sites** in `kernel/src` and `boot/efi/src` (compiler-exact;
  unique source locations): 1,206 `unsafe` blocks, 104 `unsafe fn`, 30
  `unsafe impl`, 18 `global_asm!`, one `unsafe extern` block and one
  `#[no_mangle]`. They contain **2,891 unsafe operations**, 413 of them in
  the bodies of `unsafe fn`s outside any `unsafe` block.
- **58 of 75 source files contain unsafe**, holding 116k of the 125k
  hand-written lines. Only 16 hand-written modules (9.5k lines) and the
  generated `generated_boot.rs` are free of it. All 12 crates under
  `crates/` are unsafe-free, but none says so with `#![forbid(unsafe_code)]`.
- **926 of 1,206 unsafe blocks (77 %) have no `// SAFETY:` comment.**
- **Biggest offenders:** `address_space.rs` (349 sites, 1,079 operations,
  mostly raw page-table entry reads and writes), `linux_socket.rs` (158,
  almost all `&'static mut` accessors to one global owner cell),
  `cpu.rs` (131 sites, sparse for 45k lines but home of the entry
  assembly and the trap-frame pointers), `arch/x86_64/pci.rs` (69, MMIO and
  DMA for the in-kernel virtio drivers), `paging.rs` (56) and
  `linux_process.rs` (56). By density `acpi.rs` (85 sites per 1,000 lines)
  and `linux_socket.rs` (63) lead.
- **By category** (heuristic, see §3.1): owner cells and `static mut` 313,
  page tables 267, direct-map views of kernel frames 205, MMIO/PIO 189,
  entry and context switch 105, DMA 94, firmware 72, frame allocator and
  heap 37, CPU control 28, user memory 22, convenience 21, locks 7.
- **Soundness hazards that exist today**, beyond the count: 108 safe
  functions dereference an integer or raw-pointer argument (their signature
  promises safety they cannot deliver), 42 safe functions return
  `&'static mut` into global state, and every owner cell is sound only
  because the recursive `kernel_entry_lock` serializes the kernel, which
  `docs/SCHEDULER.md` step 6 removes.

**Proposed boundary.** A `trusted` module (later its own crate,
`ginux-trusted`) holding: entry and context switch, CPU control, per-CPU
state, the frame allocator and heap, page tables behind an
`AddressSpace`/`Cursor` API, user-memory copies behind `UserPtr<T: Pod>`,
`IoMem`/`IoPort`/`DmaBuffer` (today's `drivers/device_memory.rs`), the I/O
MMU, locks, and the boot/firmware handoff. Everything else (the Linux
personality, file systems, sockets, domains, driver logic) becomes safe
Rust: first `#![deny(unsafe_code)]` with a shrinking allowlist, then
`#![forbid(unsafe_code)]` on the kernel crate once the core is a crate.

**First three steps** (§5): `#![forbid(unsafe_code)]` in the 12 crates; the
same in the 13 kernel leaf modules that already have no unsafe; then
`#![deny(unsafe_op_in_unsafe_fn)]` kernel-wide so the 413 hidden operations
become visible blocks. Step 4 turns on crate-level `deny(unsafe_code)` with
an allowlist and a ratchet check wired into `make check`.

## 2. What a framekernel requires

Asterinas ([USENIX ATC '25](https://www.usenix.org/conference/atc25/presentation/peng-yuke),
[arXiv 2506.03876](https://arxiv.org/abs/2506.03876)) splits the kernel
into a privileged framework, OSTD, which is the only code allowed to use
`unsafe`, and de-privileged services written entirely in safe Rust, in
one address space and one privilege level. The isolation is the type system,
so it costs nothing at run time. The paper's rules, in short:

- **Soundness:** the framework guarantees no undefined behaviour under any
  use of its safe API: language-level UB, corruption of the kernel's stacks,
  heap or code, and architecture-level UB (bad page tables, bad CPU state).
- **Minimality:** a piece stays in the framework only if moving it out would
  lose needed functionality or soundness.
- **Sensitive and insensitive resources.** Kernel memory, kernel-mode CPU
  state and core devices (interrupt controller, IOMMU, timers) are
  sensitive and never exposed. User memory, user-mode state and peripheral
  devices are insensitive and are what the safe API hands out.
- **Typed and untyped memory.** Frames holding Rust objects (kernel stacks,
  page tables, slabs) are typed and only ever reached through Rust
  references. Frames that user space or devices can write (`UFrame`,
  `USegment`) are untyped: no reference to them is ever formed, and they are
  read and written only by copying plain-old-data in and out (OSTD's
  `VmReader`/`VmWriter`).
- **Invariants the safe API maintains**, among them: a new `Frame` or
  `Segment` only comes from unused memory; user mappings (`VmSpace`) accept
  only untyped frames; `IoMem` and `IoPort` can only be created for
  insensitive regions; no memory is DMA-reachable until a `DmaCoherent` or
  `DmaStream` over untyped memory makes it so, with the IOMMU enforcing it;
  a task runs on at most one CPU at a time.
- **Result:** the TCB (crates containing unsafe, plus their dependencies) is
  14 % of Asterinas (10.6k of 75k linked lines), against 44-66 % for Tock,
  Theseus and RedLeaf. The authors test the framework under KernMiri, a
  Miri extended with simulated physical memory and paging.

For Ginux this comes down to three rules:

1. **R1. Only the core contains `unsafe`,** and the compiler enforces it
   (`#![forbid(unsafe_code)]` everywhere else).
2. **R2. Every safe function of the core is sound for every argument.** A
   signature like `fn read32(base: usize, offset: usize) -> u32` that
   dereferences `base` is a bug even if every caller passes a valid
   address, because R1 then proves nothing.
3. **R3. Memory that user space or a device can write is never behind a
   Rust reference,** only behind copy-in/copy-out or volatile accessors.

Ginux differs from Asterinas in a way that helps: drivers and protocol
services are meant to run in ring-3 domains with IOMMU-confined DMA, so much
of today's in-kernel driver code can leave the kernel instead of being made
safe inside it.

## 3. Inventory

### 3.1 Method

`tools/architecture/inventory-unsafe.sh` runs `cargo clippy` on
`ginux-kernel` and `ginux-boot` with four extra lints raised to warnings,
in its own target directory (`target/unsafe-inventory`), and parses the JSON
diagnostics:

- `unsafe_code` reports every unsafe block, `unsafe fn`, `unsafe impl`,
  `global_asm!`, `unsafe extern` block and unsafe attribute: the site list
  is the compiler's, so it is exact.
- `clippy::multiple_unsafe_ops_per_block` lists every operation of a block
  with more than one; a block it does not report has exactly one (an empty
  block would fail `unused_unsafe`), which the script identifies lexically.
- `unsafe_op_in_unsafe_fn` lists the operations in `unsafe fn` bodies that
  sit outside any block.
- `clippy::undocumented_unsafe_blocks` marks blocks and impls without a
  `// SAFETY:` comment.

A lexical pass over the same files (comments and strings blanked) adds what
lints do not report: `static mut` declarations, `asm!` invocations,
`global_asm!` size, the enclosing function of each site, safe functions that
dereference an integer or raw-pointer parameter, and safe functions that
return `&'static mut`. Each site then gets one category from an ordered rule
list in the script (file, function name and source text). The categories are
a planning aid: spot checks put the large ones right, but individual sites
can be argued. A one-line macro in `linux_socket.rs` expands into 15
accessor functions; it counts once.

All code is compiled in the default build (feature switches use `cfg!()`
at run time, not `#[cfg]`), so the default-feature check sees everything.

```
tools/architecture/inventory-unsafe.sh            # Markdown summary (default)
tools/architecture/inventory-unsafe.sh --sites    # one row per site, with category
tools/architecture/inventory-unsafe.sh --ops      # one row per unsafe operation
tools/architecture/inventory-unsafe.sh --unsound  # safe fns dereferencing an argument
```

The first run checks the dependencies into its own target directory (about
20 s); later runs take about 10 s.

### 3.2 Headline numbers

| measure | count |
|---|---:|
| Rust lines in scope (`kernel/src`, `boot/efi/src`; 45,000 of them generated) | 170,440 |
| unsafe sites (unique source locations) | 1,360 |
| &nbsp;&nbsp;`unsafe` blocks | 1,206 |
| &nbsp;&nbsp;`unsafe fn` (93 functions and 25 methods as the compiler counts, less 14 macro repeats) | 104 |
| &nbsp;&nbsp;`unsafe impl` (25 `Sync`, 1 `Send`, 1 `GlobalAlloc`, 2 in `sync.rs`, 1 `OwnedState`) | 30 |
| &nbsp;&nbsp;`global_asm!` | 18 |
| &nbsp;&nbsp;`unsafe extern` block, `#[no_mangle]` | 1 + 1 |
| unsafe operations inside the sites | 2,891 |
| &nbsp;&nbsp;in `unsafe fn` bodies outside any block | 413 |
| blocks without a `// SAFETY:` comment | 926 of 1,206 |
| `unsafe impl`s without one | 24 of 30 |
| `static mut` declarations | 46 |
| `asm!` invocations | 121 |
| `global_asm!` source lines (including `include_str!` files) | 2,011 |
| sites inside functions named `verify*` (boot-time self-tests) | 116 |
| safe fns that dereference an integer or raw-pointer parameter | 108 |
| safe fns that return `&'static mut` | 42 |

Operations by kind: pointer reads and writes (`read`, `write`, the volatile
and unaligned variants, `copy_nonoverlapping`, `write_bytes`) 1,109; pointer
arithmetic (`add`, `offset`) 611; calls of the kernel's own `unsafe fn`s
562; raw dereferences (`*p`, `&*p`, `&mut *p`) 283; pointer-to-reference
conversions (`from_raw_parts`, `as_ref`, `assume_init_*`) 148; `asm!` 121;
`static mut` accesses 50; calls through function pointers (UEFI) 7. The
most-called kernel `unsafe fn`s are the socket owner accessors (`socket_slots`
alone 123 times), `activate` (CR3 load, 38), `write_msr`/`read_msr` (48),
`zero_frame` (22), PCI config accessors (35) and `outb` (19).

### 3.3 The biggest offenders

| file | lines | sites | ops | per kLOC | what the unsafe is |
|---|---:|---:|---:|---:|---|
| `address_space.rs` | 14,144 | 349 | 1,079 | 24.7 | Page-table entries read and written through `*mut u64` (212 sites), CR3 loads (`activate`, 38 calls), frames reached through the direct map (76), owner cells (37), 12 `global_asm!` that embed ring-3 test programs, the user-copy wrappers. 321 of 349 undocumented. |
| `linux_socket.rs` | 2,494 | 158 | 235 | 63.4 | A macro generates 15 `unsafe fn x() -> &'static mut T` accessors into `SOCKET_RUNTIME_OWNER`; 131 blocks call them. The rest is socket data pages reached through the direct map and an in-kernel virtio-net driver (rings at raw DMA addresses). |
| `arch/x86_64/cpu.rs` | 44,988 | 131 | 192 | 2.9 | Sparse, but it is the entry: a 560-line `global_asm!` with the syscall, interrupt, NMI and user-copy stubs; 37 `frame.as_ref()`/`as_mut()` on raw trap-frame pointers; MSR, CR4 and FS-base access; `enter_user` and friends; the `X86_MUTABLE_RUNTIME` cells. Its 415 `X86_RUNTIME_BACKING_*` statics are almost all atomics and need no unsafe. |
| `arch/x86_64/pci.rs` | 4,532 | 69 | 90 | 15.2 | PCI config space by port I/O, virtio-blk and virtio-net queues by raw volatile access (`read_dma_u32(address)` and similar), the virtio interrupt stub, 13 large `unsafe fn`s for device bring-up and probes. |
| `arch/x86_64/paging.rs` | 2,195 | 56 | 260 | 25.5 | The kernel page tables: `install_initial_identity_map` is one 923-line `unsafe fn` with 127 unsafe operations; validation walks over raw table pointers. |
| `linux_process.rs` | 4,892 | 56 | 94 | 11.4 | Process tables in `UnsafeCell` owners handed out as `&'static mut`, direct-map copies of process pages, test hierarchies in verification code. |
| `arch/x86_64/acpi.rs` | 492 | 42 | 77 | 85.4 | Parsing firmware tables with `read_unaligned` at raw offsets. One slice per table would make the parser safe. |
| `lib.rs` | 5,176 | 40 | 73 | 7.7 | `kernel_main` is a 4,224-line `unsafe extern "sysv64" fn` (21 blocks plus 7 bare operations), boot-time device bring-up, serial port I/O. |
| `memory.rs` | 1,146 | 29 | 45 | 25.3 | The frame allocator: metadata and bitmap tables reached by pointer, `assume_init_mut` on the allocator behind its lock. 27 of 29 documented. |
| `bringup.rs` | 1,017 | 23 | 48 | 22.6 | Hardware report path: driver `open`s, ACPI table dumps, UEFI `reset_system`. |

So the expectation holds for `address_space.rs` and, by role rather than
count, for `cpu.rs`. `linux_process.rs` is moderate. `linux_socket.rs` is the
surprise: one shortcut (a macro that returns `&'static mut`) multiplied
across the whole socket layer.

### 3.4 By category

| category | sites | ops | where | goes to |
|---|---:|---:|---|---|
| **owner-cell**: `UnsafeCell` owners with `unsafe impl Sync`, `&'static mut` accessors, `static mut` | 313 | 424 | `linux_socket.rs` 131, `address_space.rs` 37, `cpu.rs` 22, `linux_process.rs` 21, image store, tmpfs, overlay, mount, user, signal, packet, volume | Disappears: `SpinLock<T>` fields or `CpuLocal<T>` |
| **paging**: page-table entries, CR3, `invlpg` | 267 | 718 | `address_space.rs` 212, `paging.rs` 42 | Core: `AddressSpace`/`Cursor` |
| **frame-view**: kernel frames reached through the direct map as `&mut Page`, byte slices, zeroing and copying | 205 | 733 | `address_space.rs` 76, `linux_process.rs` 25, overlay 16, sysv IPC 14, tmpfs, image store, file cache, aio, keyring, signal | Disappears: heap `Box`, or `Frame`/`UntypedFrame` with copy methods |
| **mmio-pio**: device registers, PCI config space, APIC, serial, framebuffer, driver bring-up | 189 | 307 | `pci.rs` 50, `lib.rs` 23, `timer.rs` 16, `apic.rs` 12, `bringup.rs` 12, every driver | Core: `IoMem`, `IoPort`, `PciConfig`, `LocalApic` |
| **entry**: entry/exit assembly, trap frames, GDT/IDT/TSS, FS base, extended state, activation stacks | 105 | 142 | `cpu.rs` 77, `architecture.rs` 7, `activation.rs` 5 | Core: `UserContext`, `UserMode`, `TrapFrame` by reference |
| **dma**: descriptor rings, static DMA pages, I/O MMU tables | 94 | 233 | `pci.rs` 18, `xhci.rs` 14, `amd_iommu.rs` 13, `linux_socket.rs` 13 | Core: `DmaBuffer` plus I/O MMU binding |
| **firmware**: UEFI calls, ACPI tables, `BootInfo` | 72 | 187 | `acpi.rs` 42, boot loader 10, `bringup.rs` 7, `manifest.rs` 7 | Core at the boundary; parsers become safe |
| **frame-heap**: frame allocator and kernel heap internals | 37 | 49 | `memory.rs` 29, `heap.rs` 8 | Core, as is |
| **cpu**: MSRs, CR0/CR4 features, `cli`/`sti`/`hlt`, TSC | 28 | 39 | `cpu.rs` 14, `smp.rs` 4 | Core: named safe operations |
| **user**: user-memory copies | 22 | 39 | `cpu.rs` 14, `address_space.rs` 6 | Core: `UserPtr<T: Pod>` |
| **convenience**: safe today with no new API | 21 | 14 | 12 `global_asm!` embedding ring-3 programs, plain structs viewed as bytes, `read_unaligned` in `pe.rs`, `OwnedState` | Disappears |
| **lock**: `SpinLock`, `IrqSpinLock`, kernel-entry lock | 7 | 6 | `sync.rs` | Core, as is |

The full file-by-category matrix is in Appendix A.

What the categories look like in code:

- **owner-cell.** `linux_tmpfs.rs` declares
  `struct TmpfsRuntimeOwner { instances: UnsafeCell<[Tmpfs; N]> }` with
  `unsafe impl Sync for TmpfsRuntimeOwner {}` and no SAFETY comment, and
  `live_mut` returns `&mut *TMPFS_RUNTIME.instances.get().cast::<Tmpfs>().add(index)`.
  There are 25 such owner structs. The SAFETY comments that exist name the
  real invariant: "Socket lifecycle operations are serialized by the active
  domain until Gate 8 supplies the owner lock"
  (`linux_socket.rs:235`), "the recursive kernel-entry boundary"
  (`linux_process.rs:86`). Drivers keep their DMA pages and state in
  `static mut` (29 of the 46).
- **paging.** `let value = unsafe { entry.read() }; ... unsafe { entry.write(value & !WRITABLE) };`
  over `*mut u64` from `current_linux_leaf(page)`, once per operation
  (protect, replace, reserve, map, CoW, seal, prune, release), each with its
  own `invlpg`.
- **frame-view.** `fn segment_page_mut(frame: FrameLease) -> Option<&'static mut SegmentPage> { Some(unsafe { &mut *(frame.direct_map_address()? as *mut SegmentPage) }) }`
  (`linux_sysv_ipc.rs`), and the same shape in tmpfs, overlay, aio, keyring
  and signal. These modules predate the kernel heap.
- **mmio-pio.** Every driver has `fn read32(base: usize, offset: usize) -> u32 { unsafe { ((base + offset) as *const u32).read_volatile() } }`.
  `drivers/virtio_gpu.rs` is the exception: it uses `device_memory::Mmio`
  and needs four unsafe blocks in 640 lines.
- **entry.** `extern "sysv64" fn syscall_handler(frame: *mut UserTrapFrame)`
  and 34 per-call helpers that start with `let Some(frame) = (unsafe { frame.as_ref() }) else { ... }`.
- **user.** The fault-recovering `ginux_raw_copy_{from,to}_user` stubs and
  the `copy_*_current_user*` wrappers in `address_space.rs`, each with its
  own range check.

### 3.5 Soundness findings

These are about correctness under the framekernel rules, not just counts.

1. **Safe functions that are unsound by signature (R2): 108.** Each takes
   an integer address or a raw pointer and dereferences it in an `unsafe`
   block, so a caller in safe code can cause UB by passing a bad value
   (`--unsound` lists them). They group into: trap-frame pointers in the
   syscall dispatch (`cpu.rs`, about 36: these are entry points called from
   assembly and should take `&mut UserTrapFrame`); MMIO and DMA helpers
   taking `base: usize` in every driver and in `pci.rs` (43);
   `manifest.rs` (`pub(crate) fn parse_and_verify(pointer: *const u8, size: usize, ...)`
   and six siblings); the ACPI parsers taking `*const u8`; `pe.rs`. Six of
   the 108 are user-copy wrappers that are sound by design: they check the
   range against the user half (or the current user mappings) and copy
   through the fault-recovering stubs, so a bad address yields a short copy, not UB.
   `hardware_user_range_is_zero` (`cpu.rs`) has no range check of its own
   and relies on its two (self-test) callers.
2. **42 safe functions return `&'static mut`** (overlay 6, `cpu.rs` 5, sysv
   IPC 5, sockets 4, tmpfs 3, scheduler 3, ...). Two calls yield two
   aliasing mutable references, which is UB the moment both are live. The
   kernel-entry lock does not prevent it: it serializes CPUs, not call
   sites, and it is recursive.
3. **The owner cells' soundness rests on `kernel_entry_lock`.** Syscalls,
   timer and virtio interrupts take it, so today one CPU at a time runs
   kernel code. `docs/SCHEDULER.md` step 6 splits it into per-subsystem
   locks; at that point every owner cell that has not become a real lock is
   a data race. This is the strongest argument for doing the owner-cell
   migration (§5 step 6) before that scheduler step.
4. **Hidden unsafe.** 413 operations sit in `unsafe fn` bodies with no
   block of their own (`unsafe_op_in_unsafe_fn` is off in edition 2021),
   most in `install_initial_identity_map` (127), `kernel_main`, `pci.rs`'s
   bring-up functions and the boot loader.
5. **Undocumented invariants.** 926 of 1,206 blocks lack a SAFETY comment.
   The modules that would form the core are already well documented
   (`memory.rs` 27 of 29, `heap.rs` 8 of 8, `device_memory.rs` 7 of 7,
   `xhci.rs` 18 of 20); the gaps are in the code that should not have unsafe
   at all (`address_space.rs` 28 of 349 documented, `linux_socket.rs` 9 of
   158).
6. **`FrameLease` is `Copy`, and forgeable.** A lease is an address plus
   a generation; the allocator checks the generation on release, but
   `FrameLease::direct_map_address` does not, so a copy kept after release
   still reaches the frame, and the safe `FrameLease::from_parts` builds a
   lease for any page-aligned address above 1 MiB. Ownership of a frame is
   therefore not something the type system knows, and every
   `&mut *(lease.direct_map_address()? as *mut T)` trusts its caller.
7. **Verification code in the production image.** 116 sites sit in
   `verify*` functions run at boot (`verify_linux_elf_mapping` is one
   587-line unsafe block). They keep unsafe alive wherever they live unless
   they use the same safe APIs as the code they test.
8. **Small leftovers.** `linux_socket.rs` has `#![allow(static_mut_refs)]`
   but no `static mut`; twelve `global_asm!(include_str!("../packet-*.S"))`
   in `address_space.rs` assemble ring-3 test programs into the kernel's
   text, while `build.rs` already assembles the other ring-3 programs
   (`linux-probe.S` and others) with clang into blobs.

### 3.6 Already free of unsafe

The compiler reports nothing in these hand-written modules (9.5k lines):
`linux_elf.rs` (4,746 lines), `cpu/linux_abi.rs` (907), `cpu/linux_futex.rs`
(711), `network.rs` (657), `native_elf.rs` (488), `drivers/virtio.rs` (441),
`drivers/gpt.rs` (366), `capability.rs` (285), `drivers/net.rs` (206),
`crypto.rs` (186), `control_abi.rs` (129), `drivers/keyboard.rs` (125),
`executable.rs` (117), and the module-list files `arch.rs`,
`arch/x86_64.rs`, `drivers/mod.rs`. `boot/efi/src/generated_boot.rs`
(45,000 generated lines) is also clean.

All twelve crates are unsafe-free: `command`, `image-store`, `native-abi`,
`oci`, `oci-cache`, `protocol-state`, `runtime-memory`, `usb-audio`,
`usb-hid`, `virtio-gpu`, `volume-format`, `volume-service`. Nine of them are
linked into the kernel. None declares `#![forbid(unsafe_code)]`.

## 4. The proposed boundary

### 4.1 Shape

Stage A is a module, `kernel/src/trusted/`, inside the kernel crate. The
crate root gets `#![deny(unsafe_code)]`; `trusted` (and, during migration,
the legacy files on an allowlist) get `#![allow(unsafe_code)]`. Inside
`trusted`, `unsafe_op_in_unsafe_fn`, `clippy::undocumented_unsafe_blocks`
and `clippy::multiple_unsafe_ops_per_block` are denied, so every operation
carries its own argument.

Stage B moves `trusted` into its own crate, `crates/ginux-trusted`
(`no_std`, built for `x86_64-unknown-uefi` like the kernel), and the kernel
crate switches to `#![forbid(unsafe_code)]`. Only a crate boundary makes the
rule absolute: `forbid` at a crate root cannot be overridden by any module,
and the TCB becomes a measurable unit (Asterinas counts crates containing
unsafe plus their dependencies). The UEFI loader in `boot/efi` is core in
its entirety; it is firmware glue and stays a separate crate.

The name is not `core`: a crate-level module called `core` makes every
`core::` path in the kernel ambiguous.

### 4.2 What goes in

```
trusted/
  boot      kernel entry, BootInfo -> safe owned BootView (memory map,
            framebuffer, RSDP), ACPI tables as validated &'static [u8]
  cpu       MSR/CR access (private), SMEP/SMAP/UMIP/NX enable, GDT/IDT/TSS,
            per-CPU state (CpuLocal, GS base), interrupt flag guards and
            halt, local APIC, SMP start-up, TSC
  entry     syscall/interrupt/NMI stubs (today's cpu.rs global_asm!),
            TrapFrame, UserContext, UserMode::execute, activation stacks,
            task context switch
  mm        frame allocator (memory.rs), heap (heap.rs), Frame/Segment/
            UntypedFrame, direct map, kernel page tables (paging.rs),
            AddressSpace and Cursor (from address_space.rs), TLB shootdown,
            user copy (UserPtr, fault fix-ups)
  io        IoMem and DmaBuffer (drivers/device_memory.rs), IoPort, PCI
            configuration space, I/O MMU (iommu.rs, amd_iommu.rs)
  sync      SpinLock, IrqSpinLock, the kernel-entry lock, OwnedState
```

A rough size estimate, from the files that move whole and the parts of
others: 12-16k lines, about 10 % of the 125k hand-written lines, with a few
hundred documented unsafe sites instead of 1,360 spread over 58 files.

### 4.3 The safe APIs

Each entry gives the API, why it is sound, what it absorbs and what already
exists.

**A. Locks and cells instead of owner cells.** Owner structs keep their
fields but wrap mutable state in `SpinLock<T>`/`IrqSpinLock<T>` (with a
rank) or, for per-CPU data, `CpuLocal<T>` (`with(|&T|)`, `with_mut` only
with interrupts off). Accessors become `fn with_sockets<R>(f: impl FnOnce(&mut Sockets) -> R) -> R`
instead of `fn socket_slots() -> &'static mut [Slot]`. Sound because the
guard is the only path to `&mut T` and lives no longer than the lock is
held. The existing lock-rank checker already fails closed on order
violations; adding owner-CPU detection to `SpinLock::lock` turns a
re-entrant acquire (today's latent aliasing) into a reported failure instead
of a deadlock. `OwnedState<T>` keeps its publication protocol but loses
`get_mut_ptr`; mutable access goes through a lock. Absorbs the 313
owner-cell sites and the 42 `&'static mut` returns. Exists: `sync.rs`
(ticket locks, ranks, `KernelEntryLock`), `owned_state.rs`, and the
writable-globals manifest (`docs/feedback-hardening/writable-globals.tsv`).

**B. User memory.** `UserPtr<T: Pod>` and `UserSlice<T: Pod>` are user
addresses, constructed from syscall arguments without validation; reading
and writing go through `CurrentUser::read(ptr) -> Result<T, Fault>`,
`write(ptr, &T)`, `read_slice`, `write_slice`. The range check (whole range
below the user limit, no overflow) and the copy through the
fault-recovering stubs happen inside, once. `Pod` is a sealed or derived
trait for types valid for every bit pattern with no padding, so copying
bytes in and out cannot create an invalid value and copying out cannot leak
kernel data through padding. Sound because no Rust reference to user memory
is ever formed (R3), the asm fix-up turns any fault into an error, and a
kernel address can never pass the range check. Cross-process access
(`copy_live_process_bytes`, `write_live_process_u32`) goes through the
target's `AddressSpace` and an owned frame instead of a direct-map
pointer. Absorbs the 22 user sites, the plain-struct-as-bytes conversions in
`cpu/linux_signal.rs`, and makes the six sound-by-design wrappers the only
implementation. Exists: `ginux_raw_copy_{from,to}_user` with fix-ups and
`verify_user_copy_fault_fixups` in `cpu.rs`, `copy_from_current_user_partial`
and friends in `address_space.rs`, and `check-user-access.sh`, which already
confines `with_supervisor_user_access`.

**C. Frames.** `Frame` and `Segment` are owning handles: not `Copy`,
released to the allocator (scrubbed) on drop, so no stale handle can reach
a reused frame. `FrameLease` stays as a plain identifier for snapshots and
tables, without access rights. Kernel-private structures that live in a
frame today become heap objects (`Box<SegmentPage>`); where a frame is
required, `FrameBox<T>` gives typed access to a frame that is never mapped
to user space or a device. Frames that are or may be mapped to user space
or a device are `UntypedFrame`/`UntypedSegment` with `read_bytes`,
`write_bytes`, `fill`, `copy_from`, `read::<T: Pod>` and no reference
access. Sound because typed frames are unique (or reference-counted) and
never shared with user or device, so the borrow rules hold, and untyped
frames are only copied. Absorbs the 205 frame-view sites. Exists: the frame
allocator with per-owner accounting and generations (`memory.rs`),
`DmaBuffer` (an untyped segment with owner and drop already), the heap.

**D. Page tables.** `AddressSpace` owns its root and table frames; the
kernel half is shared and immutable to safe code. A `Cursor` over a virtual
range offers `query(va) -> Option<Mapping>` (a value: frame, permissions,
the Ginux software bits), `map(va, UntypedFrame, Perms)`,
`unmap(va) -> Option<UntypedFrame>`, `protect(range, Perms)`, and the Linux
operations built from them (copy-on-write marking, fork clone,
`MADV_WIPEONFORK`/`DONTFORK` bits, sealing). `activate(&self)` returns a
guard that restores the previous root. TLB invalidation and cross-CPU
shootdown happen inside, and `unmap` hands the frame back only after
invalidation completed. Sound because safe code can only map frames it
owns into the user half, can never name a page-table frame or a kernel
frame, and the user-half/kernel-half split is checked at construction
(`verify_linux_process_root_activation` checks it today). Absorbs 267
paging sites and most of `address_space.rs`. The per-process VMA work
(roadmap item 3) should be written against this API from the start. Exists:
`paging.rs` (direct map, `MmioMapping`, kernel stack window,
`ValidatedUserRootFrames`), the many validation walks in
`address_space.rs`, `smp.rs`'s translation invalidation.

**E. Device registers.** `IoMem` is today's `device_memory::Mmio`
(bounds-checked, aligned, volatile, `!Sync`) with a safe constructor that
takes a PCI function's BAR (or an ACPI-described range), refuses ranges that
overlap RAM or a core device, and maps them uncached; the `unsafe fn new`
stays private to the core. `IoPort` covers fixed port ranges handed out
once (COM1); PCI configuration space is a core service (`PciConfig` keyed
by bus/device/function) rather than raw `0xCF8`/`0xCFC` accesses in two
places. The local APIC, I/O APIC, timers and I/O MMU registers are core
devices and never become `IoMem`. Sound because a volatile write to device
registers that are not RAM cannot change memory that Rust code reasons
about, and the core keeps sensitive devices for itself. Absorbs the 189
MMIO/PIO sites and every `read32(base, offset)` in the unsound list.
Exists: `drivers/device_memory.rs` and its first client,
`drivers/virtio_gpu.rs`; `paging::MmioMapping::address` bounds checks.

**F. DMA.** `DmaBuffer` (exists) becomes the only way to give a device
memory: an untyped segment that the core admits into the device's I/O MMU
domain on allocation and removes (with IOTLB invalidation) before the frames
return on drop. Later split into a coherent buffer for rings and a
streaming buffer for data, as OSTD does. Sound because devices can only
reach memory admitted this way when the I/O MMU translates, and no Rust
reference into DMA memory exists. Absorbs the 94 DMA sites: the `static mut`
rings and buffers in `e1000e`, `realtek`, `hda`, `nvme`, `ahci`, `xhci`, the
virtio queues in `pci.rs` and `linux_socket.rs`. Exists: `DmaBuffer`, the
admission path (`DmaBuffer::region`), `iommu.rs` and `amd_iommu.rs`.

**G. CPU, entry and context switch.** Syscall and interrupt entry points
receive `&mut TrapFrame` (the assembly guarantees a valid, exclusive frame
on the entry stack: that is the single audited fact). User execution is
`UserMode::execute(&mut UserContext) -> ReturnReason`, with the general
registers, FS base and extended state in the context, replacing
`enter_user`/`enter_linux_process`/`enter_linux_runtime_process` and their
raw `*const u64` register arrays. The scheduler rework puts the context
switch (`switch_to(next: &Task)`) and the activation stacks in the core.
CPU control becomes named operations (`cpu::enable_smap()`,
`cpu::set_fs_base(u64)`, `cpu::halt_until_interrupt()`,
`cpu::without_interrupts(|| ...)`). Absorbs the 105 entry and 28 CPU sites
outside the core and the 36 trap-frame functions in the unsound list.
Exists: `cpu/activation.rs` (stacks with guard pages, `ginux_call_on_stack`),
`cpu/architecture.rs` (per-CPU GDT/IDT/TSS, IST guard pages),
`cpu/execution.rs` (xsave state), the entry invariants checked by
`check-privilege-entry.sh`.

**H. Boot and firmware.** At entry the core turns `*const BootInfo` into a
safe view: the memory map as a slice of descriptors, the framebuffer
description, the manifest and images as `&'static [u8]` after range checks,
and ACPI tables as checksummed `&'static [u8]`. Parsing then uses slice
indexing and `from_le_bytes` (`acpi.rs`'s 42 sites become about three).
`kernel_main` becomes a safe function called by the core's entry with that
view.

### 4.4 What stays unsafe for good

The entry and exit assembly (about 560 lines in `cpu.rs`, plus the timer,
virtio, SMP trampoline and stack-switch stubs), the context switch, CR3
loads and TLB invalidation, MSR and control-register writes,
GDT/IDT/TSS installation, the user-copy fix-up stubs, the frame allocator's
metadata tables, the `GlobalAlloc` implementation, page-table entry writes,
volatile MMIO, I/O MMU programming, the lock implementations, per-CPU access
through GS, UEFI calls and `ExitBootServices`, and the AP start-up
trampoline. These are what OSTD contains too.

## 5. Migration plan

Every step is a separate commit that keeps the system booting and passing
`make check` (with `rg` on `PATH`, see CLAUDE.md). The suites named per step
are the ones that exercise the code it touches. "Removes" counts sites from
the inventory; rerun the script to confirm.

**Coordination.** The scheduler rework is changing `cpu.rs` and
`linux_process.rs` now. Steps 1 and 2 do not touch them. Step 3 wraps the
operations of eight `unsafe fn`s in `cpu.rs` and step 4 adds one line at the
top of both files; both are mechanical and can be rebased onto the
scheduler commits at any time. Steps 5 to 9 leave the parts of those two
files that they would touch (`cpu.rs`'s copy wrappers and owner cells,
`linux_process.rs`'s tables) until the rework has landed. Steps 10 and 11
wait for the scheduler steps that rewrite entry and process switching, and
the context switch those steps introduce should be written into
`trusted::entry` from the start.

1. **Forbid unsafe in the crates.** Add `#![forbid(unsafe_code)]` to the
   twelve `crates/*/src/lib.rs`. Removes nothing, prevents regressions in
   about 9 of the kernel's dependencies. Verify: `make check` (it runs
   clippy and the tests of each crate).
2. **Forbid unsafe in the clean kernel leaves.** `#![forbid(unsafe_code)]` at
   the top of `linux_elf.rs`, `network.rs`, `native_elf.rs`,
   `capability.rs`, `crypto.rs`, `executable.rs`, `control_abi.rs`,
   `drivers/{gpt,keyboard,net,virtio}.rs`, `cpu/{linux_abi,linux_futex}.rs`
   (one line each; the last two are children of `cpu.rs`, not `cpu.rs`
   itself). Not on `arch.rs`, `arch/x86_64.rs` or `drivers/mod.rs`: a
   `forbid` there would cover their unsafe children. Have the manifest tool
   emit the attribute at the top of `generated_boot.rs`. Covers 9.5k lines.
   Verify: `make check`, `make build`.
3. **Make hidden unsafe visible.** `#![deny(unsafe_op_in_unsafe_fn)]` in
   `kernel/src/lib.rs` and `boot/efi/src/main.rs`. The lint carries a fix
   suggestion (it is how `cargo fix --edition` moves code to edition 2024),
   so the 413 operations get explicit blocks mechanically; then shrink the giant ones by hand
   (`install_initial_identity_map`, `kernel_main`, `pci.rs` bring-up) and
   add SAFETY comments as they shrink. No behaviour change. Verify:
   `make check`, `make test-alpine` as a boot smoke test.
4. **Deny by default, with an allowlist and a ratchet (§6).**
   `#![deny(unsafe_code)]` in `kernel/src/lib.rs` and the boot crate;
   `#![allow(unsafe_code)]` as the first line of the 58 files that need it
   today, each listed in `tools/architecture/unsafe-allowlist.tsv` with its
   role (`core` or `legacy`) and its current site count; add
   `tools/architecture/check-unsafe.sh` to `check.sh`. From here a new file
   cannot use unsafe without an allowlist change in review, and a legacy
   file cannot grow. Verify: `make check`, including the check's negative
   test.
5. **Typed user memory.** Add `UserPtr<T: Pod>`, `UserSlice`, the `Pod`
   trait and `CurrentUser` next to the existing copy primitives; reimplement
   `copy_from_current_user*`/`copy_to_current_user*` on them; replace the
   plain-struct-as-bytes conversions in `cpu/linux_signal.rs` with `Pod`;
   give `hardware_user_range_is_zero` the shared range check. Migrate call
   sites module by module (the syscall code mostly already calls the safe
   wrappers, so this is about types, not unsafe count). Removes about 25
   sites and the user-copy entries in the unsound list. Verify: `make check`,
   `make test-alpine`, `make test-linux-abi`, `tests/qemu/rust-workloads.sh`,
   `make test-rust-userland`, and `make test-ltp` against the
   `docs/LTP.md` baseline (EFAULT behaviour).
6. **Owner cells become locks, one module per commit,** smallest first:
   `ipc.rs`, `volume.rs`, `packet.rs`, `linux_mount.rs`, `linux_user.rs`,
   `linux_signal.rs`, `linux_file_cache.rs`, `initramfs.rs`,
   `image_store.rs`, `linux_tmpfs.rs`, `linux_overlay.rs`, then
   `linux_socket.rs` (131 sites: replace the `owner_field!` macro with one
   `IrqSpinLock<SocketRuntime>` taken once per socket call). Then
   `domain.rs`, `scheduler.rs`, `address_space.rs`'s owners and, after the
   scheduler rework, `cpu.rs`'s `X86_MUTABLE_RUNTIME` and `linux_process.rs`.
   The drivers' `static mut` go in step 8. Removes about 310 sites and the
   42 `&'static mut` returns. Must finish before SCHEDULER.md step 6 splits
   `kernel_entry_lock`. Verify per module: `make check`, `make test-alpine`,
   `tests/qemu/rust-workloads.sh`, `make test-desktop`; for sockets also
   `make test-multi-domain` and the network suites; `make test-smp` and the
   `test-rocky-smp-*` targets where the images are available. Any
   lock-order violation fails closed at run time.
7. **Kernel-private pages onto the heap.** tmpfs, overlay, sysv IPC, aio,
   keyring, signal queues, the file cache and the published-rootfs index
   keep page-sized structures in frames reached through the direct map. Move
   the kernel-private ones to `Box`/`Vec` (the heap exists since
   SCHEDULER.md step 1); pages that are mapped into user space (shared
   memory segments, `mmap`ed file pages) become `UntypedFrame`s with copy
   methods instead (check each structure for this before moving it).
   Introduce owning `Frame`/`Segment` in `memory.rs` as part of this step.
   Removes most of the 205 frame-view sites outside `address_space.rs`.
   Verify: `make check`, `make test-alpine`,
   `tests/qemu/rust-workloads.sh`, `make test-storage`,
   `make test-oci-cache`, `make test-ltp` (the sysv IPC and tmpfs
   clusters).
8. **Drivers onto `IoMem` and `DmaBuffer`.** Give `Mmio` a safe constructor
   from a PCI BAR, then port the drivers the way `virtio_gpu.rs` is
   written: `e1000e`, `realtek`, `hda`, `nvme`, `ahci`, `xhci` and
   `usb_input`, `amd_iommu`'s command and event rings, the virtio-net device
   in `linux_socket.rs`, and the virtio-blk/net code in `pci.rs`. Each
   driver's `unsafe fn open` becomes safe. For drivers that the roadmap
   moves into ring-3 domains, moving them is the better fix. Removes about
   230 mmio/dma sites, the 29 driver `static mut`s and most of the unsound
   list. Verify: `make check`; `make test-desktop` (xhci input),
   `make test-desktop-virtio-gpu`, `make test-storage` (nvme, ahci,
   virtio-blk), `make test-boot-media`, `make test-hardware-profile`, and a
   real-hardware boot for `realtek`, `hda` and AMD-Vi.
9. **Firmware and leftovers.** ACPI tables as checked slices with a safe
   parser (`acpi.rs`, `bringup.rs` report functions); `BootInfo` view at
   entry (`manifest.rs`, memory-map descriptors, `paging::read_descriptor`);
   `pe.rs` with `from_le_bytes`; assemble the twelve ring-3 test programs
   in `build.rs` like `linux-probe.S` and `include_bytes!` them (removes 12
   `global_asm!`); drop the stale `allow(static_mut_refs)`. Removes about
   80 sites. Verify: `make check`, `make build`, `make test-boot-media`,
   `make test-hardware-profile`, `make test-c1`.
10. **Entry by reference.** (After the scheduler steps that rewrite entry.)
    Entry points take `&mut TrapFrame`; per-call helpers take
    `&UserTrapFrame`/`&mut UserTrapFrame`; `UserContext` and
    `UserMode::execute` replace the `enter_*` family; FS base and extended
    state move into the context. Removes about 40 sites in `cpu.rs` and
    `timer.rs` and 36 unsound signatures. Verify: everything, `make
    test-smp` and `make test-ltp` included.
11. **The page-table API.** `AddressSpace`/`Cursor` in the core, then move
    `address_space.rs`'s operations onto it one family per commit: queries,
    protect, map/unmap, copy-on-write, fork clone, runtime-page bits,
    release. Build the VMA work (roadmap item 3) on the same API. Removes
    the 212 paging sites and the remaining 76 frame-view sites in
    `address_space.rs`, and turns its verification routines into users of
    the safe API. Verify: everything; `make test-ltp` (mm cluster),
    `tests/qemu/rust-workloads.sh` (fork- and mmap-heavy cargo builds).
12. **Gather the core.** Move what remains allowlisted as `core` under
    `kernel/src/trusted/`, deny `clippy::undocumented_unsafe_blocks` and
    `clippy::multiple_unsafe_ops_per_block` there, and reduce the legacy
    allowlist to empty.
13. **Split the crate.** `crates/ginux-trusted`; the kernel crate becomes
    `#![forbid(unsafe_code)]`; report the TCB share (lines of the trusted
    crate and its dependencies against the whole) in this document.
14. **Test the core like a library.** Host-side unit tests for the logic
    that does not need hardware (lock ranks, `Pod` and `UserPtr` range
    arithmetic, the frame bitmap and slab classes, `Cursor` index
    arithmetic over a simulated table) under Miri; later, a KernMiri-style
    harness with simulated physical memory.

## 6. CI enforcement

`tools/architecture/check-unsafe.sh`, called from `tools/architecture/check.sh`
(and so from `make architecture-check` and `make check`), modelled on
`check-writable-globals.sh`:

1. `kernel/src/lib.rs` and `boot/efi/src/main.rs` carry
   `#![deny(unsafe_code)]` (after step 13: the kernel carries `forbid`) and
   `#![deny(unsafe_op_in_unsafe_fn)]`.
2. Every `crates/*/src/lib.rs` carries `#![forbid(unsafe_code)]`, and so
   does `generated_boot.rs`.
3. The set of files containing `#![allow(unsafe_code)]` equals the file set
   of `tools/architecture/unsafe-allowlist.tsv` (`file`, `role`, `sites`).
   Adding a file to the core is a reviewed manifest change.
4. A ratchet: each file's site count from `inventory-unsafe.sh --sites`
   equals the manifest's count. Like the writable-globals manifest it must
   match exactly, so a commit that removes unsafe also lowers the number,
   and progress shows in the diff. `role = legacy` rows may only go down;
   `role = core` rows may change, with review.
5. Files with `role = core` deny `clippy::undocumented_unsafe_blocks`.
6. No safe function outside the core returns `&'static mut` (lexical check,
   as `--summary` does today).
7. A negative test, as the other checks have: append an unsafe block to a
   scratch copy of an unlisted file and assert that the check fails.

The ratchet needs the compiler-backed inventory, which adds one clippy run
over the kernel in its own target directory: about 20 s cold and 10 s warm.
If that is too slow for `make check`, a lexical count of `unsafe` tokens
(comments and strings blanked, as the script already does) is a cheaper
ratchet; the compiler's `deny(unsafe_code)` remains the actual guard either
way. `make unsafe-report` can print the full summary for humans.

## 7. Risks, and what cannot be made safe

- **Removing the big kernel lock before the owner cells.** The single
  largest risk. Every owner cell's SAFETY argument is "kernel entry is
  serialized". Splitting `kernel_entry_lock` (SCHEDULER.md step 6), or
  releasing it while user code runs, before this plan's step 6 is done
  turns that argument false and the cells into data races, with no compiler
  warning.
- **Recursion inside the entry lock.** The lock is recursive and init still
  runs other processes from inside its system calls, so two activations on
  one CPU can each hold a `&'static mut` into the same owner. The lock
  migration (step 6) must take each lock at the API boundary, once, and
  treat a nested acquire as a bug.
- **DMA without an I/O MMU.** `DmaBuffer`'s soundness argument needs the
  I/O MMU to confine the device. In QEMU without an emulated I/O MMU, or on
  hardware where it is off, a driver bug in safe code (a wrong descriptor
  address) can still make a device overwrite kernel memory. Until the I/O
  MMU is mandatory, in-kernel drivers remain trusted in fact if not in
  syntax; moving drivers to ring-3 domains limits what that trust covers.
- **Device quiescence.** A `DmaBuffer` must not be freed while the device
  can still write it. The core can enforce ordering only for buffers it
  admitted to the I/O MMU (remove the mapping, invalidate, then free);
  without translation it depends on the driver stopping the device first.
- **Invariants no type can express:** the kernel half of every page table is
  identical and immutable; the direct map covers all usable RAM; firmware
  tables are well formed (the core checksums and bounds-checks them, but a
  lying ACPI table is still trusted); the entry assembly saves and restores
  what it claims; `asm!` `options(nomem, nostack)` are correct.
- **Global assembly and linker scripts** are outside what the Rust compiler
  checks at all. `check-privilege-entry.sh` and `check-user-access.sh`
  already pin some of their invariants textually; they should grow with the
  core.
- **Third-party code in the TCB.** By the Asterinas rule, dependencies of
  the trusted crate are in the TCB, and today everything the kernel links
  (`smoltcp`, `ed25519-dalek` and its curve crate, `miniz_oxide`,
  `font8x8`, the nine Ginux crates) shares its address space. Keep the
  trusted crate's dependencies to `core` and `alloc`; audit the others'
  unsafe with `cargo geiger` and pin versions (already done in
  `kernel/Cargo.toml`).
- **Performance.** Bounds checks in `IoMem` and `DmaBuffer`, owning frame
  handles, real locks instead of one big lock, and copies instead of
  references for untyped memory all cost something. The fast user-copy
  path (`copy_to_current_linux_user_fast`) and per-page `invlpg` batching
  must survive the API change; measure with `docs/BENCHMARKING.md` before
  and after steps 6, 10 and 11.
- **Verification code.** The boot-time self-tests poke memory directly
  (116 sites). Rewriting them on the safe API is part of each step; deleting
  a test to delete its unsafe is not.
- **Edition.** The kernel is edition 2021. Edition 2024 makes
  `unsafe_op_in_unsafe_fn` warn by default, requires `unsafe extern` and
  `#[unsafe(no_mangle)]`, and denies references to `static mut`; it is worth
  doing after step 3, but it also changes `impl Trait` capture rules and
  should be its own step.
- **The heuristic categories.** Counts per category come from rules over
  file names, function names and source text; they are good enough to
  order the work, not to promise exact savings per step. The site counts
  and the per-file ratchet are exact.

## Appendix A: per-file and per-category tables

Generated by `tools/architecture/inventory-unsafe.sh` at `e321d83d`. `k/` is
`kernel/src/`.

### Per file

| file | lines | sites | blocks | unsafe fn | unsafe impl | asm/extern/attr | ops | no SAFETY | static mut | asm! | sites/kLOC |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| k/address_space.rs | 14144 | 349 | 329 | 5 | 3 | 12 | 1079 | 321 | 0 | 31 | 24.7 |
| k/linux_socket.rs | 2494 | 158 | 149 | 8 | 1 | 0 | 235 | 149 | 0 | 0 | 63.4 |
| k/arch/x86_64/cpu.rs | 44988 | 131 | 119 | 8 | 3 | 1 | 192 | 99 | 2 | 24 | 2.9 |
| k/arch/x86_64/pci.rs | 4532 | 69 | 55 | 13 | 0 | 1 | 90 | 54 | 0 | 15 | 15.2 |
| k/arch/x86_64/paging.rs | 2195 | 56 | 49 | 6 | 1 | 0 | 260 | 45 | 0 | 8 | 25.5 |
| k/linux_process.rs | 4892 | 56 | 53 | 0 | 3 | 0 | 94 | 43 | 0 | 0 | 11.4 |
| k/arch/x86_64/acpi.rs | 492 | 42 | 41 | 1 | 0 | 0 | 77 | 41 | 0 | 0 | 85.4 |
| k/lib.rs | 5176 | 40 | 32 | 6 | 1 | 1 | 73 | 16 | 1 | 3 | 7.7 |
| k/memory.rs | 1146 | 29 | 27 | 1 | 1 | 0 | 45 | 2 | 2 | 0 | 25.3 |
| k/bringup.rs | 1017 | 23 | 19 | 4 | 0 | 0 | 48 | 0 | 2 | 1 | 22.6 |
| k/arch/x86_64/timer.rs | 826 | 21 | 13 | 7 | 0 | 1 | 52 | 4 | 0 | 7 | 25.4 |
| k/arch/x86_64/cpu/architecture.rs | 586 | 20 | 16 | 2 | 2 | 0 | 52 | 13 | 0 | 3 | 34.1 |
| k/drivers/xhci.rs | 1805 | 20 | 18 | 2 | 0 | 0 | 55 | 2 | 2 | 0 | 11.1 |
| k/linux_overlay.rs | 1543 | 19 | 18 | 0 | 1 | 0 | 24 | 19 | 0 | 0 | 12.3 |
| k/image_store.rs | 786 | 18 | 17 | 0 | 1 | 0 | 24 | 17 | 0 | 0 | 22.9 |
| boot/main.rs | 689 | 17 | 7 | 9 | 0 | 1 | 65 | 3 | 2 | 2 | 24.7 |
| k/drivers/amd_iommu.rs | 436 | 15 | 12 | 3 | 0 | 0 | 29 | 3 | 6 | 0 | 34.4 |
| k/arch/x86_64/smp.rs | 665 | 14 | 12 | 0 | 0 | 2 | 13 | 11 | 0 | 6 | 21.1 |
| k/drivers/realtek.rs | 380 | 14 | 11 | 3 | 0 | 0 | 30 | 0 | 4 | 0 | 36.8 |
| k/linux_sysv_ipc.rs | 1848 | 14 | 14 | 0 | 0 | 0 | 15 | 14 | 0 | 0 | 7.6 |
| k/linux_tmpfs.rs | 721 | 14 | 13 | 0 | 1 | 0 | 19 | 14 | 0 | 0 | 19.4 |
| k/arch/x86_64/apic.rs | 229 | 12 | 2 | 10 | 0 | 0 | 22 | 0 | 0 | 2 | 52.4 |
| k/arch/x86_64/cpu/linux_signal.rs | 2547 | 12 | 12 | 0 | 0 | 0 | 12 | 1 | 0 | 0 | 4.7 |
| k/initramfs.rs | 906 | 11 | 10 | 0 | 1 | 0 | 10 | 2 | 0 | 0 | 12.1 |
| k/linux_file_cache.rs | 325 | 11 | 10 | 0 | 1 | 0 | 20 | 11 | 0 | 0 | 33.8 |
| k/drivers/hda.rs | 494 | 10 | 9 | 1 | 0 | 0 | 20 | 0 | 4 | 0 | 20.2 |
| k/drivers/nvme.rs | 434 | 10 | 9 | 1 | 0 | 0 | 16 | 0 | 5 | 0 | 23.0 |
| k/framebuffer.rs | 700 | 10 | 7 | 3 | 0 | 0 | 17 | 1 | 2 | 0 | 14.3 |
| k/arch/x86_64/cpu/execution.rs | 311 | 9 | 9 | 0 | 0 | 0 | 16 | 6 | 0 | 12 | 28.9 |
| k/arch/x86_64/iommu.rs | 931 | 9 | 9 | 0 | 0 | 0 | 12 | 7 | 1 | 0 | 9.7 |
| k/published_rootfs.rs | 1055 | 9 | 9 | 0 | 0 | 0 | 9 | 8 | 0 | 0 | 8.5 |
| k/drivers/e1000e.rs | 267 | 8 | 7 | 1 | 0 | 0 | 25 | 0 | 4 | 0 | 30.0 |
| k/heap.rs | 178 | 8 | 4 | 3 | 1 | 0 | 4 | 0 | 0 | 0 | 44.9 |
| k/drivers/device_memory.rs | 220 | 7 | 6 | 1 | 0 | 0 | 8 | 0 | 0 | 0 | 31.8 |
| k/manifest.rs | 299 | 7 | 7 | 0 | 0 | 0 | 7 | 6 | 0 | 0 | 23.4 |
| k/sync.rs | 356 | 7 | 5 | 0 | 2 | 0 | 6 | 2 | 0 | 3 | 19.7 |
| k/drivers/ahci.rs | 301 | 6 | 4 | 2 | 0 | 0 | 26 | 0 | 3 | 0 | 19.9 |
| k/drivers/virtio_gpu.rs | 640 | 6 | 4 | 1 | 1 | 0 | 4 | 0 | 0 | 0 | 9.4 |
| k/linux_input.rs | 342 | 6 | 6 | 0 | 0 | 0 | 6 | 0 | 3 | 0 | 17.5 |
| k/linux_signal.rs | 534 | 6 | 5 | 0 | 1 | 0 | 8 | 6 | 0 | 0 | 11.2 |
| k/linux_user.rs | 432 | 6 | 5 | 0 | 1 | 0 | 6 | 6 | 0 | 0 | 13.9 |
| k/arch/x86_64/cpu/activation.rs | 203 | 5 | 3 | 1 | 0 | 1 | 3 | 0 | 0 | 0 | 24.6 |
| k/linux_aio.rs | 267 | 5 | 5 | 0 | 0 | 0 | 5 | 5 | 0 | 0 | 18.7 |
| k/linux_mount.rs | 387 | 5 | 4 | 0 | 1 | 0 | 4 | 5 | 0 | 0 | 12.9 |
| k/drivers/pci.rs | 272 | 4 | 2 | 2 | 0 | 0 | 6 | 0 | 0 | 2 | 14.7 |
| k/owned_state.rs | 112 | 4 | 3 | 0 | 1 | 0 | 5 | 0 | 0 | 0 | 35.7 |
| k/packet.rs | 515 | 4 | 3 | 0 | 1 | 0 | 4 | 4 | 0 | 0 | 7.8 |
| k/scheduler.rs | 2844 | 4 | 4 | 0 | 0 | 0 | 17 | 0 | 0 | 0 | 1.4 |
| k/drivers/usb_input.rs | 304 | 3 | 3 | 0 | 0 | 0 | 3 | 0 | 1 | 0 | 9.9 |
| k/linux_keyring.rs | 254 | 3 | 3 | 0 | 0 | 0 | 3 | 3 | 0 | 0 | 11.8 |
| k/volume.rs | 285 | 3 | 2 | 0 | 1 | 0 | 2 | 3 | 0 | 0 | 10.5 |
| k/arch/x86_64/cpu/linux_syscall.rs | 1765 | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 1.1 |
| k/domain.rs | 3262 | 2 | 2 | 0 | 0 | 0 | 2 | 0 | 0 | 0 | 0.6 |
| k/linux_exe.rs | 97 | 2 | 2 | 0 | 0 | 0 | 3 | 0 | 2 | 0 | 20.6 |
| k/pe.rs | 142 | 2 | 2 | 0 | 0 | 0 | 4 | 2 | 0 | 0 | 14.1 |
| k/arch/x86_64/cpu/linux_poll.rs | 1077 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 0.9 |
| k/arch/x86_64/cpu/linux_time.rs | 694 | 1 | 1 | 0 | 0 | 0 | 1 | 1 | 0 | 1 | 1.4 |
| k/ipc.rs | 605 | 1 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | 0 | 1.7 |

### Per category

| category | what | sites | blocks | unsafe fn | unsafe impl | global_asm! | ops | main files |
|---|---|---:|---:|---:|---:|---:|---:|---|
| paging | Page tables, CR3, TLB | 267 | 261 | 6 | 0 | 0 | 718 | address_space.rs (212), paging.rs (42), linux_process.rs (7) |
| entry | Context switch, entry/exit asm, trap frames, GDT/IDT/TSS | 105 | 91 | 7 | 0 | 6 | 142 | cpu.rs (77), architecture.rs (7), activation.rs (5) |
| cpu | CPU control: MSRs, CR0/CR4, interrupt flag, halt | 28 | 26 | 2 | 0 | 0 | 39 | cpu.rs (14), smp.rs (4), execution.rs (2) |
| mmio-pio | MMIO and port I/O: device registers, PCI config, APIC, serial, framebuffer | 189 | 142 | 47 | 0 | 0 | 307 | pci.rs (50), lib.rs (23), timer.rs (16) |
| dma | DMA buffers, descriptor rings, I/O MMU tables | 94 | 78 | 16 | 0 | 0 | 233 | pci.rs (18), xhci.rs (14), amd_iommu.rs (13) |
| user | User-memory access | 22 | 19 | 3 | 0 | 0 | 39 | cpu.rs (14), address_space.rs (6), linux_process.rs (2) |
| frame-heap | Frame allocator and kernel heap internals | 37 | 31 | 4 | 2 | 0 | 49 | memory.rs (29), heap.rs (8) |
| frame-view | Typed views and byte slices of kernel-owned frames | 205 | 202 | 3 | 0 | 0 | 733 | address_space.rs (76), linux_process.rs (25), linux_overlay.rs (16) |
| owner-cell | Per-CPU and owner-struct cells: UnsafeCell, static mut, unsafe impl Sync | 313 | 286 | 1 | 26 | 0 | 424 | linux_socket.rs (131), address_space.rs (37), cpu.rs (22) |
| lock | Lock primitives | 7 | 5 | 0 | 2 | 0 | 6 | sync.rs (7) |
| firmware | Firmware and boot handoff: UEFI, ACPI tables, BootInfo | 72 | 57 | 14 | 0 | 0 | 187 | acpi.rs (42), main.rs (10), bringup.rs (7) |
| convenience | Convenience: replaceable by safe code without a new core API | 21 | 8 | 1 | 0 | 12 | 14 | address_space.rs (12), linux_signal.rs (4), owned_state.rs (2) |

### File x category (sites)

| file | paging | entry | cpu | mmio-pio | dma | user | frame-heap | frame-view | owner-cell | lock | firmware | convenience |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| address_space.rs | 212 |  | 1 | 1 | 4 | 6 |  | 76 | 37 |  |  | 12 |
| linux_socket.rs |  |  |  | 3 | 13 |  |  | 11 | 131 |  |  |  |
| x86_64/cpu.rs | 1 | 77 | 14 |  |  | 14 |  | 3 | 22 |  |  |  |
| x86_64/pci.rs |  | 1 |  | 50 | 18 |  |  |  |  |  |  |  |
| x86_64/paging.rs | 42 |  | 1 |  |  |  |  | 1 | 9 |  | 3 |  |
| linux_process.rs | 7 |  |  | 1 |  | 2 |  | 25 | 21 |  |  |  |
| x86_64/acpi.rs |  |  |  |  |  |  |  |  |  |  | 42 |  |
| lib.rs | 1 | 2 | 1 | 23 |  |  |  | 8 | 1 |  | 3 | 1 |
| memory.rs |  |  |  |  |  |  | 29 |  |  |  |  |  |
| bringup.rs |  |  | 1 | 12 | 2 |  |  |  | 1 |  | 7 |  |
| x86_64/timer.rs |  | 4 | 1 | 16 |  |  |  |  |  |  |  |  |
| cpu/architecture.rs |  | 7 | 1 |  |  |  |  |  | 12 |  |  |  |
| xhci.rs |  |  |  | 6 | 14 |  |  |  |  |  |  |  |
| linux_overlay.rs |  |  |  |  |  |  |  | 16 | 3 |  |  |  |
| image_store.rs |  |  |  |  |  |  |  | 8 | 10 |  |  |  |
| main.rs |  |  |  | 7 |  |  |  |  |  |  | 10 |  |
| amd_iommu.rs |  |  |  | 2 | 13 |  |  |  |  |  |  |  |
| x86_64/smp.rs | 2 | 2 | 4 | 5 |  |  |  | 1 |  |  |  |  |
| realtek.rs |  |  |  | 8 | 6 |  |  |  |  |  |  |  |
| linux_sysv_ipc.rs |  |  |  |  |  |  |  | 14 |  |  |  |  |
| linux_tmpfs.rs |  |  |  | 2 |  |  |  | 6 | 6 |  |  |  |
| x86_64/apic.rs |  |  |  | 12 |  |  |  |  |  |  |  |  |
| cpu/linux_signal.rs |  | 1 |  |  |  |  |  |  | 7 |  |  | 4 |
| initramfs.rs |  |  |  |  |  |  |  | 8 | 3 |  |  |  |
| linux_file_cache.rs |  |  |  |  |  |  |  | 8 | 3 |  |  |  |
| hda.rs |  |  |  | 6 | 4 |  |  |  |  |  |  |  |
| nvme.rs |  |  |  | 6 | 4 |  |  |  |  |  |  |  |
| framebuffer.rs | 1 |  |  | 5 |  |  |  |  | 4 |  |  |  |
| cpu/execution.rs |  | 4 | 2 |  |  |  |  |  | 3 |  |  |  |
| x86_64/iommu.rs |  |  |  | 4 | 5 |  |  |  |  |  |  |  |
| published_rootfs.rs |  |  |  |  |  |  |  | 9 |  |  |  |  |
| e1000e.rs |  |  |  | 3 | 5 |  |  |  |  |  |  |  |
| heap.rs |  |  |  |  |  |  | 8 |  |  |  |  |  |
| device_memory.rs |  |  |  | 5 | 2 |  |  |  |  |  |  |  |
| manifest.rs |  |  |  |  |  |  |  |  |  |  | 7 |  |
| sync.rs |  |  |  |  |  |  |  |  |  | 7 |  |  |
| ahci.rs |  |  |  | 4 | 2 |  |  |  |  |  |  |  |
| virtio_gpu.rs |  |  |  | 2 | 1 |  |  |  | 3 |  |  |  |
| linux_input.rs |  |  |  |  |  |  |  |  | 6 |  |  |  |
| linux_signal.rs |  |  |  |  |  |  |  | 3 | 3 |  |  |  |
| linux_user.rs |  |  |  |  |  |  |  |  | 6 |  |  |  |
| cpu/activation.rs |  | 5 |  |  |  |  |  |  |  |  |  |  |
| linux_aio.rs |  |  |  |  |  |  |  | 5 |  |  |  |  |
| linux_mount.rs | 1 |  |  |  |  |  |  |  | 4 |  |  |  |
| pci.rs |  |  |  | 4 |  |  |  |  |  |  |  |  |
| owned_state.rs |  |  |  |  |  |  |  |  | 2 |  |  | 2 |
| packet.rs |  |  |  |  |  |  |  |  | 4 |  |  |  |
| scheduler.rs |  |  |  |  |  |  |  |  | 4 |  |  |  |
| usb_input.rs |  |  |  | 2 | 1 |  |  |  |  |  |  |  |
| linux_keyring.rs |  |  |  |  |  |  |  | 3 |  |  |  |  |
| volume.rs |  |  |  |  |  |  |  |  | 3 |  |  |  |
| cpu/linux_syscall.rs |  | 2 |  |  |  |  |  |  |  |  |  |  |
| domain.rs |  |  |  |  |  |  |  |  | 2 |  |  |  |
| linux_exe.rs |  |  |  |  |  |  |  |  | 2 |  |  |  |
| pe.rs |  |  |  |  |  |  |  |  |  |  |  | 2 |
| cpu/linux_poll.rs |  |  | 1 |  |  |  |  |  |  |  |  |  |
| cpu/linux_time.rs |  |  | 1 |  |  |  |  |  |  |  |  |  |
| ipc.rs |  |  |  |  |  |  |  |  | 1 |  |  |  |

### Operations by family

| family | ops |
|---|---:|
| pointer read/write | 1109 |
| pointer arithmetic | 611 |
| call of a kernel unsafe fn | 562 |
| raw deref | 283 |
| pointer to reference/slice | 148 |
| asm! | 121 |
| static mut | 50 |
| fn-pointer call | 7 |

Most-called kernel unsafe fns: `socket_slots` (123), `activate` (38), `write_msr` (25), `read_msr` (23), `zero_frame` (22), `write_config_u16` (22), `outb` (19), `with_supervisor_user_access` (14), `read_config_u16` (13), `unix_socket_types` (13), `frame_is_zero` (12), `unix_inflight_rights_state` (12), `zero_entries` (11), `ensure_fine_region` (11), `unix_path_lengths` (11)

### Safe fns returning &'static mut

| file | fns |
|---|---:|
| kernel/src/linux_overlay.rs | 6 |
| kernel/src/arch/x86_64/cpu.rs | 5 |
| kernel/src/linux_sysv_ipc.rs | 5 |
| kernel/src/linux_socket.rs | 4 |
| kernel/src/linux_tmpfs.rs | 3 |
| kernel/src/scheduler.rs | 3 |
| kernel/src/linux_aio.rs | 2 |
| kernel/src/linux_process.rs | 2 |
| kernel/src/linux_signal.rs | 2 |
| kernel/src/packet.rs | 2 |
| kernel/src/arch/x86_64/cpu/execution.rs | 1 |
| kernel/src/domain.rs | 1 |
| kernel/src/ipc.rs | 1 |
| kernel/src/linux_exe.rs | 1 |
| kernel/src/linux_keyring.rs | 1 |
| kernel/src/linux_mount.rs | 1 |
| kernel/src/linux_user.rs | 1 |
| kernel/src/volume.rs | 1 |

### Safe fns that dereference an integer or raw-pointer parameter

| file | fns | of which pub(crate) | parameter types | categories |
|---|---:|---:|---|---|
| kernel/src/arch/x86_64/cpu.rs | 40 | 1 | `*const`, `*mut`, `u64` | entry, user |
| kernel/src/arch/x86_64/pci.rs | 21 | 0 | `usize` | dma, mmio-pio |
| kernel/src/manifest.rs | 7 | 7 | `*const` | firmware |
| kernel/src/drivers/realtek.rs | 6 | 0 | `usize` | mmio-pio |
| kernel/src/address_space.rs | 5 | 4 | `u64`, `usize` | frame-view, user |
| kernel/src/drivers/hda.rs | 5 | 0 | `usize` | mmio-pio |
| kernel/src/arch/x86_64/acpi.rs | 3 | 1 | `*const` | firmware |
| kernel/src/drivers/nvme.rs | 3 | 0 | `*mut`, `usize` | mmio-pio |
| kernel/src/drivers/ahci.rs | 2 | 0 | `usize` | mmio-pio |
| kernel/src/drivers/amd_iommu.rs | 2 | 0 | `usize` | mmio-pio |
| kernel/src/drivers/e1000e.rs | 2 | 0 | `usize` | mmio-pio |
| kernel/src/drivers/xhci.rs | 2 | 0 | `usize` | mmio-pio |
| kernel/src/pe.rs | 2 | 0 | `*const` | convenience |
| boot/efi/src/main.rs | 1 | 0 | `*mut` | firmware |
| kernel/src/arch/x86_64/cpu/activation.rs | 1 | 0 | `*mut` | entry |
| kernel/src/arch/x86_64/cpu/architecture.rs | 1 | 0 | `*mut` | entry |
| kernel/src/arch/x86_64/cpu/linux_syscall.rs | 1 | 0 | `*mut` | entry |
| kernel/src/arch/x86_64/timer.rs | 1 | 0 | `*mut` | entry |
| kernel/src/bringup.rs | 1 | 0 | `u64` | firmware |
| kernel/src/lib.rs | 1 | 0 | `*const` | firmware |
| kernel/src/linux_process.rs | 1 | 0 | `*mut` | user |
