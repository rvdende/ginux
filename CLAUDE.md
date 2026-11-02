# Ginux working notes

## Direction

Ginux is a new kernel written in Rust that runs unmodified Linux programs
through a Linux ABI personality. It is not a rewrite of Linux:

- **Linux is the specification and the reference design, not the source.**
  Match Linux's observable behaviour (syscall results, errno, signal and wait
  semantics, `/proc` and device interfaces) and borrow its proven designs, but
  write idiomatic Rust with ownership designed in. Never translate or copy
  Linux (GPL-2.0) code; Ginux is Apache-2.0. Reading Linux sources and
  datasheets to understand behaviour or hardware is fine.
- **Keep what Ginux does better than Linux:** memory safety in the kernel,
  isolation as a first-class design (domains with their own roots,
  capabilities and lifecycle), drivers and protocol services in separate
  ring-3 domains with IOMMU-confined DMA, and measured, signed boot inputs and
  verified OCI roots. Root in a domain may switch to other user ids only when
  the domain is set `user-switching=true`: one flag, checked in one place
  (`linux_user::user_switching_allowed`), so it is the single point to secure.
- **Small trusted core.** Confine `unsafe` to a minimal layer (page tables,
  context switch, MMIO, DMA) with documented invariants; everything above it
  is safe Rust (the "framekernel" idea).
- **The userland should be Rust too.** Domains boot `image=builtin://rust`
  (ginux-init, brush, uutils coreutils, the desktop in `userland/`); libc is
  still musl until a Rust libc (mustang/c-ward, relibc) is viable.

## Roadmap (in order)

1. ~~Merge upstream~~ (done 2026-10-31, fb3f793b: SMP, `cpu/` modules,
   lock ranks, runtime owner structs). Keep merging upstream regularly
   (`git fetch upstream`); new globals go in upstream's owner structs and
   `docs/feedback-hardening/writable-globals.tsv`.
2. **Per-thread kernel stacks and a preemptive per-CPU scheduler**
   (design and migration steps: `docs/SCHEDULER.md`). Today a
   process runs nested inside the syscall of the process that started it, on
   one kernel stack: that bounds process-tree depth (the stack is 2 MiB as a
   stopgap), and a parent can be resumed nested inside its child's syscall
   (the desktop's shutdown failure). Each Linux thread gets its own kernel
   stack with guard pages, and switching saves one stack pointer and loads
   another, on any CPU, as Linux does.
3. **A real task and memory model:** per-process memory-area tracking (VMAs),
   a shared page cache, and dynamically sized tables in place of the fixed
   arrays (32 threads per process, kept in per-thread arrays that the
   scheduler's task struct should replace; 256 processes per domain, set
   by the u8 runtime slot ids). The socket table (which pipes share), the
   scheduler's thread table and each process's address-space lists grow
   on demand. Pages have a map count in the frame allocator
   (`memory::share_frames`): every address space that maps another's frame
   takes a count, and releasing drops one. Anonymous MAP_SHARED memory is
   an unnamed overlay shmem node, freed with its last mapping. Move large
   structures off the kernel stack. Memory areas: `crates/memory-areas`
   (host-tested, safe) holds a process's areas; `kernel/src/linux_areas.rs`
   keeps one set per process from mmap, munmap, mprotect, mremap and exec's
   segments (copied at fork, dropped at exec and exit) and `/proc/PID/maps`
   names files from it. The page tables are still the authority; next:
   record the stack and heap, then let fault handling and placement use
   the areas instead of page-table bits.
4. **Compatibility driven by the Linux Test Project (LTP)** rather than by
   finding bugs one program at a time: `just test-ltp` (docs/LTP.md has the
   baseline and failure clusters).
5. **Drivers:** virtio in VMs; Rust drivers for the hardware we target (this
   PC: Ryzen 7600X, AMD-Vi, NVMe, AMD xHCI, RTL8125, MT7922 Wi-Fi, Radeon
   RX 6800) — ultimately a GPU driver for Vulkan; software Vulkan meanwhile.
6. Run [cadrs](https://github.com/rvdende/cadrs) (Bevy/wgpu CAD) built and
   running inside the Ginux desktop.

## Build, run, test

- `just` lists recipes; `just desktop` builds, boots Ginux in a QEMU window
  with USB keyboard and tablet, and starts the Wayland desktop on the all-Rust
  userland. `make help` lists all targets.
- QEMU tests need `OVMF_CODE=/usr/share/OVMF/OVMF_CODE_4M.fd
  OVMF_VARS=/usr/share/OVMF/OVMF_VARS_4M.fd`; the shared `/tmp` is often full,
  so set `TMPDIR` to a private directory (not for `test-hardware-profile`,
  whose monitor socket path must stay under 108 bytes).
- `make check` needs ripgrep (`rg`) for the architecture checks; it is not
  installed system-wide, so put VS Code's copy on PATH:
  `PATH=/usr/share/code/resources/app/node_modules.asar.unpacked/@vscode/ripgrep-universal/bin/linux-x64:$PATH`.
- Quick gate before committing: `make test-quick` (about 2 minutes: check,
  the all-Rust userland, the 4-CPU multicore test). The full suites and LTP
  take half an hour; run them for wide changes, not every commit.
- Key suites: `make check`, `make userland-check`, `make test-alpine`,
  `tests/qemu/rust-workloads.sh` (cargo builds serde inside Ginux),
  `make test-rust-userland`, `make test-desktop`,
  `make test-desktop-virtio-gpu`, `make test-boot-media`,
  `make test-hardware-profile`.
- `tools/qemu/run.sh` boots whatever is in the ESP directory and does not
  build. `make build ESP_DIR=dir` with `GINUX_ESP_DIR=dir` keeps a separate
  image so a running VM's `build/esp` is not rewritten under it.
- run.sh switches: `GINUX_QEMU_MONITOR=sock` (HMP monitor: `screendump`,
  `sendkey`, `info registers`), `GINUX_QEMU_DISPLAY=gtk`,
  `GINUX_QEMU_USB_INPUT=1`, `GINUX_QEMU_GPU=virtio` (virtio-gpu, no VGA;
  `virtio-vga` keeps a VGA framebuffer for the firmware; `venus` adds 3D,
  Vulkan on the host GPU through Mesa's Venus) with
  `GINUX_QEMU_GPU_SIZE=WxH` (docs/GRAPHICS.md), `GINUX_QEMU_LOG=file` (pauses instead of exiting
  on a guest reset), `GINUX_QEMU_LOG_INTERRUPTS=1` with `QEMU_ACCEL=tcg`
  (logs every exception: finds triple faults).

## Debugging kernel crashes

A fatal exception prints vector, error, all registers, CR0/2/3/4, the kernel
image base and the kernel addresses on the stack, then `GINUX_KERNEL_PANIC`.
The image base is also printed at boot. Symbolize with
`tools/debug/symbolize.sh IMAGE_BASE ADDRESS...` (same sources as the run).
A CR2 just below RSP is a kernel stack overflow. If the machine resets with no
report, rerun under `QEMU_ACCEL=tcg GINUX_QEMU_LOG=... GINUX_QEMU_LOG_INTERRUPTS=1`.

For a hang or a slow domain, `echo t > /proc/sysrq-trigger` lists every
task's threads (state, wait kind and key, saved registers), `echo u` each
CPU's user/kernel/idle/lock-wait time, the process banks in use and the
threads run on other CPUs (docs/SCHEDULER.md), and `echo l`
profiles the runtime CPU for 1000 ticks (system calls, lock ranks, DRM
ioctls, timed spans in `kernel/src/linux_profile.rs`). Tick samples miss
kernel work done with interrupts off; sample CPU 0 from the host instead
(monitor `info registers`, symbolized as above).

To see which system call a Linux program trips on, run it with
`GINUX_STRACE=1` in its environment: that process and every process it
starts log each call to the kernel log as `ginux: strace PID/TID
NUMBER(args, "path") = result` (errors as `-errno`;
`kernel/src/linux_strace.rs`). Domains have no ptrace and images seldom
ship strace.

## Conventions

- Commit and push straight to `main` of origin (github.com/rvdende/ginux);
  commit messages end with the `Co-Authored-By` line. Run the affected suites
  first and say in the message what still fails.
- `boot/efi/src/generated_boot.rs` is generated by `make manifest`/`make build`;
  commit it with controller and service changes, never edit it by hand.
- Clippy runs with `-D warnings` and unused code fails the build.
- Test and debug scripts poll for the event they need (a serial line, the
  monitor reporting `paused`) and stop at once; no fixed sleeps or
  `timeout`-killed waits. Run long suites in the background.
- Kill only your own QEMU by PID (`GINUX_QEMU_PID_FILE`); never
  `pkill -f` a pattern that also appears in your own command line.
- Never write to the host's NVMe except a partition with the Ginux type GUID
  `80769f29-5413-45a3-abab-5b44b6125922`.
