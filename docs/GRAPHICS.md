# Graphics

Ginux shows its console and the Wayland desktop on one of two displays:

- the **UEFI GOP framebuffer** the firmware leaves behind (any PC, and QEMU's
  standard VGA), or
- a **virtio-gpu** in a virtual machine, driven by the kernel as a 2D
  display.

Either way, Linux programs see the same `/dev/fb0` (fbdev: `FBIOGET_VSCREENINFO`,
`FBIOGET_FSCREENINFO`, read/write, `MAP_SHARED` mmap), and the kernel console
draws on it until a domain maps it. The Rust compositor in `userland/`
composes in software and copies each frame into its mapping of `/dev/fb0`.

## virtio-gpu 2D driver

| Piece | Where | What it does |
| --- | --- | --- |
| Protocol | `crates/virtio-gpu` (`ginux-virtio-gpu`) | Encodes `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`, `RESOURCE_ATTACH_BACKING`, `SET_SCANOUT`, `TRANSFER_TO_HOST_2D` and `RESOURCE_FLUSH`, checks replies, picks the mode, and packs damage rectangles into one atomic word. Pure, `no_std`, host-tested (`cargo test -p ginux-virtio-gpu`). |
| Unsafe floor | `kernel/src/drivers/device_memory.rs` | `Mmio` (device registers in the kernel's uncached device window) and `DmaBuffer` (contiguous kernel frames from the frame allocator, reached through the direct map). Bounds-checked volatile access, no references to device-visible memory; the only `unsafe` the driver needs. |
| Transport | `kernel/src/drivers/virtio.rs` | Modern virtio 1.x over PCI, polled: capability parsing, reset, feature negotiation (`VERSION_1`, `ACCESS_PLATFORM`), and a split virtqueue used one batch of request/response chains at a time. Safe Rust. |
| Driver | `kernel/src/drivers/virtio_gpu.rs` | Discovery, bring-up, the scanout owner and the flush policy. Safe Rust apart from the owner's latch (`SCANOUT`, one `UnsafeCell` behind a try-only `AtomicBool`). |
| Hooks | `kernel/src/lib.rs`, `kernel/src/framebuffer.rs`, `kernel/src/arch/x86_64/timer.rs` | Device-window mapping and I/O MMU admission at boot; `framebuffer::adopt` moves the console and `/dev/fb0` to the GPU surface; the Linux timer tick calls `framebuffer::refresh`. |

### Bring-up

The driver follows the xHCI input driver's pattern:

1. **Discover** (before the kernel page tables): find `1af4:1050` on bus 0
   or behind its bridges, read its virtio capabilities, and require the
   common, notification and device structures in one memory BAR, within
   64 KiB. That span joins the device window (mapped uncached, no identity
   alias).
2. **Prepare** (DMA translation still off): reset, negotiate, set up the
   control queue (8 descriptors), `DRIVER_OK`, `GET_DISPLAY_INFO`, then
   allocate a surface for the first enabled scanout's mode (at most 8 MiB,
   e.g. 1920x1080; otherwise 1280x800) and run `RESOURCE_CREATE_2D`
   (`B8G8R8X8`, the same byte order as a BGRX GOP framebuffer) and
   `RESOURCE_ATTACH_BACKING` with a single entry, since the surface is
   physically contiguous.
3. **Admit**: the GPU's three DMA regions (ring, command page, surface) are
   admitted to the I/O MMU as standing devices in the same, single admission
   as the USB controllers, so the GPU keeps working while a volume or network
   translation is active. If both do not fit the standing table budget, USB
   is admitted alone and the GPU is reset.
4. **Activate**: `SET_SCANOUT`, then `framebuffer::adopt` re-lays out the
   console for the new size, keeps the text it already had (from a GOP
   console, if there was one), repaints, and flushes.

Without a virtio-gpu, or if any step fails, the firmware framebuffer stays
the display and the log says why.

### Flushing

A virtio-gpu surface is guest memory; the host shows only what the guest
flushes (`TRANSFER_TO_HOST_2D` of a rectangle, then `RESOURCE_FLUSH`).

- **Kernel console and `write(2)` to `/dev/fb0`: on demand.** The console
  tracks the bounding box of the cells it drew during a write and hands it
  to the driver; `/dev/fb0` writes report the rows they touched. Damage
  accumulates in one `AtomicU64` (four 16-bit edges, merged with a CAS loop),
  so it can be added from any context. Whoever holds the GPU takes the damage
  and submits one transfer+flush batch without waiting for it. A console
  writer that finds an earlier batch still in flight waits up to 20 ms for
  it, so the last line written is never left unflushed.
- **A domain's `mmap` of `/dev/fb0`: periodic.** The kernel does not see
  those writes, so while a domain owns the screen the 1 kHz Linux timer tick
  flushes the whole surface at 60 Hz. The tick never waits: if a flush is
  still in flight it tries again on the next tick.

The GPU is behind a latch that is only ever *tried*: the console reaches it
from interrupt handlers and from code that holds ranked locks, so it must
never spin or take a ranked lock. A caller that finds the latch held leaves
its damage for the holder, which re-checks before returning, or for the next
tick. The device is polled; MSI-X stays off.

The periodic full-surface refresh costs the host a 4 MB copy per frame at
1280x800 whether or not anything changed. Linux's fbdev emulation instead
uses deferred I/O (write-protect the mapping, collect the pages that fault,
flush those after a delay); Ginux could do the same with the dirty bits of
the domain's page-table entries, or let the compositor report damage.

### Running it

```sh
GINUX_QEMU_GPU=virtio tools/qemu/run.sh       # virtio-gpu-pci, no VGA
GINUX_QEMU_GPU=virtio-vga tools/qemu/run.sh   # GOP on the VGA part, then virtio-gpu
GINUX_QEMU_GPU_SIZE=1920x1080                 # the mode the host reports
make test-desktop-virtio-gpu                  # the Wayland desktop on virtio-gpu
```

`make test-desktop-virtio-gpu` runs `tests/qemu/wayland-desktop.sh` with no
VGA device at all and the host asking for 1024x768: OVMF's own virtio-gpu
GOP is blit-only, so there is no firmware framebuffer, and the screendump of
the virtio-gpu scanout shows the compositor and terminal only if the driver
became the display in the host's mode and flushed what the compositor wrote
through its mapping.

## Toward 3D: virgl, Venus and Vulkan

The 2D driver is the base for GPU acceleration in VMs. Venus (Mesa's
Vulkan-over-virtio-gpu driver) needs, roughly in order:

1. **Interrupts and fences.** Replace polling with an MSI-X vector for the
   control queue, and use `VIRTIO_GPU_FLAG_FENCE` so a submission can be
   waited on without spinning. Many commands in flight, not one batch.
2. **Feature negotiation for 3D.** Accept `VIRTIO_GPU_F_VIRGL`,
   `VIRTIO_GPU_F_RESOURCE_BLOB` and `VIRTIO_GPU_F_CONTEXT_INIT` (the driver
   already reports which the host offers at boot), read capsets with
   `GET_CAPSET_INFO`/`GET_CAPSET` (Venus is capset 4).
3. **Contexts per domain.** `CTX_CREATE` with the Venus capset in the
   context-init flags, one or more per domain, destroyed with the domain;
   `SUBMIT_3D` carries Venus command streams.
4. **Blob resources and host-visible memory.** `RESOURCE_CREATE_BLOB`, and
   the virtio shared-memory region (PCI capability type 8, the `hostmem`
   BAR) mapped into a domain with `RESOURCE_MAP_BLOB` for Vulkan memory the
   host GPU writes.
5. **A Linux uAPI for Mesa.** Venus talks to `/dev/dri/renderD128` through
   the virtgpu DRM ioctls (`GETPARAM`, `GET_CAPS`, `CONTEXT_INIT`,
   `RESOURCE_CREATE_BLOB`, `MAP`, `EXECBUFFER`, `WAIT`, `RESOURCE_INFO`),
   plus the generic DRM version/prime calls. The Linux personality would
   expose that render node and route it to the domain's contexts.
6. **Isolation.** The command streams are untrusted; per-domain contexts and
   resource IDs, and eventually the driver in a ring-3 driver domain with
   IOMMU-confined DMA (decision 0002), keep one domain from reaching
   another's resources.

On the host side this needs QEMU's `virtio-gpu-gl-pci` with `blob=on` and
`venus=on`, a `hostmem` size, virglrenderer built with Venus, and an EGL
display (`-display egl-headless` or `gtk,gl=on`).

Smaller follow-ups for the 2D path: the cursor queue (hardware cursor for the
compositor), display-change events (`VIRTIO_GPU_EVENT_DISPLAY`, resizing the
host window) with an fbdev mode change, EDID, multiple scanouts, and damage
tracking for mapped `/dev/fb0` instead of the periodic full refresh.
