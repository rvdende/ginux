# Ginux Boot Handoff v8

**Status:** Current. Supersedes the version-7 structure in source.

Version 8 adds the firmware framebuffer so Ginux has a console on machines
without a serial port, which is the common case for physical hardware.

## Framebuffer description

Before `ExitBootServices`, the unified EFI image locates the Graphics Output
Protocol and records its active mode in `BootInfo.framebuffer`:

| Field | Meaning |
|---|---|
| `base` | Physical address of the first pixel. |
| `size` | Framebuffer size in bytes, as reported by firmware. |
| `width`, `height` | Visible resolution in pixels. |
| `stride` | Pixels per scan line; at least `width`. |
| `format` | `0` none, `1` RGBX byte order, `2` BGRX byte order. |

Bit-mask modes are accepted when their masks match one of the two byte orders.
Blt-only modes, missing protocols, and any other layout are recorded as format
`0`. The firmware does not change modes on Ginux's behalf.

## Kernel contract

- A missing or unsupported framebuffer is not an error; serial remains the
  authoritative interface used by automated tests.
- The kernel accepts a framebuffer only when `stride * height * 4` fits in
  `size`. It draws through the firmware identity map until its own page tables
  are active.
- The initial page tables map the framebuffer into a dedicated 1 GiB slot of
  the direct map (slot 510) with 2 MiB write-combining pages, so framebuffers
  above 4 GiB, such as resizable-BAR graphics memory, are reachable. PAT entry
  1 is programmed as write-combining for this; every other mapping that sets
  PWT also sets PCD and is unaffected. The framebuffer page directory is
  hardened read-only with the other static page tables.
- Every byte written to the serial console is mirrored to the framebuffer text
  console, which interprets the ANSI SGR, cursor-position, and erase sequences
  emitted by the controller and common Linux shells.
