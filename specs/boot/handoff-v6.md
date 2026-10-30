# Ginux Boot Handoff v6

**Status:** Superseded by [handoff v8](handoff-v8.md); retained
as the architectural contract for the wall-clock addition.

The unified EFI image reads the firmware wall clock before
`ExitBootServices`. The boot handoff carries validated Unix seconds to the
kernel. Native TLS services receive that value through their own capability
scoped bootstrap and use it only for certificate-validity checks.

Failure to obtain a credible firmware date is fatal during boot. Ginux never
silently disables certificate time validation and never substitutes a build
timestamp.
