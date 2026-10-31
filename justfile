# Everyday Ginux workflows; `make help` lists the full build and test targets.

ovmf_code := env_var_or_default("OVMF_CODE", "/usr/share/OVMF/OVMF_CODE_4M.fd")
ovmf_vars := env_var_or_default("OVMF_VARS", "/usr/share/OVMF/OVMF_VARS_4M.fd")

# List the recipes.
default:
    @just --list

# Build, boot Ginux in a window and start the Rust Wayland desktop in an Alpine domain.
desktop:
    tools/qemu/desktop.sh

# Like `desktop`, without rebuilding first.
desktop-fast:
    tools/qemu/desktop.sh --no-build

# Boot Ginux in a QEMU window with USB keyboard and tablet (console on this terminal).
window:
    make build
    OVMF_CODE={{ovmf_code}} OVMF_VARS={{ovmf_vars}} GINUX_QEMU_DISPLAY=gtk GINUX_QEMU_USB_INPUT=1 GINUX_MEMORY=4G make run

# Attach to the desktop VM's serial console (detach with Ctrl-b d).
console:
    tmux attach -t ginux

# Stop the desktop VM.
stop:
    tmux kill-session -t ginux

# Build the desktop programs (ginux-wm, ginux-term, ginux-fetch).
userland:
    make userland

# Lint and unit-test the kernel crates and the desktop programs.
check:
    make check userland-check

# Run the end-to-end desktop test (USB typing, screendump, clean shutdown).
test-desktop:
    OVMF_CODE={{ovmf_code}} OVMF_VARS={{ovmf_vars}} make test-desktop
