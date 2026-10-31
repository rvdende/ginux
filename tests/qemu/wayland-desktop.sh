#!/usr/bin/env bash
# Boots Ginux, starts an Alpine domain, and runs the Rust Wayland desktop
# from userland/ in it: ginux-wm composes onto /dev/fb0 and ginux-term
# connects over a Wayland socket, sharing its window buffers through memfd
# pools passed with SCM_RIGHTS. Keys typed on QEMU's USB keyboard travel
# through xHCI, evdev and the compositor to the terminal's shell, which
# must echo a marker to the serial console, and a QEMU screendump of the
# real framebuffer must show the compositor's title bar and the terminal.
# The guest downloads the static binaries from a host HTTP server at
# 10.0.2.2.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ginux-desktop.XXXXXX")
output_file="$work_dir/serial.log"
volume_image="$work_dir/volume.raw"
qemu_pid_file="$work_dir/qemu.pid"
screenshot="$work_dir/screen.ppm"
# Unix socket paths are limited to 108 bytes, so the monitor lives in target/.
monitor="$repo_root/target/desktop-monitor.$$"
http_port="${GINUX_DESKTOP_HTTP_PORT:-18184}"
serve_dir="$work_dir/serve"
qemu_pid=""
http_pid=""

stop_qemu() {
    local pid=""
    if [[ -s "$qemu_pid_file" ]]; then
        read -r pid <"$qemu_pid_file" || true
    fi
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
        kill "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_qemu
    if [[ -n "$qemu_pid" ]] && kill -0 "$qemu_pid" 2>/dev/null; then
        kill "$qemu_pid" 2>/dev/null || true
        wait "$qemu_pid" 2>/dev/null || true
    fi
    if [[ -n "$http_pid" ]]; then
        kill "$http_pid" 2>/dev/null || true
    fi
    cp "$output_file" "$repo_root/target/wayland-desktop-serial.log" 2>/dev/null || true
    cp "$screenshot" "$repo_root/target/wayland-desktop.ppm" 2>/dev/null || true
    rm -rf "$work_dir" "$monitor"
}
trap cleanup EXIT

wait_for() {
    local marker=$1
    local seconds=${2:-120}
    for _ in $(seq 1 "$seconds"); do
        grep -aEq "$marker" "$output_file" && return 0
        if grep -aEq '^GINUX_(BOOT|KERNEL)_PANIC|domain marked failed' "$output_file"; then
            break
        fi
        sleep 1
    done
    tail -n 60 "$output_file" >&2
    echo "Wayland desktop test failed while waiting for '$marker'." >&2
    stop_qemu
    return 1
}

monitor_command() {
    printf '%s\n' "$1" | socat - "UNIX-CONNECT:$monitor" >/dev/null
}

# Types text on the USB keyboard with the monitor's sendkey.
type_text() {
    local text=$1 index character key
    for ((index = 0; index < ${#text}; index++)); do
        character=${text:index:1}
        case "$character" in
            ' ') key=spc ;;
            '>') key=shift-dot ;;
            '/') key=slash ;;
            '_') key=shift-minus ;;
            '-') key=minus ;;
            [A-Z]) key="shift-${character,,}" ;;
            *) key=$character ;;
        esac
        monitor_command "sendkey $key"
        sleep 0.1
    done
    monitor_command "sendkey ret"
}

(cd "$repo_root/userland" && cargo build --release --target x86_64-unknown-linux-musl)
mkdir -p "$serve_dir"
cp "$repo_root/userland/target/x86_64-unknown-linux-musl/release/ginux-wm" \
    "$repo_root/userland/target/x86_64-unknown-linux-musl/release/ginux-term" "$serve_dir/"
python3 -I -m http.server "$http_port" --bind 127.0.0.1 --directory "$serve_dir" \
    >/dev/null 2>&1 &
http_pid=$!

fetch="wget -q http://10.0.2.2:${http_port}"
dd if=/dev/zero of="$volume_image" bs=1048576 count=1 2>/dev/null
: >"$output_file"
{
    wait_for 'ginux> ' 300
    printf '%s\n' \
        'domain new desktop' \
        'domain set desktop image=alpine:latest init=/bin/sh' \
        'domain start desktop --attach'
    wait_for 'ginux: OCI image ready' 900
    sleep 5
    printf '%s\n' \
        "cd /tmp && $fetch/ginux-wm && $fetch/ginux-term && chmod +x ginux-wm ginux-term && echo FETCHED\"_OK\""
    wait_for '^FETCHED_OK' 120
    printf '%s\n' "./ginux-wm --terminal /tmp/ginux-term --spawn /tmp/ginux-term &"
    wait_for 'GINUX_WM_READY' 60
    # Give the terminal time to connect, draw and take keyboard focus.
    sleep 15
    type_text 'echo KEYBOARD_INPUT_OK >/dev/console'
    wait_for 'KEYBOARD_INPUT_OK' 60
    type_text 'uname -a'
    sleep 5
    monitor_command "screendump $screenshot"
    sleep 2
    echo DESKTOP_SCREENDUMP_TAKEN >>"$output_file"
    # Leaving init with the desktop running must still shut the domain down
    # cleanly: the kernel kills the remaining processes, as Linux does when
    # a PID namespace's init exits.
    printf '%s\n' 'exit 0'
    wait_for 'ginux: Linux init exited cleanly' 120
    sleep 2
    printf '%s\n' 'shutdown'
} | GINUX_MEMORY=4G GINUX_VOLUME_IMAGE="$volume_image" GINUX_QEMU_PID_FILE="$qemu_pid_file" \
    GINUX_QEMU_MONITOR="$monitor" GINUX_QEMU_USB_INPUT=1 "$repo_root/tools/qemu/run.sh" >>"$output_file" 2>&1 &
qemu_pid=$!

for _ in $(seq 1 1800); do
    if ! kill -0 "$qemu_pid" 2>/dev/null; then
        break
    fi
    sleep 1
done
if kill -0 "$qemu_pid" 2>/dev/null; then
    tail -n 60 "$output_file"
    echo "Wayland desktop test failed: QEMU did not shut down." >&2
    exit 1
fi
wait "$qemu_pid" || true
qemu_pid=""

if ! grep -aq 'KEYBOARD_INPUT_OK' "$output_file"; then
    tail -n 60 "$output_file"
    echo "Wayland desktop test failed: typed input did not reach the terminal's shell." >&2
    exit 1
fi
if ! grep -aq 'ginux: Linux init exited cleanly' "$output_file"; then
    tail -n 60 "$output_file"
    echo "Wayland desktop test failed: the domain did not shut down cleanly." >&2
    exit 1
fi
if [[ ! -s "$screenshot" ]]; then
    tail -n 60 "$output_file"
    echo "Wayland desktop test failed: no screendump." >&2
    exit 1
fi
# The focused window's title bar (0x2f5d8c) and the terminal background
# (0x101418) must both cover a window-sized area of the real framebuffer.
python3 -I - "$screenshot" <<'EOF'
import sys

data = open(sys.argv[1], "rb").read()
fields = data.split(maxsplit=4)
width, height = int(fields[1]), int(fields[2])
pixels = fields[4][: width * height * 3]
counts = {}
for offset in range(0, len(pixels), 3):
    key = pixels[offset : offset + 3]
    counts[key] = counts.get(key, 0) + 1
title = counts.get(bytes.fromhex("2f5d8c"), 0)
terminal = counts.get(bytes.fromhex("101418"), 0)
print(f"screen {width}x{height}: title bar {title} px, terminal {terminal} px")
if title < 5000 or terminal < 50000:
    sys.exit("Wayland desktop test failed: the terminal window is not on screen.")
EOF
echo "Wayland desktop test passed."
