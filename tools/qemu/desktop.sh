#!/usr/bin/env bash
# Boots Ginux in a QEMU window with USB keyboard and tablet, starts an
# Alpine domain, and launches the Rust Wayland desktop in it. The VM runs in
# the tmux session "ginux" (its serial console), which this script replaces
# if it already exists; the static desktop binaries are served to the
# domain from the host over HTTP while the VM runs.
#
# Usage: tools/qemu/desktop.sh [--no-build]
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
session=ginux
domain=desk
http_port="${GINUX_DESKTOP_HTTP_PORT:-18185}"
release_dir="$repo_root/userland/target/x86_64-unknown-linux-musl/release"

if [[ "${1:-}" != "--no-build" ]]; then
    make -C "$repo_root" build userland
fi
for binary in ginux-wm ginux-term ginux-fetch; do
    [[ -x "$release_dir/$binary" ]] || { echo "missing $release_dir/$binary; run make userland" >&2; exit 1; }
done
command -v tmux >/dev/null || { echo "tmux is required" >&2; exit 1; }

# Prints the console's last non-empty line. tmux trims trailing spaces, so
# prompts are matched without them.
last_line() {
    tmux capture-pane -pt "$session" | grep -v '^$' | tail -n 1
}

wait_for_prompt() {
    local pattern=$1 seconds=$2
    for _ in $(seq 1 "$seconds"); do
        last_line | grep -Eq "$pattern" && return 0
        sleep 1
    done
    echo "timed out waiting for '$pattern' on the console; see: tmux attach -t $session" >&2
    return 1
}

if tmux has-session -t "$session" 2>/dev/null; then
    echo "Stopping the running '$session' VM."
    tmux kill-session -t "$session"
    sleep 1
fi

ovmf_code="${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}"
ovmf_vars="${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}"
tmux new-session -d -s "$session" -x 200 -y 50 "
    cd '$repo_root'
    python3 -I -m http.server $http_port --bind 127.0.0.1 --directory '$release_dir' >/dev/null 2>&1 &
    server=\$!
    OVMF_CODE='$ovmf_code' OVMF_VARS='$ovmf_vars' GINUX_QEMU_DISPLAY=\${GINUX_QEMU_DISPLAY:-gtk} \
        GINUX_QEMU_USB_INPUT=1 GINUX_MEMORY=\${GINUX_MEMORY:-4G} \
        DISPLAY='${DISPLAY:-}' WAYLAND_DISPLAY='${WAYLAND_DISPLAY:-}' XDG_RUNTIME_DIR='${XDG_RUNTIME_DIR:-}' \
        make run
    kill \$server
    exec bash"

echo "Booting Ginux (console: tmux attach -t $session)."
wait_for_prompt 'ginux>' 180
# Creating the domain fails harmlessly when it already exists.
for command in "domain new $domain" "domain set $domain image=alpine:latest init=/bin/sh"; do
    tmux send-keys -t "$session" "$command" Enter
    sleep 1
done
tmux send-keys -t "$session" "domain start $domain --attach" Enter
echo "Starting the '$domain' domain (the first boot pulls Alpine)."
wait_for_prompt '# ?$' 900
fetch="wget -q http://10.0.2.2:$http_port"
tmux send-keys -t "$session" \
    "cd /tmp && $fetch/ginux-wm -O ginux-wm && $fetch/ginux-term -O ginux-term && $fetch/ginux-fetch -O ginux-fetch && chmod +x ginux-wm ginux-term ginux-fetch && ./ginux-wm --terminal /tmp/ginux-term --spawn /tmp/ginux-term &" Enter
echo "Desktop starting in the QEMU window: Alt+Enter terminal, Alt+Tab switch, Alt+M maximize, Alt+Q close."
echo "Serial console: tmux attach -t $session (detach with Ctrl-b d); stop with: just stop"
