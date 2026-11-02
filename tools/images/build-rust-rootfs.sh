#!/usr/bin/env bash
# Builds build/rootfs-rust.tar.gz: a domain root filesystem whose programs
# are all written in Rust, for `image=builtin://rust`. It holds ginux-init
# as /sbin/init, the brush shell as /bin/sh, the uutils coreutils multicall
# binary with a link per utility, and the Wayland desktop from userland/.
# The tarball is POSIX ustar with fixed owners and times, so the same inputs
# give the same bytes.
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
target=x86_64-unknown-linux-musl
tools_root="$repo_root/build/rust-tools"
stage="$repo_root/build/rust-rootfs"
output="$repo_root/build/rootfs-rust.tar.gz"
release="$repo_root/userland/target/$target/release"

# Third-party Rust programs, pinned and built from crates.io as static
# musl binaries.
install_tool() {
    local crate=$1 version=$2 binary=$3
    if [[ ! -x "$tools_root/bin/$binary" ]] \
        || ! grep -q "\"$crate $version " "$tools_root/.crates.toml" 2>/dev/null; then
        CARGO_TARGET_DIR="$repo_root/target/rust-tools" cargo install "$crate" \
            --version "$version" --locked --target "$target" --root "$tools_root"
    fi
}
install_tool brush-shell 0.4.0 brush
install_tool coreutils 0.12.0 coreutils

(cd "$repo_root/userland" && cargo build --release --target "$target")

rm -rf "$stage"
mkdir -p "$stage"/{bin,sbin,etc/ginux,root,tmp,dev,proc,sys,run}
chmod 1777 "$stage/tmp"
chmod 700 "$stage/root"

install -m 755 "$release/ginux-init" "$stage/sbin/init"
for program in ginux-wm ginux-term ginux-fetch ginux-memtest ginux-threadtest; do
    install -m 755 "$release/$program" "$stage/bin/$program"
done
install -m 755 "$tools_root/bin/brush" "$stage/bin/brush"
install -m 755 "$tools_root/bin/coreutils" "$stage/bin/coreutils"
strip "$stage"/bin/* "$stage/sbin/init"
ln -s brush "$stage/bin/sh"
ln -s brush "$stage/bin/bash"
for utility in $("$stage/bin/coreutils" --list); do
    [[ -e "$stage/bin/$utility" ]] || ln -s coreutils "$stage/bin/$utility"
done

cat >"$stage/etc/os-release" <<'EOF'
NAME="Ginux Rust"
ID=ginux-rust
PRETTY_NAME="Ginux Rust (all-Rust userland)"
HOME_URL="https://github.com/rvdende/ginux"
EOF
printf 'root:x:0:0:root:/root:/bin/sh\n' >"$stage/etc/passwd"
printf 'root:x:0:\n' >"$stage/etc/group"
printf 'ginux\n' >"$stage/etc/hostname"
# The basic line editor works on the serial console and on ginux-term's
# pipes, where brush's default editor would query a terminal.
printf '/bin/brush -i --input-backend basic\n' >"$stage/etc/ginux/shell"
cat >"$stage/etc/ginux/motd" <<'EOF'
Ginux Rust: kernel, init, shell (brush), coreutils (uutils) and desktop are
all written in Rust. Start the desktop with:
  ginux-wm --terminal ginux-term --spawn ginux-term &
EOF

mkdir -p "$(dirname "$output")"
(
    cd "$stage"
    # Paths without a leading "./", as OCI layers carry them.
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort |
        tar --format=ustar --no-recursion --owner=0 --group=0 --numeric-owner \
            --mtime=@0 -cf - -T -
) | gzip -n -9 >"$output"
sha256sum "$output" | cut -d' ' -f1 >"$output.sha256"
echo "Built $output ($(stat -c %s "$output") bytes, sha256 $(cat "$output.sha256"))"
