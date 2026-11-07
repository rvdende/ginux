#!/bin/sh
# Runs in the domain's init shell (busybox ash): fetches the LTP tree, the
# runner and the run list from the host's HTTP server, then execs the runner
# as the domain's init. Used by the LTP harness (tests/ltp/src/session.rs).
#
#   sh setup.sh BASE_URL FIRST_INDEX
base=$1
first=$2

fail() {
    echo "@@LTP SETUP_FAILED $*"
    exit 1
}

mkdir -p /opt /tmp/ltp && chmod 1777 /tmp/ltp || fail mkdir
if [ ! -f /opt/ltp/runtest/syscalls ]; then
    wget -q -O - "$base/ltp.tar.xz" | xzcat | tar -xf - -C /opt
    [ -f /opt/ltp/runtest/syscalls ] || fail "LTP tree download or extraction"
fi
# The module index a Linux kernel package installs: Ginux loads no modules,
# and these are the parts LTP asks modprobe for that it has built in, so
# "modprobe x509_key_parser" succeeds as on a kernel with them built in.
modules=/lib/modules/$(uname -r)
mkdir -p "$modules" || fail "module directory"
: > "$modules/modules.dep"
cat > "$modules/modules.builtin" <<'EOF' || fail "module index"
kernel/crypto/asymmetric_keys/asymmetric_keys.ko
kernel/crypto/asymmetric_keys/public_key.ko
kernel/crypto/asymmetric_keys/x509_key_parser.ko
kernel/crypto/asymmetric_keys/pkcs8_key_parser.ko
kernel/mm/hwpoison-inject.ko
kernel/net/dns_resolver/dns_resolver.ko
kernel/security/keys/encrypted-keys/encrypted-keys.ko
EOF
# The shadow user tools (useradd, userdel, ...) a distribution has and
# busybox lacks, from the LTP tree (tools/ltp/container-build.sh). Files the
# image already has are kept (busybox's cp -n skips whole directories, so
# each file is copied on its own).
overlay=/opt/ltp/distro/shadow
if [ -d "$overlay" ] && ! command -v useradd >/dev/null 2>&1; then
    for file in $(cd "$overlay" && find . -type f); do
        file=${file#./}
        [ -e "/$file" ] && continue
        mkdir -p "/${file%/*}" && cp -a "$overlay/$file" "/$file" || fail "shadow tools: $file"
    done
fi
# e2fsprogs, for the tests that format a device (mkfs.ext2); without it
# they report mkfs missing.
if [ ! -x /sbin/mke2fs ]; then
    wget -q -O - "$base/e2fsprogs.tar.gz" 2>/dev/null | tar -xzf - -C / 2>/dev/null
fi
# disk-tmpdir.sh TEST [ARG...]: runs a test with its TMPDIR on an ext2
# filesystem of its own, for the tests whose files must live on a block
# device (the domain's /tmp is the overlay, which has none).
cat > /opt/ltp/disk-tmpdir.sh <<'EOF' || fail "disk-tmpdir.sh"
#!/bin/sh
image=/tmp/ltp/disk-tmpdir.img
mount=/tmp/ltp/disk-tmpdir
dd if=/dev/zero of="$image" bs=1M count=64 2>/dev/null &&
    device=$(losetup -f) && losetup "$device" "$image" &&
    mkfs.ext2 -q -F "$device" && mkdir -p "$mount" &&
    mount -t ext2 "$device" "$mount" && chmod 1777 "$mount" ||
    { echo "disk-tmpdir.sh: TBROK: cannot make an ext2 TMPDIR"; exit 2; }
TMPDIR=$mount "$@"
status=$?
umount "$mount"
losetup -d "$device"
rm -rf "$image" "$mount"
exit $status
EOF
chmod +x /opt/ltp/disk-tmpdir.sh || fail chmod
wget -q -O /opt/ltp/ltp-runner "$base/ltp-runner" || fail "runner download"
chmod +x /opt/ltp/ltp-runner || fail chmod
wget -q -O /opt/ltp/runlist.txt "$base/runlist.txt" || fail "run list download"

export LTPROOT=/opt/ltp
export PATH=/opt/ltp/testcases/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export TMPDIR=/tmp/ltp
export LTP_COLORIZE_OUTPUT=0
# Tests that loop for a runtime (races, stress) run a tenth of it; the run
# list's budgets (tools/ltp/make-list.py) assume this.
export LTP_RUNTIME_MUL=0.1
# Ginux has no kernel .config (/proc/config.gz); without this, every test
# that checks a CONFIG_ option stops with "TBROK: Cannot parse kernel
# .config". LTP's switch treats the options as present, so they run.
export KCONFIG_SKIP_CHECK=1
exec /opt/ltp/ltp-runner /opt/ltp/runlist.txt "$first"
