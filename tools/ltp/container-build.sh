#!/bin/sh
# Runs inside the Alpine builder container started by tools/ltp/build.sh.
#   /cache    the verified LTP release tarball (read-only)
#   /scripts  tools/ltp (read-only)
#   /work     the persistent build tree (target/ltp-build[-VARIANT] on the host)
#   /out      the published tree and tarballs (build/ltp[-VARIANT] on the host)
set -eu

# Files written here are owned by root; hand them back to the host user.
fix_owner() { chown -R "$HOST_UID:$HOST_GID" /work /out 2>/dev/null || true; }
trap fix_owner EXIT

# numactl-dev: libnuma (with libnuma.a) for the NUMA tests (set_mempolicy,
# mbind, move_pages, migrate_pages, ...), which configure finds.
apk add --no-cache --quiet \
    build-base linux-headers autoconf automake bash perl pkgconf \
    tar gzip xz findutils libaio-dev libcap-dev libcap-static shadow numactl-dev

# The guest-side runner that tests/qemu/ltp.sh starts in the domain.
gcc -static-pie -fPIE -O2 -Wall -Wextra -Werror -o /out/ltp-runner.new /scripts/ltp-runner.c
strip --strip-all /out/ltp-runner.new
mv /out/ltp-runner.new /out/ltp-runner
if [ "${RUNNER_ONLY:-0}" = 1 ]; then
    exit 0
fi

src="/work/ltp-full-$LTP_VERSION"
# Changing these options rebuilds from a fresh source tree.
#
# Static position-independent executables (static-pie): Ginux loads a file
# written at runtime only if it is position independent; its fixed-address
# (ET_EXEC) loader takes only tiny programs (5 code pages, 8 in all).
cflags="-O2 -pipe -fPIE"
ldflags="-static-pie"
case "${VARIANT:-}" in
    # harness: a copy of the default build for trying harness changes
    # without touching build/ltp.
    "" | harness) ;;
    no-oom-protection)
        # See tools/ltp/no-oom-protection.c: a diagnostic build only.
        gcc -c -O2 -fPIE -Wall -Wextra -Werror -o /work/no-oom-protection.o \
            /scripts/no-oom-protection.c
        ldflags="$ldflags -Wl,-z,muldefs /work/no-oom-protection.o"
        ;;
    *) echo "unknown variant $VARIANT" >&2; exit 2 ;;
esac
# The libraries configure finds are part of the stamp, so a tree configured
# before libnuma was installed is configured again.
configure_args="--prefix=/opt/ltp CFLAGS=$cflags LDFLAGS=$ldflags libs=numa"
stamp="$src/.ginux-configured"

if [ ! -f "$stamp" ] || [ "$(cat "$stamp")" != "$configure_args" ]; then
    echo "Configuring LTP $LTP_VERSION"
    rm -rf "$src"
    tar -xJf "/cache/ltp-full-$LTP_VERSION.tar.xz" -C /work
    cd "$src"
    ./configure --prefix=/opt/ltp CFLAGS="$cflags" LDFLAGS="$ldflags" >/work/configure.log 2>&1 ||
        { tail -n 40 /work/configure.log; exit 1; }
    printf '%s\n' "$configure_args" >"$stamp"
fi
cd "$src"

echo "Compiling with $JOBS jobs (log: make.log in the build tree)"
# libltp.a must build; the helper libraries are built up front so parallel
# test directories do not race to build them.
make -j"$JOBS" -C lib >/work/make-lib.log 2>&1 ||
    { tail -n 40 /work/make-lib.log; exit 1; }
make -j"$JOBS" -k -C libs >/work/make-libs.log 2>&1 || true
make -j"$JOBS" -k -C testcases/lib >/work/make-testcases-lib.log 2>&1 || true
# The old API's shell commands (tst_resm, tst_brkm, tst_exit, ...), which
# old-API shell tests such as ioctl02's test_ioctl call.
make -j"$JOBS" -C tools/apicmds >/work/make-apicmds.log 2>&1 ||
    { tail -n 40 /work/make-apicmds.log; exit 1; }

# LTP's directory loop stops at the first directory that fails, so every
# leaf directory is built on its own, in parallel, with -k: a test that does
# not build under musl is skipped, not patched.
#
# runtest/syscalls also names a few tests that live elsewhere (dirtyc0w,
# msgstress01, pipeio, ...); their directories are built too.
{
    find testcases/kernel/syscalls -mindepth 2 -name Makefile | sed 's,/Makefile$,,'
    awk '!/^#/ && NF { print $2 ".c" }' runtest/syscalls >/work/runtest-sources.txt
    find testcases/kernel -path testcases/kernel/syscalls -prune -o -name '*.c' -print |
        awk -F/ 'NR == FNR { want[$0]; next } ($NF in want) { sub("/[^/]*$", ""); print }' \
            /work/runtest-sources.txt -
    # The memory controller's tests (memcontrol01-04, runtest/controllers)
    # and the stack guard gap's (stack_clash, runtest/cve).
    echo testcases/kernel/controllers/memcg
    echo testcases/cve
} | LC_ALL=C sort -u >/work/leaf-dirs.txt
xargs -P "$JOBS" -I{} sh -c 'make -k -C "$1" >"$1/.ginux-make.log" 2>&1 || true' sh {} \
    </work/leaf-dirs.txt
while IFS= read -r dir; do cat "$dir/.ginux-make.log"; done </work/leaf-dirs.txt >/work/make.log

echo "Installing"
rm -rf /work/install
xargs -I{} sh -c 'make -k -C "$1" install DESTDIR=/work/install || true' sh {} \
    </work/leaf-dirs.txt >/work/install.log 2>&1
make -k -C testcases/lib install DESTDIR=/work/install >>/work/install.log 2>&1 || true
make -C tools/apicmds install DESTDIR=/work/install >>/work/install.log 2>&1
root=/work/install/opt/ltp

# Ginux's own tests (tools/ltp/tests), built against libltp as LTP's are.
: >/work/ginux-tests.txt
for test in /scripts/tests/*.c; do
    name=${test##*/}
    name=${name%.c}
    gcc $cflags $ldflags -Wall -Wextra -I"$src/include" -I"$src/include/old" \
        -o "$root/testcases/bin/$name" "$test" \
        -L"$src/libs/swap" -L"$src/lib" -lltpswap -lltp ||
        { echo "building $name failed"; exit 1; }
    printf '%s\tginux\n' "$name" >>/work/ginux-tests.txt
done

# useradd and friends, which tests run as on a distribution that has them
# (add_key05, prot_hsymlinks); the domain's Alpine has only busybox's
# adduser. The builder is the same Alpine release as the domain image, so
# its shadow tools and the two libraries they need are copied as a small
# overlay that tests/ltp/setup.sh installs into the domain.
overlay="$root/distro/shadow"
mkdir -p "$overlay/usr/sbin" "$overlay/usr/lib" "$overlay/etc"
for tool in useradd userdel usermod groupadd groupdel groupmod; do
    cp -a "/usr/sbin/$tool" "$overlay/usr/sbin/$tool"
done
for library in $(ldd /usr/sbin/useradd /usr/sbin/userdel /usr/sbin/usermod \
    /usr/sbin/groupadd /usr/sbin/groupdel /usr/sbin/groupmod |
    awk '$3 ~ "^/usr/lib/" { print $3 }' | LC_ALL=C sort -u); do
    cp -L "$library" "$overlay/usr/lib/${library##*/}"
done
cp /etc/login.defs "$overlay/etc/login.defs"

# Packages the tests run tools of, as the same kind of overlay: every file
# of the builder's packages and the libraries they link, so the domain
# needs no network to get them. package_overlay NAME PACKAGE...
package_overlay() {
    overlay="$root/distro/$1"
    shift
    apk add --no-cache --quiet "$@"
    for file in $(apk info -qL "$@" | grep -v '^$'); do
        mkdir -p "$overlay/${file%/*}"
        cp -a "/$file" "$overlay/$file"
    done
    for library in $(find "$overlay" -type f -perm -u+x -exec ldd {} \; 2>/dev/null |
        awk '$3 ~ "^/usr/lib/" { print $3 }' | LC_ALL=C sort -u); do
        mkdir -p "$overlay/usr/lib"
        cp -L "$library" "$overlay/usr/lib/${library##*/}"
    done
}
# e2fsprogs (mkfs.ext2/3/4, e2fsck, tune2fs, debugfs, chattr, e4crypt,
# ...), which the tests that format a device run.
package_overlay e2fsprogs e2fsprogs e2fsprogs-extra
# The quota tools (quotacheck, quotaon, setquota, repquota), which the
# quotactl tests run to make quota files.
package_overlay quota quota-tools

# Map each test binary to its syscall directory, for grouping results.
while IFS= read -r dir; do
    for file in "$dir"/*; do
        if [ -f "$file" ] && [ -x "$file" ] &&
            [ "$(od -An -tx1 -N4 "$file" | tr -d ' ')" = 7f454c46 ]; then
            printf '%s\t%s\n' "${file##*/}" "${dir#testcases/kernel/}"
        fi
    done
done </work/leaf-dirs.txt | cat - /work/ginux-tests.txt | LC_ALL=C sort >/work/test-dirs.txt
mkdir -p "$root/runtest"
cp runtest/syscalls "$root/runtest/syscalls"
cp VERSION "$root/VERSION"

# Strip every ELF file; shell helpers are left alone.
find "$root" -type f | while IFS= read -r file; do
    if [ "$(od -An -tx1 -N4 "$file" | tr -d ' ')" = 7f454c46 ]; then
        strip --strip-all "$file"
    fi
done

rm -rf /out/ltp /out/ltp.tar.gz /out/ltp.tar.xz
cp -a "$root" /out/ltp
cp /work/test-dirs.txt /out/test-dirs.txt
find /out/ltp/testcases/bin -maxdepth 1 -type f |
    while IFS= read -r file; do
        if [ "$(od -An -tx1 -N4 "$file" | tr -d ' ')" = 7f454c46 ]; then
            basename "$file"
        fi
    done | LC_ALL=C sort >/out/binaries.txt

# Each failed make target appears as "*** [rule: TARGET] Error N".
grep -o '\*\*\* \[[^]]*\] Error [0-9]*' /work/make.log |
    sed 's/^\*\*\* \[.*: \([^]]*\)\] Error [0-9]*$/\1/' |
    LC_ALL=C sort -u >/out/build-failures.txt || true

# Reproducible tarballs: fixed order, owner and timestamps (the release
# date). The static binaries share most of their code, which gzip's 32 KiB
# window cannot see but xz's dictionary can: the .tar.xz is about a tenth of
# the .tar.gz, so the QEMU test downloads that one into the domain.
tar --sort=name --mtime=@1790726400 --owner=0 --group=0 --numeric-owner \
    -C /out -cf /work/ltp.tar ltp
gzip -n -9 -c /work/ltp.tar >/out/ltp.tar.gz
xz -9 -T1 -c /work/ltp.tar >/out/ltp.tar.xz
rm -f /work/ltp.tar
