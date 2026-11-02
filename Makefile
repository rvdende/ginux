SHELL := /bin/bash

TARGET := x86_64-unknown-uefi
PROFILE ?= release
CARGO_PROFILE_FLAG := $(if $(filter release,$(PROFILE)),--release,)
EFI_SOURCE := target/$(TARGET)/$(PROFILE)/ginux-boot.efi
ESP_DIR := build/esp
EFI_DESTINATION := $(ESP_DIR)/EFI/BOOT/BOOTX64.EFI
LINUX_PROBE := build/linux-probe.elf
LINUX_DYNAMIC_DIR := build/linux-dynamic
VOLUME_SERVICE := target/x86_64-unknown-none/$(PROFILE)/ginux-volume-service-runtime
CONTROLLER_RUNTIME := target/x86_64-unknown-none/$(PROFILE)/ginux-controller-runtime
NETWORK_SERVICE := target/x86_64-unknown-none/$(PROFILE)/ginux-network-service-runtime
PROTOCOL_SERVICE := target/x86_64-unknown-none/$(PROFILE)/ginux-protocol-service-runtime
INITRAMFS := build/initramfs-v0.cpio
SYSTEM_PROFILE := profiles/minimal-system-v0/profile.tsv

.DEFAULT_GOAL := help

.PHONY: help doctor manifest system-image test-alpine test-rocky-shell test-rocky-dnf test-multi-domain test-multi-domain-detached test-linux-abi test-linux-runtime test-storage test-oci-cache test-smp test-rocky-smp-futex test-rocky-smp-shared-page test-rocky-smp-thread-context probe-rocky-systemd test-rocky-systemd test-rocky-detached test-domain-responsiveness benchmark-rocky-systemd benchmark-prepare-linux benchmark-prepare-ginux benchmark-linux-comparison benchmark-ginux-boot benchmark-boot-comparison benchmark-ginux-sysbench benchmark-compare benchmark-topology-matrix benchmark-topology-compare profile-rocky-systemd rocky-image rocky-image-check linux-probe controller-runtime network-service protocol-service volume-service abi-conformance architecture-check linux-compat-check build build-verification build-linux-profile run reset-storage boot-media test-boot-media test-hardware-profile test-rust-workloads test-desktop test-desktop-virtio-gpu test-multicore test-multithread test-bigmem test-quick test-rust-userland rust-rootfs userland userland-check ltp test-ltp ltp-check test test-c1 test-c2 fmt gate clean

help:
	@echo "Ginux development targets"
	@echo
	@echo "  make doctor  Check the local development prerequisites"
	@echo "  make manifest Regenerate the signed development boot inputs"
	@echo "  make system-image Build the pinned minimal system-container candidate"
	@echo "  make test-alpine Download Alpine at runtime and verify its real shell in QEMU"
	@echo "  make test-rust-workloads Build and run Rust stress programs and a serde cargo build in rust:alpine"
	@echo "  make userland            Build the Rust Wayland desktop (ginux-wm, ginux-term) for musl"
	@echo "  make userland-check      Lint and test the Rust Wayland desktop on the host"
	@echo "  make rust-rootfs         Build the all-Rust root filesystem embedded as image=builtin://rust"
	@echo "  make test-rust-userland  Boot a builtin://rust domain and run its brush/uutils test"
	@echo "  make test-desktop        Run the Wayland compositor and terminal on /dev/fb0, all-Rust userland"
	@echo "  make test-desktop-virtio-gpu  The same desktop on a virtio-gpu display (no VGA)"
	@echo "  make test-multicore      Four CPU-bound processes run at once in a 4-CPU domain"
	@echo "  make test-bigmem         One 16 GiB process in a 24 GB domain; faulting/OOM children die alone"
	@echo "  make test-multithread    One process's threads run on all CPUs of a 4-CPU domain"
	@echo "  make test-quick          Quick gate (~2 min): check, all-Rust userland, multicore"
	@echo "  make ltp                 Build the LTP syscall tests statically for musl (Docker)"
	@echo "  make test-ltp            Run the LTP syscall tests in an Alpine domain (docs/LTP.md)"
	@echo "  make ltp-check           Check the LTP harness (tests/ltp): fmt, clippy, unit tests"
	@echo "  make test-rocky-shell Download Rocky at runtime and verify its glibc shell in QEMU"
	@echo "  make test-rocky-dnf   Download Rocky and verify a real dnf update in QEMU"
	@echo "  make test-multi-domain Run concurrent Rocky domains in QEMU"
	@echo "  make test-multi-domain-detached Run detached Alpine and Rocky domains side by side"
	@echo "  make probe-rocky-systemd Probe Rocky systemd and verify the documented next blocker"
	@echo "  make test-rocky-systemd  Verify cold and cached warm Rocky systemd login boots"
	@echo "  make test-rocky-detached Verify detached Rocky start returns to the controller"
	@echo "  make test-domain-responsiveness Verify controller latency under detached Linux work"
	@echo "  make benchmark-rocky-systemd Benchmark warm Rocky init (3 s gate on KVM)"
	@echo "  make benchmark-boot-comparison Compare matched QEMU-to-multi-user boot times"
	@echo "  make benchmark-prepare-linux Prepare the pinned Rocky Linux comparison image"
	@echo "  make benchmark-linux-comparison Run Rocky Linux boot and sysbench measurements"
	@echo "  make benchmark-prepare-ginux Build and seed the matched Ginux sysbench image"
	@echo "  make benchmark-ginux-sysbench Run the matching workload under Ginux"
	@echo "  make benchmark-compare Verify matched benchmark inputs and show result paths"
	@echo "  make benchmark-topology-matrix Compare Linux/Ginux at 1, 2, and 4 vCPUs"
	@echo "  make profile-rocky-systemd   Profile Rocky init inside the Ginux kernel"
	@echo "  make rocky-image Fetch and export the pinned Rocky 10 x86-64 system image"
	@echo "  make rocky-image-check Verify the prepared Rocky image without downloading"
	@echo "  make linux-probe Build the static probe and dynamic Linux ELF fixtures"
	@echo "  make controller-runtime Build the embedded Linux-ABI ring-3 controller"
	@echo "  make network-service Build the freestanding isolated network service"
	@echo "  make protocol-service Build the freestanding isolated protocol service"
	@echo "  make volume-service Build the freestanding isolated volume service"
	@echo "  make abi-conformance Compile the public native ABI as freestanding C"
	@echo "  make architecture-check Check architecture and roadmap consistency"
	@echo "  make linux-compat-check Validate the Linux syscall compatibility ledger"
	@echo "  make test-linux-abi     Run the complete controller Linux ABI report"
	@echo "  make test-linux-runtime Verify ELF, loader, PIE, TLS, heap, and memory behavior"
	@echo "  make build   Build the x86-64 UEFI image"
	@echo "  make run     Build Ginux and boot it in headless QEMU"
	@echo "  make reset-storage Delete the default persistent volume"
	@echo "  make boot-media Build a UEFI hybrid ISO and a raw USB image in build/media"
	@echo "  make test-boot-media Boot the ISO and USB image in QEMU as CD-ROM and USB stick"
	@echo "  make test-hardware-profile Boot an AMD/NVMe/xHCI machine without virtio into bring-up mode"
	@echo "  make test-storage Verify fresh, recovered, and reset persistent boots"
	@echo "  make test-oci-cache Verify OCI layers are reused after reboot"
	@echo "  make test    Build and verify the automated QEMU boot test"
	@echo "  make test-smp Qualify 1/2/4 CPUs and repeat the two-CPU stress run"
	@echo "  make test-rocky-smp-futex Verify two-CPU private-futex compatibility"
	@echo "  make test-rocky-smp-shared-page Verify 2/4-vCPU shared writable pages"
	@echo "  make test-rocky-smp-thread-context Verify 2/4-vCPU thread context integrity"
	@echo "  make test-c1 Build and verify the interactive controller console"
	@echo "  make test-c2 Verify configured domain lifecycle management"
	@echo "  make check   Run formatting and lint checks"
	@echo "  make fmt     Format Rust sources"
	@echo "  make gate    Run the clean reproducible build and QEMU test gate"
	@echo "  make clean   Remove generated build artifacts"

doctor:
	@tools/qemu/doctor.sh

manifest: linux-probe controller-runtime network-service protocol-service volume-service
	@mkdir -p "$(dir $(INITRAMFS))"
	@cargo run --quiet --package ginux-manifest-tool -- boot/manifest-v0.conf control-plane/bootstrap.hex "$(INITRAMFS)" "$(LINUX_DYNAMIC_DIR)" "$(CONTROLLER_RUNTIME)" "$(NETWORK_SERVICE)" "$(PROTOCOL_SERVICE)" "$(VOLUME_SERVICE)" "$(SYSTEM_PROFILE)" boot/efi/src/generated_boot.rs
	@test -s "$(INITRAMFS)"

system-image: manifest
	@echo "Built $(INITRAMFS) from $(SYSTEM_PROFILE)"

rocky-image:
	@tools/images/prepare-rocky.sh fetch

rocky-image-check:
	@tools/images/prepare-rocky.sh check

linux-probe:
	@mkdir -p "$(dir $(LINUX_PROBE))"
	@GINUX_LINUX_PROBE_EXPORT="$(abspath $(LINUX_PROBE))" GINUX_LINUX_DYNAMIC_EXPORT_DIR="$(abspath $(LINUX_DYNAMIC_DIR))" cargo build --package ginux-kernel --target $(TARGET) $(CARGO_PROFILE_FLAG)
	@test -f "$(LINUX_PROBE)"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-linked-main.elf"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-linked-graph-main.elf"
	@test -f "$(LINUX_DYNAMIC_DIR)/libginux.so"
	@test -f "$(LINUX_DYNAMIC_DIR)/libginux-aux.so"
	@test -f "$(LINUX_DYNAMIC_DIR)/ld-ginux.so"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-exec-second.elf"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-signal-probe.elf"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-conformance.elf"
	@test -f "$(LINUX_DYNAMIC_DIR)/linux-system-init.elf"
	@echo "Built $(LINUX_PROBE) and $(LINUX_DYNAMIC_DIR)"

volume-service:
	@cargo build --package ginux-volume-service-runtime --target x86_64-unknown-none $(CARGO_PROFILE_FLAG)
	@test -f "$(VOLUME_SERVICE)"
	@echo "Built $(VOLUME_SERVICE)"

controller-runtime:
	@cargo build --package ginux-controller-runtime --target x86_64-unknown-none $(CARGO_PROFILE_FLAG)
	@test -f "$(CONTROLLER_RUNTIME)"
	@echo "Built $(CONTROLLER_RUNTIME)"

network-service:
	@cargo build --package ginux-network-service-runtime --target x86_64-unknown-none $(CARGO_PROFILE_FLAG)
	@test -f "$(NETWORK_SERVICE)"
	@echo "Built $(NETWORK_SERVICE)"

protocol-service:
	@cargo build --package ginux-protocol-service-runtime --target x86_64-unknown-none $(CARGO_PROFILE_FLAG)
	@test -f "$(PROTOCOL_SERVICE)"
	@echo "Built $(PROTOCOL_SERVICE)"

abi-conformance:
	@clang -target x86_64-none-elf -std=c11 -ffreestanding -fsyntax-only \
		-Wall -Wextra -Werror -I. tests/abi/native-service-v0.c
	@echo "Native service ABI C conformance passed"

build: manifest
	@echo "Building Ginux for $(TARGET) ($(PROFILE))"
	@GINUX_LINUX_PROBE_EXPORT="$(abspath $(LINUX_PROBE))" GINUX_LINUX_DYNAMIC_EXPORT_DIR="$(abspath $(LINUX_DYNAMIC_DIR))" cargo build --package ginux-boot --target $(TARGET) $(CARGO_PROFILE_FLAG)
	@mkdir -p "$(dir $(EFI_DESTINATION))"
	@cp "$(EFI_SOURCE)" "$(EFI_DESTINATION)"
	@echo "Built $(EFI_DESTINATION)"

build-verification: manifest
	@echo "Building Ginux verification boot for $(TARGET) ($(PROFILE))"
	@GINUX_LINUX_PROBE_EXPORT="$(abspath $(LINUX_PROBE))" GINUX_LINUX_DYNAMIC_EXPORT_DIR="$(abspath $(LINUX_DYNAMIC_DIR))" cargo build --package ginux-boot --features verification-boot --target $(TARGET) $(CARGO_PROFILE_FLAG)
	@mkdir -p "$(dir $(EFI_DESTINATION))"
	@cp "$(EFI_SOURCE)" "$(EFI_DESTINATION)"
	@echo "Built verification image $(EFI_DESTINATION)"

build-linux-profile: manifest
	@echo "Building Ginux Linux boot profiler for $(TARGET) ($(PROFILE))"
	@GINUX_LINUX_PROBE_EXPORT="$(abspath $(LINUX_PROBE))" GINUX_LINUX_DYNAMIC_EXPORT_DIR="$(abspath $(LINUX_DYNAMIC_DIR))" cargo build --package ginux-boot --features linux-boot-profile --target $(TARGET) $(CARGO_PROFILE_FLAG)
	@mkdir -p "$(dir $(EFI_DESTINATION))"
	@cp "$(EFI_SOURCE)" "$(EFI_DESTINATION)"
	@echo "Built profiling image $(EFI_DESTINATION)"

test-alpine: build
	@tests/qemu/alpine-shell.sh

test-rocky-shell: build
	@tests/qemu/rocky-shell.sh

test-rocky-dnf: build
	@tests/qemu/rocky-dnf.sh

test-multi-domain: build
	@tests/qemu/multi-domain.sh

test-multi-domain-detached: build
	@tests/qemu/multi-domain-detached.sh

probe-rocky-systemd: build
	@tests/qemu/rocky-systemd.sh

test-rocky-systemd: build
	@tests/qemu/rocky-systemd.sh
	@GINUX_REQUIRE_OCI_CACHE_HIT=1 tests/qemu/rocky-systemd.sh
	@GINUX_ROCKY_START_MODE=detached-return GINUX_REQUIRE_OCI_CACHE_HIT=1 tests/qemu/rocky-systemd.sh

test-rocky-detached: build
	@GINUX_ROCKY_START_MODE=detached-return GINUX_REQUIRE_OCI_CACHE_HIT=1 tests/qemu/rocky-systemd.sh

test-domain-responsiveness: build
	@GINUX_ROCKY_START_MODE=responsive GINUX_REQUIRE_OCI_CACHE_HIT=1 tests/qemu/rocky-systemd.sh

benchmark-rocky-systemd: build
	@accelerator="$${QEMU_ACCEL:-$$(source tools/qemu/common.sh; default_accelerator)}"; \
	if [[ "$$accelerator" == kvm ]]; then budget=3000; else budget=; fi; \
	echo "Benchmarking Rocky systemd with QEMU/$$accelerator$${budget:+ (budget: $${budget} ms)}"; \
	GINUX_VERIFY_LOGIN_SHELL=1 GINUX_REQUIRE_OCI_CACHE_HIT=1 \
	GINUX_MAX_LINUX_INIT_MS="$$budget" tests/qemu/rocky-systemd.sh

benchmark-prepare-linux:
	@tools/benchmarks/prepare-rocky-linux.sh

benchmark-linux-comparison:
	@tools/benchmarks/run-rocky-linux.sh

benchmark-prepare-ginux:
	@tools/benchmarks/prepare-ginux-sysbench.sh

benchmark-ginux-boot: build
	@tools/benchmarks/run-ginux-boot.sh

benchmark-boot-comparison: build benchmark-prepare-linux
	@BENCHMARK_BOOT_ONLY=1 tools/benchmarks/run-rocky-linux.sh
	@tools/benchmarks/run-ginux-boot.sh
	@tools/benchmarks/summarize-boot.sh

benchmark-ginux-sysbench: build
	@tools/benchmarks/run-ginux.sh

benchmark-compare:
	@tools/benchmarks/compare.sh

benchmark-topology-matrix: build
	@tools/benchmarks/run-topology-matrix.sh

benchmark-topology-compare:
	@tools/benchmarks/summarize-topology-matrix.py

profile-rocky-systemd: build-linux-profile
	@GINUX_REQUIRE_OCI_CACHE_HIT=1 tests/qemu/rocky-systemd.sh

run: build
	@tools/qemu/run.sh

reset-storage:
	@rm -f build/qemu/volume.raw
	@echo "Removed build/qemu/volume.raw; the next make run starts clean."

boot-media: build
	@tools/images/build-boot-media.sh

test-boot-media: boot-media
	@tests/qemu/boot-media.sh

test-hardware-profile: build
	@tests/qemu/hardware-profile.sh

test-rust-workloads: build
	@tests/qemu/rust-workloads.sh

userland:
	@cd userland && cargo build --release --target x86_64-unknown-linux-musl

userland-check:
	@cd userland && cargo fmt --check
	@cd userland && cargo clippy --release --target x86_64-unknown-linux-musl --all-targets -- -D warnings
	@cd userland && cargo test --release

rust-rootfs:
	@tools/images/build-rust-rootfs.sh

ltp:
	@tools/ltp/build.sh

# LTP_TESTS="a b" or LTP_FILTER=REGEX select tests, LTP_STRICT=1 fails on
# every failure (not only regressions against tests/ltp/baseline.txt), and
# LTP_ARGS passes options to tests/qemu/ltp.sh (e.g. LTP_ARGS='-- -q');
# see docs/LTP.md.
test-ltp: build
	@GINUX_ESP_DIR="$${GINUX_ESP_DIR:-$(abspath $(ESP_DIR))}" tests/qemu/ltp.sh $(LTP_ARGS)

# The LTP harness's own checks: formatting, clippy and its unit tests.
ltp-check:
	@cargo fmt --manifest-path tests/ltp/Cargo.toml --check
	@cargo clippy --manifest-path tests/ltp/Cargo.toml --all-targets -- -D warnings
	@cargo test --manifest-path tests/ltp/Cargo.toml --lib

test-rust-userland: rust-rootfs build
	@tests/qemu/rust-userland.sh

test-desktop: rust-rootfs build
	@tests/qemu/wayland-desktop.sh

# The same desktop with a virtio-gpu as the only display adapter, in a mode
# the host picks (not the firmware's 1280x800).
test-desktop-virtio-gpu: rust-rootfs build
	@GINUX_QEMU_GPU=virtio GINUX_QEMU_GPU_SIZE=1024x768 tests/qemu/wayland-desktop.sh

# A domain given four CPUs runs four CPU-bound processes at once (tests/smp).
test-multicore: rust-rootfs build
	@cargo test --manifest-path tests/smp/Cargo.toml multicore -- --nocapture

# One process uses 16 GiB of a 24 GB domain, and children that fault or run
# out of memory die alone (tests/smp/tests/bigmem.rs). Boots a 26 GiB guest:
# run it on its own, not in test-quick.
# One process's threads run on all the CPUs of a 4-CPU domain (tests/smp).
test-multithread: rust-rootfs build
	@cargo test --manifest-path tests/smp/Cargo.toml multithread -- --nocapture

test-bigmem: rust-rootfs build
	@cargo test --manifest-path tests/smp/Cargo.toml bigmem -- --nocapture

# The quick gate before a commit: the full suites and LTP take half an hour.
test-quick: check test-rust-userland test-multicore test-multithread

test-storage: build
	@tests/qemu/persistent-storage.sh

test-oci-cache: build
	@tests/qemu/oci-cache.sh

test: build-verification
	@tests/qemu/boot.sh

test-smp: build-verification
	@tests/qemu/smp-matrix.sh

test-rocky-smp-futex: build
	@tests/qemu/rocky-smp-futex.sh

test-rocky-smp-shared-page: build
	@tests/qemu/rocky-smp-shared-page.sh

test-rocky-smp-thread-context: build
	@tests/qemu/rocky-smp-thread-context.sh

test-linux-runtime: test

test-c1: build
	@tests/qemu/controller-console.sh

test-c2: test-c1
	@tests/config/container-config.sh

architecture-check:
	@bash tools/architecture/check.sh

linux-compat-check:
	@bash tools/architecture/check-linux-compat.sh

test-linux-abi: build
	@tests/qemu/linux-abi-report.sh

check: manifest architecture-check linux-compat-check
	@$(MAKE) abi-conformance
	@cargo fmt --all -- --check
	@cargo clippy --package ginux-boot --target $(TARGET) -- -D warnings
	@cargo clippy --package ginux-native-abi -- -D warnings
	@cargo test --package ginux-native-abi
	@cargo clippy --package ginux-command -- -D warnings
	@cargo test --package ginux-command
	@cargo clippy --package ginux-oci -- -D warnings
	@cargo test --package ginux-oci
	@cargo clippy --package ginux-oci-cache -- -D warnings
	@cargo test --package ginux-oci-cache
	@cargo clippy --package ginux-image-store -- -D warnings
	@cargo test --package ginux-image-store
	@cargo clippy --package ginux-runtime-memory -- -D warnings
	@cargo test --package ginux-runtime-memory
	@cargo clippy --package ginux-credentials --all-targets -- -D warnings
	@cargo test --package ginux-credentials
	@cargo clippy --package ginux-memory-areas --all-targets -- -D warnings
	@cargo test --package ginux-memory-areas
	@cargo clippy --package ginux-keyrings --all-targets -- -D warnings
	@cargo test --package ginux-keyrings
	@cargo clippy --package ginux-drm --all-targets -- -D warnings
	@cargo test --package ginux-drm
	@cargo clippy --package ginux-usb-audio --all-targets -- -D warnings
	@cargo test --package ginux-usb-audio
	@cargo clippy --package ginux-usb-hid --all-targets -- -D warnings
	@cargo test --package ginux-usb-hid
	@cargo clippy --package ginux-virtio-gpu --all-targets -- -D warnings
	@cargo test --package ginux-virtio-gpu
	@cargo clippy --package ginux-controller-runtime --target x86_64-unknown-none -- -D warnings
	@cargo clippy --package ginux-protocol-state -- -D warnings
	@cargo test --package ginux-protocol-state
	@cargo clippy --package ginux-volume-format -- -D warnings
	@cargo test --package ginux-volume-format
	@cargo clippy --package ginux-volume-service -- -D warnings
	@cargo test --package ginux-volume-service
	@cargo clippy --package ginux-network-service-runtime --target x86_64-unknown-none -- -D warnings
	@cargo clippy --package ginux-protocol-service-runtime --target x86_64-unknown-none -- -D warnings
	@cargo clippy --package ginux-volume-service-runtime --target x86_64-unknown-none -- -D warnings
	@cargo clippy --package ginux-manifest-tool -- -D warnings

fmt: manifest
	@cargo fmt --all

gate:
	@$(MAKE) fmt
	@$(MAKE) clean
	@$(MAKE) check
	@$(MAKE) test-c2
	@$(MAKE) test
	@git diff --check
	@echo "Clean build and QEMU test gate passed"

clean:
	@cargo clean
	@rm -rf build
	@echo "Removed generated build artifacts"
