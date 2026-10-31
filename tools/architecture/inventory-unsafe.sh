#!/usr/bin/env bash
# Inventories the unsafe code of the kernel and boot crates. Read-only: it
# changes no tracked file; cargo's output goes to an ignored target directory.
#
#   tools/architecture/inventory-unsafe.sh [--summary | --sites | --ops | --unsound]
#
# --summary (default) prints Markdown tables: sites per kind, per file and per
# category, the operations inside them, SAFETY-comment coverage, modules with
# no unsafe at all, safe functions that dereference an integer or raw-pointer
# argument and safe functions that return &'static mut. --sites, --ops and
# --unsound print the underlying rows as tab-separated values.
#
# The sites come from the compiler, so they are exact: cargo clippy checks
# ginux-kernel and ginux-boot with unsafe_code, unsafe_op_in_unsafe_fn,
# clippy::multiple_unsafe_ops_per_block and clippy::undocumented_unsafe_blocks
# raised to warnings, in a target directory of its own (target/unsafe-inventory,
# or GINUX_UNSAFE_INVENTORY_TARGET) so the normal build cache is untouched. The
# first run checks the dependencies too (about 20 s); later runs replay the
# cached diagnostics. A lexical pass over the same sources adds what the lints
# do not report (static mut declarations, asm! invocations, enclosing
# functions) and gives each site a category from CATEGORY_RULES below. The
# categories are a planning heuristic; the counts are not.
#
# docs/FRAMEKERNEL.md explains the categories and uses this output.

set -euo pipefail

root=$(git rev-parse --show-toplevel)
mode=${1:---summary}
case "$mode" in
--summary | --sites | --ops | --unsound) ;;
*)
    printf 'usage: %s [--summary | --sites | --ops | --unsound]\n' "$0" >&2
    exit 2
    ;;
esac

target_dir=${GINUX_UNSAFE_INVENTORY_TARGET:-$root/target/unsafe-inventory}
diagnostics=$(mktemp "${TMPDIR:-/tmp}/ginux-unsafe-inventory.XXXXXX")
trap 'rm -f "$diagnostics"' EXIT

(
    cd "$root"
    CARGO_TARGET_DIR="$target_dir" cargo clippy --quiet --locked \
        --package ginux-kernel --package ginux-boot --target x86_64-unknown-uefi \
        --message-format=json -- \
        -W unsafe_code -W unsafe_op_in_unsafe_fn \
        -W clippy::multiple_unsafe_ops_per_block \
        -W clippy::undocumented_unsafe_blocks >"$diagnostics"
)

python3 -I - "$root" "$diagnostics" "$mode" <<'PY'
import collections
import json
import os
import re
import sys

root, diagnostics, mode = sys.argv[1:4]
SCOPE = ("kernel/src/", "boot/efi/src/")

# --------------------------------------------------------------------------
# Lexing: blank comments (and optionally string contents) without moving any
# character, so compiler line/column positions still apply.

SPECIAL = re.compile(r'//|/\*|(?<![A-Za-z0-9_])[bc]?r#*"|"|\'')


def strip(text, keep_strings):
    out = list(text)

    def blank(start, end):
        for index in range(start, end):
            if out[index] != "\n":
                out[index] = " "

    position, length = 0, len(text)
    while True:
        match = SPECIAL.search(text, position)
        if not match:
            break
        token, start = match.group(0), match.start()
        if token == "//":
            end = text.find("\n", start)
            end = length if end < 0 else end
            blank(start, end)
            position = end
        elif token == "/*":
            depth, end = 1, start + 2
            while end < length and depth:
                if text.startswith("/*", end):
                    depth, end = depth + 1, end + 2
                elif text.startswith("*/", end):
                    depth, end = depth - 1, end + 2
                else:
                    end += 1
            blank(start, end)
            position = end
        elif token.endswith('"') and "r" in token:
            hashes = token[token.index("r") + 1:-1]
            end = text.find('"' + hashes, match.end())
            end = length if end < 0 else end
            if not keep_strings:
                blank(match.end(), end)
            position = end + 1 + len(hashes)
        elif token == '"':
            end = start + 1
            while end < length and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            if not keep_strings:
                blank(start + 1, end)
            position = end + 1
        else:  # a quote: a char literal or a lifetime
            if start + 1 < length and text[start + 1] == "\\":
                end = text.find("'", start + 3)
                position = length if end < 0 else end + 1
            elif start + 2 < length and text[start + 2] == "'":
                position = start + 3
            else:
                position = start + 1
    return "".join(out)


class Source:
    def __init__(self, path):
        self.path = path
        with open(os.path.join(root, path), encoding="utf-8") as handle:
            self.text = handle.read()
        self.code = strip(self.text, keep_strings=False)
        self.readable = strip(self.text, keep_strings=True)
        self.line_starts = [0]
        for index, char in enumerate(self.text):
            if char == "\n":
                self.line_starts.append(index + 1)
        self.line_count = len(self.line_starts) - (1 if self.text.endswith("\n") else 0)
        self.functions = self._functions()

    def offset(self, line, column=1):
        return self.line_starts[line - 1] + column - 1

    def line_of(self, offset):
        low, high = 0, len(self.line_starts) - 1
        while low < high:
            middle = (low + high + 1) // 2
            if self.line_starts[middle] <= offset:
                low = middle
            else:
                high = middle - 1
        return low + 1

    def _functions(self):
        """Every `fn` with a body: (name, start, open, close, unsafe, params)."""
        code, found = self.code, []
        for match in re.finditer(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*|\$[a-z_]+)", code):
            index, depth = match.end(), 0
            while index < len(code):
                char = code[index]
                if char in "(<[":
                    depth += 1
                elif char in ")>]":
                    depth -= 1 if char != ">" or code[index - 1] != "-" else 0
                elif char in "{;" and depth <= 0:
                    break
                index += 1
            if index >= len(code) or code[index] == ";":
                continue
            open_brace, depth, close = index, 0, index
            while close < len(code):
                if code[close] == "{":
                    depth += 1
                elif code[close] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                close += 1
            line_start = code.rfind("\n", 0, match.start()) + 1
            prefix = code[line_start:match.start()]
            params = code[match.end():open_brace]
            # Start at the signature's line, so a span that begins at
            # `pub unsafe fn` lies inside the function.
            found.append((match.group(1), line_start, open_brace, close,
                          re.search(r"\bunsafe\b", prefix) is not None, params))
        return found

    def enclosing(self, offset):
        best = None
        for function in self.functions:
            if function[1] <= offset <= function[3]:
                if best is None or function[1] > best[1]:
                    best = function
        return best


sources = {}


def source(path):
    if path not in sources:
        sources[path] = Source(path)
    return sources[path]


def in_scope(path):
    return path.startswith(SCOPE)


all_files = []
for base in SCOPE:
    for directory, _, names in os.walk(os.path.join(root, base)):
        for name in names:
            if name.endswith(".rs"):
                all_files.append(os.path.relpath(os.path.join(directory, name), root))
all_files.sort()

# --------------------------------------------------------------------------
# Compiler diagnostics.

SITE_KINDS = {
    "usage of an `unsafe` block": "block",
    "declaration of an `unsafe` function": "unsafe fn",
    "implementation of an `unsafe` method": "unsafe fn",
    "implementation of an `unsafe` trait": "unsafe impl",
    "usage of `core::arch::global_asm`": "global_asm!",
    "usage of an `unsafe extern` block": "unsafe extern",
    "usage of the unsafe `no_mangle` attribute": "unsafe attribute",
}
OP_NOTES = {
    "unsafe method call occurs here": "method call",
    "unsafe function call occurs here": "fn call",
    "raw pointer dereference occurs here": "raw deref",
    "inline assembly used here": "asm!",
    "access of a mutable static occurs here": "static mut",
    "modification of a mutable static occurs here": "static mut",
    "access of a union field occurs here": "union field",
}

sites = {}
ops = []


def highlighted(span):
    parts = [entry["text"][entry["highlight_start"] - 1:entry["highlight_end"] - 1]
             for entry in span.get("text") or []]
    return " ".join(part.strip() for part in parts)


def callee(text):
    text = text.strip()
    if text.endswith(")"):
        depth = 0
        for index in range(len(text) - 1, -1, -1):
            if text[index] == ")":
                depth += 1
            elif text[index] == "(":
                depth -= 1
                if depth == 0:
                    text = text[:index]
                    break
    text = re.sub(r"::<[^<>]*>$", "", text.strip()).rstrip(") ")
    match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", text)
    return match.group(1) if match else "?"


with open(diagnostics, encoding="utf-8") as handle:
    for raw in handle:
        message = json.loads(raw)
        if message.get("reason") != "compiler-message":
            continue
        diagnostic = message["message"]
        code = (diagnostic.get("code") or {}).get("code")
        primary = [span for span in diagnostic["spans"] if span["is_primary"]]
        if not primary or not in_scope(primary[0]["file_name"]):
            continue
        span = primary[0]
        key = (span["file_name"], span["line_start"], span["column_start"])
        if code == "unsafe_code":
            site = sites.setdefault(key, {"expansions": 0, "documented": True, "ops": []})
            site["kind"] = SITE_KINDS.get(diagnostic["message"], diagnostic["message"])
            site["end"] = (span["line_end"], span["column_end"])
            site["expansions"] += 1
        elif code == "clippy::undocumented_unsafe_blocks":
            sites.setdefault(key, {"expansions": 0, "documented": True, "ops": []})["documented"] = False
        elif code == "clippy::multiple_unsafe_ops_per_block":
            site = sites.setdefault(key, {"expansions": 0, "documented": True, "ops": []})
            site["multi"] = True
            for child in diagnostic["children"]:
                if not child["spans"] or child["message"] not in OP_NOTES:
                    continue
                child_span = child["spans"][0]
                text = highlighted(child_span)
                kind = OP_NOTES[child["message"]]
                site["ops"].append({
                    "file": child_span["file_name"], "line": child_span["line_start"],
                    "kind": kind, "callee": callee(text) if "call" in kind else "",
                    "text": text, "source": "compiler"})
        elif code == "E0133":
            text = diagnostic["message"]
            named = re.search(r"call to unsafe function `([^`]*)`", text)
            if named:
                kind, name = "fn call", named.group(1).split("::")[-1]
            elif "call to unsafe function" in text:
                kind, name = "fn call", "(fn pointer)"
            elif "dereference of raw pointer" in text:
                kind, name = "raw deref", ""
            elif "inline assembly" in text:
                kind, name = "asm!", ""
            elif "mutable static" in text:
                kind, name = "static mut", ""
            else:
                kind, name = "other", ""
            ops.append({"file": span["file_name"], "line": span["line_start"],
                        "column": span["column_start"], "kind": kind, "callee": name,
                        "text": highlighted(span), "source": "compiler", "in": "unsafe fn body"})

# Drop documentation-only entries the unsafe_code lint did not also report.
sites = {key: value for key, value in sites.items() if "kind" in value}

# --------------------------------------------------------------------------
# Lexical facts.

static_muts = collections.defaultdict(list)  # file -> names
asm_calls = collections.Counter()
global_asm_lines = collections.Counter()
for path in all_files:
    src = source(path)
    for match in re.finditer(r"(?<!')\bstatic\s+mut\s+([A-Z_][A-Z0-9_]*)\s*:", src.code):
        static_muts[path].append(match.group(1))
    asm_calls[path] = len(re.findall(r"(?<![A-Za-z0-9_])asm!\s*\(", src.code))
    for match in re.finditer(r"\bglobal_asm!\s*\(", src.code):
        depth, index = 0, match.end() - 1
        while index < len(src.code):
            if src.code[index] == "(":
                depth += 1
            elif src.code[index] == ")":
                depth -= 1
                if depth == 0:
                    break
            index += 1
        body = src.text[match.end():index]
        include = re.search(r'include_str!\("([^"]+)"\)', body)
        if include:
            included = os.path.normpath(os.path.join(os.path.dirname(os.path.join(root, path)), include.group(1)))
            with open(included, encoding="utf-8") as handle:
                global_asm_lines[path] += sum(1 for line in handle if line.strip())
        else:
            global_asm_lines[path] += sum(1 for line in body.splitlines() if line.strip())
static_mut_names = {name for names in static_muts.values() for name in names}

# Safe fns that hand out `&'static mut`: two calls give two aliasing mutable
# references unless something outside the type system prevents the second.
static_mut_returners = []
for path in all_files:
    src = source(path)
    for name, start, _, _, is_unsafe, signature in src.functions:
        returns = signature.split("->", 1)[1] if "->" in signature else ""
        if not is_unsafe and "&'static mut" in returns:
            static_mut_returners.append((path, src.line_of(start), name))

PTR_ACCESS = {"read", "write", "read_volatile", "write_volatile", "read_unaligned",
              "write_unaligned", "copy_nonoverlapping", "copy", "copy_from",
              "copy_to", "copy_from_nonoverlapping", "copy_to_nonoverlapping",
              "write_bytes", "replace", "swap", "drop_in_place", "fill"}
PTR_ARITH = {"add", "offset", "sub", "byte_add", "byte_offset", "offset_from"}
PTR_TO_REF = {"as_ref", "as_mut", "from_raw_parts", "from_raw_parts_mut",
              "assume_init", "assume_init_ref", "assume_init_mut", "assume_init_read",
              "assume_init_drop", "get_unchecked", "get_unchecked_mut",
              "from_utf8_unchecked", "transmute", "zeroed", "drop"}


def op_family(op):
    kind, name = op["kind"], op["callee"]
    if kind in ("raw deref", "asm!", "static mut", "union field", "other"):
        return kind
    if name in PTR_ACCESS:
        return "pointer read/write"
    if name in PTR_ARITH:
        return "pointer arithmetic"
    if name in PTR_TO_REF:
        return "pointer to reference/slice"
    return "call of a kernel unsafe fn" if name not in ("(fn pointer)",) else "fn-pointer call"


def lexical_op(text):
    """The single operation of a block the compiler reported as one-op."""
    if re.search(r"(?<![A-Za-z0-9_])asm!\s*\(", text):
        return "asm!", ""
    for name in static_mut_names:
        if re.search(r"\b%s\b" % name, text):
            return "static mut", ""
    calls = re.findall(r"(?:\.|::)\s*([a-z_][a-z0-9_]*)\s*(?:::<[^>]*>)?\s*\(", text)
    for name in calls:
        if name in PTR_ACCESS or name in PTR_TO_REF:
            return "method call", name
    if re.search(r"&\s*(mut\s+)?\*|\(\s*\*[A-Za-z_(]|^\s*\*[A-Za-z_(]|=\s*\*[A-Za-z_(]", text):
        return "raw deref", ""
    for name in calls:
        if name in PTR_ARITH:
            return "method call", name
    plain = re.findall(r"(?<![.\w])([a-z_][a-z0-9_]*)\s*\(", text)
    plain = [name for name in plain + calls if name not in ("unsafe", "if", "while", "match", "for", "Some", "Ok")]
    return "fn call", plain[0] if plain else "?"


# --------------------------------------------------------------------------
# Site records.

records = []
for (path, line, column), site in sites.items():
    src = source(path)
    start = src.offset(line, column)
    end_line, end_column = site.get("end", (line, column))
    end = src.offset(end_line, end_column)
    kind = site["kind"]
    function = src.enclosing(start)
    owner = function
    if kind == "unsafe fn":
        # The diagnostic spans the signature: the site is the whole function,
        # and its context is the next function out.
        line_begin = src.offset(line)
        own = [f for f in src.functions if f[1] == line_begin or line_begin <= f[1] <= end]
        function = min(own, key=lambda f: f[1]) if own else function
        if function is not None:
            start, end = min(start, function[1]), max(end, function[3] + 1)
            end_line = src.line_of(end - 1)
        outer = [f for f in src.functions if f[1] < function[1] <= f[3] and f is not function] if function else []
        owner = max(outer, key=lambda f: f[1]) if outer else None
    text = src.readable[start:end]
    code = src.code[start:end]
    name = function[0] if function and kind in ("block", "unsafe fn") else "-"
    record = {
        "file": path, "line": line, "end": end_line, "kind": kind, "fn": name,
        "in_unsafe_fn": bool(owner and owner[4]) if kind == "block" else False,
        "verification": bool(re.search(r"verify", name)),
        "documented": site["documented"], "expansions": site["expansions"],
        "text": text, "code": code, "ops": site["ops"],
    }
    if kind == "block" and not site.get("multi"):
        op_kind, op_callee = lexical_op(code)
        record["ops"] = [{"file": path, "line": line, "kind": op_kind,
                          "callee": op_callee, "text": "", "source": "lexical"}]
    records.append(record)

# Operations in unsafe fn bodies outside any unsafe block (E0133 above).
for op in ops:
    candidates = [r for r in records if r["file"] == op["file"] and r["kind"] == "unsafe fn"
                  and r["line"] <= op["line"] <= r["end"]]
    if candidates:
        max(candidates, key=lambda r: r["line"])["ops"].append(op)

# --------------------------------------------------------------------------
# Categories. The first matching rule wins. A rule matches when every given
# part matches: the file path, the enclosing function name, and the site's
# source text (comments stripped, strings kept).

CATEGORIES = [
    ("paging", "Page tables, CR3, TLB"),
    ("entry", "Context switch, entry/exit asm, trap frames, GDT/IDT/TSS"),
    ("cpu", "CPU control: MSRs, CR0/CR4, interrupt flag, halt"),
    ("mmio-pio", "MMIO and port I/O: device registers, PCI config, APIC, serial, framebuffer"),
    ("dma", "DMA buffers, descriptor rings, I/O MMU tables"),
    ("user", "User-memory access"),
    ("frame-heap", "Frame allocator and kernel heap internals"),
    ("frame-view", "Typed views and byte slices of kernel-owned frames"),
    ("owner-cell", "Per-CPU and owner-struct cells: UnsafeCell, static mut, unsafe impl Sync"),
    ("lock", "Lock primitives"),
    ("firmware", "Firmware and boot handoff: UEFI, ACPI tables, BootInfo"),
    ("convenience", "Convenience: replaceable by safe code without a new core API"),
    ("other", "Unclassified"),
]

DRIVER_FILES = (r"kernel/src/drivers/(ahci|e1000e|hda|nvme|realtek|xhci|usb_input|virtio_gpu|device_memory)\.rs"
                r"|kernel/src/arch/x86_64/pci\.rs")
STATIC_MUT = "|".join(sorted(static_mut_names)) or "NO_STATIC_MUT"

CATEGORY_RULES = [
    ("lock", r"kernel/src/sync\.rs", None, None),
    ("frame-heap", r"kernel/src/(heap|memory)\.rs", None, None),
    # Bounds-checked reads of a byte buffer: from_le_bytes on a slice does it.
    ("convenience", r"kernel/src/pe\.rs", None, None),
    # Ring-3 test and service programs assembled into the kernel image; a
    # build step can produce them as include_bytes! blobs instead.
    ("convenience", None, None, r'global_asm!\(include_str!\("\.\./(packet|volume-service)'),
    ("entry", None, None, r"global_asm!|unsafe extern\b"),
    ("mmio-pio", None, None, r"\b(inb|outb|inl|outl|in_u8|out_u8)\b|in al, dx|out dx, al"),
    ("firmware", r"boot/efi/src/main\.rs|kernel/src/arch/x86_64/acpi\.rs|kernel/src/manifest\.rs", None, None),
    ("user", None, None,
     r"raw_copy_(from|to)_user|with_supervisor_user_access|ginux_raw_copy|copy_to_linux_process"),
    ("user", None, r"^(write_live_process_u32|copy_live_process_bytes)$", None),
    # A plain-data struct viewed as bytes: a Pod/AsBytes trait does this safely.
    ("convenience", None, None, r"from_raw_parts(_mut)?\(\s*(core::)?ptr::from_(ref|mut)"),
    ("owner-cell", None, None, r"unsafe impl(<[^>]*>)? (Sync|Send)|self\.owner\."),
    # Device code: register access and bring-up is MMIO/PIO, the rest (rings,
    # descriptors, static DMA pages) is DMA. The socket layer's virtio-net
    # device is the same kind of code inside linux_socket.rs.
    ("dma", None, r"^verify_dma_confinement$", None),
    ("mmio-pio", r"kernel/src/(drivers/amd_iommu|arch/x86_64/iommu)\.rs", r"^(read|write)(_u)?(32|64)$", None),
    ("dma", r"kernel/src/(drivers/amd_iommu|arch/x86_64/iommu)\.rs", None, None),
    ("dma", r"kernel/src/drivers/device_memory\.rs", None, r"self\.len\(\)"),
    ("dma", r"kernel/src/linux_socket\.rs",
     r"^(post_receive|consume|receive|transmit|write_u(16|32|64)|read_u(16|32))$", None),
    ("mmio-pio", DRIVER_FILES,
     r"^(read|write)(8|16|32|64)?$|^(read|write)_(mmio|common)_u(8|16|32|64)$|^(open|open_inner|probe|open_controller|new|prepare|start)$"
     r"|config|msix|^set_pci_command$|^bus_master|interrupt|^initialize|^revoke|^discover|^verify|^quiesce|^activate_",
     None),
    ("dma", DRIVER_FILES, None, None),
    ("owner-cell", None, None,
     r"\b[A-Z][A-Z0-9_]{2,}\b[^;{}]*\.get\(\)|get_mut_ptr|addr_of(_mut)?!\(\s*\(?\*?[A-Z][A-Z0-9_]+"
     r"|process_scratch\(\)|\(\*registry\)|socket_slots\(\)|unix_[a-z_]+\(\)|file_rights\(\)"
     r"|socket_runtime_state\(\)|socket_platform\(\)|\$field|\b(" + STATIC_MUT + r")\b"
     r"|live_process_table|&mut \*table\b|\(\*parent\)|&mut \*manager|&mut \*\*(entry|record)"
     r"|process_runtime\(\)|\(\*record\)|\(\*table\)|&(mut )?\*tmpfs\b|&\*table\b|self\.as_mut_ptr\(\)|claim\.as_mut_ptr\(\)"),
    ("entry", None, None,
     r"\b(enter_user|enter_linux_process|enter_linux_runtime_process|ginux_process_user_enter|ginux_user_enter"
     r"|ginux_call_on_stack|enter_on_own_stack|ginux_kernel_stack_entry)\b|frame\.as_(ref|mut)\(\)|&\*frame\b"
     r"|\bframe\.add\(|registers\.read\(\)|FS_BASE|xsave|xrstor|fxsave|fxrstor|lgdt|lidt|\bltr\b"
     r"|install_(gdt|idt|interrupt_gate|user_interrupt_gate)|clear_interrupt_gate|idt\.add|gdt\.add|\btss\b"
     r"|current_entry_state|stacks\.cast|STAR_MSR|LSTAR|SFMASK|argument\.cast::<EntryArguments>"),
    ("entry", None, r"^(install_gdt_and_tss|install_idt|current_idt|exception_\w+|task_register\w+"
                    r"|user_interrupt_surface\w*|scrub_service_restart_stack|write_linux_(thread_)?live_return"
                    r"|install_for_cpu|\w*extended_state\w*|configure_linux_syscall|restore_linux_syscall"
                    r"|user_fault_handler|fatal_exception_handler|syscall_handler|linux_syscall_handler)$", None),
    ("paging", None, None,
     r"\bactivate\(|current_root|\bcr3\b|invlpg|\b(entry|leaf|leaves|entries|root_entries|pdpt|directory"
     r"|directory_entry|pdpt_entry|root_entry|table|kernel|process|parent|child|active|parent_leaf|child_leaf"
     r"|kernel_entries|created_entries|root)(\[[^\]]*\])?\.(add\([^)]*\)\.)?(read|write)(_volatile)?\("
     r"|mapped_frame::<u64>|zero_entries|ensure_fine_region|map_device_window|map_framebuffer_window"
     r"|install_initial_identity_map|PAGING\.|\bpml4\b|map_kernel_stack_page|linux_leaf_in_root"
     r"|current_linux_leaf|\(entries as \*const u64\)|\bentries\.add\(|\btable\.add\(|self\.table\(\)"
     r"|0x1ff|\b(directory_entries|identity_pdpt|direct_pdpt|base|root_entries|pdpt|directory)\.add\("
     r"|as \*mut u64\)\.add\(|tables\[\d\]\.add\(|\(\*directory\)\.0"),
    ("dma", None, None, r"dma_page_has_completed_transaction|native_dma_completion_state"),
    ("mmio-pio", None, None,
     r"apic\.|LocalApic|local_apic|Mmio::new|framebuffer::|::Controller::open|Controller::open|::open\(|::probe\("
     r"|ahci::|Remapping::enable|DeviceTableBuilder|e1000e::|realtek::|hda::|nvme::|xhci::|virtio_gpu::"
     r"|read_volatile|write_volatile|verify_local_apic_interrupt|verify_device_wait_timeout_interrupt|apic_timer"
     r"|VirtioBlockBackend|activate_network_queues|activate_kernel_network_queues|transmit_network_probe"
     r"|receive_network_arp_reply|read_blank_sector_interrupt|network_arp_exchange|attempt_unmapped_network_receive"
     r"|wait_for_one_virtio_interrupt|VirtioNet::new|post_receive"),
    ("mmio-pio", r"kernel/src/framebuffer\.rs|kernel/src/arch/x86_64/apic\.rs", None, None),
    ("frame-view", None, None,
     r"direct_map_address|from_raw_parts(_mut)?\s*\(|write_bytes\s*\(|copy_nonoverlapping|zero_frame|frame_is_zero"
     r"|copy_linux_frame|\[u8; PAGE_SIZE\]|as \*(const|mut) [A-Z][A-Za-z]*Page\b|mapped_frame::<u8>"
     r"|\bpage\.write\(|\b(sources|frames|set)\.add\("
     r"|code_frame|first_stack_frame|user_frame|stack_words|\.as_mut_ptr\(\)\.add|mapped\.add"
     r"|as \*(const|mut) u(8|16|32|64)\)(\.add\([^)]*\))?\.(read|write)"),
    ("firmware", None, None,
     r"boot_info|BootInfo|UefiMemoryDescriptor|reset_system|rsdp|xsdt|rsdt|\bmadt\b|ivrs|mcfg|dmar|acpi"
     r"|kernel_entry|kernel_main|read_descriptor|EfiBootServices|system_table"),
    ("firmware", None, r"^(report_madt|report_ivrs|report_mcfg|read_bytes|summarize_memory|report_memory|report_acpi)$", None),
    ("dma", None, None, r"\.dma\b|dma_virtual|dma_device"),
    ("cpu", None, None,
     r"(?<![A-Za-z0-9_])asm!|read_msr|write_msr|wrmsr|rdmsr|\bcr0\b|\bcr4\b|cpuid|\bcli\b|\bsti\b|\bhlt\b|pushfq|int3|EFER|xgetbv|xsetbv"),
    ("convenience", None, None, r"read_unaligned|assume_init|ManuallyDrop::drop|checksum\s*\("),
]


# Unsafe fns are judged by their name first: a driver's `open` is device
# bring-up even when its body also touches a static buffer.
UNSAFE_FN_RULES = [
    ("firmware", None, r"^kernel_main$"),
    ("entry", None, r"^kernel_entry$"),
    ("frame-view", None, r"^(zero_frame|frame_is_zero)$"),
    ("dma", None, r"^(dma_page_has_completed_transaction|native_dma_completion_state)$"),
    ("dma", r"kernel/src/drivers/amd_iommu\.rs", r"^(new|enable)$"),
    ("mmio-pio", DRIVER_FILES, r"^(open|open_inner|probe|open_controller|prepare|start|new)$"),
    ("mmio-pio", r"kernel/src/linux_socket\.rs", r"^new$"),
    ("dma", r"kernel/src/linux_socket\.rs", r"^(post_receive|write_u(16|32|64)|read_u(16|32))$"),
    ("mmio-pio", r"kernel/src/framebuffer\.rs", None),
    ("paging", r"kernel/src/arch/x86_64/paging\.rs", r"^(map_\w+|ensure_fine_region|zero_entries|install_\w+)$"),
    ("firmware", r"kernel/src/bringup\.rs", r"^(report_\w+|read_bytes)$"),
]


def categorize(path, function, text):
    # Rules see method chains on one line: `entries\n    .add(i)` as `entries.add(i)`.
    text = re.sub(r"\s*\.\s*(?=[A-Za-z_])", ".", text)
    for category, file_rule, function_rule, text_rule in CATEGORY_RULES:
        if file_rule and not re.search(file_rule, path):
            continue
        if function_rule and not re.search(function_rule, function):
            continue
        if text_rule and not re.search(text_rule, text):
            continue
        return category
    return "other"


# A short site is judged by its own text. A long one (a verification routine
# wrapped in one unsafe block, a 900-line unsafe fn) by its operations: each
# is judged by its source lines, and the site takes the most common answer.
LONG_SITE_LINES = 15
for record in records:
    src = source(record["file"])
    if record["kind"] == "unsafe fn":
        named = [category for category, file_rule, function_rule in UNSAFE_FN_RULES
                 if (not file_rule or re.search(file_rule, record["file"]))
                 and (not function_rule or re.search(function_rule, record["fn"]))]
        if named:
            record["category"] = named[0]
            continue
    if record["end"] - record["line"] < LONG_SITE_LINES or len(record["ops"]) < 3:
        record["category"] = categorize(record["file"], record["fn"], record["text"])
        continue
    votes = collections.Counter()
    for op in record["ops"]:
        # The operation's line and the two before it, which hold the start
        # of a method chain split over lines.
        first = max(op["line"] - 2, record["line"])
        line_text = src.readable[src.offset(first):src.offset(min(op["line"] + 1, len(src.line_starts)))]
        votes[categorize(record["file"], record["fn"], line_text)] += 1
    ranked = [category for category, _ in votes.most_common() if category != "other"]
    record["category"] = ranked[0] if ranked else "other"

# Safe functions whose unsafe blocks dereference one of their own integer or
# raw-pointer parameters: their signature promises safety for every argument,
# which only holds if every caller passes a valid address.
unsound = []
seen_functions = set()
for record in sorted(records, key=lambda r: (r["file"], r["line"])):
    if record["kind"] != "block":
        continue
    src = source(record["file"])
    function = src.enclosing(src.offset(record["line"]))
    if function is None or function[4] or (record["file"], function[1]) in seen_functions:
        continue
    params = re.findall(r"\b([a-z_][a-z0-9_]*)\s*:\s*(usize|u64|u32|\*const|\*mut)\b", function[5])
    for param, kind in params:
        if kind.startswith("*"):
            pattern = r"\b%s\b\s*\.\s*(read|write|add|offset|cast|as_ref|as_mut)|\*\s*%s\b|from_raw_parts(_mut)?\(\s*%s\b" % (param, param, param)
        else:
            pattern = r"\(?\s*\(?\s*\b%s\b(\s*\+[^)]*)?\)?\s*as\s+\*(const|mut)" % param
        if re.search(pattern, record["code"]):
            visibility = "pub(crate)" if re.search(r"pub(\([^)]*\))?\s+(const\s+)?fn\s+%s\b" % re.escape(function[0]),
                                                     src.code[src.code.rfind("\n", 0, function[1]) + 1:function[2]]) else "private"
            unsound.append({"file": record["file"], "line": record["line"], "fn": function[0],
                            "param": param, "type": kind, "visibility": visibility,
                            "category": record["category"]})
            seen_functions.add((record["file"], function[1]))
            break

# --------------------------------------------------------------------------
# Output.

KINDS = ["block", "unsafe fn", "unsafe impl", "global_asm!", "unsafe extern", "unsafe attribute"]


def first_line(text):
    return " ".join(text.split())[:120]


if mode == "--sites":
    print("file\tline\tend\tkind\tcategory\tfn\tin_unsafe_fn\tverification\tdocumented\tops\texpansions\ttext")
    for r in sorted(records, key=lambda r: (r["file"], r["line"])):
        print("\t".join(str(x) for x in (r["file"], r["line"], r["end"], r["kind"], r["category"], r["fn"],
                                         r["in_unsafe_fn"], r["verification"], r["documented"],
                                         len(r["ops"]), r["expansions"], first_line(r["text"]))))
    sys.exit(0)

if mode == "--ops":
    print("file\tline\tsite_line\tsite_kind\tcategory\tkind\tfamily\tcallee\tsource")
    for r in sorted(records, key=lambda r: (r["file"], r["line"])):
        for op in r["ops"]:
            print("\t".join(str(x) for x in (r["file"], op["line"], r["line"], r["kind"], r["category"],
                                             op["kind"], op_family(op), op["callee"], op["source"])))
    sys.exit(0)

if mode == "--unsound":
    print("file\tline\tfn\tvisibility\tparameter\ttype\tcategory")
    for u in sorted(unsound, key=lambda u: (u["file"], u["line"])):
        print("\t".join(str(u[k]) for k in ("file", "line", "fn", "visibility", "param", "type", "category")))
    sys.exit(0)

# --summary
def table(header, rows):
    numeric = [all(re.fullmatch(r"[0-9.]*|[0-9]+ of [0-9]+", str(row[i])) for row in rows)
               for i in range(len(header))]
    print("| " + " | ".join(header) + " |")
    print("|" + "|".join("---:" if numeric[i] else "---" for i in range(len(header))) + "|")
    for row in rows:
        print("| " + " | ".join(str(cell) for cell in row) + " |")
    print()


kind_counts = collections.Counter(r["kind"] for r in records)
op_total = sum(len(r["ops"]) for r in records)
fn_body_ops = sum(1 for r in records if r["kind"] == "unsafe fn" for op in r["ops"])
blocks = [r for r in records if r["kind"] == "block"]
impls = [r for r in records if r["kind"] == "unsafe impl"]
undocumented_blocks = sum(1 for r in blocks if not r["documented"])
undocumented_impls = sum(1 for r in impls if not r["documented"])
expanded = [r for r in records if r["expansions"] > 1]
static_total = sum(len(v) for v in static_muts.values())
lines_total = sum(source(f).line_count for f in all_files)

print("## Headline\n")
table(["measure", "count"], [
    ["Rust lines in scope (kernel/src, boot/efi/src)", lines_total],
    ["unsafe sites (unique source locations)", len(records)],
] + [["  " + kind, kind_counts[kind]] for kind in KINDS if kind_counts[kind]] + [
    ["unsafe operations inside them", op_total],
    ["  of which in unsafe fn bodies outside any unsafe block", fn_body_ops],
    ["unsafe blocks without a SAFETY comment", "%d of %d" % (undocumented_blocks, len(blocks))],
    ["unsafe impls without a SAFETY comment", "%d of %d" % (undocumented_impls, len(impls))],
    ["static mut declarations", static_total],
    ["asm! invocations", sum(asm_calls.values())],
    ["global_asm! source lines (incl. include_str! files)", sum(global_asm_lines.values())],
    ["sites in functions named verify*", sum(1 for r in records if r["verification"])],
    ["safe fns dereferencing an int/raw-pointer parameter", len(unsound)],
    ["safe fns returning &'static mut", len(static_mut_returners)],
])
for r in expanded:
    print("Note: %s:%d is inside a macro and expands %d times; it counts once above.\n"
          % (r["file"], r["line"], r["expansions"]))

print("## Per file\n")
per_file = collections.defaultdict(list)
for r in records:
    per_file[r["file"]].append(r)
rows = []
for path in sorted(per_file, key=lambda p: (-len(per_file[p]), p)):
    rs = per_file[path]
    k = collections.Counter(r["kind"] for r in rs)
    lines = source(path).line_count
    rows.append([path.replace("kernel/src/", "k/").replace("boot/efi/src/", "boot/"), lines,
                 len(rs), k["block"], k["unsafe fn"], k["unsafe impl"],
                 k["global_asm!"] + k["unsafe extern"] + k["unsafe attribute"],
                 sum(len(r["ops"]) for r in rs), sum(1 for r in rs if not r["documented"]),
                 len(static_muts.get(path, [])), asm_calls[path],
                 "%.1f" % (1000.0 * len(rs) / max(lines, 1))])
table(["file", "lines", "sites", "blocks", "unsafe fn", "unsafe impl", "asm/extern/attr",
       "ops", "no SAFETY", "static mut", "asm!", "sites/kLOC"], rows)

print("## Per category\n")
rows = []
for category, description in CATEGORIES:
    rs = [r for r in records if r["category"] == category]
    if not rs:
        continue
    k = collections.Counter(r["kind"] for r in rs)
    files = collections.Counter(r["file"] for r in rs).most_common(3)
    rows.append([category, description, len(rs), k["block"], k["unsafe fn"], k["unsafe impl"],
                 k["global_asm!"], sum(len(r["ops"]) for r in rs),
                 ", ".join("%s (%d)" % (f.split("/")[-1], n) for f, n in files)])
table(["category", "what", "sites", "blocks", "unsafe fn", "unsafe impl", "global_asm!", "ops", "main files"], rows)

print("## File x category (sites)\n")
used = [c for c, _ in CATEGORIES if any(r["category"] == c for r in records)]
rows = []
for path in sorted(per_file, key=lambda p: (-len(per_file[p]), p)):
    counts = collections.Counter(r["category"] for r in per_file[path])
    rows.append([path.split("/")[-1] if path.count("/") < 4 else "/".join(path.split("/")[-2:])]
                + [counts[c] or "" for c in used])
table(["file"] + used, rows)

print("## Operations by family\n")
families = collections.Counter()
callees = collections.Counter()
for r in records:
    for op in r["ops"]:
        families[op_family(op)] += 1
        if op_family(op) == "call of a kernel unsafe fn":
            callees[op["callee"]] += 1
table(["family", "ops"], families.most_common())
print("Most-called kernel unsafe fns: " + ", ".join("`%s` (%d)" % c for c in callees.most_common(15)) + "\n")

print("## Modules with no unsafe site\n")
clean = [f for f in all_files if f not in per_file]
table(["file", "lines"], [[f, source(f).line_count] for f in clean])

print("## Safe fns returning &'static mut\n")
table(["file", "fns"], collections.Counter(p for p, _, _ in static_mut_returners).most_common())

print("## Safe fns that dereference an integer or raw-pointer parameter\n")
by_file = collections.defaultdict(list)
for u in unsound:
    by_file[u["file"]].append(u)
table(["file", "fns", "of which pub(crate)", "parameter types", "categories"],
      [[f, len(us), sum(1 for u in us if u["visibility"] != "private"),
        ", ".join("`%s`" % t for t in sorted({u["type"] for u in us})), ", ".join(sorted({u["category"] for u in us}))]
       for f, us in sorted(by_file.items(), key=lambda item: -len(item[1]))])
PY
