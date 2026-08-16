#!/usr/bin/env python3
"""Adapt an ARM64 kernel module to an evidenced Android kernel ABI."""

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path


TOOL_VERSION = "1.1.0"
ELF_HEADER_SIZE = 64
ELF_SECTION_HEADER_SIZE = 64
ELF_SYMBOL_SIZE = 24
ELF_RELA_SIZE = 24
EM_AARCH64 = 183
ET_REL = 1
SHT_PROGBITS = 1
SHT_RELA = 4
SHT_NOTE = 7
SHF_ALLOC = 1 << 1
SHN_UNDEF = 0
STB_GLOBAL = 1
STB_WEAK = 2
R_AARCH64_ABS64 = 257
NT_GNU_PROPERTY_TYPE_0 = 5
GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xC0000000
GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1 << 0
GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 1 << 1
VERSION_RECORD_SIZE = 64
VERSION_NAME_SIZE = 56
CRC_SIZE = 4
PREL32_KSYM_SIZE = 12
THIS_MODULE_SECTION = ".gnu.linkonce.this_module"
THIS_MODULE_RELA_SECTION = ".rela.gnu.linkonce.this_module"
CFI_STUB_SECTION = ".text.ls_cfi_stub"
CFI_STUB_CODE = bytes.fromhex("5f2403d5c0035fd6")  # bti c; ret
MODULE_SIGNATURE_MAGIC = b"~Module signature appended~\n"
DEFAULT_ALIASES = {
    "__memcpy": "memcpy",
    "__memmove": "memmove",
    "__memset": "memset",
}
GPL_COMPATIBLE_LICENSES = {
    "GPL",
    "GPL v2",
    "GPL and additional rights",
    "Dual BSD/GPL",
    "Dual MIT/GPL",
    "Dual MPL/GPL",
}
CRITICAL_CONFIG_KEYS = (
    "CONFIG_SMP",
    "CONFIG_PREEMPT",
    "CONFIG_MODULE_UNLOAD",
    "CONFIG_MODVERSIONS",
    "CONFIG_MODULE_REL_CRCS",
    "CONFIG_EXTENDED_MODVERSIONS",
    "CONFIG_MODULE_SIG_FORCE",
    "CONFIG_CFI_CLANG",
    "CONFIG_ARM64_BTI_KERNEL",
    "CONFIG_SHADOW_CALL_STACK",
    "CONFIG_LTO_CLANG",
)
CONFIG_EVIDENCE_MARKERS = (
    "CONFIG_ARM64",
    "CONFIG_MODULES",
    "CONFIG_MODULE_SIG",
    "CONFIG_SMP",
    "CONFIG_PREEMPT",
    "CONFIG_MODULE_UNLOAD",
    "CONFIG_MODVERSIONS",
    "CONFIG_ARM64_BTI_KERNEL",
)
INTERNAL_KABI_SPEC = {
    "delayed_work": ("work", "timer", "wq", "cpu"),
    "device": (),
    "dentry": ("d_name",),
    "dir_context": ("pos",),
    "fault_info": ("fn", "sig", "code", "name"),
    "file": ("f_path",),
    "file_operations": ("owner", "unlocked_ioctl", "mmap", "open", "release"),
    "filename": ("name",),
    "hrtimer": ("function",),
    "input_absinfo": ("minimum", "maximum"),
    "input_dev": (
        "name",
        "evbit",
        "keybit",
        "absbit",
        "mt",
        "absinfo",
        "key",
        "grab",
        "event_lock",
        "mutex",
        "h_list",
        "node",
        "num_vals",
        "max_vals",
        "vals",
        "timestamp",
    ),
    "input_device_id": ("driver_info",),
    "input_handle": ("open", "name", "dev", "handler", "d_node", "h_node"),
    "input_handler": (
        "event",
        "events",
        "filter",
        "match",
        "connect",
        "disconnect",
        "start",
        "name",
        "id_table",
        "h_list",
        "node",
    ),
    "input_mt": ("trkid", "num_slots", "slot", "flags", "frame", "red", "slots"),
    "input_mt_slot": ("abs",),
    "input_value": ("type", "code", "value"),
    "kernel_param": ("name", "mod", "ops", "perm", "level", "flags", "arg"),
    "kprobe": ("addr", "symbol_name", "pre_handler"),
    "kobject": ("name", "parent"),
    "ls_vtime_hook_entry": ("esr_mask", "esr_val", "handler"),
    "miscdevice": ("minor", "name", "fops", "mode"),
    "mm_struct": (
        "mmap",
        "pgd",
        "page_table_lock",
        "mmap_lock",
        "arg_start",
        "arg_end",
    ),
    "module_kobject": ("kobj",),
    "mutex": ("owner", "wait_lock", "wait_list"),
    "page": ("flags", "ptl"),
    "path": ("dentry",),
    "pid": ("level", "numbers"),
    "pt_regs": ("regs", "sp", "pc", "pstate"),
    "qstr": ("name",),
    "raw_spinlock": (),
    "rw_semaphore": ("count", "owner", "wait_lock", "wait_list"),
    "signal_struct": ("pids",),
    "spinlock": (),
    "task_struct": ("usage", "mm", "signal", "thread"),
    "thread_struct": ("uw", "uw.fpsimd_state"),
    "timer_list": ("entry", "expires", "function", "flags"),
    "upid": ("nr",),
    "user_fpsimd_state": ("vregs",),
    "vm_area_struct": (
        "vm_start",
        "vm_end",
        "vm_next",
        "vm_page_prot",
        "vm_flags",
        "vm_pgoff",
        "vm_file",
    ),
    "work_struct": ("data", "entry", "func"),
}
KABI_RUNTIME_MARKERS = (
    "INSMOD_EXIT=0",
    "HIDE_PROC_MODULES=PASS",
    "HIDE_SYSFS=PASS",
    "SUMMARY pass=13 fail=0",
    "SMOKE_TEST_EXIT=0",
    "SHOW_PROC_MODULES=PASS",
    "SHOW_SYSFS=PASS",
    "RMMOD_EXIT=0",
    "RMMOD_CLEAN=PASS",
    "GUEST_ALIVE_AFTER_MODULE_TEST",
)
KABI_FUNCTION_PASS_RE = re.compile(
    r"^PASS ([A-Za-z0-9_]+)(?:\s|$)", re.MULTILINE
)
KABI_FAILURE_RE = re.compile(r"(?:^|[^A-Za-z0-9])FAIL(?:=|\s|$)")
KABI_REQUIRED_FUNCTION_PASSES = (
    "control_open",
    "touch_caps",
    "shared_mmap",
    "touch_event_open",
    "touch_down",
    "touch_move",
    "touch_up",
    "touch_event_stream",
    "read_own_memory",
    "write_own_memory",
    "invalid_touch_rejected",
    "clear_runtime",
    "show_module",
)
KABI_TIMESTAMPED_HAZARD_RE = re.compile(
    r"^\[\s*\d+\.\d+\](?:\[.*?\])?\s*"
    r"(?:WARNING: CPU:|BUG:|Oops:|Internal error:\s*Oops:|Kernel panic|"
    r"Call trace:|Unable to handle kernel|"
    r"-+\[ cut here \]-+)",
    re.MULTILINE,
)
KABI_PRIVATE_TARGET_TABLES = (
    "debug_fault_info",
    "sys64_hooks",
    "cp15_64_hooks",
    "cp15_32_hooks",
)
KALLSYMS_UNIQUE_NAMES = {
    "_text",
    "_stext",
    "__start___ksymtab",
    "__stop___ksymtab",
    "__start___kcrctab",
    "__stop___kcrctab",
    "__start___ksymtab_gpl",
    "__stop___ksymtab_gpl",
    "__start___kcrctab_gpl",
    "__stop___kcrctab_gpl",
}


class AdapterError(RuntimeError):
    def __init__(self, code, message, details=None):
        super().__init__(message)
        self.code = code
        self.details = details


def fail(code, message, details=None):
    raise AdapterError(code, message, details)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_power_of_two(value):
    return value > 0 and value & (value - 1) == 0


def align_up(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def checked_range(data, offset, size, label):
    if offset < 0 or size < 0 or offset + size > len(data):
        fail("invalid_elf", f"{label} is outside the file")
    return data[offset:offset + size]


def decode_ascii(data, label):
    try:
        return data.decode("ascii")
    except UnicodeDecodeError as error:
        fail("invalid_elf", f"{label} is not ASCII: {error}")


@dataclass(frozen=True)
class Section:
    index: int
    name: str
    header_offset: int
    section_type: int
    flags: int
    address: int
    offset: int
    size: int
    link: int
    info: int
    alignment: int
    entry_size: int


@dataclass(frozen=True)
class Symbol:
    index: int
    name: str
    binding: int
    symbol_type: int
    section_index: int
    value: int
    size: int
    file_offset: int


@dataclass(frozen=True)
class Relocation:
    index: int
    offset: int
    relocation_type: int
    symbol_index: int
    symbol_name: str
    addend: int
    file_offset: int


@dataclass(frozen=True)
class RelocationShape:
    offset: int
    relocation_type: int
    addend: int


@dataclass(frozen=True)
class ModuleLayout:
    size: int
    alignment: int
    flags: int
    name_offset: int
    module_name: str
    relocations: dict


@dataclass(frozen=True)
class ArchitectureProperty:
    raw: bytes
    feature_bits: int


@dataclass(frozen=True)
class KernelExports:
    crcs: dict
    gpl_only: frozenset
    namespaces: dict
    normal_count: int
    gpl_count: int
    source: str
    crc_encoding: str
    direct_matches: int
    relative_matches: int
    reference_matches: int


@dataclass
class Analysis:
    source: object
    references: list
    source_layout: ModuleLayout
    target_layout: ModuleLayout
    reference_versions: dict
    target_release: str
    target_vermagic: str
    reference_vermagic_flags: tuple
    kernel_exports: KernelExports
    aliases: dict
    source_imports: set
    final_imports: set
    required_versions: set
    source_namespaces: set
    required_namespaces: set
    architecture_property_sha256: str
    architecture_feature_bits: int
    source_architecture_feature_bits: int
    required_architecture_feature_bits: int
    internal_kabi_verified: bool
    internal_kabi_structures: int
    internal_kabi_members: int
    internal_kabi_spec_sha256: str
    internal_kabi_assurance: str
    internal_kabi_private_tables_verified: bool
    input_records: dict
    cfi_required: bool
    kcfi_required: bool
    source_has_kcfi: bool
    cfi_stub_added: bool
    cfi_mode: str
    config: dict
    warnings: list


class ElfModule:
    def __init__(self, path):
        self.path = Path(path)
        try:
            self.data = self.path.read_bytes()
        except OSError as error:
            fail("input_error", f"cannot read {self.path}: {error}")
        self.sections = []
        self._sections_by_name = {}
        self._symbols = None
        self._parse()

    def _parse(self):
        data = self.data
        if len(data) < ELF_HEADER_SIZE or data[:4] != b"\x7fELF":
            fail("invalid_elf", f"not an ELF file: {self.path}")
        if data[4] != 2 or data[5] != 1 or data[6] != 1:
            fail(
                "unsupported_elf",
                f"expected ELF64 little-endian v1: {self.path}",
            )
        fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
        (
            elf_type,
            machine,
            version,
            _entry,
            _program_offset,
            section_offset,
            _flags,
            header_size,
            _program_entry_size,
            _program_count,
            section_entry_size,
            section_count,
            section_names_index,
        ) = fields
        if elf_type != ET_REL or machine != EM_AARCH64 or version != 1:
            fail(
                "unsupported_elf",
                f"expected AArch64 ET_REL module: {self.path}",
            )
        if header_size != ELF_HEADER_SIZE:
            fail("invalid_elf", f"unexpected ELF header size in {self.path}")
        if section_entry_size != ELF_SECTION_HEADER_SIZE or section_count == 0:
            fail("unsupported_elf", f"unsupported section table in {self.path}")
        if section_names_index >= section_count:
            fail("invalid_elf", f"invalid section-name table in {self.path}")

        raw_headers = []
        for index in range(section_count):
            header_offset = section_offset + index * section_entry_size
            checked_range(data, header_offset, section_entry_size, "section header")
            raw_headers.append(
                struct.unpack_from("<IIQQQQIIQQ", data, header_offset)
            )
        names_header = raw_headers[section_names_index]
        names = checked_range(
            data, names_header[4], names_header[5], "section-name table"
        )
        for index, header in enumerate(raw_headers):
            name_offset = header[0]
            if name_offset >= len(names):
                fail("invalid_elf", f"invalid section name in {self.path}")
            end = names.find(b"\0", name_offset)
            if end < 0:
                fail("invalid_elf", f"unterminated section name in {self.path}")
            name = decode_ascii(names[name_offset:end], "section name")
            section = Section(
                index=index,
                name=name,
                header_offset=section_offset + index * section_entry_size,
                section_type=header[1],
                flags=header[2],
                address=header[3],
                offset=header[4],
                size=header[5],
                link=header[6],
                info=header[7],
                alignment=header[8],
                entry_size=header[9],
            )
            if section.section_type != 8:  # SHT_NOBITS has no file payload.
                checked_range(data, section.offset, section.size, section.name)
            self.sections.append(section)
            self._sections_by_name.setdefault(name, []).append(section)

    def section(self, name, required=True):
        matches = self._sections_by_name.get(name, [])
        if len(matches) > 1:
            fail("invalid_elf", f"duplicate section {name!r} in {self.path}")
        if not matches:
            if required:
                fail("missing_section", f"missing section {name!r} in {self.path}")
            return None
        return matches[0]

    def section_data(self, name):
        section = self.section(name)
        return self.data[section.offset:section.offset + section.size]

    def symbols(self):
        if self._symbols is not None:
            return self._symbols
        symtab = self.section(".symtab")
        if symtab.entry_size not in (0, ELF_SYMBOL_SIZE):
            fail("unsupported_elf", f"unsupported symbol size in {self.path}")
        if symtab.size % ELF_SYMBOL_SIZE or symtab.link >= len(self.sections):
            fail("invalid_elf", f"invalid symbol table in {self.path}")
        strings_section = self.sections[symtab.link]
        strings = self.data[
            strings_section.offset:strings_section.offset + strings_section.size
        ]
        symbols = []
        for index, offset in enumerate(
            range(symtab.offset, symtab.offset + symtab.size, ELF_SYMBOL_SIZE)
        ):
            name_offset, info, _other, section_index, value, size = (
                struct.unpack_from("<IBBHQQ", self.data, offset)
            )
            if name_offset >= len(strings):
                fail("invalid_elf", f"invalid symbol name in {self.path}")
            end = strings.find(b"\0", name_offset)
            if end < 0:
                fail("invalid_elf", f"unterminated symbol name in {self.path}")
            name = decode_ascii(strings[name_offset:end], "symbol name")
            symbols.append(
                Symbol(
                    index=index,
                    name=name,
                    binding=info >> 4,
                    symbol_type=info & 0xF,
                    section_index=section_index,
                    value=value,
                    size=size,
                    file_offset=offset,
                )
            )
        self._symbols = symbols
        return symbols

    def undefined_symbols(self):
        return {
            symbol.name
            for symbol in self.symbols()
            if symbol.section_index == SHN_UNDEF
            and symbol.name
            and symbol.binding in (STB_GLOBAL, STB_WEAK)
        }

    def defined_symbols(self):
        return {
            symbol.name
            for symbol in self.symbols()
            if symbol.section_index != SHN_UNDEF
            and symbol.name
            and symbol.binding in (STB_GLOBAL, STB_WEAK)
        }

    def relocations(self, name):
        section = self.section(name)
        if section.section_type != SHT_RELA:
            fail("invalid_elf", f"{name} is not RELA in {self.path}")
        if section.entry_size not in (0, ELF_RELA_SIZE):
            fail("unsupported_elf", f"unsupported RELA size in {self.path}")
        if section.size % ELF_RELA_SIZE or section.link >= len(self.sections):
            fail("invalid_elf", f"invalid RELA section in {self.path}")
        symbols = self.symbols()
        relocations = []
        for index, offset in enumerate(
            range(section.offset, section.offset + section.size, ELF_RELA_SIZE)
        ):
            relocation_offset, info, addend = struct.unpack_from(
                "<QQq", self.data, offset
            )
            symbol_index = info >> 32
            if symbol_index >= len(symbols):
                fail("invalid_elf", f"invalid relocation symbol in {self.path}")
            relocations.append(
                Relocation(
                    index=index,
                    offset=relocation_offset,
                    relocation_type=info & 0xFFFFFFFF,
                    symbol_index=symbol_index,
                    symbol_name=symbols[symbol_index].name,
                    addend=addend,
                    file_offset=offset,
                )
            )
        return relocations

    def modinfo_entries(self):
        data = self.section_data(".modinfo")
        return [entry for entry in data.split(b"\0") if entry]

    def modinfo_values(self, key):
        prefix = key.encode("ascii") + b"="
        return [
            decode_ascii(entry[len(prefix):], f"{key} modinfo")
            for entry in self.modinfo_entries()
            if entry.startswith(prefix)
        ]

    def modinfo_value(self, key):
        matches = self.modinfo_values(key)
        if len(matches) != 1:
            fail(
                "invalid_modinfo",
                f"expected one {key}= entry in {self.path}, found {len(matches)}",
            )
        return matches[0]

    def vermagic(self):
        return "vermagic=" + self.modinfo_value("vermagic")

    def module_name(self):
        return self.modinfo_value("name")

    def license(self):
        return self.modinfo_value("license")

    def imported_namespaces(self):
        return set(self.modinfo_values("import_ns"))

    def version_records(self):
        if self.section("__version_ext_names", required=False) or self.section(
            "__version_ext_crcs", required=False
        ):
            fail(
                "unsupported_modversions",
                f"extended modversions are not supported: {self.path}",
            )
        data = self.section_data("__versions")
        if len(data) == 0 or len(data) % VERSION_RECORD_SIZE:
            fail("unsupported_modversions", f"invalid __versions in {self.path}")
        records = {}
        for offset in range(0, len(data), VERSION_RECORD_SIZE):
            crc = struct.unpack_from("<Q", data, offset)[0]
            raw_name = data[offset + 8:offset + VERSION_RECORD_SIZE]
            name = decode_ascii(raw_name.split(b"\0", 1)[0], "version symbol")
            if not name or name in records:
                fail("invalid_elf", f"invalid version symbol in {self.path}")
            records[name] = crc
        return records

    def has_module_signature(self):
        return self.data.endswith(MODULE_SIGNATURE_MAGIC)

    def has_kcfi(self):
        if any("kcfi" in section.name.lower() for section in self.sections):
            return True
        return any(
            symbol.name.startswith("__kcfi_typeid_") for symbol in self.symbols()
        )


def parse_vermagic(vermagic):
    if not vermagic.startswith("vermagic="):
        fail("invalid_modinfo", f"invalid vermagic: {vermagic!r}")
    value = vermagic[len("vermagic="):]
    fields = value.split(" ")
    if not fields or any(not field for field in fields):
        fail("invalid_modinfo", "vermagic must use single ASCII spaces")
    if any(any(character.isspace() for character in field) for field in fields):
        fail("invalid_modinfo", "vermagic contains non-space whitespace")
    validate_release(fields[0])
    return fields[0], tuple(fields[1:])


def validate_release(release):
    try:
        encoded = release.encode("ascii")
    except UnicodeEncodeError:
        fail("invalid_release", f"kernel release is not ASCII: {release!r}")
    if not encoded or not re.fullmatch(rb"[!-~]+", encoded):
        fail("invalid_release", f"kernel release is not one token: {release!r}")


def kernel_series(release):
    validate_release(release)
    match = re.match(r"^(\d+)\.(\d+)(?:\.|-)", release)
    if not match:
        fail("invalid_release", f"cannot parse kernel release {release!r}")
    return int(match.group(1)), int(match.group(2))


def extract_image_release(image_path):
    try:
        data = image_path.read_bytes()
    except OSError as error:
        fail("input_error", f"cannot read kernel Image {image_path}: {error}")
    pattern = re.compile(rb"Linux version ([0-9]+\.[0-9]+\.[^\x00\r\n ]+)")
    releases = {
        decode_ascii(match.group(1), "kernel release")
        for match in pattern.finditer(data)
    }
    if len(releases) != 1:
        fail(
            "target_evidence_missing",
            f"expected one concrete Linux banner in {image_path}, found {sorted(releases)}",
        )
    return next(iter(releases))


def parse_config(path):
    if path is None:
        return {}
    values = {}
    try:
        lines = path.read_text(encoding="ascii", errors="strict").splitlines()
    except (OSError, UnicodeError) as error:
        fail("input_error", f"cannot read config {path}: {error}")
    for line in lines:
        if line.startswith("CONFIG_") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
        else:
            match = re.fullmatch(r"# (CONFIG_[A-Za-z0-9_]+) is not set", line)
            if match:
                values[match.group(1)] = "n"
    return values


def config_enabled(config, key):
    return config.get(key) == "y"


def discover_layout(module):
    section = module.section(THIS_MODULE_SECTION)
    if section.section_type != SHT_PROGBITS or section.flags != 3:
        fail(
            "layout_mismatch",
            f"unsupported {THIS_MODULE_SECTION} flags/type in {module.path}",
        )
    if not is_power_of_two(section.alignment):
        fail("layout_mismatch", f"invalid module alignment in {module.path}")
    name = module.module_name()
    encoded_name = name.encode("ascii")
    if len(encoded_name) >= VERSION_NAME_SIZE:
        fail("layout_mismatch", f"module name is too long in {module.path}")
    payload = module.section_data(THIS_MODULE_SECTION)
    needle = encoded_name + b"\0"
    offsets = []
    cursor = 0
    while True:
        found = payload.find(needle, cursor)
        if found < 0:
            break
        offsets.append(found)
        cursor = found + 1
    if len(offsets) != 1:
        fail(
            "layout_mismatch",
            f"cannot locate unique module name in {THIS_MODULE_SECTION}: {module.path}",
        )
    name_offset = offsets[0]
    for index, value in enumerate(payload):
        if name_offset <= index < name_offset + len(encoded_name):
            continue
        if value:
            fail(
                "layout_mismatch",
                f"nonzero unsupported field at {THIS_MODULE_SECTION}+0x{index:x} in {module.path}",
            )
    rela_section = module.section(THIS_MODULE_RELA_SECTION)
    if rela_section.info != section.index:
        fail(
            "layout_mismatch",
            f"{THIS_MODULE_RELA_SECTION} does not target {THIS_MODULE_SECTION}",
        )
    relocations = {}
    used_offsets = set()
    for relocation in module.relocations(THIS_MODULE_RELA_SECTION):
        if not relocation.symbol_name or relocation.symbol_name in relocations:
            fail("layout_mismatch", f"duplicate module relocation in {module.path}")
        if relocation.relocation_type != R_AARCH64_ABS64 or relocation.addend != 0:
            fail(
                "layout_mismatch",
                f"unsupported module relocation for {relocation.symbol_name} in {module.path}",
            )
        if relocation.offset % 8 or relocation.offset + 8 > section.size:
            fail(
                "layout_mismatch",
                f"invalid module relocation offset 0x{relocation.offset:x} in {module.path}",
            )
        if relocation.offset in used_offsets:
            fail("layout_mismatch", f"overlapping module relocations in {module.path}")
        used_offsets.add(relocation.offset)
        relocations[relocation.symbol_name] = RelocationShape(
            relocation.offset, relocation.relocation_type, relocation.addend
        )
    if not relocations:
        fail("layout_mismatch", f"module has no layout relocations: {module.path}")
    return ModuleLayout(
        size=section.size,
        alignment=section.alignment,
        flags=section.flags,
        name_offset=name_offset,
        module_name=name,
        relocations=relocations,
    )


def architecture_property(module):
    section = module.section(".note.gnu.property", required=False)
    if section is None:
        return None
    if (
        section.section_type != SHT_NOTE
        or not section.flags & SHF_ALLOC
        or section.alignment != 8
        or section.offset % 8
    ):
        fail(
            "invalid_elf",
            f"invalid .note.gnu.property section metadata in {module.path}",
        )

    data = module.section_data(".note.gnu.property")
    cursor = 0
    descriptor = None
    while cursor < len(data):
        if len(data) - cursor < 12:
            fail("invalid_elf", f"truncated GNU property note in {module.path}")
        name_size, descriptor_size, note_type = struct.unpack_from(
            "<III", data, cursor
        )
        name_start = cursor + 12
        name_end = name_start + name_size
        descriptor_start = align_up(name_end, 4)
        descriptor_end = descriptor_start + descriptor_size
        note_end = align_up(descriptor_end, 4)
        if name_size == 0 or note_end > len(data):
            fail("invalid_elf", f"invalid GNU property note bounds in {module.path}")
        name = data[name_start:name_end]
        if any(data[name_end:descriptor_start]) or any(data[descriptor_end:note_end]):
            fail("invalid_elf", f"nonzero GNU property note padding in {module.path}")
        if name != b"GNU\0" or note_type != NT_GNU_PROPERTY_TYPE_0:
            fail("invalid_elf", f"unexpected record in .note.gnu.property: {module.path}")
        if descriptor is not None:
            fail("invalid_elf", f"duplicate GNU property note in {module.path}")
        descriptor = data[descriptor_start:descriptor_end]
        cursor = note_end

    if descriptor is None or not descriptor:
        fail("invalid_elf", f"empty GNU property note in {module.path}")

    feature_bits = None
    cursor = 0
    while cursor < len(descriptor):
        if len(descriptor) - cursor < 8:
            fail("invalid_elf", f"truncated GNU property descriptor in {module.path}")
        property_type, property_size = struct.unpack_from("<II", descriptor, cursor)
        value_start = cursor + 8
        value_end = value_start + property_size
        next_property = align_up(value_end, 8)
        if property_size == 0 or next_property > len(descriptor):
            fail("invalid_elf", f"invalid GNU property bounds in {module.path}")
        if any(descriptor[value_end:next_property]):
            fail("invalid_elf", f"nonzero GNU property padding in {module.path}")
        if property_type != GNU_PROPERTY_AARCH64_FEATURE_1_AND:
            fail(
                "unsupported_architecture_property",
                f"unsupported GNU property 0x{property_type:08x} in {module.path}",
            )
        if feature_bits is not None or property_size != 4:
            fail(
                "invalid_elf",
                f"invalid AArch64 feature property in {module.path}",
            )
        feature_bits = struct.unpack_from("<I", descriptor, value_start)[0]
        unknown_bits = feature_bits & ~(
            GNU_PROPERTY_AARCH64_FEATURE_1_BTI
            | GNU_PROPERTY_AARCH64_FEATURE_1_PAC
        )
        if unknown_bits:
            fail(
                "unsupported_architecture_property",
                f"unsupported AArch64 feature bits 0x{unknown_bits:x} in {module.path}",
            )
        cursor = next_property

    if feature_bits is None:
        fail("invalid_elf", f"AArch64 feature property is missing in {module.path}")
    return ArchitectureProperty(raw=data, feature_bits=feature_bits)


def merge_references(references, config):
    if not references:
        fail("target_evidence_missing", "at least one reference module is required")
    layouts = [discover_layout(reference) for reference in references]
    first = layouts[0]
    target_relocations = {}
    versions = {}
    vermagic_flags = None
    releases = []
    cfi_definitions = []
    kcfi_definitions = []
    for reference, layout in zip(references, layouts):
        if (
            layout.size,
            layout.alignment,
            layout.flags,
            layout.name_offset,
        ) != (first.size, first.alignment, first.flags, first.name_offset):
            fail("layout_mismatch", "reference modules disagree on target layout")
        for name, shape in layout.relocations.items():
            previous = target_relocations.get(name)
            if previous is not None and previous != shape:
                fail(
                    "layout_mismatch",
                    f"reference modules disagree on relocation {name}",
                )
            target_relocations[name] = shape
        for name, crc in reference.version_records().items():
            previous = versions.get(name)
            if previous is not None and previous != crc:
                fail(
                    "crc_conflict",
                    f"reference modules disagree on CRC for {name}",
                )
            versions[name] = crc
        release, flags = parse_vermagic(reference.vermagic())
        releases.append(release)
        if vermagic_flags is None:
            vermagic_flags = flags
        elif vermagic_flags != flags:
            fail("vermagic_conflict", "reference vermagic feature flags disagree")
        reference_has_kcfi = reference.has_kcfi()
        kcfi_definitions.append(reference_has_kcfi)
        cfi_definitions.append(
            "__cfi_check" in reference.defined_symbols() and not reference_has_kcfi
        )
    if "module_layout" not in versions:
        fail("target_evidence_missing", "reference modules lack module_layout CRC")
    config_cfi = config.get("CONFIG_CFI_CLANG")
    if config_cfi == "n" and (any(cfi_definitions) or any(kcfi_definitions)):
        fail("target_evidence_conflict", "config disables CFI but reference defines it")
    if any(cfi_definitions) and any(kcfi_definitions):
        fail("target_evidence_conflict", "reference modules mix legacy CFI and KCFI")
    kcfi_required = any(kcfi_definitions)
    cfi_required = config_cfi == "y" or any(cfi_definitions) or kcfi_required
    return (
        ModuleLayout(
            size=first.size,
            alignment=first.alignment,
            flags=first.flags,
            name_offset=first.name_offset,
            module_name=first.module_name,
            relocations=target_relocations,
        ),
        versions,
        tuple(vermagic_flags or ()),
        tuple(releases),
        cfi_required,
        kcfi_required,
    )


def load_kallsyms(path):
    symbols = {}
    try:
        stream = path.open("r", encoding="ascii", errors="strict")
    except (OSError, UnicodeError) as error:
        fail("input_error", f"cannot read kallsyms {path}: {error}")
    with stream:
        for line_number, line in enumerate(stream, 1):
            fields = line.split()
            if len(fields) < 3:
                continue
            try:
                address = int(fields[0], 16)
            except ValueError:
                fail("invalid_kallsyms", f"invalid address at {path}:{line_number}")
            name = fields[2]
            previous = symbols.get(name)
            if (
                previous is not None
                and previous != address
                and name in KALLSYMS_UNIQUE_NAMES
            ):
                fail("invalid_kallsyms", f"conflicting symbol {name} in {path}")
            symbols[name] = address
    return symbols


def read_image_c_string(image, offset, label="kernel symbol", allow_empty=False):
    if offset < 0 or offset >= len(image):
        fail("invalid_image", f"kernel string offset is outside Image: 0x{offset:x}")
    end = image.find(b"\0", offset)
    if end < 0 or end - offset > 512:
        fail("invalid_image", f"invalid kernel string at Image+0x{offset:x}")
    name = decode_ascii(image[offset:end], label)
    if not name and allow_empty:
        return ""
    if not re.fullmatch(r"[A-Za-z0-9_.$]+", name):
        fail("invalid_image", f"invalid {label} {name!r}")
    return name


def parse_export_range(image, image_base, symbols, table_suffix):
    ksym_start_name = "__start___ksymtab" + table_suffix
    ksym_stop_name = "__stop___ksymtab" + table_suffix
    crc_start_name = "__start___kcrctab" + table_suffix
    crc_stop_name = "__stop___kcrctab" + table_suffix
    required = (ksym_start_name, ksym_stop_name, crc_start_name, crc_stop_name)
    missing = [name for name in required if name not in symbols]
    if missing:
        fail("target_evidence_missing", f"kallsyms lacks {', '.join(missing)}")
    ksym_start, ksym_stop = symbols[ksym_start_name], symbols[ksym_stop_name]
    crc_start, crc_stop = symbols[crc_start_name], symbols[crc_stop_name]
    ksym_bytes = ksym_stop - ksym_start
    crc_bytes = crc_stop - crc_start
    if ksym_bytes <= 0 or crc_bytes <= 0 or crc_bytes % CRC_SIZE:
        fail("invalid_image", f"invalid export table range {table_suffix!r}")
    count = crc_bytes // CRC_SIZE
    if ksym_bytes % count:
        fail("unsupported_exports", "kernel export entry size is not integral")
    entry_size = ksym_bytes // count
    if entry_size != PREL32_KSYM_SIZE:
        fail(
            "unsupported_exports",
            f"unsupported kernel_symbol size {entry_size}; expected PREL32 size 12",
        )
    records = {}
    for index in range(count):
        entry_address = ksym_start + index * entry_size
        entry_offset = entry_address - image_base
        checked_range(image, entry_offset, entry_size, "kernel export entry")
        _value_rel, name_rel, namespace_rel = struct.unpack_from(
            "<iii", image, entry_offset
        )
        name_address = entry_address + 4 + name_rel
        name = read_image_c_string(image, name_address - image_base)
        namespace_address = entry_address + 8 + namespace_rel
        namespace = read_image_c_string(
            image,
            namespace_address - image_base,
            label="kernel namespace",
            allow_empty=True,
        )
        crc_address = crc_start + index * CRC_SIZE
        crc_offset = crc_address - image_base
        checked_range(image, crc_offset, CRC_SIZE, "kernel export CRC")
        raw_crc = struct.unpack_from("<I", image, crc_offset)[0]
        if name in records:
            fail("invalid_image", f"duplicate exported symbol {name}")
        records[name] = (raw_crc, crc_address, namespace)
    return records


def relative_crc(image, image_base, raw_crc, crc_address):
    signed = struct.unpack("<i", struct.pack("<I", raw_crc))[0]
    target_offset = crc_address + signed - image_base
    if target_offset < 0 or target_offset + CRC_SIZE > len(image):
        return None
    return struct.unpack_from("<I", image, target_offset)[0]


def exports_from_image(image_path, kallsyms_path, reference_versions, config):
    try:
        image = image_path.read_bytes()
    except OSError as error:
        fail("input_error", f"cannot read Image {image_path}: {error}")
    symbols = load_kallsyms(kallsyms_path)
    image_base = symbols.get("_text") or symbols.get("_stext")
    if image_base is None:
        fail("target_evidence_missing", "kallsyms lacks _text and _stext")
    normal = parse_export_range(image, image_base, symbols, "")
    gpl = parse_export_range(image, image_base, symbols, "_gpl")
    duplicates = set(normal) & set(gpl)
    if duplicates:
        fail("invalid_image", f"exports appear in normal and GPL tables: {sorted(duplicates)}")
    raw_exports = dict(normal)
    raw_exports.update(gpl)
    missing_reference = sorted(set(reference_versions) - set(raw_exports))
    if missing_reference:
        fail(
            "target_evidence_conflict",
            "reference symbols are absent from the target Image",
            missing_reference,
        )
    direct_matches = 0
    relative_matches = 0
    for name, expected64 in reference_versions.items():
        raw_crc, crc_address, _namespace = raw_exports[name]
        expected = expected64 & 0xFFFFFFFF
        if raw_crc == expected:
            direct_matches += 1
        if relative_crc(image, image_base, raw_crc, crc_address) == expected:
            relative_matches += 1
    reference_count = len(reference_versions)
    direct_complete = direct_matches == reference_count
    relative_complete = relative_matches == reference_count
    if direct_complete == relative_complete:
        fail(
            "crc_ambiguous",
            f"cannot prove CRC encoding: direct={direct_matches}, relative={relative_matches}, references={reference_count}",
        )
    encoding = "direct" if direct_complete else "relative"
    config_rel = config.get("CONFIG_MODULE_REL_CRCS")
    if config_rel in ("y", "n"):
        expected_encoding = "relative" if config_rel == "y" else "direct"
        if encoding != expected_encoding:
            fail(
                "target_evidence_conflict",
                f"config expects {expected_encoding} CRCs but Image proves {encoding}",
            )
    crcs = {}
    namespaces = {}
    for name, (raw_crc, crc_address, namespace) in raw_exports.items():
        crc = (
            relative_crc(image, image_base, raw_crc, crc_address)
            if encoding == "relative"
            else raw_crc
        )
        if crc is None:
            fail("invalid_image", f"relative CRC outside Image for {name}")
        crcs[name] = crc
        namespaces[name] = namespace
    return KernelExports(
        crcs=crcs,
        gpl_only=frozenset(gpl),
        namespaces=namespaces,
        normal_count=len(normal),
        gpl_count=len(gpl),
        source="image+kallsyms",
        crc_encoding=encoding,
        direct_matches=direct_matches,
        relative_matches=relative_matches,
        reference_matches=reference_count,
    )


def exports_from_module_symvers(path, reference_versions):
    crcs = {}
    gpl = set()
    namespaces = {}
    try:
        lines = path.read_text(encoding="ascii", errors="strict").splitlines()
    except (OSError, UnicodeError) as error:
        fail("input_error", f"cannot read Module.symvers {path}: {error}")
    for line_number, line in enumerate(lines, 1):
        fields = line.split()
        if not fields:
            continue
        if len(fields) < 2:
            fail("invalid_symvers", f"invalid line {line_number} in {path}")
        try:
            crc = int(fields[0], 0) & 0xFFFFFFFF
        except ValueError:
            fail("invalid_symvers", f"invalid CRC at {path}:{line_number}")
        name = fields[1]
        namespace = fields[4] if len(fields) >= 5 else ""
        if namespace == "-":
            namespace = ""
        if namespace and not re.fullmatch(r"[A-Za-z0-9_.$]+", namespace):
            fail(
                "invalid_symvers",
                f"invalid namespace at {path}:{line_number}",
            )
        previous = crcs.get(name)
        if previous is not None and previous != crc:
            fail("crc_conflict", f"conflicting Module.symvers CRC for {name}")
        crcs[name] = crc
        previous_namespace = namespaces.get(name)
        if previous_namespace is not None and previous_namespace != namespace:
            fail("invalid_symvers", f"conflicting namespace for {name}")
        namespaces[name] = namespace
        if any(field.startswith("EXPORT_SYMBOL_GPL") for field in fields[2:]):
            gpl.add(name)
    if "module_layout" not in crcs:
        fail("target_evidence_missing", "Module.symvers lacks module_layout")
    missing_reference = sorted(set(reference_versions) - set(crcs))
    if missing_reference:
        fail(
            "target_evidence_conflict",
            "Module.symvers lacks reference symbols",
            missing_reference,
        )
    mismatched_reference = sorted(
        name
        for name, expected in reference_versions.items()
        if crcs[name] != (expected & 0xFFFFFFFF)
    )
    if mismatched_reference:
        fail(
            "target_evidence_conflict",
            "Module.symvers CRCs disagree with reference modules",
            mismatched_reference,
        )
    return KernelExports(
        crcs=crcs,
        gpl_only=frozenset(gpl),
        namespaces=namespaces,
        normal_count=len(crcs) - len(gpl),
        gpl_count=len(gpl),
        source="Module.symvers",
        crc_encoding="module_symvers",
        direct_matches=0,
        relative_matches=0,
        reference_matches=len(reference_versions),
    )


def parse_aliases(values, include_defaults):
    aliases = dict(DEFAULT_ALIASES if include_defaults else {})
    for value in values:
        if "=" not in value:
            fail("invalid_argument", f"alias must be OLD=NEW: {value!r}")
        old, new = value.split("=", 1)
        if not old or not new:
            fail("invalid_argument", f"alias must be OLD=NEW: {value!r}")
        previous = aliases.get(old)
        if previous is not None and previous != new:
            fail("invalid_argument", f"conflicting alias for {old}")
        aliases[old] = new
    return aliases


def argument_input_paths(args):
    paths = [args.source_module, *args.reference_module]
    paths.extend(
        path
        for path in (
            args.image,
            args.kallsyms,
            args.module_symvers,
            args.config,
            args.target_kabi_profile,
            args.target_kabi_carrier_module,
            args.objcopy,
            args.dwarfdump,
        )
        if path is not None
    )
    paths.extend(args.target_kabi_runtime_log or ())
    return {Path(path).resolve() for path in paths}


def verify_config_flags(config, vermagic_flags):
    for key in ("CONFIG_ARM64", "CONFIG_MODULES"):
        if key in config and not config_enabled(config, key):
            fail("target_evidence_conflict", f"{key} must be enabled")
    checks = (
        ("CONFIG_SMP", "SMP"),
        ("CONFIG_MODULE_UNLOAD", "mod_unload"),
        ("CONFIG_MODVERSIONS", "modversions"),
    )
    for config_key, flag in checks:
        if config_key not in config:
            continue
        enabled = config_enabled(config, config_key)
        if enabled != (flag in vermagic_flags):
            fail(
                "target_evidence_conflict",
                f"{config_key} conflicts with vermagic flag {flag}",
            )
    if config.get("CONFIG_PREEMPT") in ("y", "n"):
        if config_enabled(config, "CONFIG_PREEMPT") != ("preempt" in vermagic_flags):
            fail("target_evidence_conflict", "CONFIG_PREEMPT conflicts with vermagic")


def plan_analysis(args):
    input_records = {
        str(path): input_record(path) for path in argument_input_paths(args)
    }
    source = ElfModule(args.source_module)
    references = [ElfModule(path) for path in args.reference_module]
    config = parse_config(args.config)
    source.version_records()
    if source.has_module_signature():
        fail("signed_source", "source module has an appended signature")
    source_has_kcfi = source.has_kcfi()
    if config_enabled(config, "CONFIG_EXTENDED_MODVERSIONS"):
        fail("unsupported_modversions", "CONFIG_EXTENDED_MODVERSIONS is unsupported")
    if config_enabled(config, "CONFIG_MODULE_SIG_FORCE"):
        fail("signature_required", "target kernel enforces module signatures")

    source_property = architecture_property(source)
    reference_properties = [architecture_property(reference) for reference in references]
    evidenced_properties = [value for value in reference_properties if value]
    target_property = evidenced_properties[0] if evidenced_properties else None
    target_feature_bits = 0
    for value in evidenced_properties:
        target_feature_bits |= value.feature_bits
    source_feature_bits = source_property.feature_bits if source_property else 0
    required_feature_bits = target_feature_bits & GNU_PROPERTY_AARCH64_FEATURE_1_BTI
    if config_enabled(config, "CONFIG_ARM64_BTI_KERNEL"):
        required_feature_bits |= GNU_PROPERTY_AARCH64_FEATURE_1_BTI
    if source_feature_bits & required_feature_bits != required_feature_bits:
        fail(
            "architecture_feature_mismatch",
            "source module lacks required GNU AArch64 feature bits "
            f"0x{required_feature_bits & ~source_feature_bits:x}",
        )

    source_layout = discover_layout(source)
    (
        target_layout,
        reference_versions,
        reference_flags,
        reference_releases,
        cfi_required,
        kcfi_required,
    ) = merge_references(references, config)
    for name, source_relocation in source_layout.relocations.items():
        target_relocation = target_layout.relocations.get(name)
        if target_relocation is None:
            fail("layout_mismatch", f"target references do not prove relocation {name}")
        if (
            source_relocation.relocation_type != target_relocation.relocation_type
            or source_relocation.addend != target_relocation.addend
        ):
            fail("layout_mismatch", f"incompatible relocation semantics for {name}")

    image_release = extract_image_release(args.image) if args.image else None
    if args.target_vermagic:
        provided_vermagic = args.target_vermagic
        if not provided_vermagic.startswith("vermagic="):
            provided_vermagic = "vermagic=" + provided_vermagic
        target_release, target_flags = parse_vermagic(provided_vermagic)
        target_vermagic = "vermagic=" + " ".join(
            (target_release,) + target_flags
        )
        if provided_vermagic != target_vermagic:
            fail("invalid_modinfo", "target vermagic is not canonical")
        if target_flags != reference_flags:
            fail("vermagic_conflict", "target vermagic flags differ from references")
    else:
        if args.kernel_release:
            validate_release(args.kernel_release)
        target_release = args.kernel_release or image_release
        if not target_release:
            fail(
                "target_evidence_missing",
                "target release requires an Image, --kernel-release, or --target-vermagic",
            )
        target_flags = reference_flags
        target_vermagic = "vermagic=" + " ".join((target_release,) + target_flags)
    if image_release and image_release != target_release:
        fail(
            "target_evidence_conflict",
            f"Image release {image_release} differs from requested {target_release}",
        )
    source_release, source_flags = parse_vermagic(source.vermagic())
    if source_flags != target_flags:
        fail(
            "vermagic_conflict",
            "source and target vermagic feature flags differ",
        )
    series = kernel_series(target_release)
    mismatched = []
    if kernel_series(source_release) != series:
        mismatched.append(f"source={source_release}")
    for release in reference_releases:
        if kernel_series(release) != series:
            mismatched.append(f"reference={release}")
    warnings = []
    if len(evidenced_properties) != len(reference_properties):
        warnings.append("reference_gnu_architecture_property_incomplete")
    if len({value.feature_bits for value in evidenced_properties}) > 1:
        warnings.append("reference_gnu_architecture_properties_mixed")
    if not config:
        warnings.append(
            "target_config_not_supplied_build_and_signature_flags_unverified"
        )
    if mismatched:
        if not args.allow_kernel_series_mismatch:
            fail(
                "kernel_series_mismatch",
                "kernel major/minor mismatch: " + ", ".join(mismatched),
            )
        warnings.append("kernel_series_mismatch_explicitly_allowed")
    verify_config_flags(config, target_flags)
    if "modversions" not in target_flags:
        fail("unsupported_modversions", "target kernel does not advertise modversions")

    internal_kabi_verified = False
    internal_kabi_structures = 0
    internal_kabi_members = 0
    internal_kabi_spec_sha256 = ""
    internal_kabi_assurance = "none"
    internal_kabi_private_tables_verified = False
    if args.target_kabi_profile:
        dwarfdump = resolve_dwarfdump(args.dwarfdump, args.objcopy)
        internal_layouts, internal_coverage, internal_limitations = verify_internal_kabi(
            source.path,
            args.target_kabi_profile,
            target_release,
            args.image,
            args.config,
            args.target_kabi_carrier_module,
            args.target_kabi_runtime_log,
            dwarfdump,
        )
        internal_kabi_verified = True
        internal_kabi_structures = len(internal_layouts)
        internal_kabi_members = internal_coverage["members"]
        internal_kabi_spec_sha256 = internal_coverage["spec_sha256"]
        internal_kabi_assurance = "target_carrier_with_unsigned_runtime_evidence"
        internal_kabi_private_tables_verified = internal_limitations[
            "private_target_tables_verified"
        ]
    else:
        warnings.append("target_internal_kabi_profile_not_supplied")

    if args.module_symvers:
        exports = exports_from_module_symvers(
            args.module_symvers, reference_versions
        )
    else:
        if not args.image or not args.kallsyms:
            fail(
                "target_evidence_missing",
                "provide --module-symvers or both --image and --kallsyms",
            )
        exports = exports_from_image(
            args.image, args.kallsyms, reference_versions, config
        )
    if exports.crcs.get("module_layout") != (
        reference_versions["module_layout"] & 0xFFFFFFFF
    ):
        fail("target_evidence_conflict", "module_layout CRC disagrees with reference")

    alias_candidates = parse_aliases(args.alias, not args.no_default_aliases)
    source_imports = source.undefined_symbols()
    aliases = {}
    for old in sorted(source_imports):
        if old in exports.crcs:
            continue
        new = alias_candidates.get(old)
        if new is not None:
            if new not in exports.crcs:
                fail("missing_export", f"alias target {new} for {old} is not exported")
            aliases[old] = new
    final_imports = {aliases.get(name, name) for name in source_imports}
    required_versions = set(final_imports)
    required_versions.add("module_layout")
    missing = sorted(required_versions - set(exports.crcs))
    if missing:
        fail("missing_export", "target kernel lacks required exports", missing)
    source_namespaces = source.imported_namespaces()
    required_namespaces = {
        namespace
        for name in final_imports
        for namespace in (exports.namespaces.get(name, ""),)
        if namespace
    }
    missing_namespaces = sorted(required_namespaces - source_namespaces)
    if missing_namespaces:
        fail(
            "missing_namespace_import",
            "source module does not import required symbol namespaces",
            missing_namespaces,
        )
    if source.license() not in GPL_COMPATIBLE_LICENSES:
        gpl_imports = sorted(final_imports & set(exports.gpl_only))
        if gpl_imports:
            fail(
                "gpl_export_mismatch",
                "non-GPL source imports GPL-only symbols",
                gpl_imports,
            )

    source_has_cfi = "__cfi_check" in source.defined_symbols()
    if kcfi_required:
        if not source_has_kcfi:
            fail(
                "kcfi_rebuild_required",
                "target KCFI requires a source module built with target KCFI",
            )
        if args.cfi_mode == "stub":
            fail("cfi_mode_mismatch", "legacy CFI stub mode is invalid for KCFI")
        cfi_stub_added = False
        warnings.append("source_kcfi_metadata_preserved")
    elif source_has_kcfi:
        fail("cfi_mode_mismatch", "source uses KCFI but target evidence does not")
    elif args.cfi_mode == "strict":
        if cfi_required and not source_has_cfi:
            fail("cfi_rebuild_required", "target CFI requires a source-built __cfi_check")
        cfi_stub_added = False
    elif args.cfi_mode == "stub":
        cfi_stub_added = not source_has_cfi
    else:
        cfi_stub_added = cfi_required and not source_has_cfi
    if cfi_stub_added:
        warnings.append("legacy_cfi_stub_added_runtime_validation_required")
    if source_has_cfi:
        warnings.append("existing_source_cfi_entry_preserved")
    warnings.append("normal_insmod_and_runtime_test_required")

    verify_input_records(input_records)
    return Analysis(
        source=source,
        references=references,
        source_layout=source_layout,
        target_layout=target_layout,
        reference_versions=reference_versions,
        target_release=target_release,
        target_vermagic=target_vermagic,
        reference_vermagic_flags=reference_flags,
        kernel_exports=exports,
        aliases=aliases,
        source_imports=source_imports,
        final_imports=final_imports,
        required_versions=required_versions,
        source_namespaces=source_namespaces,
        required_namespaces=required_namespaces,
        architecture_property_sha256=(
            hashlib.sha256(target_property.raw).hexdigest()
            if target_property is not None
            else ""
        ),
        architecture_feature_bits=target_feature_bits,
        source_architecture_feature_bits=source_feature_bits,
        required_architecture_feature_bits=required_feature_bits,
        internal_kabi_verified=internal_kabi_verified,
        internal_kabi_structures=internal_kabi_structures,
        internal_kabi_members=internal_kabi_members,
        internal_kabi_spec_sha256=internal_kabi_spec_sha256,
        internal_kabi_assurance=internal_kabi_assurance,
        internal_kabi_private_tables_verified=internal_kabi_private_tables_verified,
        input_records=input_records,
        cfi_required=cfi_required,
        kcfi_required=kcfi_required,
        source_has_kcfi=source_has_kcfi,
        cfi_stub_added=cfi_stub_added,
        cfi_mode=args.cfi_mode,
        config=config,
        warnings=warnings,
    )


def relocation_manifest(layout):
    return {
        name: {
            "offset": shape.offset,
            "type": shape.relocation_type,
            "addend": shape.addend,
        }
        for name, shape in sorted(layout.relocations.items())
    }


def input_record(path):
    path = Path(path).resolve()
    try:
        size = path.stat().st_size
        digest = sha256_file(path)
    except OSError as error:
        fail("input_error", f"cannot fingerprint {path}: {error}")
    return {"name": path.name, "size": size, "sha256": digest}


def verify_input_records(records):
    changed = []
    for raw_path, expected in records.items():
        path = Path(raw_path)
        try:
            actual = input_record(path)
        except AdapterError:
            changed.append(raw_path)
            continue
        if actual != expected:
            changed.append(raw_path)
    if changed:
        fail("input_changed", "input files changed during adaptation", changed)


def recorded_input(analysis, path):
    return dict(analysis.input_records[str(Path(path).resolve())])


def make_manifest(args, analysis, output_path=None):
    source = analysis.source
    references = sorted(
        (recorded_input(analysis, reference.path) for reference in analysis.references),
        key=lambda item: (item["name"], item["sha256"]),
    )
    evidence = {
        "references": references,
        "image": recorded_input(analysis, args.image) if args.image else None,
        "kallsyms": recorded_input(analysis, args.kallsyms) if args.kallsyms else None,
        "module_symvers": (
            recorded_input(analysis, args.module_symvers)
            if args.module_symvers
            else None
        ),
        "config": recorded_input(analysis, args.config) if args.config else None,
        "target_kabi_profile": (
            recorded_input(analysis, args.target_kabi_profile)
            if args.target_kabi_profile
            else None
        ),
        "target_kabi_carrier_module": (
            recorded_input(analysis, args.target_kabi_carrier_module)
            if args.target_kabi_carrier_module
            else None
        ),
        "target_kabi_runtime_logs": [
            recorded_input(analysis, path)
            for path in (args.target_kabi_runtime_log or ())
        ],
    }
    required = [
        {
            "name": name,
            "crc": f"0x{analysis.kernel_exports.crcs[name]:08x}",
            "gpl_only": name in analysis.kernel_exports.gpl_only,
            "namespace": analysis.kernel_exports.namespaces.get(name, ""),
        }
        for name in sorted(analysis.required_versions)
    ]
    layout_changed = (
        analysis.source_layout.size != analysis.target_layout.size
        or analysis.source_layout.alignment != analysis.target_layout.alignment
        or analysis.source_layout.name_offset != analysis.target_layout.name_offset
        or any(
            analysis.source_layout.relocations[name]
            != analysis.target_layout.relocations[name]
            for name in analysis.source_layout.relocations
        )
    )
    missing_config_markers = sorted(
        set(CONFIG_EVIDENCE_MARKERS) - set(analysis.config)
    )
    if (
        analysis.config.get("CONFIG_MODULE_SIG") == "y"
        and "CONFIG_MODULE_SIG_FORCE" not in analysis.config
    ):
        missing_config_markers.append("CONFIG_MODULE_SIG_FORCE")
    missing_config_markers = sorted(set(missing_config_markers))
    unresolved_checks = []
    if missing_config_markers:
        unresolved_checks.append("target_config_evidence_incomplete")
    if "kernel_series_mismatch_explicitly_allowed" in analysis.warnings:
        unresolved_checks.append("kernel_series_mismatch_overridden")
    reference_releases = {
        parse_vermagic(reference.vermagic())[0]
        for reference in analysis.references
    }
    release_corroborated = analysis.target_release in reference_releases
    if args.image:
        release_source = "kernel_image"
    elif args.target_vermagic:
        release_source = "target_vermagic_argument"
    else:
        release_source = "kernel_release_argument"
    if not args.image and not release_corroborated:
        unresolved_checks.append("target_release_user_asserted")
    if not analysis.internal_kabi_verified:
        unresolved_checks.append("target_internal_kabi_unverified")
    elif not analysis.internal_kabi_private_tables_verified:
        unresolved_checks.append("target_private_table_layout_unverified")
    if analysis.internal_kabi_verified:
        unresolved_checks.append("runtime_evidence_authenticity_unverified")
    manifest = {
        "schema_version": 1,
        "tool": {
            "name": "auto-adapt-android-module",
            "version": TOOL_VERSION,
        },
        "status": (
            "adapted"
            if output_path
            else ("compatible_plan" if not unresolved_checks else "unresolved_plan")
        ),
        "source": {
            **recorded_input(analysis, source.path),
            "module_name": source.module_name(),
            "license": source.license(),
            "vermagic": source.vermagic(),
            "imports": len(analysis.source_imports),
            "imported_namespaces": sorted(analysis.source_namespaces),
            "layout": {
                "size": analysis.source_layout.size,
                "alignment": analysis.source_layout.alignment,
                "name_offset": analysis.source_layout.name_offset,
                "relocations": relocation_manifest(analysis.source_layout),
            },
        },
        "target": {
            "release": analysis.target_release,
            "release_source": release_source,
            "release_corroborated_by_reference": release_corroborated,
            "vermagic": analysis.target_vermagic,
            "evidence": evidence,
            "critical_config": {
                key: analysis.config[key]
                for key in CRITICAL_CONFIG_KEYS
                if key in analysis.config
            },
            "layout": {
                "size": analysis.target_layout.size,
                "alignment": analysis.target_layout.alignment,
                "name_offset": analysis.target_layout.name_offset,
                "relocations": relocation_manifest(analysis.target_layout),
            },
            "exports": {
                "source": analysis.kernel_exports.source,
                "normal": analysis.kernel_exports.normal_count,
                "gpl": analysis.kernel_exports.gpl_count,
                "crc_encoding": analysis.kernel_exports.crc_encoding,
                "reference_matches": analysis.kernel_exports.reference_matches,
                "direct_matches": analysis.kernel_exports.direct_matches,
                "relative_matches": analysis.kernel_exports.relative_matches,
                "module_layout_crc": (
                    f"0x{analysis.kernel_exports.crcs['module_layout']:08x}"
                ),
            },
            "cfi_required": analysis.cfi_required,
            "kcfi_required": analysis.kcfi_required,
            "gnu_architecture_property_sha256": (
                analysis.architecture_property_sha256
            ),
            "gnu_aarch64_feature_bits": {
                "reference_union": analysis.architecture_feature_bits,
                "source": analysis.source_architecture_feature_bits,
                "required": analysis.required_architecture_feature_bits,
                "reference_bti": bool(
                    analysis.architecture_feature_bits
                    & GNU_PROPERTY_AARCH64_FEATURE_1_BTI
                ),
                "reference_pac": bool(
                    analysis.architecture_feature_bits
                    & GNU_PROPERTY_AARCH64_FEATURE_1_PAC
                ),
            },
            "internal_kabi": {
                "verified": analysis.internal_kabi_verified,
                "source_layout_matches_profile": analysis.internal_kabi_verified,
                "target_evidence_bound": analysis.internal_kabi_verified,
                "assurance": analysis.internal_kabi_assurance,
                "structures_checked": analysis.internal_kabi_structures,
                "members_checked": analysis.internal_kabi_members,
                "spec_sha256": analysis.internal_kabi_spec_sha256,
                "private_target_tables": list(KABI_PRIVATE_TARGET_TABLES),
                "private_target_tables_verified": (
                    analysis.internal_kabi_private_tables_verified
                ),
                "runtime_evidence_authenticated": False,
            },
        },
        "adaptation": {
            "layout_changed": layout_changed,
            "aliases": [
                {"from": old, "to": new}
                for old, new in sorted(analysis.aliases.items())
            ],
            "cfi_mode": analysis.cfi_mode,
            "cfi_stub_added": analysis.cfi_stub_added,
            "kcfi_metadata_preserved": analysis.kcfi_required,
            "final_imports": len(analysis.final_imports),
            "version_records": len(analysis.required_versions),
            "required_symbols": required,
            "required_namespaces": sorted(analysis.required_namespaces),
        },
        "compatibility": {
            "offline_abi_checks_passed": not unresolved_checks,
            "config_checks_performed": not missing_config_markers,
            "missing_config_evidence": missing_config_markers,
            "unresolved_checks": unresolved_checks,
            "runtime_tested": False,
            "warnings": sorted(set(analysis.warnings)),
        },
        "output": None,
    }
    if output_path:
        output = ElfModule(output_path)
        manifest["output"] = {
            **input_record(output_path),
            "vermagic": output.vermagic(),
        }
    return manifest


def resolve_objcopy(explicit):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    llvm_bin = os.environ.get("LLVM_BIN")
    if llvm_bin:
        candidates.extend(
            [Path(llvm_bin) / "llvm-objcopy", Path(llvm_bin) / "llvm-objcopy.exe"]
        )
    for name in ("llvm-objcopy", "aarch64-linux-gnu-objcopy", "objcopy"):
        found = shutil.which(name)
        if found:
            candidates.append(Path(found))
    for variable in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        root = os.environ.get(variable)
        if root:
            candidates.extend(Path(root).glob("toolchains/llvm/prebuilt/*/bin/llvm-objcopy*"))
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        ndk_root = Path(local_app_data) / "Android" / "Sdk" / "ndk"
        if ndk_root.is_dir():
            candidates.extend(
                sorted(
                    ndk_root.glob("*/toolchains/llvm/prebuilt/*/bin/llvm-objcopy.exe"),
                    reverse=True,
                )
            )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    fail("tool_missing", "llvm-objcopy was not found; pass --objcopy")


def resolve_dwarfdump(explicit, objcopy=None):
    candidates = []
    if explicit:
        candidates.append(Path(explicit))
    if objcopy:
        objcopy = Path(objcopy)
        candidates.extend(
            [
                objcopy.with_name("llvm-dwarfdump"),
                objcopy.with_name("llvm-dwarfdump.exe"),
            ]
        )
    llvm_bin = os.environ.get("LLVM_BIN")
    if llvm_bin:
        candidates.extend(
            [
                Path(llvm_bin) / "llvm-dwarfdump",
                Path(llvm_bin) / "llvm-dwarfdump.exe",
            ]
        )
    found = shutil.which("llvm-dwarfdump")
    if found:
        candidates.append(Path(found))
    for variable in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT"):
        root = os.environ.get(variable)
        if root:
            candidates.extend(
                Path(root).glob("toolchains/llvm/prebuilt/*/bin/llvm-dwarfdump*")
            )
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        ndk_root = Path(local_app_data) / "Android" / "Sdk" / "ndk"
        if ndk_root.is_dir():
            candidates.extend(
                sorted(
                    ndk_root.glob(
                        "*/toolchains/llvm/prebuilt/*/bin/llvm-dwarfdump.exe"
                    ),
                    reverse=True,
                )
            )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    fail(
        "tool_missing",
        "llvm-dwarfdump was not found; pass --dwarfdump for internal KABI checks",
    )


def dwarf_integer(line, attribute):
    match = re.search(rf"{re.escape(attribute)}\s+\((0x[0-9a-fA-F]+|[0-9]+)\)", line)
    return int(match.group(1), 0) if match else None


def parse_dwarf_structure(output, structure_name, required_members):
    roots = []
    stack = []
    tag_pattern = re.compile(r"^( *)(DW_TAG_[A-Za-z0-9_]+)\s*$")
    name_pattern = re.compile(r'DW_AT_name\s+\("([^"\\]+)"\)')
    type_pattern = re.compile(r'DW_AT_type\s+\("([^"\\]+)"\)')

    for line in output.splitlines():
        tag_match = tag_pattern.match(line)
        if tag_match:
            indent = len(tag_match.group(1))
            node = {
                "tag": tag_match.group(2),
                "indent": indent,
                "attrs": {},
                "children": [],
            }
            while stack and stack[-1]["indent"] >= indent:
                stack.pop()
            if stack:
                stack[-1]["children"].append(node)
            else:
                roots.append(node)
            stack.append(node)
            continue
        if not stack or line.strip() == "NULL":
            continue
        attrs = stack[-1]["attrs"]
        name_match = name_pattern.search(line)
        if name_match:
            attrs["name"] = name_match.group(1)
        type_match = type_pattern.search(line)
        if type_match:
            attrs["type"] = type_match.group(1)
        size = dwarf_integer(line, "DW_AT_byte_size")
        if size is not None:
            attrs["size"] = size
        location = dwarf_integer(line, "DW_AT_data_member_location")
        if location is not None:
            attrs["location"] = location

    aggregate_tags = {"DW_TAG_structure_type", "DW_TAG_union_type"}

    def flatten_members(node, base=0, prefix=""):
        members = {}
        conflicts = set()

        def add(name, location):
            previous = members.get(name)
            if previous is not None and previous != location:
                conflicts.add(name)
            else:
                members[name] = location

        children = node["children"]
        for index, child in enumerate(children):
            if child["tag"] != "DW_TAG_member":
                continue
            attrs = child["attrs"]
            location = attrs.get("location")
            if location is None:
                continue
            name = attrs.get("name")
            if name:
                add(prefix + name, base + location)
            nested = (
                children[index + 1]
                if index + 1 < len(children)
                and children[index + 1]["tag"] in aggregate_tags
                else None
            )
            if nested is not None:
                nested_kind = (
                    "structure"
                    if nested["tag"] == "DW_TAG_structure_type"
                    else "union"
                )
                member_type = attrs.get("type", "")
                inline_type = re.search(
                    rf"::{nested_kind}\s*$", member_type
                )
            else:
                inline_type = None
            if nested is not None and inline_type:
                nested_prefix = prefix + name + "." if name else prefix
                nested_members, nested_conflicts = flatten_members(
                    nested, base + location, nested_prefix
                )
                for nested_name, nested_location in nested_members.items():
                    add(nested_name, nested_location)
                conflicts.update(nested_conflicts)
        return members, conflicts

    candidates = []
    for root in roots:
        attrs = root["attrs"]
        if (
            root["tag"] != "DW_TAG_structure_type"
            or attrs.get("name") != structure_name
            or attrs.get("size") is None
        ):
            continue
        members, conflicts = flatten_members(root)
        if conflicts:
            continue
        candidates.append(
            {
                "name": attrs["name"],
                "size": attrs["size"],
                "members": members,
            }
        )

    complete = []
    for candidate in candidates:
        missing = set(required_members) - set(candidate["members"])
        if not missing:
            complete.append(
                {
                    "size": candidate["size"],
                    "members": {
                        name: candidate["members"][name]
                        for name in required_members
                    },
                }
            )
    unique = {
        (
            value["size"],
            tuple(sorted(value["members"].items())),
        ): value
        for value in complete
    }
    if not unique:
        fail(
            "internal_kabi_missing",
            f"DWARF lacks complete struct {structure_name}",
            {"required_members": list(required_members)},
        )
    if len(unique) != 1:
        fail(
            "internal_kabi_ambiguous",
            f"DWARF contains conflicting struct {structure_name} layouts",
            [
                {"size": size, "members": dict(members)}
                for size, members in sorted(unique)
            ],
        )
    return next(iter(unique.values()))


def extract_internal_kabi(module_path, dwarfdump, specification=None):
    specification = specification or INTERNAL_KABI_SPEC
    layouts = {}
    for structure_name, required_members in sorted(specification.items()):
        command = [
            str(dwarfdump),
            f"--name={structure_name}",
            "--show-children",
            "--recurse-depth=4",
            "--diff",
            str(module_path),
        ]
        try:
            completed = subprocess.run(
                command,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
        except OSError as error:
            fail("dwarfdump_failed", f"cannot execute llvm-dwarfdump: {error}")
        if completed.returncode:
            fail(
                "dwarfdump_failed",
                f"llvm-dwarfdump failed for struct {structure_name}",
                {
                    "command": command,
                    "stdout": completed.stdout,
                    "stderr": completed.stderr,
                    "exit_code": completed.returncode,
                },
            )
        layouts[structure_name] = parse_dwarf_structure(
            completed.stdout, structure_name, required_members
        )
    return layouts


def validate_profile_artifact_record(value, label):
    if not isinstance(value, dict):
        fail("invalid_kabi_profile", f"invalid {label} artifact record")
    name = value.get("name")
    size = value.get("size")
    digest = value.get("sha256")
    if not isinstance(name, str) or not name or "\0" in name:
        fail("invalid_kabi_profile", f"invalid {label} artifact name")
    if type(size) is not int or size <= 0:
        fail("invalid_kabi_profile", f"invalid {label} artifact size")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        fail("invalid_kabi_profile", f"invalid {label} artifact SHA-256")
    return {"name": name, "size": size, "sha256": digest}


def verify_profile_artifact_binding(expected, actual_path, label):
    expected = validate_profile_artifact_record(expected, label)
    actual = input_record(actual_path)
    if (
        expected["size"] != actual["size"]
        or expected["sha256"] != actual["sha256"]
    ):
        fail(
            "internal_kabi_evidence_mismatch",
            f"internal KABI profile {label} differs from adapter input",
            {"expected": expected, "actual": actual},
        )
    return expected


def validate_kabi_runtime_log(log_path, module_record, target_release):
    try:
        data = Path(log_path).read_bytes()
    except OSError as error:
        fail("input_error", f"cannot read KABI runtime log {log_path}: {error}")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = data.decode("utf-16", errors="replace")
    elif data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig", errors="replace")
    else:
        text = data.decode("utf-8", errors="replace")
    begin_marker = "STOCK_DRIVER_TEST_BEGIN"
    end_marker = "STOCK_DRIVER_TEST_END"
    if text.count(begin_marker) != 1 or text.count(end_marker) != 1:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log must contain one complete test section: {log_path}",
        )
    begin = text.find(begin_marker)
    end = text.find(end_marker, begin)
    if end < begin:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log test markers are out of order: {log_path}",
        )
    section = text[begin : end + len(end_marker)]
    required = [
        f"UNAME={target_release}",
        module_record["sha256"],
        *KABI_RUNTIME_MARKERS,
        "STOCK_DRIVER_TEST_END",
    ]
    missing = [value for value in required if value not in section]
    if missing:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log does not prove the target module lifecycle: {log_path}",
            missing,
        )
    failures = [
        line.strip()
        for line in section.splitlines()
        if KABI_FAILURE_RE.search(line)
        or re.search(r"SUMMARY pass=\d+ fail=[1-9]\d*", line)
    ]
    if failures:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log contains failed assertions: {log_path}",
            failures,
        )
    passes = KABI_FUNCTION_PASS_RE.findall(section)
    if tuple(passes) != KABI_REQUIRED_FUNCTION_PASSES:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log functional pass set/order is invalid: {log_path}",
            passes,
        )
    hazards = KABI_TIMESTAMPED_HAZARD_RE.findall(text)
    if hazards:
        fail(
            "kabi_profile_provenance_invalid",
            f"runtime log contains timestamped kernel hazards: {log_path}",
            hazards,
        )
    return input_record(log_path)


def make_kabi_coverage(layouts):
    specification = {
        name: sorted(value["members"])
        for name, value in sorted(layouts.items())
    }
    encoded = json.dumps(
        specification,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return {
        "spec_sha256": hashlib.sha256(encoded).hexdigest(),
        "structures": len(specification),
        "members": sum(len(members) for members in specification.values()),
    }


def dwarfdump_record(dwarfdump):
    try:
        completed = subprocess.run(
            [str(dwarfdump), "--version"],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
    except OSError as error:
        fail("dwarfdump_failed", f"cannot execute llvm-dwarfdump: {error}")
    if completed.returncode:
        fail("dwarfdump_failed", "llvm-dwarfdump --version failed")
    lines = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
    version = next((line for line in lines if "LLVM version" in line), "")
    if not version and lines:
        version = lines[0]
    if not version:
        fail("dwarfdump_failed", "llvm-dwarfdump version output is empty")
    return {**input_record(dwarfdump), "version": version}


def make_internal_kabi_profile(
    module_path,
    target_image,
    target_config,
    target_release,
    dwarfdump,
    runtime_logs,
):
    module_path = Path(module_path).resolve()
    target_image = Path(target_image).resolve()
    target_config = Path(target_config).resolve()
    dwarfdump = Path(dwarfdump).resolve()
    runtime_logs = [Path(path).resolve() for path in (runtime_logs or ())]
    input_paths = [
        module_path,
        target_image,
        target_config,
        dwarfdump,
        *runtime_logs,
    ]
    input_records = {
        str(path): input_record(path)
        for path in input_paths
    }
    validate_release(target_release)
    image_release = extract_image_release(target_image)
    if image_release != target_release:
        fail(
            "target_evidence_conflict",
            f"Image release {image_release} differs from requested {target_release}",
        )
    module = ElfModule(module_path)
    module_release, module_flags = parse_vermagic(module.vermagic())
    if module_release != target_release:
        fail(
            "kabi_profile_provenance_invalid",
            "profile source module vermagic is not the exact target release",
            {"expected": target_release, "actual": module_release},
        )
    config = parse_config(target_config)
    verify_config_flags(config, module_flags)
    module_record = {
        **input_record(module.path),
        "vermagic": module.vermagic(),
    }
    if not runtime_logs:
        fail(
            "kabi_profile_provenance_missing",
            "at least one target runtime log is required for a trusted KABI profile",
        )
    runtime_records = [
        validate_kabi_runtime_log(path, module_record, target_release)
        for path in runtime_logs
    ]
    layouts = extract_internal_kabi(module.path, dwarfdump)
    profile = {
        "schema_version": 2,
        "target": {
            "release": target_release,
            "image": input_record(target_image),
            "config": input_record(target_config),
        },
        "provenance": {
            "kind": "unsigned_phone_qemu_log_evidence",
            "module": module_record,
            "runtime_logs": runtime_records,
            "required_markers": list(KABI_RUNTIME_MARKERS),
            "dwarfdump": dwarfdump_record(dwarfdump),
        },
        "coverage": make_kabi_coverage(layouts),
        "limitations": {
            "private_target_tables": list(KABI_PRIVATE_TARGET_TABLES),
            "private_target_tables_verified": False,
            "reason": "profile contains source mirrors, not target table type evidence",
            "runtime_evidence_authenticated": False,
            "runtime_evidence_reason": "runtime logs are unsigned operator-supplied evidence",
        },
        "structures": layouts,
    }
    verify_input_records(input_records)
    return profile


def load_internal_kabi_profile(
    path, target_release, target_image, target_config
):
    try:
        profile = json.loads(path.read_text(encoding="ascii", errors="strict"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail("invalid_kabi_profile", f"cannot read internal KABI profile: {error}")
    if not isinstance(profile, dict) or profile.get("schema_version") != 2:
        fail("invalid_kabi_profile", "unsupported internal KABI profile schema")
    target = profile.get("target")
    if not isinstance(target, dict):
        fail("invalid_kabi_profile", "internal KABI target evidence is missing")
    if target.get("release") != target_release:
        fail(
            "internal_kabi_evidence_mismatch",
            "internal KABI profile target release differs",
            {
                "expected": target_release,
                "actual": target.get("release"),
            },
        )
    if target_image is None or target_config is None:
        fail(
            "internal_kabi_evidence_missing",
            "a target KABI profile requires the bound Image and config inputs",
        )
    verify_profile_artifact_binding(target.get("image"), target_image, "Image")
    verify_profile_artifact_binding(target.get("config"), target_config, "config")

    provenance = profile.get("provenance")
    if not isinstance(provenance, dict) or provenance.get("kind") != (
        "unsigned_phone_qemu_log_evidence"
    ):
        fail("invalid_kabi_profile", "invalid internal KABI profile provenance")
    module_record = validate_profile_artifact_record(
        provenance.get("module"), "provenance module"
    )
    module_vermagic = provenance["module"].get("vermagic")
    if not isinstance(module_vermagic, str):
        fail("invalid_kabi_profile", "provenance module vermagic is missing")
    module_release, _ = parse_vermagic(module_vermagic)
    if module_release != target_release:
        fail(
            "invalid_kabi_profile",
            "provenance module vermagic differs from the profile target",
        )
    runtime_logs = provenance.get("runtime_logs")
    if not isinstance(runtime_logs, list) or not runtime_logs:
        fail("invalid_kabi_profile", "profile runtime provenance is missing")
    for index, record in enumerate(runtime_logs):
        validate_profile_artifact_record(record, f"runtime log {index}")
    if provenance.get("required_markers") != list(KABI_RUNTIME_MARKERS):
        fail("invalid_kabi_profile", "profile runtime marker set is incomplete")
    dwarfdump = provenance.get("dwarfdump")
    validate_profile_artifact_record(dwarfdump, "profile dwarfdump")
    if not isinstance(dwarfdump.get("version"), str) or not dwarfdump["version"]:
        fail("invalid_kabi_profile", "profile dwarfdump version is missing")
    structures = profile.get("structures")
    if not isinstance(structures, dict):
        fail("invalid_kabi_profile", "internal KABI structures are missing")
    normalized = {}
    for name, value in structures.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            fail("invalid_kabi_profile", "invalid internal KABI structure name")
        if not isinstance(value, dict) or type(value.get("size")) is not int:
            fail("invalid_kabi_profile", f"invalid struct {name} size")
        members = value.get("members")
        if not isinstance(members, dict):
            fail("invalid_kabi_profile", f"invalid struct {name} members")
        normalized_members = {}
        for member_name, location in members.items():
            if not isinstance(member_name, str) or not re.fullmatch(
                r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
                member_name,
            ):
                fail("invalid_kabi_profile", f"invalid struct {name} member name")
            if type(location) is not int or location < 0:
                fail(
                    "invalid_kabi_profile",
                    f"invalid {name}.{member_name} offset",
                )
            if location > value["size"]:
                fail(
                    "invalid_kabi_profile",
                    f"{name}.{member_name} offset exceeds struct size",
                )
            normalized_members[member_name] = location
        if value["size"] <= 0:
            fail("invalid_kabi_profile", f"invalid struct {name} size")
        normalized[name] = {
            "size": value["size"],
            "members": normalized_members,
        }
    for name, required_members in INTERNAL_KABI_SPEC.items():
        if name not in normalized:
            fail("invalid_kabi_profile", f"required struct {name} is missing")
        missing = sorted(set(required_members) - set(normalized[name]["members"]))
        if missing:
            fail(
                "invalid_kabi_profile",
                f"required struct {name} members are missing",
                missing,
            )
    coverage = profile.get("coverage")
    expected_coverage = make_kabi_coverage(normalized)
    if not isinstance(coverage, dict) or coverage != expected_coverage:
        fail(
            "invalid_kabi_profile",
            "internal KABI coverage metadata does not match structures",
            {"expected": expected_coverage, "actual": coverage},
        )
    limitations = profile.get("limitations")
    expected_limitations = {
        "private_target_tables": list(KABI_PRIVATE_TARGET_TABLES),
        "private_target_tables_verified": False,
        "reason": "profile contains source mirrors, not target table type evidence",
        "runtime_evidence_authenticated": False,
        "runtime_evidence_reason": "runtime logs are unsigned operator-supplied evidence",
    }
    if limitations != expected_limitations:
        fail(
            "invalid_kabi_profile",
            "internal KABI limitations metadata is missing or inconsistent",
        )
    return normalized, coverage, limitations, provenance


def internal_kabi_mismatches(actual, expected):
    mismatches = []
    for name in sorted(expected):
        if actual[name]["size"] != expected[name]["size"]:
            mismatches.append(
                {
                    "field": name + ".sizeof",
                    "expected": expected[name]["size"],
                    "actual": actual[name]["size"],
                }
            )
        for member_name in sorted(expected[name]["members"]):
            if (
                actual[name]["members"][member_name]
                != expected[name]["members"][member_name]
            ):
                mismatches.append(
                    {
                        "field": f"{name}.{member_name}",
                        "expected": expected[name]["members"][member_name],
                        "actual": actual[name]["members"][member_name],
                    }
                )
    return mismatches


def verify_internal_kabi(
    source_path,
    profile_path,
    target_release,
    target_image,
    target_config,
    carrier_module_path,
    runtime_log_paths,
    dwarfdump,
):
    expected, coverage, limitations, provenance = load_internal_kabi_profile(
        profile_path, target_release, target_image, target_config
    )
    if carrier_module_path is None or not runtime_log_paths:
        fail(
            "internal_kabi_evidence_missing",
            "profile verification requires its carrier module and runtime logs",
        )
    expected_module = provenance["module"]
    verify_profile_artifact_binding(
        expected_module, carrier_module_path, "KABI carrier module"
    )
    carrier_module = ElfModule(carrier_module_path)
    if carrier_module.vermagic() != expected_module["vermagic"]:
        fail(
            "internal_kabi_evidence_mismatch",
            "KABI carrier vermagic differs from profile provenance",
        )
    expected_logs = provenance["runtime_logs"]
    if len(runtime_log_paths) != len(expected_logs):
        fail(
            "internal_kabi_evidence_mismatch",
            "KABI runtime log count differs from profile provenance",
        )
    for index, (runtime_path, expected_log) in enumerate(
        zip(runtime_log_paths, expected_logs)
    ):
        verify_profile_artifact_binding(
            expected_log, runtime_path, f"KABI runtime log {index}"
        )
        validate_kabi_runtime_log(runtime_path, expected_module, target_release)
    verify_profile_artifact_binding(
        provenance["dwarfdump"], dwarfdump, "profile dwarfdump"
    )
    if dwarfdump_record(dwarfdump)["version"] != provenance["dwarfdump"]["version"]:
        fail(
            "internal_kabi_evidence_mismatch",
            "llvm-dwarfdump version differs from profile provenance",
        )
    specification = {
        name: tuple(value["members"])
        for name, value in expected.items()
    }
    carrier_layouts = extract_internal_kabi(
        carrier_module_path, dwarfdump, specification
    )
    carrier_mismatches = internal_kabi_mismatches(carrier_layouts, expected)
    if carrier_mismatches:
        fail(
            "internal_kabi_evidence_mismatch",
            "KABI carrier DWARF differs from profile structures",
            carrier_mismatches,
        )
    actual = extract_internal_kabi(source_path, dwarfdump, specification)
    mismatches = internal_kabi_mismatches(actual, expected)
    verify_profile_artifact_binding(
        provenance["dwarfdump"], dwarfdump, "profile dwarfdump"
    )
    if mismatches:
        fail(
            "internal_kabi_mismatch",
            "source module internal kernel structure layout differs from target profile",
            mismatches,
        )
    return actual, coverage, limitations


def run_objcopy(tool, arguments, source, output):
    command = [str(tool), *arguments, str(source), str(output)]
    try:
        completed = subprocess.run(
            command, text=True, capture_output=True, check=False
        )
    except OSError as error:
        fail("objcopy_failed", f"cannot execute llvm-objcopy: {error}")
    if completed.returncode:
        details = {
            "command": command,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "exit_code": completed.returncode,
        }
        fail("objcopy_failed", "llvm-objcopy failed", details)


def make_version_blob(symbols, exports):
    output = bytearray()
    for name in sorted(symbols):
        encoded = name.encode("ascii")
        if len(encoded) >= VERSION_NAME_SIZE:
            fail("unsupported_modversions", f"version symbol is too long: {name}")
        output.extend(struct.pack("<Q", exports[name]))
        output.extend(encoded)
        output.extend(b"\0" * (VERSION_NAME_SIZE - len(encoded)))
    return bytes(output)


def symbols_in_section(module, section_name):
    section = module.section(section_name)
    return [
        symbol
        for symbol in module.symbols()
        if symbol.section_index == section.index and symbol.name
    ]


def resized_section_symbol_metadata(
    module, section_name, new_size, whole_symbol_name=None
):
    section = module.section(section_name)
    desired = {}
    for symbol in symbols_in_section(module, section_name):
        if symbol.value == 0 and symbol.size == section.size:
            desired[symbol.name] = (0, new_size)
        elif symbol.value + symbol.size <= new_size:
            desired[symbol.name] = (symbol.value, symbol.size)
        else:
            fail(
                "unsupported_elf",
                f"symbol {symbol.name} does not fit resized {section_name}",
            )
    if whole_symbol_name:
        if whole_symbol_name not in desired:
            fail(
                "unsupported_elf",
                f"missing {whole_symbol_name} in {section_name}",
            )
        whole_symbols = [
            symbol
            for symbol in symbols_in_section(module, section_name)
            if symbol.name == whole_symbol_name
        ]
        if (
            len(whole_symbols) != 1
            or whole_symbols[0].value != 0
            or whole_symbols[0].size != section.size
        ):
            fail(
                "invalid_elf",
                f"invalid existing {whole_symbol_name} metadata",
            )
        desired[whole_symbol_name] = (0, new_size)
    return desired


def modinfo_records(data):
    records = []
    cursor = 0
    while cursor < len(data):
        end = data.find(b"\0", cursor)
        if end < 0:
            fail("invalid_modinfo", "unterminated .modinfo entry")
        if end > cursor:
            records.append((cursor, data[cursor:end]))
        cursor = end + 1
    return records


def replace_vermagic_blob(module, target_vermagic):
    section_data = module.section_data(".modinfo")
    old_records = modinfo_records(section_data)
    vermagic_indices = [
        index
        for index, (_offset, record) in enumerate(old_records)
        if record.startswith(b"vermagic=")
    ]
    if len(vermagic_indices) != 1:
        fail("invalid_modinfo", f"cannot replace vermagic in {module.path}")
    replacement_index = vermagic_indices[0]
    new_data = bytearray()
    offset_mapping = {}
    for index, (old_offset, record) in enumerate(old_records):
        new_record = (
            target_vermagic.encode("ascii")
            if index == replacement_index
            else record
        )
        new_offset = len(new_data)
        new_data.extend(new_record)
        new_data.append(0)
        offset_mapping[old_offset] = (new_offset, len(new_record) + 1)
    modinfo_symbols = symbols_in_section(module, ".modinfo")
    unique_symbols = [
        symbol
        for symbol in modinfo_symbols
        if symbol.name.startswith("__UNIQUE_ID_")
    ]
    other_symbols = [
        symbol
        for symbol in modinfo_symbols
        if not symbol.name.startswith("__UNIQUE_ID_")
    ]
    if len(unique_symbols) != len(old_records):
        fail(
            "invalid_modinfo",
            ".modinfo entries do not have a one-to-one UNIQUE_ID symbol map",
        )
    desired = {}
    for symbol, (old_offset, _old_record) in zip(
        sorted(unique_symbols, key=lambda item: (item.value, item.index)),
        old_records,
    ):
        desired[symbol.name] = offset_mapping[old_offset]
    for symbol in other_symbols:
        if symbol.size != 0 or symbol.value > len(new_data):
            fail(
                "invalid_modinfo",
                f"unsupported .modinfo symbol {symbol.name}",
            )
        desired[symbol.name] = (symbol.value, symbol.size)
    return bytes(new_data), desired


def patch_symbol_metadata(path, section_name, desired):
    module = ElfModule(path)
    section = module.section(section_name)
    symbols = {}
    for symbol in symbols_in_section(module, section_name):
        if symbol.name in symbols:
            fail("invalid_elf", f"duplicate symbol {symbol.name} in {section_name}")
        symbols[symbol.name] = symbol
    missing = sorted(set(desired) - set(symbols))
    if missing:
        fail("verification_failed", f"objcopy lost section symbols: {missing}")
    data = bytearray(module.data)
    for name, (value, size) in desired.items():
        symbol = symbols[name]
        if value < 0 or size < 0 or value + size > section.size:
            fail("verification_failed", f"invalid desired metadata for {name}")
        struct.pack_into("<Q", data, symbol.file_offset + 8, value)
        struct.pack_into("<Q", data, symbol.file_offset + 16, size)
    path.write_bytes(data)
    verified = ElfModule(path)
    actual = {
        symbol.name: (symbol.value, symbol.size)
        for symbol in symbols_in_section(verified, section_name)
    }
    for name, expected in desired.items():
        if actual.get(name) != expected:
            fail("verification_failed", f"symbol metadata differs for {name}")


def verify_symbol_bounds(module):
    for symbol in module.symbols():
        if not symbol.name or symbol.section_index >= len(module.sections):
            continue
        section = module.sections[symbol.section_index]
        if symbol.value > section.size or symbol.value + symbol.size > section.size:
            fail(
                "verification_failed",
                f"symbol {symbol.name} exceeds section {section.name}",
            )


def verify_modinfo_symbols(module):
    records = {
        offset: record
        for offset, record in modinfo_records(module.section_data(".modinfo"))
    }
    for symbol in symbols_in_section(module, ".modinfo"):
        if not symbol.name.startswith("__UNIQUE_ID_"):
            continue
        record = records.get(symbol.value)
        if record is None or symbol.size != len(record) + 1:
            fail(
                "verification_failed",
                f".modinfo symbol metadata differs for {symbol.name}",
            )


def verify_whole_section_symbol(module, section_name, symbol_name):
    section = module.section(section_name)
    matches = [
        symbol
        for symbol in symbols_in_section(module, section_name)
        if symbol.name == symbol_name
    ]
    if len(matches) != 1 or (matches[0].value, matches[0].size) != (
        0,
        section.size,
    ):
        fail(
            "verification_failed",
            f"{symbol_name} does not describe all of {section_name}",
        )


def verify_layout(module, expected, source_symbols):
    actual = discover_layout(module)
    if (
        actual.size,
        actual.alignment,
        actual.flags,
        actual.name_offset,
    ) != (expected.size, expected.alignment, expected.flags, expected.name_offset):
        fail("verification_failed", "output module layout metadata differs")
    for name in source_symbols:
        if actual.relocations.get(name) != expected.relocations.get(name):
            fail("verification_failed", f"output relocation differs for {name}")


def patch_relocation_offsets(path, target_layout, source_symbols):
    module = ElfModule(path)
    relocations = module.relocations(THIS_MODULE_RELA_SECTION)
    data = bytearray(module.data)
    seen = set()
    for relocation in relocations:
        if relocation.symbol_name not in source_symbols:
            continue
        shape = target_layout.relocations[relocation.symbol_name]
        if (
            relocation.relocation_type != shape.relocation_type
            or relocation.addend != shape.addend
        ):
            fail("layout_mismatch", f"objcopy changed relocation semantics")
        struct.pack_into("<Q", data, relocation.file_offset, shape.offset)
        seen.add(relocation.symbol_name)
    missing = sorted(set(source_symbols) - seen)
    if missing:
        fail("layout_mismatch", f"objcopy lost relocations: {missing}")
    path.write_bytes(data)


def reserve_backup_path(path):
    descriptor, name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".backup", dir=path.parent
    )
    os.close(descriptor)
    return Path(name)


def publish_lock_path(path):
    return path.with_name(path.name + ".auto-adapt.lock")


def acquire_publish_locks(finals):
    locks = []
    try:
        for final in sorted(set(finals), key=lambda path: str(path).lower()):
            lock = publish_lock_path(final)
            try:
                descriptor = os.open(
                    lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
            except FileExistsError:
                fail("output_locked", f"another adaptation owns {lock}")
            except OSError as error:
                fail("publish_failed", f"cannot create publication lock {lock}: {error}")
            os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
            os.close(descriptor)
            locks.append(lock)
    except BaseException:
        for lock in reversed(locks):
            try:
                lock.unlink()
            except OSError:
                pass
        raise
    return locks


def release_publish_locks(locks):
    errors = []
    for lock in reversed(locks):
        try:
            lock.unlink()
        except OSError as error:
            errors.append({"path": str(lock), "error": str(error)})
    return errors


def transactional_publish_locked(pairs):
    backups = {}
    published = []
    try:
        for _staged, final in pairs:
            if final.exists():
                backup = reserve_backup_path(final)
                try:
                    os.replace(final, backup)
                except OSError:
                    if backup.exists():
                        backup.unlink()
                    raise
                backups[final] = backup
        for staged, final in pairs:
            os.replace(staged, final)
            published.append(final)
    except OSError as error:
        rollback_errors = []
        for final in reversed(published):
            try:
                if final.exists():
                    final.unlink()
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        for final, backup in backups.items():
            try:
                if backup.exists():
                    os.replace(backup, final)
            except OSError as rollback_error:
                rollback_errors.append(str(rollback_error))
        if rollback_errors:
            retained_backups = {
                str(final): str(backup)
                for final, backup in backups.items()
                if backup.exists()
            }
            fail(
                "publish_rollback_failed",
                f"publish failed ({error}); rollback also failed",
                {
                    "publish_error": str(error),
                    "rollback_errors": rollback_errors,
                    "retained_backups": retained_backups,
                },
            )
        fail("publish_failed", f"cannot publish output and manifest: {error}")
    cleanup_errors = []
    for backup in backups.values():
        try:
            if backup.exists():
                backup.unlink()
        except OSError as cleanup_error:
            cleanup_errors.append({"path": str(backup), "error": str(cleanup_error)})
    if cleanup_errors:
        fail(
            "publish_cleanup_failed",
            "outputs were published but old-file backup cleanup failed",
            cleanup_errors,
        )


def transactional_publish(pairs, replace_existing=True):
    pairs = tuple((Path(staged), Path(final)) for staged, final in pairs)
    locks = acquire_publish_locks(final for _staged, final in pairs)
    try:
        if not replace_existing:
            existing = [str(final) for _staged, final in pairs if final.exists()]
            if existing:
                fail("output_exists", "output appeared before publication", existing)
        transactional_publish_locked(pairs)
    except BaseException as error:
        lock_errors = release_publish_locks(locks)
        if lock_errors and isinstance(error, AdapterError):
            primary_details = error.details
            error.details = {
                "primary_details": primary_details,
                "lock_cleanup_errors": lock_errors,
            }
        raise
    lock_errors = release_publish_locks(locks)
    if lock_errors:
        fail(
            "publish_lock_cleanup_failed",
            "outputs were published but publication lock cleanup failed",
            lock_errors,
        )


def adapt_module(args, analysis):
    objcopy = resolve_objcopy(args.objcopy)
    objcopy_inputs = {str(objcopy): input_record(objcopy)}
    output = args.output.resolve()
    manifest_path = (
        args.manifest.resolve()
        if args.manifest
        else output.with_suffix(output.suffix + ".compat.json")
    )
    if output == analysis.source.path.resolve():
        fail("invalid_argument", "output must differ from source module")
    if output == objcopy or manifest_path == objcopy:
        fail("invalid_argument", "output and manifest must differ from objcopy")
    if output == manifest_path:
        fail("invalid_argument", "output and manifest must be different files")
    input_paths = argument_input_paths(args)
    if output in input_paths or manifest_path in input_paths:
        fail("invalid_argument", "output and manifest must not overwrite inputs")
    if output.exists() and not output.is_file():
        fail("invalid_argument", f"output path is not a file: {output}")
    if manifest_path.exists() and not manifest_path.is_file():
        fail("invalid_argument", f"manifest path is not a file: {manifest_path}")
    if not args.force and (output.exists() or manifest_path.exists()):
        fail("output_exists", "output or manifest already exists; pass --force")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_root = args.temp_dir.resolve() if args.temp_dir else output.parent
    temp_root.mkdir(parents=True, exist_ok=True)
    verify_input_records(analysis.input_records)

    with tempfile.TemporaryDirectory(prefix="module-adapt-", dir=temp_root) as temporary:
        temporary = Path(temporary)
        stage = temporary / "00-source.ko"
        stage.write_bytes(analysis.source.data)
        stage_index = 1

        def next_stage(label):
            nonlocal stage_index
            result = temporary / f"{stage_index:02d}-{label}.ko"
            stage_index += 1
            return result

        layout_changed = (
            analysis.source_layout.size != analysis.target_layout.size
            or analysis.source_layout.alignment != analysis.target_layout.alignment
            or analysis.source_layout.name_offset != analysis.target_layout.name_offset
            or any(
                analysis.source_layout.relocations[name]
                != analysis.target_layout.relocations[name]
                for name in analysis.source_layout.relocations
            )
        )
        layout_symbols = resized_section_symbol_metadata(
            ElfModule(stage),
            THIS_MODULE_SECTION,
            analysis.target_layout.size,
            whole_symbol_name="__this_module",
        )
        if layout_changed:
            name = analysis.source_layout.module_name.encode("ascii")
            end = analysis.target_layout.name_offset + len(name) + 1
            if end > analysis.target_layout.size:
                fail("layout_mismatch", "source module name does not fit target layout")
            payload = bytearray(analysis.target_layout.size)
            payload[
                analysis.target_layout.name_offset:
                analysis.target_layout.name_offset + len(name)
            ] = name
            blob = temporary / "this-module.bin"
            blob.write_bytes(payload)
            updated = next_stage("layout")
            run_objcopy(
                objcopy,
                [
                    "--update-section",
                    f"{THIS_MODULE_SECTION}={blob}",
                    "--set-section-alignment",
                    f"{THIS_MODULE_SECTION}={analysis.target_layout.alignment}",
                ],
                stage,
                updated,
            )
            patch_symbol_metadata(
                updated, THIS_MODULE_SECTION, layout_symbols
            )
            patch_relocation_offsets(
                updated,
                analysis.target_layout,
                set(analysis.source_layout.relocations),
            )
            stage = updated
            verify_layout(
                ElfModule(stage),
                analysis.target_layout,
                set(analysis.source_layout.relocations),
            )
        else:
            patch_symbol_metadata(
                stage, THIS_MODULE_SECTION, layout_symbols
            )

        if analysis.aliases:
            updated = next_stage("aliases")
            arguments = []
            for old, new in sorted(analysis.aliases.items()):
                arguments.extend(["--redefine-sym", f"{old}={new}"])
            run_objcopy(objcopy, arguments, stage, updated)
            stage = updated
            actual_imports = ElfModule(stage).undefined_symbols()
            if actual_imports != analysis.final_imports:
                fail("verification_failed", "symbol aliases changed the import set unexpectedly")

        if analysis.cfi_stub_added:
            current = ElfModule(stage)
            if CFI_STUB_SECTION in {section.name for section in current.sections}:
                fail("unsupported_cfi", f"source already has {CFI_STUB_SECTION}")
            stub = temporary / "cfi-stub.bin"
            stub.write_bytes(CFI_STUB_CODE)
            updated = next_stage("cfi")
            run_objcopy(
                objcopy,
                [
                    "--add-section",
                    f"{CFI_STUB_SECTION}={stub}",
                    "--set-section-flags",
                    f"{CFI_STUB_SECTION}=alloc,code,readonly,contents",
                    "--set-section-alignment",
                    f"{CFI_STUB_SECTION}=4",
                    "--add-symbol",
                    f"__cfi_check={CFI_STUB_SECTION}:0,global,function,default",
                ],
                stage,
                updated,
            )
            stage = updated
            cfi_module = ElfModule(stage)
            if "__cfi_check" not in cfi_module.defined_symbols():
                fail("verification_failed", "CFI stub symbol was not added")
            if cfi_module.section_data(CFI_STUB_SECTION) != CFI_STUB_CODE:
                fail("verification_failed", "CFI stub code differs")

        version_data = make_version_blob(
            analysis.required_versions, analysis.kernel_exports.crcs
        )
        version_symbols = resized_section_symbol_metadata(
            ElfModule(stage),
            "__versions",
            len(version_data),
            whole_symbol_name="____versions",
        )
        versions_blob = temporary / "versions.bin"
        versions_blob.write_bytes(version_data)
        updated = next_stage("versions")
        run_objcopy(
            objcopy,
            ["--update-section", f"__versions={versions_blob}"],
            stage,
            updated,
        )
        patch_symbol_metadata(updated, "__versions", version_symbols)
        stage = updated

        modinfo_data, modinfo_symbols = replace_vermagic_blob(
            ElfModule(stage), analysis.target_vermagic
        )
        modinfo_blob = temporary / "modinfo.bin"
        modinfo_blob.write_bytes(modinfo_data)
        updated = next_stage("vermagic")
        run_objcopy(
            objcopy,
            ["--update-section", f".modinfo={modinfo_blob}"],
            stage,
            updated,
        )
        patch_symbol_metadata(updated, ".modinfo", modinfo_symbols)
        stage = updated

        result = ElfModule(stage)
        if architecture_property(result) != architecture_property(analysis.source):
            fail("verification_failed", "output GNU architecture property differs")
        if result.vermagic() != analysis.target_vermagic:
            fail("verification_failed", "output vermagic differs")
        if result.undefined_symbols() != analysis.final_imports:
            fail("verification_failed", "output import set differs")
        verify_layout(
            result,
            analysis.target_layout,
            set(analysis.source_layout.relocations),
        )
        output_versions = result.version_records()
        if set(output_versions) != analysis.required_versions:
            fail("verification_failed", "output version symbol set differs")
        for name in analysis.required_versions:
            if output_versions[name] != analysis.kernel_exports.crcs[name]:
                fail("verification_failed", f"output CRC differs for {name}")
        if analysis.kcfi_required and not result.has_kcfi():
            fail("verification_failed", "target requires preserved KCFI metadata")
        if (
            analysis.cfi_required
            and not analysis.kcfi_required
            and "__cfi_check" not in result.defined_symbols()
        ):
            fail("verification_failed", "target requires __cfi_check")
        if result.has_module_signature():
            fail("verification_failed", "unexpected output module signature")
        verify_symbol_bounds(result)
        verify_whole_section_symbol(
            result, THIS_MODULE_SECTION, "__this_module"
        )
        verify_whole_section_symbol(result, "__versions", "____versions")
        verify_modinfo_symbols(result)

        output_fd, output_name = tempfile.mkstemp(
            prefix=output.name + ".", suffix=".tmp", dir=output.parent
        )
        os.close(output_fd)
        manifest_fd, manifest_name = tempfile.mkstemp(
            prefix=manifest_path.name + ".", suffix=".tmp", dir=manifest_path.parent
        )
        os.close(manifest_fd)
        staged_output = Path(output_name)
        staged_manifest = Path(manifest_name)
        try:
            shutil.copyfile(stage, staged_output)
            manifest = make_manifest(args, analysis, staged_output)
            manifest["output"]["name"] = output.name
            manifest_bytes = (
                json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True)
                + "\n"
            ).encode("ascii")
            staged_manifest.write_bytes(manifest_bytes)
            verify_input_records(analysis.input_records)
            verify_input_records(objcopy_inputs)
            transactional_publish(
                ((staged_output, output), (staged_manifest, manifest_path)),
                replace_existing=args.force,
            )
        finally:
            for path in (staged_output, staged_manifest):
                if path.exists():
                    path.unlink()
    return output, manifest_path, objcopy


def write_analysis_manifest(path, manifest, force, protected_paths):
    path = path.resolve()
    if path in protected_paths:
        fail("invalid_argument", "analysis manifest must not overwrite an input")
    if path.exists() and not path.is_file():
        fail("invalid_argument", f"manifest path is not a file: {path}")
    if path.exists() and not force:
        fail("output_exists", f"manifest exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=path.parent
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_text(
            json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="ascii",
        )
        transactional_publish(((temporary, path),), replace_existing=force)
    finally:
        if temporary.exists():
            temporary.unlink()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Adapt an ELF64 AArch64 module to an evidenced Android kernel ABI"
        )
    )
    parser.add_argument("--source-module", type=Path, required=True)
    parser.add_argument(
        "--reference-module", type=Path, action="append", required=True
    )
    parser.add_argument("--image", type=Path)
    parser.add_argument("--kallsyms", type=Path)
    parser.add_argument("--module-symvers", type=Path)
    parser.add_argument("--config", type=Path)
    parser.add_argument("--target-kabi-profile", type=Path)
    parser.add_argument(
        "--target-kabi-carrier-module",
        type=Path,
        help="runtime-tested carrier module bound by the KABI profile",
    )
    parser.add_argument(
        "--target-kabi-runtime-log",
        type=Path,
        action="append",
        help="repeat for every bound runtime log in profile provenance order",
    )
    parser.add_argument("--kernel-release")
    parser.add_argument("--target-vermagic")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--analyze-only", action="store_true")
    parser.add_argument("--objcopy", type=Path)
    parser.add_argument("--dwarfdump", type=Path)
    parser.add_argument("--temp-dir", type=Path)
    parser.add_argument("--alias", action="append", default=[])
    parser.add_argument("--no-default-aliases", action="store_true")
    parser.add_argument(
        "--cfi-mode", choices=("auto", "strict", "stub"), default="auto"
    )
    parser.add_argument("--allow-kernel-series-mismatch", action="store_true")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args(argv)
    if args.module_symvers and args.kallsyms:
        parser.error("use --module-symvers or --kallsyms, not both")
    if not args.analyze_only and args.output is None:
        parser.error("--output is required unless --analyze-only is used")
    if args.analyze_only and args.output is not None:
        parser.error("--output cannot be used with --analyze-only")
    if args.analyze_only and args.manifest is None:
        parser.error("--manifest is required with --analyze-only")
    kabi_provenance_inputs = bool(
        args.target_kabi_carrier_module or args.target_kabi_runtime_log
    )
    if args.target_kabi_profile and not (
        args.target_kabi_carrier_module and args.target_kabi_runtime_log
    ):
        parser.error(
            "--target-kabi-profile requires --target-kabi-carrier-module "
            "and at least one --target-kabi-runtime-log"
        )
    if kabi_provenance_inputs and not args.target_kabi_profile:
        parser.error("KABI carrier/runtime inputs require --target-kabi-profile")
    return args


def main(argv=None):
    try:
        args = parse_args(argv)
        analysis = plan_analysis(args)
        print(f"TARGET_RELEASE={analysis.target_release}")
        print(f"TARGET_VERMAGIC={analysis.target_vermagic}")
        print(f"CRC_ENCODING={analysis.kernel_exports.crc_encoding}")
        print(f"KERNEL_EXPORTS_NORMAL={analysis.kernel_exports.normal_count}")
        print(f"KERNEL_EXPORTS_GPL={analysis.kernel_exports.gpl_count}")
        print(
            "MODULE_LAYOUT_CRC="
            f"0x{analysis.kernel_exports.crcs['module_layout']:08x}"
        )
        print(f"ALIASES_APPLIED={len(analysis.aliases)}")
        print(f"CFI_STUB_PLANNED={str(analysis.cfi_stub_added).lower()}")
        print(f"KCFI_REQUIRED={str(analysis.kcfi_required).lower()}")
        print(f"REBUILT_VERSION_RECORDS={len(analysis.required_versions)}")
        print(
            "INTERNAL_KABI_VERIFIED="
            + str(analysis.internal_kabi_verified).lower()
        )
        print(
            "INTERNAL_KABI_PROFILE_MATCHED="
            + str(analysis.internal_kabi_verified).lower()
        )
        print(
            "PRIVATE_TARGET_TABLES_VERIFIED="
            + str(analysis.internal_kabi_private_tables_verified).lower()
        )
        print("RUNTIME_EVIDENCE_AUTHENTICATED=false")
        if args.analyze_only:
            manifest = make_manifest(args, analysis)
            verify_input_records(analysis.input_records)
            write_analysis_manifest(
                args.manifest,
                manifest,
                args.force,
                argument_input_paths(args),
            )
            print(f"MANIFEST={args.manifest.resolve()}")
            print("AUTO_ADAPT_ANALYSIS_READY")
            return 0
        output, manifest_path, objcopy = adapt_module(args, analysis)
        print(f"OBJCOPY={objcopy}")
        print(f"OUTPUT={output}")
        print(f"OUTPUT_SIZE={output.stat().st_size}")
        print(f"OUTPUT_SHA256={sha256_file(output)}")
        print(f"MANIFEST={manifest_path}")
        print("AUTO_ADAPT_MODULE_READY")
        return 0
    except AdapterError as error:
        print(f"ERROR_CODE={error.code}", file=sys.stderr)
        print(f"ERROR={error}", file=sys.stderr)
        if error.details is not None:
            print(
                "ERROR_DETAILS="
                + json.dumps(error.details, sort_keys=True, ensure_ascii=True),
                file=sys.stderr,
            )
        return 2
    except OSError as error:
        print("ERROR_CODE=io_error", file=sys.stderr)
        print(f"ERROR={error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
