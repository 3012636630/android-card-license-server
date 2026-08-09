#!/usr/bin/env python3
import argparse
import hashlib
import pathlib
import struct


TARGET_RELEASE = (
    "6.12.38-android16-5-g8c67d4274c0a-ab14275539-4k "
    "SMP preempt mod_unload modversions aarch64"
)
TARGET_MODULE_LAYOUT = 0xE976B219

# These imports are deliberately unversioned in the known-good device module.
ALLOW_UNVERSIONED = {
    "__contpte_try_fold",
    "__contpte_try_unfold",
    "__mmu_notifier_arch_invalidate_secondary_tlbs",
    "__pte_offset_map_lock",
    "__sync_icache_dcache",
    "anon_vma_name",
    "caches_clean_inval_pou",
    "copy_from_kernel_nofault",
    "kernel_neon_begin",
    "kernel_neon_end",
    "kick_all_cpus_sync",
    "mte_sync_tags",
    "stop_machine",
    "synchronize_rcu_tasks",
}


def load_elf(path):
    data = bytearray(path.read_bytes())
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError(f"{path}: expected ELF64 little-endian input")

    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    def header(index):
        return struct.unpack_from("<IIQQQQIIQQ", data, shoff + index * shentsize)

    names_header = header(shstrndx)
    names = data[names_header[4] : names_header[4] + names_header[5]]
    sections = []
    by_name = {}
    for index in range(shnum):
        current = header(index)
        name_end = names.find(b"\0", current[0])
        name = bytes(names[current[0] : name_end]).decode("ascii", "replace")
        sections.append((name, current))
        by_name[name] = (index, current)
    return data, sections, by_name


def versions_from_data(data, by_name):
    entry = by_name.get("__versions")
    if not entry:
        return {}
    header = entry[1]
    versions = {}
    for position in range(header[4], header[4] + header[5], 64):
        raw_name = data[position + 8 : position + 64].split(b"\0", 1)[0]
        if raw_name:
            versions[bytes(raw_name).decode("ascii", "replace")] = struct.unpack_from(
                "<I", data, position
            )[0]
    return versions


def read_versions(path):
    data, _, by_name = load_elf(path)
    return versions_from_data(data, by_name)


def symbol_names(data, by_name):
    symtab = by_name[".symtab"][1]
    strtab = by_name[".strtab"][1]
    strings = data[strtab[4] : strtab[4] + strtab[5]]
    result = []
    for position in range(symtab[4], symtab[4] + symtab[5], 24):
        name_offset = struct.unpack_from("<I", data, position)[0]
        name_end = strings.find(b"\0", name_offset)
        result.append(bytes(strings[name_offset:name_end]).decode("ascii", "replace"))
    return result


def emit_symvers(donor):
    versions = read_versions(donor)
    if versions.get("module_layout") != TARGET_MODULE_LAYOUT:
        raise SystemExit("donor module_layout CRC does not match RMX8899")
    for name, crc in sorted(versions.items()):
        if crc:
            print(f"0x{crc:08x}\t{name}\tvmlinux\tEXPORT_SYMBOL\t")


def patch_module(input_path, donor_path, output_path, report_path):
    donor = read_versions(donor_path)
    if donor.get("module_layout") != TARGET_MODULE_LAYOUT:
        raise SystemExit("donor module_layout CRC does not match RMX8899")

    original = input_path.read_bytes()
    data, sections, by_name = load_elf(input_path)
    if TARGET_RELEASE.encode() not in data:
        raise SystemExit("compiled module vermagic does not match target release")
    if "__versions" not in by_name:
        raise SystemExit("compiled module has no __versions section")

    patched = []
    blanked = []
    unknown = []
    versions_header = by_name["__versions"][1]
    for position in range(versions_header[4], versions_header[4] + versions_header[5], 64):
        raw_name = data[position + 8 : position + 64].split(b"\0", 1)[0]
        if not raw_name:
            continue
        name = bytes(raw_name).decode("ascii", "replace")
        old_crc = struct.unpack_from("<I", data, position)[0]
        if name in donor:
            new_crc = donor[name]
            struct.pack_into("<I", data, position, new_crc)
            patched.append((name, old_crc, new_crc))
        elif name in ALLOW_UNVERSIONED:
            struct.pack_into("<I", data, position, 0)
            data[position + 8 : position + 64] = b"\0" * 56
            blanked.append((name, old_crc))
        else:
            unknown.append((name, old_crc))

    if unknown:
        detail = "\n".join(f"{name}\t0x{crc:08x}" for name, crc in unknown)
        raise SystemExit(f"new imports are absent from donor:\n{detail}")

    names = symbol_names(data, by_name)
    cleanup = []
    for section_name, header in sections:
        if not section_name.startswith(".rela") or header[7] >= len(sections):
            continue
        if sections[header[7]][0] != ".gnu.linkonce.this_module":
            continue
        for position in range(header[4], header[4] + header[5], 24):
            relocation_offset, relocation_info, addend = struct.unpack_from(
                "<QQq", data, position
            )
            symbol_index = relocation_info >> 32
            symbol = names[symbol_index] if symbol_index < len(names) else ""
            if symbol == "cleanup_module":
                cleanup.append((section_name, relocation_offset, addend))
                if relocation_offset != 0x5F8:
                    struct.pack_into("<Q", data, position, 0x5F8)

    if len(cleanup) != 1:
        raise SystemExit(f"expected one cleanup_module relocation, found {cleanup}")
    if donor.keys() - ALLOW_UNVERSIONED and len(patched) < 80:
        raise SystemExit(f"too few version entries patched: {len(patched)}")

    output_path.write_bytes(data)
    output_versions = read_versions(output_path)
    if output_versions.get("module_layout") != TARGET_MODULE_LAYOUT:
        raise SystemExit("patched module_layout CRC verification failed")

    report = [
        f"input_sha256={hashlib.sha256(original).hexdigest()}",
        f"donor_sha256={hashlib.sha256(donor_path.read_bytes()).hexdigest()}",
        f"output_sha256={hashlib.sha256(data).hexdigest()}",
        f"patched={len(patched)}",
        f"blanked={len(blanked)}",
        f"cleanup_relocation={cleanup[0]}",
        "--- changed CRCs ---",
    ]
    report.extend(
        f"{name}\t0x{old:08x}\t0x{new:08x}"
        for name, old, new in sorted(patched)
        if old != new
    )
    report.append("--- blanked version checks ---")
    report.extend(f"{name}\t0x{old:08x}" for name, old in sorted(blanked))
    report_path.write_text("\n".join(report) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    emit = subparsers.add_parser("emit-symvers")
    emit.add_argument("donor", type=pathlib.Path)
    patch = subparsers.add_parser("patch")
    patch.add_argument("input", type=pathlib.Path)
    patch.add_argument("donor", type=pathlib.Path)
    patch.add_argument("output", type=pathlib.Path)
    patch.add_argument("report", type=pathlib.Path)
    args = parser.parse_args()

    if args.command == "emit-symvers":
        emit_symvers(args.donor)
    else:
        patch_module(args.input, args.donor, args.output, args.report)


if __name__ == "__main__":
    main()
