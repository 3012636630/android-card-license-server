#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import sys
from pathlib import Path


ADAPTER_PATH = Path(__file__).with_name("auto-adapt-android-module.py")
SPEC = importlib.util.spec_from_file_location("auto_adapt_android_module", ADAPTER_PATH)
adapter = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = adapter
SPEC.loader.exec_module(adapter)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_args():
    parser = argparse.ArgumentParser(
        description="Verify a target-built ARM64 lsdriver carrier module"
    )
    parser.add_argument("--target-id", required=True)
    parser.add_argument("--matrix", type=Path, required=True)
    parser.add_argument("--module", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--module-symvers", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--clang-revision", required=True)
    parser.add_argument("--clang-source-commit", required=True)
    parser.add_argument("--clang-source-ref", required=True)
    parser.add_argument("--clang-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def target_record(path, target_id):
    data = json.loads(path.read_text(encoding="ascii"))
    matches = [target for target in data["targets"] if target["id"] == target_id]
    if len(matches) != 1:
        raise RuntimeError(
            f"expected one target named {target_id}, found {len(matches)}"
        )
    return matches[0]


def main():
    args = parse_args()
    target = target_record(args.matrix, args.target_id)
    if args.source_commit != target["commit"]:
        raise RuntimeError("source commit differs from the pinned target matrix")
    if args.clang_revision != target["clang_revision"]:
        raise RuntimeError("Clang revision differs from the pinned target matrix")
    if len(args.clang_source_commit) != 40 or any(
        character not in "0123456789abcdef"
        for character in args.clang_source_commit
    ):
        raise RuntimeError("Clang source commit is not a lowercase SHA-1")

    module = adapter.ElfModule(args.module)
    if module.module_name() != "lsdriver":
        raise RuntimeError(f"unexpected module name: {module.module_name()}")
    if module.has_module_signature():
        raise RuntimeError("carrier module must remain unsigned and reproducible")

    release, flags = adapter.parse_vermagic(module.vermagic())
    if release != target["stock_image_release"]:
        raise RuntimeError(f"vermagic release mismatch: {release}")
    config = adapter.parse_config(args.config)
    adapter.verify_config_flags(config, flags)

    expected_layout = int(target["module_layout_crc"], 0)
    exports = adapter.exports_from_module_symvers(
        args.module_symvers, {"module_layout": expected_layout}
    )
    versions = module.version_records()
    imports = module.undefined_symbols()
    required_versions = set(imports) | {"module_layout"}
    missing_versions = sorted(required_versions - set(versions))
    extra_versions = sorted(set(versions) - required_versions)
    if missing_versions or extra_versions:
        raise RuntimeError(
            "version-record coverage mismatch: "
            f"missing={missing_versions} extra={extra_versions}"
        )
    missing_exports = sorted(required_versions - set(exports.crcs))
    if missing_exports:
        raise RuntimeError(f"target exports are missing: {missing_exports}")
    mismatched_crcs = sorted(
        name
        for name in required_versions
        if (versions[name] & 0xFFFFFFFF) != exports.crcs[name]
    )
    if mismatched_crcs:
        raise RuntimeError(f"target CRC mismatch: {mismatched_crcs}")

    defined = module.defined_symbols()
    has_kcfi = module.has_kcfi()
    has_legacy_cfi = "__cfi_check" in defined and not has_kcfi
    if target["series"] == "5.15":
        if not has_legacy_cfi:
            raise RuntimeError("5.15 carrier lacks legacy Clang CFI")
        cfi_mode = "legacy_cfi"
    else:
        if not has_kcfi:
            raise RuntimeError(f"{target['series']} carrier lacks KCFI metadata")
        cfi_mode = "kcfi"

    architecture = adapter.architecture_property(module)
    feature_bits = architecture.feature_bits if architecture else 0
    if adapter.config_enabled(config, "CONFIG_ARM64_BTI_KERNEL"):
        required_bti = adapter.GNU_PROPERTY_AARCH64_FEATURE_1_BTI
        if feature_bits & required_bti != required_bti:
            raise RuntimeError("carrier lacks the target BTI architecture property")

    debug_sections = sorted(
        section.name
        for section in module.sections
        if section.size and section.name in (".debug_info", ".zdebug_info")
    )
    if not debug_sections:
        raise RuntimeError("carrier lacks DWARF debug information")

    manifest = {
        "schema_version": 1,
        "target": {
            "id": args.target_id,
            "series": target["series"],
            "release": target["stock_image_release"],
            "source_commit": args.source_commit,
            "clang_revision": args.clang_revision,
            "clang_source_commit": args.clang_source_commit,
            "clang_source_ref": args.clang_source_ref,
            "clang_binary_sha256": sha256_file(args.clang_binary),
            "stock_image_sha256": target["stock_image_sha256"],
        },
        "module": {
            "path": str(args.module),
            "size": args.module.stat().st_size,
            "sha256": sha256_file(args.module),
            "vermagic": module.vermagic(),
            "vermagic_flags": list(flags),
            "imports": len(imports),
            "version_records": len(versions),
            "module_layout_crc": f"0x{versions['module_layout'] & 0xFFFFFFFF:08x}",
            "cfi_mode": cfi_mode,
            "gnu_aarch64_feature_bits": feature_bits,
            "dwarf_sections": debug_sections,
            "signed": False,
        },
        "evidence": {
            "config_sha256": sha256_file(args.config),
            "module_symvers_sha256": sha256_file(args.module_symvers),
            "module_symvers_exports": len(exports.crcs),
            "all_import_crcs_matched": True,
        },
        "runtime": {
            "tested": False,
            "internal_kabi_runtime_profile_pending": True,
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
        encoding="ascii",
    )
    print(f"TARGET={args.target_id}")
    print(f"RELEASE={release}")
    print(f"CFI_MODE={cfi_mode}")
    print(f"VERSION_RECORDS={len(versions)}")
    print(f"MODULE_LAYOUT_CRC={manifest['module']['module_layout_crc']}")
    print(f"OUTPUT={args.output}")
    print("MULTI_KERNEL_CARRIER_VERIFIED=true")


if __name__ == "__main__":
    main()
