from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / "third_party/dcc"
DEX_NAME = re.compile(r"classes(?:([1-9][0-9]*))?\.dex\Z")
METHOD_DESCRIPTOR = re.compile(
    r"(L[^;]+;)->([^()]+)(\([^)]*\).+)\Z"
)
ELF64_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
ELF64_PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
EM_AARCH64 = 183
ET_DYN = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1


def _load_dcc() -> tuple[Any, Any, Any, Any]:
    vendor_text = str(VENDOR_ROOT)
    if not sys.path or sys.path[0] != vendor_text:
        sys.path.insert(0, vendor_text)
    from androguard.core.analysis import analysis
    from androguard.core.bytecodes import dvm
    from dex2c.compiler import Dex2C
    from dex2c import util

    return analysis, dvm, Dex2C, util


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_generated_cpp(source: str) -> str:
    """Normalize DCC integer tokens that Clang rejects under -Werror."""
    normalized = re.sub(
        r"(?<![A-Za-z0-9_])-9223372036854775808(?![A-Za-z0-9_])",
        "INT64_MIN",
        source,
    )
    return re.sub(
        r"(?m)^(j(?:boolean|byte|char|short|int|long|float|double|object)) (v[0-9]+);$",
        r"[[maybe_unused]] \1 \2;",
        normalized,
    )


def write_clang_response_file(arguments: list[str], path: Path) -> str:
    payload = "\n".join(
        subprocess.list2cmdline([argument.replace("\\", "/")])
        for argument in arguments
    ) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8", newline="\n")
    return _sha256(path.read_bytes())


def _version_key(path: Path) -> tuple[int, ...]:
    values = re.findall(r"[0-9]+", path.name)
    return tuple(int(value) for value in values)


def discover_ndk(explicit: Path | None = None) -> Path:
    if explicit is not None:
        root = explicit.resolve()
        if not root.is_dir():
            raise FileNotFoundError(f"Android NDK directory not found: {root}")
        return root
    environment = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
    if environment:
        return discover_ndk(Path(environment))
    sdk = Path(
        os.environ.get("ANDROID_SDK_ROOT")
        or os.environ.get("ANDROID_HOME")
        or Path.home() / "AppData/Local/Android/Sdk"
    )
    versions = sorted(
        (path for path in (sdk / "ndk").glob("*") if path.is_dir()),
        key=_version_key,
    )
    if not versions:
        raise FileNotFoundError(f"Android NDK not installed under: {sdk / 'ndk'}")
    return versions[-1].resolve()


def discover_ndk_toolchain(ndk: Path) -> Path:
    prebuilt = ndk / "toolchains/llvm/prebuilt"
    candidates = [
        prebuilt / "windows-x86_64/bin",
        prebuilt / "linux-x86_64/bin",
        prebuilt / "darwin-x86_64/bin",
        prebuilt / "darwin-arm64/bin",
    ]
    matches = [candidate for candidate in candidates if candidate.is_dir()]
    if len(matches) != 1:
        raise FileNotFoundError(
            f"expected one NDK LLVM host toolchain under {prebuilt}, found {len(matches)}"
        )
    return matches[0]


def inspect_arm64_elf(path: Path) -> dict[str, Any]:
    data = path.read_bytes()
    if len(data) < ELF64_HEADER.size:
        raise ValueError("ELF output is shorter than its ELF64 header")
    header = ELF64_HEADER.unpack_from(data)
    ident = header[0]
    if ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
        raise ValueError("output must be little-endian ELF64")
    if header[1] != ET_DYN or header[2] != EM_AARCH64:
        raise ValueError(
            f"output must be AArch64 ET_DYN: type={header[1]} machine={header[2]}"
        )
    program_offset = header[5]
    program_entry_size = header[9]
    program_count = header[10]
    if program_entry_size < ELF64_PROGRAM_HEADER.size:
        raise ValueError("ELF program-header entry is too short")
    if program_offset + program_entry_size * program_count > len(data):
        raise ValueError("ELF program-header table leaves the file")
    stack_executable: bool | None = None
    for index in range(program_count):
        offset = program_offset + index * program_entry_size
        segment_type, flags, *_ = ELF64_PROGRAM_HEADER.unpack_from(data, offset)
        if segment_type == PT_GNU_STACK:
            stack_executable = bool(flags & PF_X)
    if stack_executable is not False:
        raise ValueError("ELF output must contain a non-executable GNU stack")
    return {
        "elf_class": 64,
        "endianness": "little",
        "type": "ET_DYN",
        "machine": "AArch64",
        "program_headers": program_count,
        "nx_stack": True,
    }


def _dex_sort_key(name: str) -> int:
    match = DEX_NAME.fullmatch(Path(name).name)
    if match is None:
        raise ValueError(f"invalid DEX entry name: {name}")
    return int(match.group(1) or 1)


def read_dex_inputs(path: Path) -> list[tuple[str, bytes]]:
    data = path.read_bytes()
    if data.startswith(b"dex\n"):
        return [(path.name, data)]
    if not zipfile.is_zipfile(path):
        raise ValueError("input must be an APK or DEX file")
    with zipfile.ZipFile(path) as archive:
        names = sorted(
            (
                name for name in archive.namelist()
                if "/" not in name and DEX_NAME.fullmatch(name)
            ),
            key=_dex_sort_key,
        )
        if not names:
            raise ValueError("APK contains no classes*.dex entries")
        expected = list(range(1, len(names) + 1))
        actual = [_dex_sort_key(name) for name in names]
        if actual != expected:
            raise ValueError(f"APK DEX sequence is not contiguous: {actual}")
        return [(name, archive.read(name)) for name in names]


def canonical_class_descriptor(value: str) -> str:
    """Normalize legacy Androguard class names to canonical DEX descriptors."""
    if value.startswith("L") and value.endswith(";"):
        return value
    if not value or value.startswith("[") or ";" in value:
        raise ValueError(f"invalid method class name: {value!r}")
    return f"L{value};"


def canonical_method_descriptor(method: Any) -> str:
    class_name, name, proto = method.get_triple()
    return f"{canonical_class_descriptor(class_name)}->{name}{proto}"


def parse_method_descriptor(value: str) -> tuple[str, str, str]:
    match = METHOD_DESCRIPTOR.fullmatch(value)
    if match is None or value != value.strip():
        raise ValueError(f"invalid canonical method descriptor: {value!r}")
    return match.group(1), match.group(2), match.group(3)


def load_selection(path: Path) -> list[str]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict) or payload.get("schema_version") != 1:
        raise ValueError("selection schema_version must be 1")
    methods = payload.get("required_methods")
    if not isinstance(methods, list) or not methods:
        raise ValueError("selection required_methods must be a non-empty list")
    if any(not isinstance(value, str) for value in methods):
        raise ValueError("selection descriptors must be strings")
    for value in methods:
        parse_method_descriptor(value)
    if len(methods) != len(set(methods)):
        raise ValueError("selection contains duplicate descriptors")
    if methods != sorted(methods):
        raise ValueError("selection descriptors must be sorted")
    return methods


def _method_metadata(vm: Any, util: Any) -> dict[str, dict[str, Any]]:
    methods = list(vm.get_methods())
    short_counts = Counter()
    native_names: set[tuple[str, str]] = set()
    for method in methods:
        class_name, name, proto = method.get_triple()
        class_name = canonical_class_descriptor(class_name)
        short_counts[(class_name, name, proto[: proto.index(")") + 1])] += 1
        if util.is_native_method(method):
            native_names.add((class_name, name))

    result: dict[str, dict[str, Any]] = {}
    for method in methods:
        descriptor = canonical_method_descriptor(method)
        class_name, name, proto = method.get_triple()
        class_name = canonical_class_descriptor(class_name)
        reason = ""
        if descriptor in result:
            reason = "duplicate-descriptor"
        elif name.startswith("<"):
            reason = "constructor-or-class-initializer"
        elif util.is_synthetic_method(method):
            reason = "synthetic"
        elif util.is_native_method(method):
            reason = "already-native"
        elif (class_name, name) in native_names:
            reason = "same-name-native-conflict"
        elif short_counts[(class_name, name, proto[: proto.index(")") + 1])] > 1:
            reason = "return-type-only-overload-conflict"
        elif method.get_code() is None:
            reason = "missing-code"
        result[descriptor] = {
            "descriptor": descriptor,
            "eligible": not reason,
            "reason": reason,
            "access_flags": method.get_access_flags(),
            "native": bool(util.is_native_method(method)),
            "has_code": method.get_code() is not None,
            "method": method,
        }
    return result


def inventory(input_path: Path) -> dict[str, Any]:
    _, dvm, _, util = _load_dcc()
    dex_rows = []
    descriptors: dict[str, dict[str, Any]] = {}
    duplicate_descriptors: set[str] = set()
    for name, data in read_dex_inputs(input_path):
        vm = dvm.DalvikVMFormat(data)
        rows = _method_metadata(vm, util)
        for descriptor, row in rows.items():
            if descriptor in descriptors:
                duplicate_descriptors.add(descriptor)
            descriptors[descriptor] = {
                "descriptor": descriptor,
                "dex": name,
                "eligible": row["eligible"],
                "reason": row["reason"],
                "access_flags": row["access_flags"],
                "native": row["native"],
                "has_code": row["has_code"],
            }
        dex_rows.append({
            "name": name,
            "sha256": _sha256(data),
            "method_count": len(rows),
        })
    for descriptor in duplicate_descriptors:
        descriptors[descriptor]["eligible"] = False
        descriptors[descriptor]["reason"] = "cross-dex-duplicate-descriptor"
    methods = [descriptors[key] for key in sorted(descriptors)]
    return {
        "schema_version": 1,
        "stage": "dcc-java2c-inventory",
        "input": str(input_path.resolve()),
        "input_sha256": _sha256(input_path.read_bytes()),
        "dex_files": dex_rows,
        "summary": {
            "dex_files": len(dex_rows),
            "methods": len(methods),
            "eligible_methods": sum(row["eligible"] for row in methods),
            "blocked_methods": sum(not row["eligible"] for row in methods),
        },
        "methods": methods,
    }


def _c_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_dynamic_register(
    compiled: list[dict[str, Any]],
) -> str:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in compiled:
        class_name, method_name, signature = parse_method_descriptor(
            row["descriptor"]
        )
        grouped[class_name[1:-1]].append({
            **row,
            "method_name": method_name,
            "signature": signature,
        })
    lines = ["#include <jni.h>", '#include "DynamicRegister.h"', ""]
    for row in sorted(compiled, key=lambda item: item["descriptor"]):
        lines.append(f'extern {row["prototype"]};')
    lines.extend(["", "const char *dynamic_register_compile_methods(JNIEnv *env) {"])
    for index, class_name in enumerate(sorted(grouped)):
        rows = sorted(grouped[class_name], key=lambda item: item["descriptor"])
        lines.extend([
            f"  jclass clazz_{index} = env->FindClass({_c_string(class_name)});",
            f"  if (clazz_{index} == nullptr) return "
            f"{_c_string('Class not found: ' + class_name)};",
            f"  const JNINativeMethod methods_{index}[] = {{",
        ])
        for row in rows:
            lines.append(
                "    {const_cast<char *>(%s), const_cast<char *>(%s), "
                "reinterpret_cast<void *>(%s)},"
                % (
                    _c_string(row["method_name"]),
                    _c_string(row["signature"]),
                    row["jni_name"],
                )
            )
        lines.extend([
            "  };",
            f"  if (env->RegisterNatives(clazz_{index}, methods_{index}, "
            f"sizeof(methods_{index}) / sizeof(methods_{index}[0])) != 0) {{",
            f"    env->DeleteLocalRef(clazz_{index});",
            f"    return {_c_string('RegisterNatives failed: ' + class_name)};",
            "  }",
            f"  env->DeleteLocalRef(clazz_{index});",
        ])
    lines.extend(["  return nullptr;", "}", ""])
    return "\n".join(lines)


def compile_selection(
    input_path: Path,
    selection_path: Path,
    output_dir: Path,
    report_path: Path,
) -> dict[str, Any]:
    analysis, dvm, Dex2C, util = _load_dcc()
    required = load_selection(selection_path)
    required_set = set(required)
    found: dict[str, tuple[str, Any, Any]] = {}
    blockers: list[dict[str, str]] = []
    dex_rows = []

    for name, data in read_dex_inputs(input_path):
        vm = dvm.DalvikVMFormat(data)
        metadata = _method_metadata(vm, util)
        dx = analysis.Analysis(vm)
        for descriptor in sorted(required_set & metadata.keys()):
            row = metadata[descriptor]
            if descriptor in found:
                blockers.append({
                    "descriptor": descriptor,
                    "reason": "cross-dex-duplicate-descriptor",
                })
            elif not row["eligible"]:
                blockers.append({
                    "descriptor": descriptor,
                    "reason": row["reason"],
                })
            else:
                found[descriptor] = (name, row["method"], Dex2C(vm, dx, True))
        dex_rows.append({
            "name": name,
            "sha256": _sha256(data),
            "method_count": len(metadata),
        })

    blocked_descriptors = {row["descriptor"] for row in blockers}
    for descriptor in sorted(required_set - set(found) - blocked_descriptors):
        blockers.append({"descriptor": descriptor, "reason": "not-found"})

    compiled = []
    for descriptor in required:
        if descriptor not in found:
            continue
        dex_name, method, compiler = found[descriptor]
        try:
            source, prototype = compiler.get_source_method(method)
            if not source or not prototype:
                raise ValueError("compiler returned no source or prototype")
            class_name, method_name, signature = parse_method_descriptor(descriptor)
            jni_name = util.JniLongName(class_name, method_name, signature)
            compiled.append({
                "descriptor": descriptor,
                "dex": dex_name,
                "jni_name": jni_name,
                "prototype": prototype,
                "source": normalize_generated_cpp(
                    '#include "Dex2C.h"\n' + source
                ),
            })
        except Exception as exc:  # DCC raises multiple legacy exception types.
            blockers.append({
                "descriptor": descriptor,
                "reason": "compile-error",
                "detail": f"{type(exc).__name__}: {exc}",
            })

    compiled_by_descriptor = {row["descriptor"] for row in compiled}
    complete = not blockers and compiled_by_descriptor == required_set
    generated = []
    if complete:
        output_dir.mkdir(parents=True, exist_ok=True)
        for row in compiled:
            digest = hashlib.sha256(row["descriptor"].encode("utf-8")).hexdigest()
            path = output_dir / f"method-{digest[:20]}.cpp"
            path.write_text(row["source"], encoding="utf-8", newline="\n")
            generated.append({
                "descriptor": row["descriptor"],
                "path": str(path.resolve()),
                "sha256": _sha256(path.read_bytes()),
            })
        registry = output_dir / "DynamicRegister.cpp"
        registry.write_text(
            build_dynamic_register(compiled), encoding="utf-8", newline="\n"
        )
        generated.append({
            "descriptor": "<dynamic-register>",
            "path": str(registry.resolve()),
            "sha256": _sha256(registry.read_bytes()),
        })

    report = {
        "schema_version": 1,
        "stage": "dcc-java2c-compile",
        "input": str(input_path.resolve()),
        "input_sha256": _sha256(input_path.read_bytes()),
        "selection": str(selection_path.resolve()),
        "selection_sha256": _sha256(selection_path.read_bytes()),
        "vendor_revision": json.loads(
            (VENDOR_ROOT / "UPSTREAM.json").read_text(encoding="utf-8")
        )["revision"],
        "dex_files": dex_rows,
        "required_methods": required,
        "compiled_methods": sorted(compiled_by_descriptor),
        "blockers": sorted(blockers, key=lambda row: row["descriptor"]),
        "generated_files": generated,
        "summary": {
            "required_methods": len(required),
            "compiled_methods": len(compiled_by_descriptor),
            "blockers": len(blockers),
            "gate_passed": complete,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def build_arm64(
    compile_report_path: Path,
    source_dir: Path,
    output_path: Path,
    report_path: Path,
    ndk_path: Path | None = None,
    api: int = 23,
) -> dict[str, Any]:
    if api < 23:
        raise ValueError("DCC ARM64 build requires API 23 or newer")
    compile_report = json.loads(compile_report_path.read_text(encoding="utf-8"))
    if (
        compile_report.get("stage") != "dcc-java2c-compile"
        or compile_report.get("summary", {}).get("gate_passed") is not True
    ):
        raise ValueError("DCC compile report has not passed its fail-closed gate")

    source_root = source_dir.resolve()
    expected = {
        Path(row["path"]).resolve(): row["sha256"]
        for row in compile_report.get("generated_files", [])
    }
    sources = sorted(source_root.glob("method-*.cpp"))
    registry = source_root / "DynamicRegister.cpp"
    sources.append(registry)
    if not sources[0:-1] or set(sources) != set(expected):
        raise ValueError("generated C++ source set does not match compile report")
    for source in sources:
        if not source.is_file() or _sha256_file(source) != expected[source]:
            raise ValueError(f"generated C++ source hash mismatch: {source}")

    ndk = discover_ndk(ndk_path)
    toolchain = discover_ndk_toolchain(ndk)
    compiler = toolchain / f"aarch64-linux-android{api}-clang++.cmd"
    if not compiler.is_file():
        compiler = toolchain / f"aarch64-linux-android{api}-clang++"
    if not compiler.is_file():
        raise FileNotFoundError(f"NDK ARM64 compiler not found: {compiler}")

    runtime_sources = [
        VENDOR_ROOT / "runtime/Dex2C.cpp",
        VENDOR_ROOT / "runtime/well_known_classes.cpp",
    ]
    command = [
        str(compiler),
        "-std=c++20",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-Wno-unused-parameter",
        "-Wno-unused-label",
        "-fPIC",
        "-fvisibility=hidden",
        "-shared",
        "-static-libstdc++",
        "-Wl,--no-undefined",
        "-Wl,-z,relro,-z,now",
        "-Wl,--exclude-libs,ALL",
        "-I",
        str(VENDOR_ROOT / "runtime"),
        *(str(source) for source in sources),
        *(str(source) for source in runtime_sources),
        "-llog",
        "-o",
        str(output_path.resolve()),
    ]
    output_path.parent.mkdir(parents=True, exist_ok=True)
    response_file = output_path.with_suffix(output_path.suffix + ".rsp")
    response_sha256 = write_clang_response_file(command[1:], response_file)
    completed = subprocess.run(
        [command[0], f"@{response_file.resolve()}"],
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        raise RuntimeError(
            f"DCC ARM64 build failed ({completed.returncode})\n"
            f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
        )
    elf = inspect_arm64_elf(output_path)
    report = {
        "schema_version": 1,
        "stage": "dcc-java2c-build-arm64",
        "compile_report": str(compile_report_path.resolve()),
        "compile_report_sha256": _sha256_file(compile_report_path),
        "input_apk_sha256": compile_report["input_sha256"],
        "vendor_revision": compile_report["vendor_revision"],
        "ndk": str(ndk),
        "api": api,
        "compiler": str(compiler.resolve()),
        "compiler_sha256": _sha256_file(compiler),
        "compile_flags": command[1 : command.index("-I")],
        "response_file": str(response_file.resolve()),
        "response_file_sha256": response_sha256,
        "source_files": [
            {"path": str(path), "sha256": _sha256_file(path)}
            for path in sources + runtime_sources
        ],
        "output": str(output_path.resolve()),
        "output_size": output_path.stat().st_size,
        "output_sha256": _sha256_file(output_path),
        "elf": elf,
        "summary": {
            "compiled_methods": compile_report["summary"]["compiled_methods"],
            "gate_passed": True,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def _native_method_declaration(line: str) -> str:
    newline = "\n" if line.endswith("\n") else ""
    content = line[:-1] if newline else line
    prefix, separator, method = content.rpartition(" ")
    if not separator or not method or "(" not in method:
        raise ValueError(f"invalid smali method declaration: {line!r}")
    flags = prefix.split()
    if "native" not in flags:
        prefix += " native"
    return prefix + " " + method + newline


def _preserved_method_annotations(lines: list[str]) -> list[str]:
    result: list[str] = []
    index = 0
    while index < len(lines):
        if not lines[index].strip().startswith(".annotation"):
            index += 1
            continue
        while index < len(lines):
            result.append(lines[index])
            if lines[index].strip() == ".end annotation":
                index += 1
                break
            index += 1
        else:
            raise ValueError("unterminated smali method annotation")
    return result


def transform_smali_class(
    text: str,
    descriptors: set[str],
    load_library: str | None = None,
) -> tuple[str, list[str]]:
    lines = text.splitlines(keepends=True)
    class_descriptor = ""
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(".class "):
            candidate = stripped.split()[-1]
            class_descriptor = canonical_class_descriptor(candidate)
            break
    if not class_descriptor:
        raise ValueError("smali class declaration not found")

    output: list[str] = []
    replaced: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        stripped = line.strip()
        if not stripped.startswith(".method "):
            output.append(line)
            index += 1
            continue
        method_token = stripped.split()[-1]
        descriptor = f"{class_descriptor}->{method_token}"
        end = index + 1
        while end < len(lines) and lines[end].strip() != ".end method":
            end += 1
        if end == len(lines):
            raise ValueError(f"unterminated smali method: {descriptor}")
        if descriptor not in descriptors:
            output.extend(lines[index : end + 1])
        else:
            output.append(_native_method_declaration(line))
            output.extend(_preserved_method_annotations(lines[index + 1 : end]))
            output.append(lines[end])
            replaced.append(descriptor)
        index = end + 1

    result = "".join(output)
    if load_library:
        result = inject_smali_library_load(result, load_library)
    return result, replaced


def inject_smali_library_load(text: str, library: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", library):
        raise ValueError(f"invalid Android library name: {library!r}")
    marker = f'const-string v0, "{library}"'
    if marker in text:
        return text
    lines = text.splitlines(keepends=True)
    start = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip().startswith(".method ")
            and line.strip().split()[-1] == "<clinit>()V"
        ),
        None,
    )
    instructions = [
        f'    const-string v0, "{library}"\n',
        "\n",
        "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V\n",
        "\n",
    ]
    if start is not None:
        end = start + 1
        while end < len(lines) and lines[end].strip() != ".end method":
            end += 1
        register = next(
            (
                index
                for index in range(start + 1, end)
                if lines[index].strip().startswith((".locals ", ".registers "))
            ),
            None,
        )
        if register is None:
            raise ValueError("existing <clinit> has no .locals or .registers directive")
        directive, value = lines[register].strip().split()
        count = int(value, 0)
        if count == 0:
            indent = lines[register][: len(lines[register]) - len(lines[register].lstrip())]
            lines[register] = f"{indent}{directive} 1\n"
        lines[register + 1 : register + 1] = instructions
        return "".join(lines)

    insertion = next(
        (index for index, line in enumerate(lines) if line.strip().startswith(".method ")),
        len(lines),
    )
    synthetic = [
        ".method static constructor <clinit>()V\n",
        "    .locals 1\n",
        "\n",
        *instructions,
        "    return-void\n",
        ".end method\n",
        "\n",
    ]
    lines[insertion:insertion] = synthetic
    return "".join(lines)


def patch_decoded_apk(
    decoded_dir: Path,
    compile_report_path: Path,
    build_report_path: Path,
    report_path: Path,
    library_name: str = "avmp-dcc",
) -> dict[str, Any]:
    decoded_root = decoded_dir.resolve()
    compile_report = json.loads(compile_report_path.read_text(encoding="utf-8"))
    build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
    if compile_report.get("summary", {}).get("gate_passed") is not True:
        raise ValueError("DCC compile report did not pass")
    if build_report.get("summary", {}).get("gate_passed") is not True:
        raise ValueError("DCC ARM64 build report did not pass")
    if (
        build_report.get("compile_report_sha256") != _sha256_file(compile_report_path)
        or build_report.get("input_apk_sha256") != compile_report.get("input_sha256")
        or build_report.get("vendor_revision") != compile_report.get("vendor_revision")
    ):
        raise ValueError("DCC compile/build evidence chain mismatch")
    library = Path(build_report["output"]).resolve()
    if not library.is_file() or _sha256_file(library) != build_report["output_sha256"]:
        raise ValueError("DCC ARM64 library hash mismatch")
    inspect_arm64_elf(library)

    required = set(compile_report["compiled_methods"])
    by_class: dict[str, set[str]] = defaultdict(set)
    for descriptor in required:
        class_name, _, _ = parse_method_descriptor(descriptor)
        by_class[class_name].add(descriptor)
    class_paths: dict[str, Path] = {}
    smali_roots = sorted(
        path for path in decoded_root.iterdir()
        if path.is_dir() and re.fullmatch(r"smali(?:_classes[1-9][0-9]*)?", path.name)
    )
    for class_name in sorted(by_class):
        relative = Path(class_name[1:-1] + ".smali")
        matches = [root / relative for root in smali_roots if (root / relative).is_file()]
        if len(matches) != 1:
            raise ValueError(
                f"expected one smali class for {class_name}, found {len(matches)}"
            )
        class_paths[class_name] = matches[0]

    loader_classes = sorted(by_class)
    modified_files = []
    replaced: set[str] = set()
    for class_name in sorted(by_class):
        path = class_paths[class_name]
        before = path.read_bytes()
        transformed, class_replaced = transform_smali_class(
            before.decode("utf-8"),
            by_class[class_name],
            library_name,
        )
        path.write_text(transformed, encoding="utf-8", newline="\n")
        after = path.read_bytes()
        modified_files.append({
            "path": str(path),
            "before_sha256": _sha256(before),
            "after_sha256": _sha256(after),
            "replaced_methods": sorted(class_replaced),
            "library_loader": True,
        })
        replaced.update(class_replaced)
    if replaced != required:
        raise ValueError(
            f"smali replacement incomplete: missing={sorted(required - replaced)} "
            f"extra={sorted(replaced - required)}"
        )

    destination = decoded_root / "lib/arm64-v8a" / f"lib{library_name}.so"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(library.read_bytes())
    if _sha256_file(destination) != build_report["output_sha256"]:
        raise ValueError("copied DCC library hash mismatch")
    report = {
        "schema_version": 1,
        "stage": "dcc-java2c-patch-decoded",
        "decoded_dir": str(decoded_root),
        "input_apk_sha256": compile_report["input_sha256"],
        "compile_report_sha256": _sha256_file(compile_report_path),
        "build_report_sha256": _sha256_file(build_report_path),
        "required_methods": sorted(required),
        "replaced_methods": sorted(replaced),
        "loader_classes": loader_classes,
        "library_name": library_name,
        "library_path": str(destination),
        "library_sha256": _sha256_file(destination),
        "modified_files": modified_files,
        "summary": {
            "required_methods": len(required),
            "replaced_methods": len(replaced),
            "gate_passed": True,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def verify_apk(
    apk_path: Path,
    compile_report_path: Path,
    build_report_path: Path,
    patch_report_path: Path,
    report_path: Path,
) -> dict[str, Any]:
    compile_report = json.loads(compile_report_path.read_text(encoding="utf-8"))
    build_report = json.loads(build_report_path.read_text(encoding="utf-8"))
    patch_report = json.loads(patch_report_path.read_text(encoding="utf-8"))
    if not all(
        report.get("summary", {}).get("gate_passed") is True
        for report in (compile_report, build_report, patch_report)
    ):
        raise ValueError("DCC compile/build/patch evidence chain has a failed gate")
    if (
        build_report.get("compile_report_sha256") != _sha256_file(compile_report_path)
        or patch_report.get("compile_report_sha256") != _sha256_file(compile_report_path)
        or patch_report.get("build_report_sha256") != _sha256_file(build_report_path)
    ):
        raise ValueError("DCC compile/build/patch report hashes do not chain")

    final_inventory = inventory(apk_path)
    by_descriptor = {
        row["descriptor"]: row for row in final_inventory["methods"]
    }
    required = sorted(compile_report["compiled_methods"])
    method_rows = []
    blockers = []
    for descriptor in required:
        row = by_descriptor.get(descriptor)
        if row is None:
            blockers.append({"descriptor": descriptor, "reason": "not-found"})
            continue
        verified = row.get("native") is True and row.get("has_code") is False
        method_rows.append({
            "descriptor": descriptor,
            "dex": row["dex"],
            "access_flags": row["access_flags"],
            "native": row["native"],
            "has_code": row["has_code"],
            "verified": verified,
        })
        if not verified:
            blockers.append({
                "descriptor": descriptor,
                "reason": "native-stub-or-body-removal-missing",
            })

    library_entry = (
        f"lib/arm64-v8a/lib{patch_report['library_name']}.so"
    )
    with zipfile.ZipFile(apk_path) as archive:
        entries = archive.namelist()
        entry_count = entries.count(library_entry)
        library_bytes = archive.read(library_entry) if entry_count == 1 else b""
    library_sha256 = _sha256(library_bytes) if library_bytes else ""
    if entry_count != 1:
        blockers.append({"entry": library_entry, "reason": "library-entry-count"})
    elif library_sha256 != build_report["output_sha256"]:
        blockers.append({"entry": library_entry, "reason": "library-hash-mismatch"})

    passed = not blockers and len(method_rows) == len(required)
    report = {
        "schema_version": 1,
        "stage": "dcc-java2c-verify-apk",
        "apk": str(apk_path.resolve()),
        "apk_sha256": _sha256_file(apk_path),
        "input_apk_sha256": compile_report["input_sha256"],
        "compile_report_sha256": _sha256_file(compile_report_path),
        "build_report_sha256": _sha256_file(build_report_path),
        "patch_report_sha256": _sha256_file(patch_report_path),
        "required_methods": required,
        "verified_methods": method_rows,
        "library_entry": library_entry,
        "library_entry_count": entry_count,
        "library_sha256": library_sha256,
        "library_expected_sha256": build_report["output_sha256"],
        "blockers": blockers,
        "summary": {
            "required_methods": len(required),
            "verified_methods": sum(row["verified"] for row in method_rows),
            "blockers": len(blockers),
            "gate_passed": passed,
        },
    }
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return report


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed DCC Java2C adapter")
    subparsers = parser.add_subparsers(dest="command", required=True)
    inventory_parser = subparsers.add_parser("inventory")
    inventory_parser.add_argument("--input", type=Path, required=True)
    inventory_parser.add_argument("--report", type=Path, required=True)
    compile_parser = subparsers.add_parser("compile")
    compile_parser.add_argument("--input", type=Path, required=True)
    compile_parser.add_argument("--selection", type=Path, required=True)
    compile_parser.add_argument("--out-dir", type=Path, required=True)
    compile_parser.add_argument("--report", type=Path, required=True)
    build_parser = subparsers.add_parser("build-arm64")
    build_parser.add_argument("--compile-report", type=Path, required=True)
    build_parser.add_argument("--source-dir", type=Path, required=True)
    build_parser.add_argument("--output", type=Path, required=True)
    build_parser.add_argument("--report", type=Path, required=True)
    build_parser.add_argument("--ndk", type=Path)
    build_parser.add_argument("--api", type=int, default=23)
    patch_parser = subparsers.add_parser("patch-decoded")
    patch_parser.add_argument("--decoded-dir", type=Path, required=True)
    patch_parser.add_argument("--compile-report", type=Path, required=True)
    patch_parser.add_argument("--build-report", type=Path, required=True)
    patch_parser.add_argument("--report", type=Path, required=True)
    patch_parser.add_argument("--library-name", default="avmp-dcc")
    verify_parser = subparsers.add_parser("verify-apk")
    verify_parser.add_argument("--apk", type=Path, required=True)
    verify_parser.add_argument("--compile-report", type=Path, required=True)
    verify_parser.add_argument("--build-report", type=Path, required=True)
    verify_parser.add_argument("--patch-report", type=Path, required=True)
    verify_parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.command == "inventory":
        report = inventory(args.input)
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(report["summary"], sort_keys=True))
        return 0
    if args.command == "build-arm64":
        report = build_arm64(
            args.compile_report,
            args.source_dir,
            args.output,
            args.report,
            args.ndk,
            args.api,
        )
        print(json.dumps(report["summary"], sort_keys=True))
        return 0
    if args.command == "patch-decoded":
        report = patch_decoded_apk(
            args.decoded_dir,
            args.compile_report,
            args.build_report,
            args.report,
            args.library_name,
        )
        print(json.dumps(report["summary"], sort_keys=True))
        return 0
    if args.command == "verify-apk":
        report = verify_apk(
            args.apk,
            args.compile_report,
            args.build_report,
            args.patch_report,
            args.report,
        )
        print(json.dumps(report["summary"], sort_keys=True))
        return 0 if report["summary"]["gate_passed"] else 1
    report = compile_selection(args.input, args.selection, args.out_dir, args.report)
    print(json.dumps(report["summary"], sort_keys=True))
    return 0 if report["summary"]["gate_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
