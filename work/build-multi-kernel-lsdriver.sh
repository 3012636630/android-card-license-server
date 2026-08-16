#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 TARGET_ID" >&2
  exit 2
fi

target_id=$1
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
matrix="$root/work/multi-kernel-targets.json"
evidence="$root/work/multi-kernel-build-inputs/$target_id"
driver="$root/work/multi-kernel-src/lsdriver"
artifacts="$root/outputs/multi-kernel-cloud/$target_id"

for path in "$matrix" "$driver" "$evidence/config" \
  "$evidence/Module.symvers" "$evidence/reference.ko"; do
  if [[ ! -e "$path" ]]; then
    echo "missing build input: $path" >&2
    exit 2
  fi
done

mapfile -t target < <(python3 - "$matrix" "$target_id" <<'PY'
import json
import sys

matrix_path, target_id = sys.argv[1:]
data = json.load(open(matrix_path, encoding="ascii"))
matches = [target for target in data["targets"] if target["id"] == target_id]
if len(matches) != 1:
    raise SystemExit(f"expected one target named {target_id}, found {len(matches)}")
target = matches[0]
for key in (
    "repository",
    "commit",
    "stock_image_release",
    "clang_branch",
    "clang_revision",
    "module_layout_crc",
):
    print(target[key])
PY
)
if [[ ${#target[@]} -ne 6 ]]; then
  echo "incomplete target record for $target_id" >&2
  exit 1
fi
repository=${target[0]}
commit=${target[1]}
release=${target[2]}
clang_branch=${target[3]}
clang_revision=${target[4]}
module_layout_crc=${target[5]}

build_parent="$root/.multi-kernel-build"
mkdir -p "$build_parent"
build_parent=$(cd "$build_parent" && pwd -P)
workspace="$build_parent/$target_id"
case "$workspace" in
  "$build_parent"/*) ;;
  *) echo "refusing unsafe build directory: $workspace" >&2; exit 1 ;;
esac
kernel="$workspace/kernel"
toolchain="$workspace/clang"
out="$workspace/out"

rm -rf -- "$workspace"
mkdir -p "$workspace" "$artifacts"

git init "$kernel"
git -C "$kernel" remote add origin "$repository"
git -C "$kernel" fetch --depth=1 --filter=blob:none origin "$commit"
git -C "$kernel" checkout --detach FETCH_HEAD
actual_commit=$(git -C "$kernel" rev-parse HEAD)
if [[ "$actual_commit" != "$commit" ]]; then
  echo "source commit mismatch: $actual_commit != $commit" >&2
  exit 1
fi

git clone --depth=1 --filter=blob:none --sparse \
  --branch "$clang_branch" \
  https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86 \
  "$toolchain"
git -C "$toolchain" sparse-checkout set "$clang_revision"
clang_source_commit=$(git -C "$toolchain" rev-parse HEAD)
clang_root="$toolchain/$clang_revision"
if [[ ! -x "$clang_root/bin/clang" ]]; then
  echo "missing requested compiler: $clang_root/bin/clang" >&2
  exit 1
fi
export PATH="$clang_root/bin:$PATH"

base_release=${release%%-*}
IFS=. read -r version patchlevel sublevel <<<"$base_release"
if [[ -z "${version:-}" || -z "${patchlevel:-}" || -z "${sublevel:-}" ]]; then
  echo "invalid stock release: $release" >&2
  exit 1
fi
python3 - "$kernel/Makefile" "$version" "$patchlevel" "$sublevel" <<'PY'
import re
import sys

path, version, patchlevel, sublevel = sys.argv[1:]
text = open(path, encoding="utf-8").read()
values = {
    "VERSION": version,
    "PATCHLEVEL": patchlevel,
    "SUBLEVEL": sublevel,
    "EXTRAVERSION": "",
}
for key, value in values.items():
    text, count = re.subn(
        rf"(?m)^{key}\s*=.*$", f"{key} = {value}", text, count=1
    )
    if count != 1:
        raise SystemExit(f"expected one {key} assignment in {path}")
open(path, "w", encoding="utf-8", newline="\n").write(text)
PY

mkdir -p "$out"
cp "$evidence/config" "$out/.config"
touch "$kernel/abi_symbollist.raw"
local_suffix=${release#"$base_release"}
"$kernel/scripts/config" --file "$out/.config" \
  --set-str LOCALVERSION "$local_suffix" \
  --disable LOCALVERSION_AUTO \
  --disable MODULE_SIG_ALL \
  --set-str UNUSED_KSYMS_WHITELIST "$kernel/abi_symbollist.raw"

export ARCH=arm64
export LLVM=1
export LLVM_IAS=1
export KBUILD_BUILD_USER=codex
export KBUILD_BUILD_HOST=github-actions
export KBUILD_BUILD_TIMESTAMP="1970-01-01 00:00:00 UTC"
export SOURCE_DATE_EPOCH=0

make_flags=(
  -C "$kernel"
  O="$out"
  ARCH=arm64
  LLVM=1
  LLVM_IAS=1
)
make "${make_flags[@]}" olddefconfig
make "${make_flags[@]}" -j"$(nproc)" modules_prepare
cp "$evidence/Module.symvers" "$out/Module.symvers"

generated_release=$(cat "$out/include/config/kernel.release")
if [[ "$generated_release" != "$release" ]]; then
  echo "generated release mismatch: $generated_release != $release" >&2
  exit 1
fi

make "${make_flags[@]}" \
  M="$driver" \
  LS_RELAX_TARGET_HARDENING=n \
  LS_ENABLE_DWARF=y \
  -j"$(nproc)" modules 2>&1 | tee "$artifacts/kbuild.log"

module="$artifacts/lsdriver-$target_id-carrier.ko"
cp "$driver/lsdriver.ko" "$module"
cp "$out/.config" "$artifacts/config.build"
cp "$out/Module.symvers" "$artifacts/Module.symvers.target"
"$kernel/scripts/diffconfig" -m "$evidence/config" "$out/.config" \
  > "$artifacts/config.delta" || true
"$clang_root/bin/clang" --version > "$artifacts/clang-version.txt"

python3 "$root/work/verify-multi-kernel-carrier.py" \
  --target-id "$target_id" \
  --matrix "$matrix" \
  --module "$module" \
  --config "$evidence/config" \
  --module-symvers "$evidence/Module.symvers" \
  --source-commit "$actual_commit" \
  --clang-revision "$clang_revision" \
  --clang-source-commit "$clang_source_commit" \
  --clang-binary "$clang_root/bin/clang" \
  --output "$artifacts/carrier-manifest.json"

python3 "$root/work/auto-adapt-android-module.py" \
  --source-module "$module" \
  --reference-module "$evidence/reference.ko" \
  --module-symvers "$evidence/Module.symvers" \
  --config "$evidence/config" \
  --kernel-release "$release" \
  --cfi-mode strict \
  --analyze-only \
  --manifest "$artifacts/adapter-analysis.json"

python3 - "$artifacts/carrier-manifest.json" "$module_layout_crc" <<'PY'
import json
import sys

path, expected_crc = sys.argv[1:]
manifest = json.load(open(path, encoding="ascii"))
if manifest["module"]["module_layout_crc"] != expected_crc:
    raise SystemExit("carrier manifest module_layout CRC mismatch")
print("CARRIER_BUILD_VERIFIED=true")
PY
