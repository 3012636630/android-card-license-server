import json
import hashlib
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "work" / "multi-kernel-targets.json"
BUILD = ROOT / "work" / "build-multi-kernel-lsdriver.sh"
VERIFY = ROOT / "work" / "verify-multi-kernel-carrier.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build-multi-kernel-lsdriver.yml"
INPUTS = ROOT / "work" / "multi-kernel-build-inputs"


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class MultiKernelCloudBuildTests(unittest.TestCase):
    def test_target_toolchains_and_layout_crcs_are_pinned(self):
        targets = json.loads(MATRIX.read_text(encoding="ascii"))["targets"]
        expected = {
            "5.15": ("android13-release", "clang-r450784e", "android-13.0.0_r*", "0x0222dd63"),
            "6.1": ("android14-release", "clang-r487747c", "android-14.0.0_r*", "0xea759d7f"),
            "6.6": ("android15-release", "clang-r510928", "android-15.0.0_r*", "0x4e276f37"),
        }
        for target in targets:
            actual = (
                target["clang_branch"],
                target["clang_revision"],
                target["clang_tag_pattern"],
                target["module_layout_crc"],
            )
            self.assertEqual(actual, expected[target["series"]])

    def test_build_keeps_target_hardening_and_uses_stock_symvers(self):
        script = BUILD.read_text(encoding="ascii")
        self.assertIn("LS_RELAX_TARGET_HARDENING=n", script)
        self.assertNotIn("LS_RELAX_TARGET_HARDENING=y", script)
        self.assertIn("LS_ENABLE_DWARF=y", script)
        symvers_args = '"$evidence/Module.symvers" "$out/Module.symvers"'
        self.assertIn(symvers_args, script)
        self.assertLess(script.index("modules_prepare"), script.index(symvers_args))
        self.assertIn('if fields[4] == "-":', script)
        self.assertIn("normalized_dash_namespaces", script)
        self.assertIn('generated_release" != "$release', script)
        self.assertIn("scanning $clang_tag_pattern", script)
        self.assertIn("unsafe missing Kconfig path", script)
        self.assertIn("kconfig-stubs.txt", script)
        self.assertIn(': > "$kernel/.scmversion"', script)
        self.assertIn('--set-str LOCALVERSION "$local_suffix"', script)
        self.assertNotIn('  LOCALVERSION="$local_suffix"\n)', script)
        self.assertIn('generated_release" != "$base_release', script)
        self.assertIn('> "$out/include/config/kernel.release"', script)
        self.assertIn('> "$out/include/generated/utsrelease.h"', script)
        self.assertIn('KERNELRELEASE="$release"', script)
        self.assertIn("release-normalization.txt", script)
        self.assertIn("BROKEN_SYMLINK", script)
        self.assertIn("--cfi-mode strict", script)
        self.assertNotIn("--allow-kernel-series-mismatch", script)

    def test_verifier_requires_exact_release_crc_cfi_and_dwarf(self):
        script = VERIFY.read_text(encoding="ascii")
        for marker in (
            'release != target["stock_image_release"]',
            "mismatched_crcs",
            "5.15 carrier lacks legacy Clang CFI",
            "carrier lacks KCFI metadata",
            "carrier lacks DWARF debug information",
            '"clang_binary_sha256": sha256_file(args.clang_binary)',
            '"tested": False',
        ):
            self.assertIn(marker, script)

    def test_workflow_covers_all_matrix_targets(self):
        targets = json.loads(MATRIX.read_text(encoding="ascii"))["targets"]
        workflow = WORKFLOW.read_text(encoding="ascii")
        for target in targets:
            self.assertGreaterEqual(workflow.count(target["id"]), 2)
        self.assertIn("fail-fast: false", workflow)
        self.assertIn("target: ${{ fromJSON(", workflow)
        self.assertNotIn("inputs.target == matrix.target", workflow)
        self.assertIn("ubuntu-22.04", workflow)

    def test_bundled_evidence_matches_generated_manifests(self):
        targets = json.loads(MATRIX.read_text(encoding="ascii"))["targets"]
        bundled = json.loads((INPUTS / "manifest.json").read_text(encoding="ascii"))
        self.assertEqual(bundled["schema_version"], 1)
        self.assertEqual(
            {record["id"] for record in bundled["targets"]},
            {target["id"] for target in targets},
        )
        for target in targets:
            directory = INPUTS / target["id"]
            manifest = json.loads(
                (directory / "symvers-manifest.json").read_text(encoding="ascii")
            )
            self.assertEqual(
                sha256_file(directory / "config"), manifest["config"]["sha256"]
            )
            self.assertEqual(
                sha256_file(directory / "Module.symvers"),
                manifest["outputs"]["module_symvers"]["sha256"],
            )
            self.assertEqual(
                sha256_file(directory / "reference.ko"),
                manifest["references"][0]["sha256"],
            )
            self.assertEqual(
                manifest["exports"]["module_layout_crc"],
                target["module_layout_crc"],
            )


if __name__ == "__main__":
    unittest.main()
