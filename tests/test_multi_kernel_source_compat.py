import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "work" / "multi-kernel-src" / "lsdriver"
MATRIX = ROOT / "work" / "multi-kernel-targets.json"


class MultiKernelSourceCompatTests(unittest.TestCase):
    def test_target_matrix_covers_each_vendor_and_series_once(self):
        data = json.loads(MATRIX.read_text(encoding="ascii"))
        self.assertEqual(data["schema_version"], 1)
        targets = data["targets"]
        self.assertEqual(len(targets), 6)
        pairs = {(target["vendor"], target["series"]) for target in targets}
        self.assertEqual(
            pairs,
            {
                ("xiaomi", "5.15"),
                ("xiaomi", "6.1"),
                ("xiaomi", "6.6"),
                ("oneplus", "5.15"),
                ("oneplus", "6.1"),
                ("oneplus", "6.6"),
            },
        )
        for target in targets:
            self.assertTrue(target["source_version"].startswith(target["series"] + "."))
            self.assertRegex(target["commit"], r"^[0-9a-f]{40}$")
            release = target["stock_image_release"]
            if release is not None:
                self.assertTrue(release.startswith(target["series"] + "."))
                self.assertRegex(target["stock_boot_sha256"], r"^[0-9a-f]{64}$")
                self.assertRegex(target["stock_image_sha256"], r"^[0-9a-f]{64}$")

    def test_private_input_handle_extension_is_not_used(self):
        source = (SOURCE / "touch_inject.c").read_text(encoding="utf-8")
        self.assertNotIn("->handle_events", source)
        self.assertNotRegex(source, r"\.events\s*=\s*ptm_")
        self.assertIn(".filter = ptm_filter_marker", source)
        self.assertIn("handler->events(handle, vals, count);", source)
        self.assertIn("ptm_process_values(handle, frame, count)", source)
        self.assertIn("ptm_send_downstream_locked(frame, count)", source)
        self.assertIn("capture_capacity", source)

    def test_target_hardening_is_inherited_by_default(self):
        makefile = (SOURCE / "Makefile").read_text(encoding="utf-8")
        self.assertIn("LS_RELAX_TARGET_HARDENING ?= n", makefile)
        guarded = re.search(
            r"ifeq \(\$\(LS_RELAX_TARGET_HARDENING\),y\)(.*?)endif",
            makefile,
            re.DOTALL,
        )
        self.assertIsNotNone(guarded)
        self.assertIn("-fno-sanitize=cfi", guarded.group(1))
        self.assertIn("-mbranch-protection=none", guarded.group(1))
        self.assertNotIn("-fno-sanitize=cfi", makefile[guarded.end() :])
        self.assertIn("LS_ENABLE_DWARF ?= y", makefile)

    def test_version_features_are_centralized(self):
        compat = (SOURCE / "kernel_compat.h").read_text(encoding="ascii")
        self.assertIn("KERNEL_VERSION(5, 15, 0)", compat)
        self.assertIn("CONFIG_ANON_VMA_NAME", compat)
        self.assertIn("KERNEL_VERSION(6, 1, 0)", compat)
        self.assertIn("LS_HAVE_MAPLE_TREE_VMA", compat)
        self.assertIn("LS_SCHED_SWITCH_HAS_PREV_STATE", compat)
        self.assertIn("LS_NEEDS_6_6_PRIVATE_HELPER_RESOLUTION", compat)
        self.assertIn("LS_TARGET_USES_KCFI", compat)
        tool = (SOURCE / "tool.c").read_text(encoding="utf-8")
        self.assertIn("#if LS_HAVE_ANON_VMA_NAME", tool)
        self.assertIn("vma->vm_file ? NULL : vma->anon_name", tool)
        self.assertNotIn("anon_vma_name(vma)", tool)
        self.assertIn("#if LS_HAVE_MAPLE_TREE_VMA", tool)
        stale = (SOURCE / "stale_itlb.c").read_text(encoding="utf-8")
        self.assertNotIn("set_pte_at(", stale)
        self.assertGreaterEqual(stale.count("set_pte(ptep,"), 2)
        self.assertNotRegex(stale, r"(?<!ls_)flush_tlb_mm\(")
        self.assertGreaterEqual(stale.count("ls_flush_tlb_mm("), 3)
        main = (SOURCE / "main.c").read_text(encoding="utf-8")
        kgsl = (SOURCE / "kgsl_hide.c").read_text(encoding="utf-8")
        self.assertNotIn("synchronize_rcu_tasks();", main)
        self.assertNotIn("synchronize_rcu_tasks();", kgsl)
        self.assertIn("ls_synchronize_hook_readers();", main)
        self.assertIn("ls_synchronize_hook_readers();", kgsl)
        self.assertIn("synchronize_rcu_tasks", tool)
        self.assertIn("__mmu_notifier_arch_invalidate_secondary_tlbs", tool)


if __name__ == "__main__":
    unittest.main()
