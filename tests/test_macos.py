"""macOS struct layouts and rules: pure Python, so these run on every OS."""

import ctypes
import unittest

from memtaskman import macos
from memtaskman.macos import categorize_region, module_basename, pressure_name, vm_breakdown
from memtaskman.model import CAT_GPU, CAT_HEAP, CAT_IMAGE, CAT_JIT, CAT_MAPPED, CAT_OTHER, CAT_SHM, CAT_STACK
from memtaskman.runtime import detect


class StructLayoutTests(unittest.TestCase):
    """Sizes must match the C headers exactly or the kernel writes past our buffers."""

    def test_sizes(self):
        self.assertEqual(ctypes.sizeof(macos.vm_statistics64), 152)
        self.assertEqual(macos.HOST_VM_INFO64_COUNT, 38)
        self.assertEqual(ctypes.sizeof(macos.rusage_info_v4), 296)
        self.assertEqual(ctypes.sizeof(macos.proc_taskinfo), 96)
        self.assertEqual(ctypes.sizeof(macos.proc_regioninfo), 96)
        self.assertEqual(ctypes.sizeof(macos.vinfo_stat), 136)
        self.assertEqual(ctypes.sizeof(macos.vnode_info), 152)
        self.assertEqual(ctypes.sizeof(macos.proc_regionwithpathinfo), 1272)

    def test_key_offsets(self):
        self.assertEqual(macos.rusage_info_v4.ri_phys_footprint.offset, 72)
        self.assertEqual(macos.rusage_info_v4.ri_lifetime_max_phys_footprint.offset, 16 + 8 * 28)
        self.assertEqual(macos.proc_regioninfo.pri_address.offset, 80)
        self.assertEqual(macos.vm_statistics64.compressor_page_count.offset, 128)


class RegionRuleTests(unittest.TestCase):
    def test_tags(self):
        self.assertEqual(categorize_region(1, macos.SM_PRIVATE, "", 3), CAT_HEAP)  # malloc
        self.assertEqual(categorize_region(11, macos.SM_PRIVATE, "", 3), CAT_HEAP)  # malloc nano
        self.assertEqual(categorize_region(30, macos.SM_PRIVATE, "", 3), CAT_STACK)
        self.assertEqual(categorize_region(31, macos.SM_EMPTY, "", 0), CAT_OTHER)  # guard
        self.assertEqual(categorize_region(100, macos.SM_SHARED, "", 3), CAT_GPU)  # IOAccelerator
        self.assertEqual(categorize_region(88, macos.SM_SHARED, "", 3), CAT_GPU)  # IOSurface
        self.assertEqual(categorize_region(51, macos.SM_PRIVATE, "", 3), CAT_GPU)  # CoreAnimation
        self.assertEqual(categorize_region(64, macos.SM_PRIVATE, "", 7), CAT_JIT)

    def test_files_and_sharing(self):
        cache = "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e"
        self.assertEqual(categorize_region(0, macos.SM_COW, cache, 5), CAT_IMAGE)
        self.assertEqual(categorize_region(0, macos.SM_COW, "/usr/lib/libz.1.dylib", 1), CAT_IMAGE)
        fw = "/Applications/Slack.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"
        self.assertEqual(categorize_region(0, macos.SM_COW, fw, 5), CAT_IMAGE)
        self.assertEqual(categorize_region(0, macos.SM_PRIVATE, "/Users/x/model.gguf", 1), CAT_MAPPED)
        self.assertEqual(categorize_region(0, macos.SM_TRUESHARED, "", 3), CAT_SHM)
        self.assertEqual(categorize_region(0, macos.SM_PRIVATE, "", 3), CAT_HEAP)
        self.assertEqual(module_basename(fw), "Electron Framework")

    def test_vm_breakdown_matches_activity_monitor(self):
        page = 16384
        v = {"free_count": 1000, "speculative_count": 200, "wire_count": 3000, "internal_page_count": 50000,
             "purgeable_count": 2000, "external_page_count": 20000, "compressor_page_count": 4000,
             "total_uncompressed_pages_in_compressor": 12000}
        b = vm_breakdown(v, page)
        self.assertEqual(b["app"], 48000 * page)
        self.assertEqual(b["cached"], 22000 * page)
        self.assertEqual(b["used"], (48000 + 3000 + 4000) * page)
        self.assertEqual(b["free"], 1200 * page)
        self.assertEqual(b["compressed_original"], 12000 * page)

    def test_pressure(self):
        self.assertEqual(pressure_name(1), "normal")
        self.assertEqual(pressure_name(4), "critical")
        self.assertIsNone(pressure_name(None))


class MacRuntimeTests(unittest.TestCase):
    def test_chrome_helper(self):
        r = detect("Google Chrome Helper (Renderer)", [], ["Google Chrome Helper (Renderer)", "--type=renderer"])
        self.assertEqual((r.name, r.detail), ("Chrome", "renderer"))

    def test_electron_framework(self):
        r = detect("Slack Helper (GPU)", ["Electron Framework"], ["Slack Helper (GPU)", "--type=gpu-process"])
        self.assertEqual((r.name, r.detail), ("Electron", "gpu"))

    def test_safari_and_system(self):
        self.assertEqual(detect("com.apple.WebKit.WebContent").name, "Safari")
        self.assertEqual(detect("WindowServer").detail, "WindowServer")
        self.assertEqual(detect("com.apple.Virtualization.VirtualMachine").name, "VM")

    def test_arc_prefix_does_not_overmatch(self):
        self.assertIsNone(detect("ArchiveUtility", [], []))
        self.assertEqual(detect("Arc", [], []).name, "Arc")

    def test_python_framework(self):
        self.assertTrue(detect("python3.14", ["Python", "libmlx.dylib"], []).name.startswith("Python"))


if __name__ == "__main__":
    unittest.main()
