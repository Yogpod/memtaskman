"""Linux /proc parsers run on any OS: they only take text."""

import unittest

from memtaskman.linux import categorize, parse_kb_table, parse_smaps, parse_stat_faults, parse_vmstat, summarize_smaps
from memtaskman.model import CAT_HEAP, CAT_IMAGE, CAT_MAPPED, CAT_OTHER, CAT_SHM, CAT_STACK

MEMINFO = """\
MemTotal:       16314288 kB
MemFree:         1234560 kB
MemAvailable:    9876540 kB
Buffers:          102400 kB
Cached:          6543210 kB
HugePages_Total:       0
"""

SMAPS = """\
55d0c0000000-55d0c0021000 r-xp 00000000 08:01 1234   /usr/bin/python3.12
Size:                132 kB
Rss:                 128 kB
Shared_Clean:        128 kB
Shared_Dirty:          0 kB
Swap:                  0 kB
55d0c1000000-55d0c5000000 rw-p 00000000 00:00 0      [heap]
Size:              65536 kB
Rss:               60000 kB
Shared_Clean:          0 kB
Shared_Dirty:          0 kB
Swap:               1024 kB
7f0000000000-7f0010000000 r--p 00000000 08:01 999    /data/models/llama.gguf
Size:             262144 kB
Rss:              200000 kB
Shared_Clean:     200000 kB
Swap:                  0 kB
7f1000000000-7f1000100000 rw-s 00000000 00:05 77     /dev/shm/pulse-shm-1
Size:               1024 kB
Rss:                 512 kB
Shared_Dirty:        512 kB
7f2000000000-7f2004000000 rw-p 00000000 00:00 0
Size:              65536 kB
Rss:                4096 kB
7ffd00000000-7ffd00021000 rw-p 00000000 00:00 0      [stack]
Size:                132 kB
Rss:                  64 kB
VmFlags: rd wr mr mw me gd ac
"""


class LinuxParserTests(unittest.TestCase):
    def test_meminfo(self):
        mi = parse_kb_table(MEMINFO)
        self.assertEqual(mi["MemTotal"], 16314288 * 1024)
        self.assertEqual(mi["Cached"], 6543210 * 1024)
        self.assertEqual(mi["HugePages_Total"], 0)  # unitless lines stay raw

    def test_vmstat(self):
        self.assertEqual(parse_vmstat("pgfault 123\npgmajfault 4\n"), {"pgfault": 123, "pgmajfault": 4})

    def test_stat_faults_with_spaces_in_comm(self):
        line = "1234 (Web Content (x)) S 1 1234 1234 0 -1 4194560 5000 0 30 0 10 5 0 0 20 0 1 0 100 0 0"
        self.assertEqual(parse_stat_faults(line), 5030)

    def test_categorize(self):
        self.assertEqual(categorize("", "rw-p"), CAT_HEAP)
        self.assertEqual(categorize("[heap]", "rw-p"), CAT_HEAP)
        self.assertEqual(categorize("[anon:v8]", "rw-p"), CAT_HEAP)
        self.assertEqual(categorize("[stack]", "rw-p"), CAT_STACK)
        self.assertEqual(categorize("[vdso]", "r-xp"), CAT_OTHER)
        self.assertEqual(categorize("/usr/lib/libc.so.6", "r--p"), CAT_IMAGE)
        self.assertEqual(categorize("/usr/bin/bash", "r-xp"), CAT_IMAGE)
        self.assertEqual(categorize("/home/u/data.bin", "r--p"), CAT_MAPPED)
        self.assertEqual(categorize("/dev/shm/x", "rw-s"), CAT_SHM)
        self.assertEqual(categorize("/memfd:wayland (deleted)", "rw-s"), CAT_SHM)

    def test_rollup_fields(self):
        roll = parse_kb_table("Rss: 2048 kB\nPss: 1024 kB\nPrivate_Clean: 100 kB\nPrivate_Dirty: 400 kB\n")
        self.assertEqual(roll["Pss"], 1024 * 1024)
        self.assertEqual(roll["Private_Clean"] + roll["Private_Dirty"], 500 * 1024)

    def test_smaps_summary(self):
        maps = parse_smaps(SMAPS)
        self.assertEqual(len(maps), 6)
        cats, files = summarize_smaps(maps)
        by = {c.name: c for c in cats}
        self.assertEqual(by[CAT_HEAP].resident, (60000 + 4096) * 1024)
        self.assertEqual(by[CAT_HEAP].swapped, 1024 * 1024)
        self.assertEqual(by[CAT_HEAP].regions, 2)
        self.assertEqual(by[CAT_MAPPED].resident_shared, 200000 * 1024)
        self.assertEqual(by[CAT_STACK].mapped, 132 * 1024)
        self.assertEqual(files[0].path, "/data/models/llama.gguf")
        self.assertEqual(files[0].kind, "mapped")


if __name__ == "__main__":
    unittest.main()
