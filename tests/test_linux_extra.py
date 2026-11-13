"""zram / slab / tmpfs / SysV shm / shm holder parsers (pure, any OS)."""

import unittest

from memtaskman.linux import parse_mounts_tmpfs, parse_slabinfo, parse_sysv_shm, parse_zram_mm_stat, shm_holders

SLABINFO = """slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables <limit> <batchcount> <sharedfactor> : slabdata <active_slabs> <num_slabs> <sharedavail>
dentry             120000 126000    192   21    1 : tunables    0    0    0 : slabdata   6000   6000      0
inode_cache         30000  30100    600   13    2 : tunables    0    0    0 : slabdata   2315   2315      0
kmalloc-8k             40     48   8192    4    8 : tunables    0    0    0 : slabdata     12     12      0
broken line without slabdata
"""

SHM = """       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap
         0          5  1600               4194304  1234  1300      2  1000  1000  1000  1000 1700000000 0 1700000000               2097152                     0
"""


class LinuxExtraTests(unittest.TestCase):
    def test_zram(self):
        st = parse_zram_mm_stat("524288000 131072000 140000000 0 150000000 1000 0 0 0\n")
        self.assertEqual(st, {"original": 524288000, "compressed": 131072000, "used": 140000000})
        self.assertIsNone(parse_zram_mm_stat(""))

    def test_slabinfo(self):
        rows = parse_slabinfo(SLABINFO, page=4096)
        self.assertEqual([r[0] for r in rows], ["dentry", "inode_cache", "kmalloc-8k"])
        self.assertEqual(rows[0][1], 6000 * 1 * 4096)
        self.assertEqual(rows[1][1], 2315 * 2 * 4096)
        self.assertEqual(rows[0][2], 120000)

    def test_tmpfs_mounts(self):
        text = ("none /run tmpfs rw 0 0\n/dev/sda1 / ext4 rw 0 0\nnone /run/my\\040disk tmpfs rw 0 0\n"
                "ramfs /mnt/r ramfs rw 0 0\n")
        self.assertEqual(parse_mounts_tmpfs(text), ["/run", "/run/my disk", "/mnt/r"])

    def test_sysv_shm(self):
        rows = parse_sysv_shm(SHM)
        self.assertEqual(rows, [{"shmid": 5, "size": 4194304, "rss": 2097152, "swap": 0, "cpid": 1234, "nattch": 2}])
        self.assertEqual(parse_sysv_shm(""), [])

    def test_shm_holders(self):
        maps = {
            10: "7f00-7f10 rw-s 00000000 00:1a 5 /dev/shm/pulse-shm-1\n7f20-7f30 rw-s 0 00:01 9 /memfd:wayland (deleted)\n",
            11: "7f00-7f10 rw-s 00000000 00:1a 5 /dev/shm/pulse-shm-1\n7f40-7f50 r-xp 0 08:01 3 /usr/lib/libc.so.6\n",
        }
        h = shm_holders(maps)
        self.assertEqual(h, {"/dev/shm/pulse-shm-1": {10, 11}, "/memfd:wayland": {10}})


if __name__ == "__main__":
    unittest.main()
