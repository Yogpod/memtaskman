import unittest

from memtaskman.wslhost import decode_wsl_output, guest_breakdown, parse_running, parse_wslconfig

M = 1024 * 1024


class WslHostTests(unittest.TestCase):
    def test_decode_utf16_list_output(self):
        raw = "Ubuntu\r\ndocker-desktop\r\n".encode("utf-16-le")
        self.assertEqual(parse_running(decode_wsl_output(raw)), ["Ubuntu", "docker-desktop"])

    def test_decode_utf8_command_output(self):
        self.assertEqual(decode_wsl_output(b"MemTotal: 1 kB\n"), "MemTotal: 1 kB\n")

    def test_no_running_distros(self):
        self.assertEqual(parse_running(decode_wsl_output(b"")), [])

    def test_wslconfig(self):
        cfg = parse_wslconfig("[wsl2]\nmemory=8GB  # cap\nswap = 0\n\n[experimental]\nautoMemoryReclaim=gradual\n")
        self.assertEqual(cfg["wsl2.memory"], "8GB")
        self.assertEqual(cfg["wsl2.swap"], "0")
        self.assertEqual(cfg["experimental.automemoryreclaim"], "gradual")

    def test_guest_breakdown(self):
        mi = {"MemTotal": 8192 * M, "MemAvailable": 7000 * M, "MemFree": 6000 * M, "Cached": 900 * M,
              "Buffers": 100 * M, "Shmem": 50 * M, "AnonPages": 120 * M, "Slab": 60 * M}
        g = guest_breakdown(mi)
        self.assertEqual(g["used"], 1192 * M)
        self.assertEqual(g["cache"], 1000 * M)
        self.assertEqual(g["reclaimable_cache"], 950 * M)
        self.assertIsNone(guest_breakdown({})["used"])


if __name__ == "__main__":
    unittest.main()
