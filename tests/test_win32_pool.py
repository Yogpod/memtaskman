import sys
import unittest


@unittest.skipUnless(sys.platform == "win32", "Windows only")
class PoolTagTests(unittest.TestCase):
    def test_decode(self):
        from memtaskman.win32 import decode_tag

        self.assertEqual(decode_tag(b"DAL3"), "DAL3")
        self.assertEqual(decode_tag(b"Ntf "), "Ntf")  # space padded
        self.assertEqual(decode_tag(bytes([0x41, 0x42, 0, 0])), "AB")
        self.assertEqual(decode_tag(bytes([0xFF, 0x10, 0x41, 0x42])), "ff104142")  # not text: hex

    def test_live_totals_are_sane(self):
        from memtaskman.win32 import pool_tags

        tags = pool_tags()
        self.assertIsNotNone(tags)
        self.assertGreater(len(tags), 100)
        nonpaged = sum(v[0] for v in tags.values())
        self.assertGreater(nonpaged, 16 * 1024 * 1024)  # every Windows system has tens of MB


if __name__ == "__main__":
    unittest.main()
