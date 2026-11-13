import json
import math
import os
import tempfile
import unittest

from memtaskman.cli import parse_duration
from memtaskman.leaks import fit, rank, read_jsonl, summarize

M = 1024 * 1024


def series(fn, seconds=300, step=5):
    return [(float(t), float(fn(t))) for t in range(0, seconds + 1, step)]


class TrendTests(unittest.TestCase):
    def test_linear_leak_is_flagged(self):
        tr = fit(series(lambda t: 200 * M + t * 200 * 1024))  # +200 KiB/s -> ~59 MiB in 5 min
        self.assertAlmostEqual(tr.slope, 200 * 1024, delta=1)
        self.assertGreater(tr.r2, 0.99)
        self.assertTrue(tr.is_leak)

    def test_gc_sawtooth_is_not_flagged(self):
        # Grows 2 MiB/s for 60 s then collects back down: big swings, no trend.
        tr = fit(series(lambda t: 300 * M + (t % 60) * 2 * M))
        self.assertFalse(tr.is_leak)
        self.assertLess(tr.r2, 0.85)

    def test_flat_and_noisy_is_not_flagged(self):
        tr = fit(series(lambda t: 500 * M + (M if (t // 5) % 2 else -M)))
        self.assertFalse(tr.is_leak)

    def test_small_growth_is_not_flagged(self):
        tr = fit(series(lambda t: 1024 * M + t * 10 * 1024))  # ~3 MiB over 5 min: below 16 MiB
        self.assertGreater(tr.r2, 0.99)
        self.assertFalse(tr.is_leak)

    def test_relative_threshold(self):
        tr = fit(series(lambda t: 8192 * M + t * 100 * 1024))  # ~29 MiB on 8 GiB: under 5%
        self.assertFalse(tr.is_leak)

    def test_too_short(self):
        tr = fit(series(lambda t: t * M, seconds=60))
        self.assertFalse(tr.is_leak)
        self.assertIsNone(fit([(0.0, 1.0), (1.0, 2.0)]))


class RecordingTests(unittest.TestCase):
    def _write(self, lines):
        fd, path = tempfile.mkstemp(suffix=".jsonl")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self.addCleanup(os.remove, path)
        return path

    def _snap(self, t, procs):
        return json.dumps({"version": 1, "time": t, "processes": procs})

    def test_torn_last_line_skipped(self):
        p = {"pid": 1, "name": "a", "create_time": 1.0, "private": M}
        path = self._write([self._snap(0, [p]), self._snap(5, [p]), '{"version": 1, "time": 10, "proc'])
        snaps, skipped = read_jsonl(path)
        self.assertEqual((len(snaps), skipped), (2, 1))

    def test_summary_ranks_leak_first_and_splits_pid_reuse(self):
        lines = []
        for i in range(61):
            t = i * 5.0
            procs = [
                {"pid": 10, "name": "leaky.exe", "create_time": 1.0, "private": 100 * M + int(t * 300 * 1024)},
                {"pid": 11, "name": "steady.exe", "create_time": 1.0, "private": 400 * M},
                {"pid": 12, "name": "gc.exe", "create_time": 1.0,
                 "private": 300 * M + int(40 * M * (0.5 + 0.5 * math.sin(t / 20)))},
            ]
            # pid 20 is reused halfway through: two different processes
            procs.append({"pid": 20, "name": "first" if i < 30 else "second",
                          "create_time": 2.0 if i < 30 else 3.0, "private": 50 * M})
            lines.append(self._snap(t, procs))
        snaps, _ = read_jsonl(self._write(lines))
        rows = list(rank(summarize(snaps)))
        self.assertEqual(rows[0].name, "leaky.exe")
        self.assertTrue(rows[0].trend.is_leak)
        self.assertEqual(sum(1 for r in rows if r.trend and r.trend.is_leak), 1)
        self.assertEqual({r.name for r in rows if r.pid == 20}, {"first", "second"})

    def test_parse_duration(self):
        self.assertEqual(parse_duration("90"), 90)
        self.assertEqual(parse_duration("90s"), 90)
        self.assertEqual(parse_duration("30m"), 1800)
        self.assertEqual(parse_duration("2h"), 7200)


if __name__ == "__main__":
    unittest.main()
