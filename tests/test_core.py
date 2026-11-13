import unittest

from memtaskman.app import ram_segments, stacked_bar
from memtaskman.collector import Collector, group_by_app, matches, sort_procs
from memtaskman.diff import diff_snapshots
from memtaskman.fmt import fmt_bytes, fmt_count_rate, fmt_rate, parse_size, redact
from memtaskman.model import ProcessMem, Snapshot, SystemMemory
from memtaskman.report import render_text

G = 1024**3
M = 1024**2


def proc(pid, name, resident, private, **kw):
    return ProcessMem(pid=pid, name=name, ppid=0, create_time=float(pid), resident=resident, private=private, **kw)


class FormatTests(unittest.TestCase):
    def test_bytes(self):
        self.assertEqual(fmt_bytes(None), "-")
        self.assertEqual(fmt_bytes(512), "512B")
        self.assertEqual(fmt_bytes(1536), "1.50K")
        self.assertEqual(fmt_bytes(25 * M), "25.0M")
        self.assertEqual(fmt_bytes(300 * M), "300M")
        self.assertEqual(fmt_bytes(-2 * G), "-2.00G")
        self.assertEqual(fmt_bytes(G, long=True), "1.00GiB")

    def test_decimal_units(self):
        from memtaskman.fmt import set_units, units_legend

        try:
            set_units("decimal")
            self.assertEqual(fmt_bytes(1_500_000_000), "1.50G")
            self.assertEqual(fmt_bytes(G, long=True), "1.07GB")
            self.assertIn("GB", units_legend())
        finally:
            set_units("binary")
        self.assertEqual(fmt_bytes(1_500_000_000), "1.40G")
        with self.assertRaises(ValueError):
            set_units("metric")

    def test_rates(self):
        self.assertEqual(fmt_rate(None), "-")
        self.assertEqual(fmt_rate(10), "0")
        self.assertEqual(fmt_rate(2 * M), "+2.00M/s")
        self.assertEqual(fmt_rate(-3 * 1024), "-3.00K/s")
        self.assertEqual(fmt_count_rate(0.3), "0")
        self.assertEqual(fmt_count_rate(1500), "1.5k")
        self.assertEqual(fmt_count_rate(25000), "25k")

    def test_redact_home_paths(self):
        self.assertEqual(redact(r"C:\Users\alice\AppData\x.dll"), r"~\AppData\x.dll")
        self.assertEqual(redact("c:/users/bob/x"), "~/x")
        self.assertEqual(redact("/home/carol/.cache/model.gguf"), "~/.cache/model.gguf")
        self.assertEqual(redact("/Users/dave/Library/x"), "~/Library/x")
        self.assertEqual(redact(r"C:\Windows\System32\ntdll.dll"), r"C:\Windows\System32\ntdll.dll")

    def test_parse_size(self):
        self.assertEqual(parse_size("4g"), 4 * G)
        self.assertEqual(parse_size("512M"), 512 * M)
        self.assertEqual(parse_size("2GB"), 2 * G)
        self.assertEqual(parse_size("1024"), 1024)
        self.assertIsNone(parse_size("lots"))


class AggregationTests(unittest.TestCase):
    def test_group_by_app(self):
        procs = [
            proc(10, "chrome.exe", 100 * M, 80 * M, growth_ps=1000.0, runtime="Chrome"),
            proc(11, "Chrome.exe", 50 * M, 40 * M, growth_ps=None),
            proc(12, "code.exe", 10 * M, None),
        ]
        groups = {g.name.lower(): g for g in group_by_app(procs)}
        c = groups["chrome.exe"]
        self.assertEqual((c.count, c.resident, c.private, c.growth_ps, c.runtime), (2, 150 * M, 120 * M, 1000.0, "Chrome"))
        self.assertIsNone(groups["code.exe"].private)

    def test_sort(self):
        procs = [proc(1, "b", 5, 1), proc(2, "a", 9, 3), proc(3, "c", 1, None)]
        self.assertEqual([p.pid for p in sort_procs(procs, "resident")], [2, 1, 3])
        self.assertEqual([p.pid for p in sort_procs(procs, "private")], [2, 1, 3])
        self.assertEqual([p.name for p in sort_procs(procs, "name")], ["a", "b", "c"])
        self.assertEqual([p.pid for p in sort_procs(procs, "resident", invert=True)], [3, 1, 2])
        self.assertEqual([p.name for p in sort_procs(procs, "name", invert=True)], ["c", "b", "a"])
        procs[0].runtime, procs[1].runtime = "Java", ".NET"
        self.assertEqual([p.runtime for p in sort_procs(procs, "runtime")], [".NET", "Java", None])  # unknown last


class FilterTests(unittest.TestCase):
    def test_matches(self):
        p = proc(4321, "chrome.exe", M, M, runtime="Chrome", runtime_detail="renderer")
        self.assertTrue(matches(p, "CHROME"))
        self.assertTrue(matches(p, "render"))
        self.assertTrue(matches(p, "4321"))
        self.assertTrue(matches(p, "  "))
        self.assertFalse(matches(p, "432"))  # PIDs match exactly, not as substrings
        self.assertFalse(matches(p, "firefox"))


class RateTests(unittest.TestCase):
    def test_back_to_back_samples_keep_last_rates(self):
        c = Collector(system=False)
        p0 = proc(1, "a", 10 * M, 10 * M)
        c._rates(p0, 100, now=1000.0)
        p1 = proc(1, "a", 10 * M, 12 * M)
        c._rates(p1, 300, now=1002.0)
        self.assertEqual(p1.faults_ps, 100.0)
        self.assertEqual(p1.growth_ps, 1 * M)
        p2 = proc(1, "a", 10 * M, 12 * M)
        c._rates(p2, 300, now=1002.01)  # too close to measure: reuse, don't blank
        self.assertEqual((p2.faults_ps, p2.growth_ps), (100.0, 1 * M))
        c.close()


class BarTests(unittest.TestCase):
    def test_windows_segments_sum_to_total(self):
        sm = SystemMemory(total=32 * G, available=12 * G, used=20 * G, standby=10 * G, modified=1 * G, free=2 * G)
        segs = ram_segments(sm)
        self.assertEqual([s[0] for s in segs], ["In use", "Modified", "Standby", "Free"])
        self.assertEqual(sum(s[1] for s in segs), 32 * G)

    def test_linux_segments(self):
        sm = SystemMemory(total=16 * G, available=10 * G, used=6 * G, cached=7 * G, free=2 * G)
        self.assertEqual([s[1] for s in ram_segments(sm)], [7 * G, 7 * G, 2 * G])

    def test_bar_width_exact(self):
        bar = stacked_bar([("a", 1, "red"), ("b", 2, "blue"), ("c", 0, "green")], 3, 50)
        self.assertEqual(len(bar.plain), 50)


class ReportTests(unittest.TestCase):
    def snap(self, t, procs, used):
        sm = SystemMemory(total=16 * G, available=16 * G - used, used=used)
        return Snapshot(t, "test", sm, procs)

    def test_render_text(self):
        out = render_text(self.snap(0, [proc(1, "a.exe", 2 * G, G, runtime="Java", runtime_detail="x.jar")], 4 * G))
        self.assertIn("4.00G / 16.0G used (25%)", out)
        self.assertIn("Java x.jar", out)

    def test_diff_pairs_by_pid_and_start_time(self):
        from memtaskman.diff import diff_data

        a = self.snap(0, [proc(1, "a.exe", 100 * M, 100 * M), proc(7, "reused", 50 * M, 50 * M)], G).to_dict()
        # pid 7 reused by a different process (different start time) -> gone + new, not "changed"
        p7 = proc(7, "other", 80 * M, 80 * M)
        p7.create_time = 99.0
        b = self.snap(60, [proc(1, "a.exe", 300 * M, 150 * M), p7], G).to_dict()
        st = {(e["name"], e["status"]) for e in diff_data(a, b)["processes"]}
        self.assertIn(("a.exe", "changed"), st)
        self.assertIn(("reused", "gone"), st)
        self.assertIn(("other", "new"), st)

    def test_diff_restarted_and_not_listed(self):
        from memtaskman.diff import diff_data, render

        a = self.snap(0, [proc(1, "svc.exe", 100 * M, 100 * M), proc(2, "tiny", M, M)], G)
        b = self.snap(60, [proc(5, "svc.exe", 400 * M, 400 * M)], G)
        b.truncated = True
        d = diff_data(a.to_dict(), b.to_dict())
        st = {e["name"]: e for e in d["processes"]}
        self.assertEqual(st["svc.exe"]["status"], "restarted")
        self.assertEqual(st["svc.exe"]["private_delta"], 300 * M)
        self.assertEqual(st["tiny"]["status"], "not listed")
        self.assertIsNone(st["tiny"]["private_delta"])
        self.assertTrue(d["warnings"])
        text = render(d)
        self.assertIn("1->5", text)
        self.assertIn("hidden", text)  # tiny is under the 16 MiB threshold

    def test_diff(self):
        a = self.snap(0, [proc(1, "a.exe", 100 * M, 50 * M), proc(2, "gone.exe", M, M)], 4 * G).to_dict()
        b = self.snap(60, [proc(1, "a.exe", 300 * M, 250 * M), proc(3, "new.exe", 2 * M, M)], 5 * G).to_dict()
        out = diff_snapshots(a, b, threshold=0)
        self.assertIn("Δt = 60s", out)
        self.assertIn("+1.00G", out)
        lines = out.splitlines()
        a_line = next(line for line in lines if "a.exe" in line)
        self.assertIn("+200M", a_line)
        self.assertTrue(any("new.exe" in line and "new" in line.split()[-1] for line in lines))
        self.assertTrue(any("gone.exe" in line and line.endswith("gone") for line in lines))


if __name__ == "__main__":
    unittest.main()
