import unittest

from memtaskman.collector import sort_procs
from memtaskman.model import ProcessMem
from memtaskman.tree import build_children, flatten

M = 1024 * 1024


def proc(pid, ppid, name, resident, ct=100.0, private=None):
    return ProcessMem(pid=pid, name=name, ppid=ppid, create_time=ct, resident=resident * M,
                      private=(private if private is not None else resident) * M)


def by_resident(ps):
    return sort_procs(ps, "resident")


class TreeTests(unittest.TestCase):
    def setUp(self):
        self.procs = [
            proc(1, 0, "init", 5),
            proc(10, 1, "chrome", 300),
            proc(11, 10, "renderer-a", 200),
            proc(12, 10, "renderer-b", 400),
            proc(20, 1, "editor", 100),
            proc(30, 0, "orphan", 50),
        ]

    def test_structure_and_drawing(self):
        rows = flatten(self.procs, by_resident, collapsed=set(), expanded=set())
        names = [(r.depth, r.prefix + r.proc.name) for r in rows]
        self.assertEqual(names, [
            (0, "init"),
            (1, "├─ chrome"),
            (2, "│  ├─ renderer-b"),  # siblings sorted largest first
            (2, "│  └─ renderer-a"),
            (1, "└─ editor"),
            (0, "orphan"),
        ])

    def test_roots_ranked_by_whole_subtree(self):
        # init itself is tiny (5M) but its subtree is ~1 GB: it must come before the 50M orphan
        rows = flatten(self.procs, by_resident, collapsed=set(), expanded=set())
        self.assertEqual([r.proc.name for r in rows if r.depth == 0], ["init", "orphan"])

    def test_collapsed_node_shows_subtree_totals(self):
        chrome = self.procs[1]
        rows = flatten(self.procs, by_resident, collapsed={chrome.key}, expanded=set())
        row = next(r for r in rows if r.proc.name == "chrome")
        self.assertTrue(row.collapsed)
        self.assertEqual((row.descendants, row.proc.count), (2, 3))
        self.assertEqual(row.proc.private, 900 * M)
        self.assertNotIn("renderer-a", [r.proc.name for r in rows])
        self.assertEqual(self.procs[1].private, 300 * M)  # the real process object is untouched

    def test_auto_collapse_and_explicit_expand(self):
        svc = proc(500, 0, "services", 10)
        kids = [proc(600 + i, 500, "svchost", 5) for i in range(12)]
        rows = flatten([svc, *kids], by_resident, collapsed=set(), expanded=set())
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0].collapsed)
        rows = flatten([svc, *kids], by_resident, collapsed=set(), expanded={svc.key})
        self.assertEqual(len(rows), 13)

    def test_diverse_top_level_launcher_stays_open(self):
        systemd = proc(1, 0, "systemd", 10)
        kids = [proc(100 + i, 1, f"daemon{i}", 5) for i in range(12)]
        rows = flatten([systemd, *kids], by_resident, collapsed=set(), expanded=set())
        self.assertEqual(len(rows), 13)  # diverse children: expanded
        nested = [proc(2, 1, "sshd", 1)] + [proc(200 + i, 2, f"session{i}", 1) for i in range(12)]
        rows = flatten([systemd, *nested], by_resident, collapsed=set(), expanded=set())
        self.assertTrue(next(r for r in rows if r.proc.name == "sshd").collapsed)  # crowded, not top level

    def test_reused_parent_pid_is_not_a_parent(self):
        # pid 7 started at t=500, after its "child" (t=100): the real parent exited and pid 7 was reused
        parent = proc(7, 0, "new-process", 10, ct=500.0)
        child = proc(8, 7, "old-child", 10, ct=100.0)
        roots, children = build_children([parent, child])
        self.assertEqual({r.name for r in roots}, {"new-process", "old-child"})
        self.assertEqual(children, {})

    def test_cycle_does_not_hang(self):
        a = proc(1, 2, "a", 1)
        b = proc(2, 1, "b", 1)
        rows = flatten([a, b], by_resident, collapsed=set(), expanded=set())
        self.assertEqual(sorted(r.proc.name for r in rows), ["a", "b"])  # shown once each, not lost


if __name__ == "__main__":
    unittest.main()
