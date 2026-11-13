import os
import subprocess
import sys
import time
import unittest

import psutil

from memtaskman import killer
from memtaskman.model import ProcessMem


def proc(pid, name, ct=100.0, resident=10, private=10, count=1):
    return ProcessMem(pid=pid, name=name, ppid=1, create_time=ct, resident=resident, private=private, count=count)


class RefuseTests(unittest.TestCase):
    def test_windows_critical(self):
        for name in ("csrss.exe", "wininit.exe", "lsass.exe", "MemCompression", "System"):
            self.assertIsNotNone(killer.refuse_reason(proc(1234, name), own_pid=1, platform="win32"), name)
        self.assertIsNotNone(killer.refuse_reason(proc(4, "anything"), own_pid=1, platform="win32"))
        self.assertIsNone(killer.refuse_reason(proc(1234, "notepad.exe"), own_pid=1, platform="win32"))

    def test_posix_critical_and_kernel_threads(self):
        self.assertIsNotNone(killer.refuse_reason(proc(1, "systemd"), own_pid=9, platform="linux"))
        self.assertIsNotNone(killer.refuse_reason(proc(50, "kworker/0:1", resident=0, private=None), own_pid=9,
                                                  platform="linux"))
        self.assertIsNotNone(killer.refuse_reason(proc(77, "WindowServer"), own_pid=9, platform="darwin"))
        self.assertIsNone(killer.refuse_reason(proc(500, "python3"), own_pid=9, platform="linux"))

    def test_self_and_groups(self):
        self.assertIn("memtaskman itself", killer.refuse_reason(proc(42, "mtm"), own_pid=42, platform="linux"))
        self.assertIn("group", killer.refuse_reason(proc(42, "chrome", count=5), own_pid=1, platform="linux"))


class LiveTests(unittest.TestCase):
    """Real processes: spawn a sleeper, end it."""

    def spawn(self):
        exe = getattr(sys, "_base_executable", sys.executable)  # avoid the venv launcher shim on Windows
        child = subprocess.Popen([exe, "-c", "import time; time.sleep(120)"])
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)

        self.addCleanup(cleanup)
        p = psutil.Process(child.pid)
        return child, proc(child.pid, p.name(), ct=p.create_time())

    def test_reused_pid_is_never_signalled(self):
        child, p = self.spawn()
        p.create_time -= 3600  # pretend we saw a different process with this PID an hour ago
        sent, msg = killer.end_process(p, force=True)
        self.assertFalse(sent)
        self.assertIn("different process", msg)
        self.assertIsNone(child.poll())  # still alive

    def test_force_kill(self):
        child, p = self.spawn()
        sent, _msg = killer.end_process(p, force=True)
        self.assertTrue(sent)
        child.wait(timeout=10)
        self.assertIsNotNone(child.returncode)

    def test_polite_then_exited(self):
        child, p = self.spawn()
        sent, msg = killer.end_process(p, force=False)
        if sys.platform == "win32":
            # A console process has no window to close: taskkill without /F refuses, and says so.
            self.assertFalse(sent, msg)
            self.assertIn("force it", msg)
        else:
            self.assertTrue(sent, msg)
            child.wait(timeout=10)
        child.kill()
        child.wait(timeout=10)
        time.sleep(0.2)
        self.assertEqual(killer.end_process(p, force=True), (False, "it has already exited"))


if __name__ == "__main__":
    unittest.main()
