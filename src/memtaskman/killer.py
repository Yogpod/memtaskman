"""Ending processes, carefully (opt-out with --read-only).

Rules:
- refuse kernel / critical system processes and memtaskman itself;
- verify PID + start time right before sending, so a reused PID is never hit;
- polite first (taskkill without /F on Windows, SIGTERM elsewhere); forcing is a
  separate, second confirmation in the UI.
"""

from __future__ import annotations

import os
import subprocess
import sys

import psutil

from memtaskman.model import ProcessMem

# Killing these crashes or logs out Windows (csrss / wininit / smss bluescreen the machine).
WINDOWS_CRITICAL = {
    "system", "registry", "memcompression", "memory compression", "secure system", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "lsaiso.exe", "dwm.exe", "fontdrvhost.exe",
}
POSIX_CRITICAL = {"systemd", "init", "launchd", "kernel_task", "kthreadd", "loginwindow", "windowserver"}


def refuse_reason(p: ProcessMem, *, own_pid: int | None = None, platform: str = sys.platform) -> str | None:
    """Why this process must not be ended from memtaskman, or None if it may be."""
    own = os.getpid() if own_pid is None else own_pid
    name = p.name.lower()
    if p.count > 1:
        return "this row is a group; select a single process"
    if p.pid == own:
        return "that's memtaskman itself (press q to quit)"
    if platform == "win32":
        if p.pid <= 4 or name in WINDOWS_CRITICAL:
            return f"{p.name} is a critical Windows process; ending it would crash or log out the system"
    else:
        if p.pid <= 1 or name in POSIX_CRITICAL:
            return f"{p.name} is a critical system process"
        if platform.startswith("linux") and p.resident == 0 and p.private is None:
            return "kernel thread"
    return None


def verify(p: ProcessMem) -> psutil.Process | str:
    """The live process if it is still the same one (PID + start time), else a reason."""
    try:
        proc = psutil.Process(p.pid)
        ct = proc.create_time()
    except psutil.NoSuchProcess:
        return "it has already exited"
    except psutil.AccessDenied:
        return "access denied (run elevated / with sudo)"
    if p.create_time and abs(ct - p.create_time) > 1.0:
        return "that PID now belongs to a different process; nothing was sent"
    return proc


def end_process(p: ProcessMem, *, force: bool) -> tuple[bool, str]:
    """Ask the process to exit (force=False) or kill it (force=True). Returns (sent, message)."""
    proc = verify(p)
    if isinstance(proc, str):
        return False, proc
    try:
        if force:
            proc.kill()  # TerminateProcess / SIGKILL
            return True, f"killed {p.name} ({p.pid})"
        if sys.platform == "win32":
            # Without /F, taskkill asks the process's windows to close (WM_CLOSE), like closing them.
            r = subprocess.run(["taskkill", "/PID", str(p.pid)], capture_output=True, text=True,
                               creationflags=0x08000000)
            if r.returncode != 0:
                msg = (r.stderr or r.stdout).strip().splitlines()[-1:] or ["taskkill failed"]
                return False, f"{p.name} didn't accept a polite close ({msg[0]}); force it with k again"
            return True, f"asked {p.name} ({p.pid}) to close"
        proc.terminate()  # SIGTERM
        return True, f"sent SIGTERM to {p.name} ({p.pid})"
    except psutil.NoSuchProcess:
        return False, "it has already exited"
    except psutil.AccessDenied:
        return False, "access denied (run elevated / with sudo)"
