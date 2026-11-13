"""What's inside vmmemWSL: the WSL2 guest's own view of its memory, from Windows.

Design rule: never start or prolong WSL. WSL shuts an idle VM down after a short
timeout, and any command run inside it counts as activity, so this module is only
called on demand (inspecting the vmmemWSL row, or `mtm inspect`), and only when a
distro is already running.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

from memtaskman.linux import parse_kb_table

VMMEM_NAMES = {"vmmemwsl", "vmmem"}
_NO_WINDOW = 0x08000000  # CREATE_NO_WINDOW


def decode_wsl_output(raw: bytes) -> str:
    """wsl.exe's own messages (e.g. --list) are UTF-16LE; commands run inside print UTF-8."""
    if raw[:2] == b"\xff\xfe" or (len(raw) > 1 and raw[1:2] == b"\x00"):
        return raw.decode("utf-16-le", errors="replace").lstrip("﻿")
    return raw.decode("utf-8", errors="replace")


def parse_running(text: str) -> list[str]:
    return [line.strip().strip("\x00") for line in text.splitlines() if line.strip().strip("\x00")]


def _wsl(*args: str, timeout: float = 5.0) -> str | None:
    try:
        r = subprocess.run(["wsl.exe", *args], capture_output=True, timeout=timeout,
                           creationflags=_NO_WINDOW if os.name == "nt" else 0)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    return decode_wsl_output(r.stdout)


def running_distros() -> list[str]:
    """Running distros. `--list --running` does not start the VM."""
    out = _wsl("--list", "--running", "--quiet")
    return parse_running(out) if out else []


def parse_wslconfig(text: str) -> dict[str, str]:
    """Keys from %UserProfile%\\.wslconfig, lowercased, as 'section.key'."""
    out, section = {}, ""
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        m = re.fullmatch(r"\[(.+)\]", line)
        if m:
            section = m.group(1).strip().lower()
            continue
        k, sep, v = line.partition("=")
        if sep:
            out[f"{section}.{k.strip().lower()}"] = v.strip()
    return out


def read_wslconfig() -> dict[str, str]:
    p = Path(os.environ.get("USERPROFILE", "~")).expanduser() / ".wslconfig"
    try:
        return parse_wslconfig(p.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return {}


def guest_breakdown(meminfo: dict[str, int]) -> dict[str, int | None]:
    """Split the guest's RAM into what a Windows user cares about."""
    total = meminfo.get("MemTotal")
    avail = meminfo.get("MemAvailable")
    cache = meminfo.get("Cached", 0) + meminfo.get("Buffers", 0) if "Cached" in meminfo else None
    shmem = meminfo.get("Shmem")
    return {
        "total": total,
        "used": total - avail if total is not None and avail is not None else None,
        "available": avail,
        "anon": meminfo.get("AnonPages"),
        "cache": cache,
        "reclaimable_cache": cache - (shmem or 0) if cache is not None else None,  # tmpfs can't be dropped
        "shmem": shmem,
        "slab": meminfo.get("Slab"),
        "free": meminfo.get("MemFree"),
    }


def guest_memory() -> tuple[dict | None, str | None]:
    """(guest info, reason if unavailable). Never starts WSL."""
    distros = running_distros()
    if not distros:
        return None, "no WSL distro is running (memtaskman never starts WSL)"
    text = _wsl("-d", distros[0], "-e", "cat", "/proc/meminfo")
    if not text:
        return None, f"could not read /proc/meminfo in {distros[0]}"
    mi = parse_kb_table(text)
    if "MemTotal" not in mi:
        return None, "unexpected /proc/meminfo output"
    return {"distro": distros[0], "running": distros, **guest_breakdown(mi)}, None
