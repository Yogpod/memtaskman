"""Linux memory sources: /proc/meminfo, /proc/vmstat, /proc/<pid>/{status,stat,smaps}.

Parsers are pure functions over text so they can be tested on any OS.
"""

from __future__ import annotations

import os
import re
import time
from pathlib import PurePosixPath

from memtaskman.fmt import fmt_bytes
from memtaskman.model import (
    CAT_HEAP,
    CAT_IMAGE,
    CAT_MAPPED,
    CAT_OTHER,
    CAT_SHM,
    CAT_STACK,
    DERIVED,
    MEASURED,
    Category,
    FileMapping,
    Inspection,
)


def parse_kb_table(text: str) -> dict[str, int]:
    """Parse 'Key:   1234 kB' lines (meminfo, status, smaps) into bytes."""
    out: dict[str, int] = {}
    for line in text.splitlines():
        key, sep, rest = line.partition(":")
        if not sep:
            continue
        parts = rest.split()
        if not parts or not parts[0].isdigit():
            continue
        v = int(parts[0])
        if len(parts) > 1 and parts[1].lower() == "kb":
            v *= 1024
        out[key.strip()] = v
    return out


def parse_vmstat(text: str) -> dict[str, int]:
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if v.strip().isdigit():
            out[k] = int(v)
    return out


def parse_stat_faults(text: str) -> int | None:
    """minflt + majflt from /proc/<pid>/stat (comm may contain spaces/parens)."""
    r = text.rfind(")")
    if r < 0:
        return None
    fields = text[r + 2 :].split()
    # fields[0] is state (field 3); minflt is field 10, majflt field 12.
    try:
        return int(fields[7]) + int(fields[9])
    except (IndexError, ValueError):
        return None


_HEADER = re.compile(r"^([0-9a-f]+)-([0-9a-f]+)\s+(\S+)\s+\S+\s+\S+\s+\d+\s*(.*)$")


def parse_smaps(text: str) -> list[dict]:
    """One dict per mapping: start, end, perms, path, plus kB fields in bytes."""
    maps: list[dict] = []
    cur: dict | None = None
    for line in text.splitlines():
        m = _HEADER.match(line)
        if m:
            cur = {"start": int(m.group(1), 16), "end": int(m.group(2), 16), "perms": m.group(3), "path": m.group(4).strip()}
            maps.append(cur)
            continue
        if cur is None:
            continue
        key, sep, rest = line.partition(":")
        parts = rest.split()
        if sep and parts and parts[0].isdigit() and len(parts) > 1 and parts[1] == "kB":
            cur[key.strip()] = int(parts[0]) * 1024
    return maps


def categorize(path: str, perms: str) -> str:
    if not path or path.startswith("[anon"):
        return CAT_HEAP
    if path == "[heap]":
        return CAT_HEAP
    if path.startswith("[stack"):
        return CAT_STACK
    if path.startswith("["):
        return CAT_OTHER  # vdso, vvar, vsyscall
    if path.startswith(("/dev/shm/", "/memfd:", "memfd:", "/SYSV", "/dev/zero")):
        return CAT_SHM
    name = PurePosixPath(path).name
    if "x" in perms or re.search(r"\.so(\.|$)", name):
        return CAT_IMAGE
    if path.startswith("/dev/"):
        return CAT_OTHER
    return CAT_MAPPED


def summarize_smaps(maps: list[dict], top_files: int = 12) -> tuple[list[Category], list[FileMapping]]:
    cats: dict[str, Category] = {}
    files: dict[str, FileMapping] = {}
    for m in maps:
        cat = categorize(m["path"], m["perms"])
        c = cats.setdefault(cat, Category(cat, resident=0, resident_shared=0, swapped=0))
        size = m.get("Size", m["end"] - m["start"])
        rss = m.get("Rss", 0)
        c.mapped += size
        c.resident += rss
        c.resident_shared += m.get("Shared_Clean", 0) + m.get("Shared_Dirty", 0)
        c.swapped += m.get("Swap", 0)
        c.regions += 1
        if cat in (CAT_IMAGE, CAT_MAPPED, CAT_SHM) and m["path"]:
            f = files.setdefault(m["path"], FileMapping(m["path"], "image" if cat == CAT_IMAGE else "mapped", 0, 0))
            f.mapped += size
            f.resident += rss
    top = sorted(files.values(), key=lambda f: f.resident or 0, reverse=True)[:top_files]
    return list(cats.values()), top


# --------------------------------------------------------------------------- live readers


def _read(path: str) -> str | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return None


def meminfo() -> dict[str, int]:
    return parse_kb_table(_read("/proc/meminfo") or "")


def vmstat() -> dict[str, int]:
    return parse_vmstat(_read("/proc/vmstat") or "")


def proc_status(pid: int) -> dict[str, int]:
    return parse_kb_table(_read(f"/proc/{pid}/status") or "")


def proc_faults(pid: int) -> int | None:
    t = _read(f"/proc/{pid}/stat")
    return parse_stat_faults(t) if t else None


def rollup(pid: int) -> tuple[int, int] | None:
    """(PSS, USS) from /proc/<pid>/smaps_rollup, or None when unreadable."""
    r = parse_kb_table(_read(f"/proc/{pid}/smaps_rollup") or "")
    if "Pss" not in r:
        return None
    return r["Pss"], r.get("Private_Clean", 0) + r.get("Private_Dirty", 0)


def mapped_paths(pid: int) -> list[str] | None:
    t = _read(f"/proc/{pid}/maps")
    if t is None:
        return None
    names = set()
    for line in t.splitlines():
        parts = line.split(None, 5)
        if len(parts) == 6 and parts[5].startswith("/"):
            names.add(PurePosixPath(parts[5].strip()).name)
    return sorted(names)


def inspect(pid: int, name: str, *, top_files: int = 12) -> Inspection:
    t0 = time.perf_counter()
    ins = Inspection(pid=pid, name=name)
    text = _read(f"/proc/{pid}/smaps")
    if text is None:
        ins.error = "cannot read smaps: process exited, or owned by another user (run with sudo)"
        return ins
    maps = parse_smaps(text)
    ins.categories, ins.top_files = summarize_smaps(maps, top_files)
    ins.evidence.append((MEASURED, f"{len(maps)} mappings from /proc/{pid}/smaps"))
    r = rollup(pid)
    if r:
        ins.evidence.append((MEASURED, f"PSS {fmt_bytes(r[0])}: resident with shared pages split between sharers"))
        ins.evidence.append((MEASURED, f"USS {fmt_bytes(r[1])}: freed if this process exits"))
    ins.evidence.append((DERIVED, "categories assigned from mapping names and permissions"))
    ins.elapsed = time.perf_counter() - t0
    return ins


def is_linux() -> bool:
    return os.path.exists("/proc/meminfo")
