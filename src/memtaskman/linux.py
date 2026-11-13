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


def parse_psi(text: str) -> dict[str, dict[str, float]]:
    """/proc/pressure/memory (or a cgroup's memory.pressure) -> {"some": {"avg10": ..}, "full": {..}}."""
    out: dict[str, dict[str, float]] = {}
    for line in text.splitlines():
        kind, _, rest = line.partition(" ")
        vals = {}
        for field in rest.split():
            k, _, v = field.partition("=")
            try:
                vals[k] = float(v)
            except ValueError:
                pass
        if kind in ("some", "full") and vals:
            out[kind] = vals
    return out


def parse_flat_keyed(text: str) -> dict[str, int]:
    """'key value' lines (memory.stat, memory.events) -> ints."""
    out = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if v.strip().lstrip("-").isdigit():
            out[k] = int(v)
    return out


def parse_limit(text: str | None) -> int | None:
    """memory.max / memory.high: 'max' (unlimited) -> None."""
    if text is None:
        return None
    t = text.strip()
    if not t.isdigit():
        return None
    v = int(t)
    return None if v >= 1 << 60 else v  # v1 reports 'unlimited' as a huge number


def parse_proc_cgroup(text: str) -> tuple[str, str] | None:
    """/proc/<pid>/cgroup -> ("v2", path) or ("v1", memory-controller path)."""
    v1 = None
    for line in text.splitlines():
        parts = line.split(":", 2)
        if len(parts) != 3:
            continue
        hid, controllers, path = parts
        if hid == "0" and controllers == "":
            return ("v2", path)
        if "memory" in controllers.split(","):
            v1 = ("v1", path)
    return v1


_HEX64 = re.compile(r"[0-9a-f]{64}")


def cgroup_label(path: str) -> str:
    """Human name for a cgroup path."""
    if path in ("", "/"):
        return "(root cgroup)"
    parts = [p for p in path.split("/") if p]
    leaf = parts[-1]
    m = _HEX64.search(leaf)
    if m:
        cid = m.group(0)[:12]
        if "docker" in path:
            return f"docker:{cid}"
        if "kubepods" in path:
            pm = re.search(r"[-/]pod([0-9a-f]{8})", path)
            return f"pod:{pm.group(1)}/{cid}" if pm else f"k8s:{cid}"
        if "libpod" in path or "podman" in path:
            return f"podman:{cid}"
        return f"container:{cid}"
    if leaf.endswith(".scope") and len(parts) >= 2 and parts[-2].startswith("user-"):
        return f"{leaf} ({parts[-2].removesuffix('.slice')})"
    if leaf.startswith("app-") and leaf.endswith(".scope"):
        return leaf.removeprefix("app-").removesuffix(".scope").split("@")[0]
    return leaf


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


def pressure() -> dict[str, dict[str, float]] | None:
    """System memory PSI, or None when the kernel has PSI disabled."""
    t = _read("/proc/pressure/memory")
    return parse_psi(t) if t else None


def proc_cgroup(pid: int) -> tuple[str, str] | None:
    t = _read(f"/proc/{pid}/cgroup")
    return parse_proc_cgroup(t) if t else None


CGROUP_ROOT = "/sys/fs/cgroup"


def cgroup_stats(kind: str, path: str) -> dict | None:
    """Kernel-accounted memory for one cgroup. None if the directory is unreadable."""
    if kind == "v2":
        base = CGROUP_ROOT + path.rstrip("/")
        current = _read(base + "/memory.current")
        if current is None or not current.strip().isdigit():
            return None
        stat = parse_flat_keyed(_read(base + "/memory.stat") or "")
        events = parse_flat_keyed(_read(base + "/memory.events") or "")
        swap = _read(base + "/memory.swap.current")
        psi = _read(base + "/memory.pressure")
        return {
            "current": int(current),
            "anon": stat.get("anon"),
            "file": stat.get("file"),
            "shmem": stat.get("shmem"),
            "kernel": stat.get("kernel"),
            "sock": stat.get("sock"),
            "swap": int(swap) if swap and swap.strip().isdigit() else None,
            "max": parse_limit(_read(base + "/memory.max")),
            "high": parse_limit(_read(base + "/memory.high")),
            "oom": events.get("oom"),
            "oom_kill": events.get("oom_kill"),
            "pressure": parse_psi(psi) if psi else None,
        }
    base = f"{CGROUP_ROOT}/memory" + path.rstrip("/")
    usage = _read(base + "/memory.usage_in_bytes")
    if usage is None or not usage.strip().isdigit():
        return None
    stat = parse_flat_keyed(_read(base + "/memory.stat") or "")
    return {
        "current": int(usage),
        "anon": stat.get("total_rss", stat.get("rss")),
        "file": stat.get("total_cache", stat.get("cache")),
        "shmem": stat.get("total_shmem", stat.get("shmem")),
        "kernel": None, "sock": None, "swap": stat.get("total_swap"),
        "max": parse_limit(_read(base + "/memory.limit_in_bytes")),
        "high": None, "oom": None,
        "oom_kill": parse_flat_keyed(_read(base + "/memory.oom_control") or "").get("oom_kill"),
        "pressure": None,
    }


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


def is_wsl() -> bool:
    if os.path.exists("/proc/sys/fs/binfmt_misc/WSLInterop") or os.path.exists("/run/WSL"):
        return True
    rel = (_read("/proc/sys/kernel/osrelease") or "").lower()
    return "microsoft" in rel and "wsl" in rel


WSL_NOTE = ("WSL2 VM: this RAM is the Windows process vmmemWSL. Page cache here still holds host RAM "
            "until reclaimed. Cap it with [wsl2] memory= in %UserProfile%\\.wslconfig; "
            "autoMemoryReclaim returns cache to Windows")


def is_linux() -> bool:
    return os.path.exists("/proc/meminfo")
