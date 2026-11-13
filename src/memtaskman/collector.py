"""Sampling: turns OS sources into Snapshots, tracks rates and runtime identity."""

from __future__ import annotations

import sys
import threading
import time
from dataclasses import dataclass, field

import psutil

from memtaskman import runtime as rt
from memtaskman.model import (
    CATEGORY_ORDER,
    HINT,
    Inspection,
    ProcessMem,
    Snapshot,
    SystemMemory,
)

WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")

if WINDOWS:
    from memtaskman import win32 as native
elif LINUX:
    from memtaskman import linux as native
else:  # macOS & others: psutil only
    native = None

GROWTH_ALPHA = 0.35  # EMA weight for the private-bytes growth rate
RUNTIME_TTL = 45.0  # seconds before re-checking a process's loaded modules
PSS_TTL = 2.0  # smaps_rollup makes the kernel walk page tables; refresh visible rows at most this often


def private_label() -> str:
    if WINDOWS:
        return "Private"  # private commit charge (Task Manager "Commit size")
    if LINUX:
        return "Anon"  # resident anonymous memory (RssAnon)
    return "Private"


@dataclass
class _Track:
    t: float
    private: int
    faults: int | None
    growth: float | None = None
    faults_ps: float | None = None


@dataclass
class _RuntimeEntry:
    info: rt.RuntimeInfo | None
    cmdline: list[str] = field(default_factory=list)
    checked: float = 0.0


class Collector:
    def __init__(self, system: bool = True):
        self.want_system = system
        self._pdh = native.PdhQuery() if WINDOWS and system else None
        self._tracks: dict[tuple[int, float], _Track] = {}
        self._runtimes: dict[tuple[int, float], _RuntimeEntry] = {}
        self._pss: dict[tuple[int, float], tuple[float, int, int]] = {}  # key -> (checked, pss, uss)
        self._vm_prev: tuple[float, dict[str, int]] | None = None
        self._first = True
        self._lock = threading.RLock()  # sampling and inspection run on different threads

    # ------------------------------------------------------------------ snapshot
    def sample(self) -> Snapshot:
        with self._lock:
            return self._sample()

    def _sample(self) -> Snapshot:
        now = time.time()
        procs = self._processes(now)
        system = self._system(now, procs) if self.want_system else None
        for p in procs:
            entry = self._runtimes.get(p.key)
            if entry and entry.info:
                p.runtime = entry.info.name
                p.runtime_detail = entry.info.detail
            cached = self._pss.get(p.key)
            if cached:
                _t, p.pss, p.uss = cached
        return Snapshot(now, sys.platform, system, procs, private_label())

    # ------------------------------------------------------------------ processes
    def _processes(self, now: float) -> list[ProcessMem]:
        out: list[ProcessMem] = []
        seen = set()
        for proc in psutil.process_iter(["pid", "name", "ppid", "create_time", "memory_info"]):
            info = proc.info
            mi = info.get("memory_info")
            if mi is None:
                continue
            pid = info["pid"]
            ct = info.get("create_time") or 0.0
            p = ProcessMem(
                pid=pid,
                name=info.get("name") or f"pid {pid}",
                ppid=info.get("ppid") or 0,
                create_time=ct,
                resident=mi.rss,
                private=None,
            )
            faults = None
            if WINDOWS:
                p.private = getattr(mi, "private", None)
                p.peak = getattr(mi, "peak_wset", None)
                p.paged_pool = getattr(mi, "paged_pool", None)
                p.nonpaged_pool = getattr(mi, "nonpaged_pool", None)
                faults = getattr(mi, "num_page_faults", None)
            elif LINUX:
                st = native.proc_status(pid)
                if "RssAnon" in st:
                    p.private = st["RssAnon"]
                    p.shared = st.get("RssFile", 0) + st.get("RssShmem", 0)
                p.swapped = st.get("VmSwap")
                p.peak = st.get("VmHWM")
                faults = native.proc_faults(pid)
            self._rates(p, faults, now)
            seen.add(p.key)
            out.append(p)
        for k in list(self._tracks):
            if k not in seen:
                del self._tracks[k]
        for cache in (self._runtimes, self._pss):
            for k in list(cache):
                if k not in seen:
                    del cache[k]
        return out

    def _rates(self, p: ProcessMem, faults: int | None, now: float) -> None:
        basis = p.private if p.private is not None else p.resident
        prev = self._tracks.get(p.key)
        if prev is None:
            self._tracks[p.key] = _Track(now, basis, faults)
            return
        dt = now - prev.t
        if dt <= 0.05:  # two samples back to back: reuse the last rates
            p.growth_ps, p.faults_ps = prev.growth, prev.faults_ps
            return
        inst = (basis - prev.private) / dt
        prev.growth = inst if prev.growth is None else GROWTH_ALPHA * inst + (1 - GROWTH_ALPHA) * prev.growth
        p.growth_ps = prev.growth
        if faults is not None and prev.faults is not None:
            p.faults_ps = prev.faults_ps = max(0.0, (faults - prev.faults) / dt)
        prev.t, prev.private, prev.faults = now, basis, faults

    # ------------------------------------------------------------------ system
    def _system(self, now: float, procs: list[ProcessMem]) -> SystemMemory:
        vm = psutil.virtual_memory()
        sm = SystemMemory(total=vm.total, available=vm.available, used=vm.total - vm.available)
        try:
            sw = psutil.swap_memory()
            sm.swap_total, sm.swap_used = sw.total, sw.used
        except Exception:  # noqa: BLE001 - psutil raises varied errors on locked-down hosts
            pass
        if WINDOWS:
            self._system_windows(sm, procs)
        elif LINUX:
            self._system_linux(sm, now)
        else:
            sm.free = getattr(vm, "free", None)
            sm.cached = getattr(vm, "inactive", None)
            sm.extra = {k: getattr(vm, k) for k in ("active", "inactive", "wired") if hasattr(vm, k)}
        return sm

    def _system_windows(self, sm: SystemMemory, procs: list[ProcessMem]) -> None:
        sm.source = "PDH + GetPerformanceInfo"
        perf = native.performance_info() or {}
        c = self._pdh.sample() if self._pdh else {}
        if c:
            sb = [c.get(k) for k in ("standby_core", "standby_normal", "standby_reserve")]
            if any(v is not None for v in sb):
                sm.standby = int(sum(v or 0 for v in sb))
            if "modified" in c:
                sm.modified = int(c["modified"])
            if "free_zero" in c:
                sm.free = int(c["free_zero"])
            if "cache" in c:
                sm.cached = int(c["cache"])
            if "pool_paged" in c:
                sm.kernel_paged = int(c["pool_paged"])
            if "pool_nonpaged" in c:
                sm.kernel_nonpaged = int(c["pool_nonpaged"])
            if not self._first:
                sm.page_faults_ps = c.get("page_faults_ps")
                sm.hard_faults_ps = c.get("pages_input_ps")
            for key, label in (("driver_resident", "Driver resident"), ("code_resident", "System code resident")):
                if key in c:
                    sm.extra[label] = int(c[key])
        if perf:
            sm.commit_used = perf["commit_total"]
            sm.commit_limit = perf["commit_limit"]
            sm.extra["Commit peak"] = perf["commit_peak"]
            if sm.kernel_paged is None:
                sm.kernel_paged = perf["kernel_paged"]
                sm.kernel_nonpaged = perf["kernel_nonpaged"]
            if sm.cached is None:
                sm.cached = perf["system_cache"]
        comp = next((p for p in procs if p.name.lower() in ("memory compression", "memcompression")), None)
        if comp is not None:
            sm.compressed = comp.resident
        self._first = False

    def _system_linux(self, sm: SystemMemory, now: float) -> None:
        sm.source = "/proc/meminfo + /proc/vmstat"
        mi = native.meminfo()
        sm.free = mi.get("MemFree")
        sm.cached = mi.get("Cached", 0) + mi.get("Buffers", 0) if "Cached" in mi else None
        sm.compressed = mi.get("Zswap")
        sm.commit_used = mi.get("Committed_AS")
        sm.commit_limit = mi.get("CommitLimit")
        sm.kernel_paged = mi.get("SReclaimable")
        sm.kernel_nonpaged = mi.get("SUnreclaim")
        sm.modified = mi.get("Dirty")
        for k, label in (("Shmem", "Shmem / tmpfs"), ("AnonPages", "Anonymous"), ("PageTables", "Page tables"),
                         ("KernelStack", "Kernel stacks"), ("AnonHugePages", "Transparent hugepages"),
                         ("Zswapped", "Zswapped (uncompressed)")):
            if k in mi:
                sm.extra[label] = mi[k]
        vs = native.vmstat()
        if self._vm_prev and vs:
            t0, prev = self._vm_prev
            dt = now - t0
            if dt > 0 and "pgfault" in vs and "pgfault" in prev:
                sm.page_faults_ps = (vs["pgfault"] - prev["pgfault"]) / dt
                sm.hard_faults_ps = (vs.get("pgmajfault", 0) - prev.get("pgmajfault", 0)) / dt
        self._vm_prev = (now, vs)

    # ------------------------------------------------------------------ runtimes
    def resolve_runtimes(self, procs: list[ProcessMem], *, time_budget: float = 0.25) -> int:
        """Identify runtimes for processes in the given priority order, within a time budget."""
        with self._lock:
            return self._resolve(procs, time_budget)

    def _resolve(self, procs: list[ProcessMem], time_budget: float) -> int:
        deadline = time.perf_counter() + time_budget
        now = time.time()
        done = 0
        for p in procs:
            entry = self._runtimes.get(p.key)
            if entry and now - entry.checked < RUNTIME_TTL:
                continue
            if time.perf_counter() > deadline:
                break
            self._runtimes[p.key] = self._identify(p, now)
            info = self._runtimes[p.key].info
            p.runtime = info.name if info else None
            p.runtime_detail = info.detail if info else None
            done += 1
        return done

    def refresh_pss(self, procs: list[ProcessMem], *, time_budget: float = 0.2) -> int:
        """Linux only: read PSS/USS from smaps_rollup for processes in priority order."""
        if not LINUX:
            return 0
        with self._lock:
            deadline = time.perf_counter() + time_budget
            now = time.time()
            done = 0
            for p in procs:
                cached = self._pss.get(p.key)
                if cached and now - cached[0] < PSS_TTL:
                    p.pss, p.uss = cached[1], cached[2]
                    continue
                if time.perf_counter() > deadline:
                    break
                r = native.rollup(p.pid)
                if r is None:
                    continue  # other users' processes: unreadable without root, left as None
                p.pss, p.uss = r
                self._pss[p.key] = (now, r[0], r[1])
                done += 1
            return done

    def _identify(self, p: ProcessMem, now: float) -> _RuntimeEntry:
        mods: list[str] = []
        if native is not None and p.pid > 4:
            try:
                mods = (native.module_names(p.pid) if WINDOWS else native.mapped_paths(p.pid)) or []
            except OSError:
                mods = []
        try:
            cmd = psutil.Process(p.pid).cmdline()
        except (psutil.Error, OSError):
            cmd = []
        exe = p.name
        return _RuntimeEntry(rt.detect(exe, mods, cmd), cmd, now)

    def runtime_of(self, key: tuple[int, float]) -> tuple[rt.RuntimeInfo | None, list[str]]:
        e = self._runtimes.get(key)
        return (e.info, e.cmdline) if e else (None, [])

    # ------------------------------------------------------------------ inspector
    def inspect(self, p: ProcessMem) -> Inspection:
        if native is None:
            ins = Inspection(p.pid, p.name, error="address-space inspection is implemented for Windows and Linux")
        else:
            try:
                ins = native.inspect(p.pid, p.name)
            except Exception as e:  # noqa: BLE001 - a racing process exit can surface many error types
                ins = Inspection(p.pid, p.name, error=f"{type(e).__name__}: {e}")
        ins.categories.sort(key=lambda c: CATEGORY_ORDER.index(c.name) if c.name in CATEGORY_ORDER else 99)
        with self._lock:
            if p.key not in self._runtimes or time.time() - self._runtimes[p.key].checked > RUNTIME_TTL:
                self._runtimes[p.key] = self._identify(p, time.time())
            info, cmd = self.runtime_of(p.key)
        ins.cmdline = cmd
        if info:
            ins.evidence = [e for e in info.evidence if e[1]] + ins.evidence
        elif not ins.error:
            ins.evidence.insert(0, (HINT, "no known runtime recognised"))
        return ins

    def close(self) -> None:
        if self._pdh:
            self._pdh.close()


# ---------------------------------------------------------------------- aggregation


def group_by_app(procs: list[ProcessMem]) -> list[ProcessMem]:
    """Sum processes sharing an executable name (e.g. every chrome.exe).

    Resident totals double count pages shared between the members, so they are an
    upper bound; private totals do not overlap.
    """
    groups: dict[str, ProcessMem] = {}
    for p in procs:
        k = p.name.lower()
        g = groups.get(k)
        if g is None:
            groups[k] = ProcessMem(
                pid=p.pid, name=p.name, ppid=0, create_time=0.0, resident=p.resident, private=p.private,
                shared=p.shared, swapped=p.swapped, pss=p.pss, uss=p.uss, faults_ps=p.faults_ps, growth_ps=p.growth_ps,
                paged_pool=p.paged_pool, nonpaged_pool=p.nonpaged_pool,
                runtime=p.runtime, runtime_detail=None, count=1,
            )
            continue
        g.count += 1
        g.resident += p.resident
        g.private = _add(g.private, p.private)
        g.shared = _add(g.shared, p.shared)
        g.swapped = _add(g.swapped, p.swapped)
        g.pss = _add(g.pss, p.pss)
        g.uss = _add(g.uss, p.uss)
        g.faults_ps = _add(g.faults_ps, p.faults_ps)
        g.growth_ps = _add(g.growth_ps, p.growth_ps)
        g.paged_pool = _add(g.paged_pool, p.paged_pool)
        g.nonpaged_pool = _add(g.nonpaged_pool, p.nonpaged_pool)
        g.runtime = g.runtime or p.runtime
        g.pid = min(g.pid, p.pid)
    return list(groups.values())


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return a + b


SORTS = {
    "resident": lambda p: p.resident,
    "private": lambda p: p.private or 0,
    "pss": lambda p: p.pss or 0,
    "growth": lambda p: p.growth_ps or 0,
    "faults": lambda p: p.faults_ps or 0,
    "name": lambda p: p.name.lower(),
    "pid": lambda p: p.pid,
}


def sort_procs(procs: list[ProcessMem], key: str) -> list[ProcessMem]:
    return sorted(procs, key=SORTS[key], reverse=key not in ("name", "pid"))
