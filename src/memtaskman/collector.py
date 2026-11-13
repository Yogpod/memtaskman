"""Sampling: turns OS sources into Snapshots, tracks rates and runtime identity."""

from __future__ import annotations

import os
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field

import psutil

from memtaskman import leaks
from memtaskman import runtime as rt
from memtaskman.model import (
    CATEGORY_ORDER,
    IDENTIFIED,
    WHY_NEEDS_TWO,
    WHY_OTHER_USER_LINUX,
    WHY_OTHER_USER_MAC,
    DERIVED,
    MEASURED,
    HINT,
    Inspection,
    ProcessMem,
    Snapshot,
    SystemMemory,
)

WINDOWS = sys.platform == "win32"
LINUX = sys.platform.startswith("linux")
MACOS = sys.platform == "darwin"

if WINDOWS:
    from memtaskman import win32 as native
elif LINUX:
    from memtaskman import linux as native
elif MACOS:
    from memtaskman import macos as native
else:  # other platforms: psutil only
    native = None

GROWTH_ALPHA = 0.35  # EMA weight for the private-bytes growth rate
RUNTIME_TTL = 45.0  # seconds before re-checking a process's loaded modules
LEAK_WINDOW = 600.0  # seconds of private-bytes history kept per process for leak detection
LEAK_EVERY = 5.0  # re-fit trends at most this often
PSS_TTL = 2.0  # smaps_rollup makes the kernel walk page tables; refresh visible rows at most this often


def unique_column() -> tuple[str, str] | None:
    """(header, ProcessMem attribute) of the per-platform "real RAM" column, if any.

    Linux: PSS (shared pages split between sharers). Windows: private working set
    (Task Manager's "Memory" column). Both avoid counting shared pages in full.
    """
    if LINUX:
        return ("PSS", "pss")
    if WINDOWS:
        return ("PrivWS", "uss")
    return None


def private_label() -> str:
    if WINDOWS:
        return "Private"  # private commit charge (Task Manager "Commit size")
    if LINUX:
        return "Anon"  # resident anonymous memory (RssAnon)
    if MACOS:
        return "Footprint"  # phys_footprint: Activity Monitor's "Memory" (incl. compressed + GPU)
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
    def __init__(self, system: bool = True, wsl_guest: bool = True):
        self.want_system = system
        self.wsl_guest = wsl_guest and WINDOWS
        self._pdh = native.PdhQuery() if WINDOWS and system else None
        self._pws = native.PrivateWorkingSet() if WINDOWS else None
        self._tracks: dict[tuple[int, float], _Track] = {}
        self._runtimes: dict[tuple[int, float], _RuntimeEntry] = {}
        self._pss: dict[tuple[int, float], tuple[float, int, int]] = {}  # key -> (checked, pss, uss)
        self._vm_prev: tuple[float, dict[str, int]] | None = None
        self._cg_tracks: dict[str, _Track] = {}
        self._pss_why: dict[tuple[int, float], str] = {}
        self._series: dict[tuple[int, float], deque[tuple[float, float]]] = {}
        self._leaks: dict[tuple[int, float], leaks.Trend] = {}
        self._leaks_at = 0.0
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
        self._update_leaks(now)
        for p in procs:
            tr = self._leaks.get(p.key)
            if tr is not None:
                p.leak = leaks.describe(tr)
        snap = Snapshot(now, sys.platform, system, procs, private_label())
        if LINUX:
            snap.cgroups = self._cgroup_rows(procs, now)
        return snap

    # ------------------------------------------------------------------ processes
    def _processes(self, now: float) -> list[ProcessMem]:
        out: list[ProcessMem] = []
        seen = set()
        private_ws = self._pws.sample() if self._pws else {}
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
                p.uss = private_ws.get(pid)
            elif MACOS:
                ru = native.rusage(pid)
                if ru:
                    p.private = ru["footprint"]
                    p.peak = ru["peak"]
                faults = native.task_faults(pid)
            elif LINUX:
                st = native.proc_status(pid)
                if "RssAnon" in st:
                    p.private = st["RssAnon"]
                    p.shared = st.get("RssFile", 0) + st.get("RssShmem", 0)
                p.swapped = st.get("VmSwap")
                p.peak = st.get("VmHWM")
                faults = native.proc_faults(pid)
                cg = native.proc_cgroup(pid)
                if cg:
                    p.cgroup = f"{cg[0]}:{cg[1]}"
            self._rates(p, faults, now)
            self._explain(p, faults)
            seen.add(p.key)
            out.append(p)
        for k in list(self._tracks):
            if k not in seen:
                del self._tracks[k]
        for cache in (self._runtimes, self._pss, self._series, self._leaks, self._pss_why):
            for k in list(cache):
                if k not in seen:
                    del cache[k]
        return out

    def _rates(self, p: ProcessMem, faults: int | None, now: float) -> None:
        basis = p.private if p.private is not None else p.resident
        ser = self._series.get(p.key)
        if ser is None:
            ser = self._series[p.key] = deque()
        ser.append((now, float(basis)))
        while ser and now - ser[0][0] > LEAK_WINDOW:
            ser.popleft()
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

    def _explain(self, p: ProcessMem, faults: int | None) -> None:
        """Record why per-process values are missing, so the UI never shows a bare '-'."""
        why = p.unavailable
        if p.growth_ps is None:
            why["growth_ps"] = WHY_NEEDS_TWO
        if p.faults_ps is None:
            why["faults_ps"] = WHY_NEEDS_TWO if faults is not None else "fault counter not readable"
        if WINDOWS:
            if p.uss is None and self._pws is not None:
                why["uss"] = "not in the Process counter set (protected, or just started/exited)"
            elif p.uss is None:
                why["uss"] = "PDH Process counters unavailable on this system"
        elif LINUX:
            if p.private is None:
                why["private"] = "kernel thread (no user memory)" if p.resident == 0 else "no RssAnon in /proc/<pid>/status"
            if p.swapped is None:
                why["swapped"] = "no VmSwap (kernel thread)"
            if p.pss is None:
                why["pss"] = self._pss_why.get(p.key, "PSS is read for visible rows only")
        elif MACOS:
            if p.private is None:
                why["private"] = WHY_OTHER_USER_MAC
            why["swapped"] = "macOS doesn't report swap per process (it's inside Footprint)"
        else:
            why["private"] = "not available on this platform"

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
        elif MACOS:
            self._system_macos(sm, now)
        else:
            sm.free = getattr(vm, "free", None)
            sm.cached = getattr(vm, "inactive", None)
            sm.extra = {k: getattr(vm, k) for k in ("active", "inactive", "wired") if hasattr(vm, k)}
        self._explain_system(sm)
        return sm

    def _explain_system(self, sm: SystemMemory) -> None:
        why = sm.unavailable
        if sm.page_faults_ps is None:
            why["page_faults_ps"] = WHY_NEEDS_TWO
        if WINDOWS:
            if self._pdh is None or not self._pdh.counters:
                why["standby"] = "PDH memory counters unavailable (disabled or corrupted: lodctr /r)"
            if sm.compressed is None:
                why["compressed"] = "MemCompression process not visible (compression off, or access denied)"
        elif LINUX:
            if sm.pressure_some is None:
                why["pressure_some"] = "kernel without PSI (CONFIG_PSI off or psi=0 boot option)"
            if sm.compressed is None:
                why["compressed"] = "zswap not enabled"
            if not sm.swap_total:
                why["swap_total"] = "no swap configured"
        elif MACOS:
            why["commit_used"] = "macOS has no commit charge"
            if sm.pressure_level is None:
                why["pressure_level"] = "sysctl kern.memorystatus_vm_pressure_level unreadable"

    def _system_windows(self, sm: SystemMemory, procs: list[ProcessMem]) -> None:
        sm.source = "PDH + GetPerformanceInfo"
        perf = native.performance_info() or {}
        c = self._pdh.sample() if self._pdh else {}
        if c:
            sb = [c.get(k) for k in ("standby_core", "standby_normal", "standby_reserve")]
            if any(v is not None for v in sb):
                sm.standby = int(sum(v or 0 for v in sb))
                # Reuse order when RAM is needed: reserve first, then normal, core last.
                for key, label in (("standby_reserve", "Standby: reserve (reused 1st)"),
                                   ("standby_normal", "Standby: normal (reused 2nd)"),
                                   ("standby_core", "Standby: core (reused last)")):
                    if c.get(key) is not None:
                        sm.extra[label] = int(c[key])
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
        sm.pagefiles = native.pagefiles()
        sm.low_memory = native.low_memory()
        self._first = False

    def _system_macos(self, sm: SystemMemory, now: float) -> None:
        sm.source = "host_statistics64 + sysctl"
        v = native.vm_stats()
        if v is None:
            return
        b = native.vm_breakdown(v, native.page_size())
        sm.used = b["used"]
        sm.available = max(0, sm.total - sm.used)
        sm.free = b["free"]
        sm.cached = b["cached"]
        sm.compressed = b["compressed"]
        sm.kernel_nonpaged = b["wired"]
        sm.pressure_level = native.pressure_level()
        sm.extra["App memory"] = b["app"]
        sm.extra["Wired"] = b["wired"]
        sm.extra["Purgeable"] = b["purgeable"]
        if b["compressed_original"]:
            sm.extra["Compressed (original size)"] = b["compressed_original"]
        if self._vm_prev:
            t0, prev = self._vm_prev
            dt = now - t0
            if dt > 0:
                sm.page_faults_ps = (v["faults"] - prev["faults"]) / dt
                sm.hard_faults_ps = (v["pageins"] - prev["pageins"]) / dt
        self._vm_prev = (now, v)

    def _system_linux(self, sm: SystemMemory, now: float) -> None:
        sm.source = "/proc/meminfo + /proc/vmstat"
        if native.is_wsl():
            sm.vm_note = native.WSL_NOTE
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
        psi = native.pressure()
        if psi:
            sm.pressure_some = psi.get("some", {}).get("avg10")
            sm.pressure_full = psi.get("full", {}).get("avg10")
        vs = native.vmstat()
        if self._vm_prev and vs:
            t0, prev = self._vm_prev
            dt = now - t0
            if dt > 0 and "pgfault" in vs and "pgfault" in prev:
                sm.page_faults_ps = (vs["pgfault"] - prev["pgfault"]) / dt
                sm.hard_faults_ps = (vs.get("pgmajfault", 0) - prev.get("pgmajfault", 0)) / dt
        self._vm_prev = (now, vs)

    def _update_leaks(self, now: float) -> None:
        if now - self._leaks_at < LEAK_EVERY:
            return
        self._leaks_at = now
        found = {}
        for key, ser in self._series.items():
            if len(ser) < leaks.MIN_POINTS or ser[-1][0] - ser[0][0] < leaks.MIN_SPAN_S:
                continue
            tr = leaks.fit(list(ser))
            if tr is not None and tr.is_leak:
                found[key] = tr
        self._leaks = found

    # ------------------------------------------------------------------ cgroups (Linux)
    def _cgroup_rows(self, procs: list[ProcessMem], now: float) -> list[ProcessMem]:
        """One row per leaf cgroup. Sizes come from the kernel's cgroup accounting, so shared
        pages are charged once (to the cgroup that first touched them), never per member."""
        members: dict[str, list[ProcessMem]] = {}
        for p in procs:
            if p.cgroup:
                members.setdefault(p.cgroup, []).append(p)
        rows = []
        for key, ms in members.items():
            kind, _, path = key.partition(":")
            stats = native.cgroup_stats(kind, path)
            row = ProcessMem(
                pid=min(m.pid for m in ms), name=native.cgroup_label(path), ppid=0, create_time=0.0,
                resident=0, private=None, count=len(ms), cgroup=key, cgroup_stats=stats,
            )
            if stats:
                row.resident = stats["current"]
                row.private = stats.get("anon")
                row.shared = (stats.get("file") or 0) + (stats.get("shmem") or 0) if stats.get("file") is not None else None
                row.swapped = stats.get("swap")
            else:  # root cgroup / unreadable: fall back to member sums (an upper bound)
                row.resident = sum(m.resident for m in ms)
                row.private = sum(m.private or 0 for m in ms) if any(m.private is not None for m in ms) else None
            row.pss = sum(m.pss for m in ms if m.pss is not None) if any(m.pss is not None for m in ms) else None
            row.faults_ps = sum(m.faults_ps for m in ms if m.faults_ps is not None) if any(m.faults_ps is not None for m in ms) else None
            row.runtime = next((m.runtime for m in sorted(ms, key=lambda m: -m.resident) if m.runtime), None)
            basis = row.private if row.private is not None else row.resident
            tr = self._cg_tracks.get(key)
            if tr is None:
                self._cg_tracks[key] = _Track(now, basis, None)
            elif now - tr.t > 0.05:
                inst = (basis - tr.private) / (now - tr.t)
                tr.growth = inst if tr.growth is None else GROWTH_ALPHA * inst + (1 - GROWTH_ALPHA) * tr.growth
                tr.t, tr.private = now, basis
                row.growth_ps = tr.growth
            else:
                row.growth_ps = tr.growth
            rows.append(row)
        for k in list(self._cg_tracks):
            if k not in members:
                del self._cg_tracks[k]
        # Disambiguate identical labels (e.g. /init.scope vs user@1000.service/init.scope).
        seen: dict[str, int] = {}
        for r in rows:
            seen[r.name] = seen.get(r.name, 0) + 1
        for r in rows:
            if seen[r.name] > 1:
                parts = [p for p in r.cgroup.partition(":")[2].split("/") if p]
                if len(parts) >= 2:
                    r.name = f"{r.name} ({parts[-2].removesuffix('.service').removesuffix('.slice')})"
        return rows

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
                if r is None:  # other users' processes: unreadable without root, left as None
                    self._pss_why[p.key] = WHY_OTHER_USER_LINUX if _other_user(p.pid) else "smaps_rollup unreadable"
                    p.unavailable["pss"] = self._pss_why[p.key]
                    continue
                p.pss, p.uss = r
                self._pss[p.key] = (now, r[0], r[1])
                done += 1
            return done

    def _identify(self, p: ProcessMem, now: float) -> _RuntimeEntry:
        mods: list[str] = []
        if native is not None and p.pid > 4:
            try:
                mods = native.module_names(p.pid) or []
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
        if self.wsl_guest and rt.stem(p.name) in ("vmmemwsl", "vmmem"):
            self._add_wsl_guest(ins, p)
        self._add_models(ins, p)
        if WINDOWS:
            self._add_policy(ins, p)
        ins.categories.sort(key=lambda c: CATEGORY_ORDER.index(c.name) if c.name in CATEGORY_ORDER else 99)
        with self._lock:
            if p.key not in self._runtimes or time.time() - self._runtimes[p.key].checked > RUNTIME_TTL:
                self._runtimes[p.key] = self._identify(p, time.time())
            info, cmd = self.runtime_of(p.key)
            tr = self._leaks.get(p.key)
        if tr is not None:
            ins.evidence.insert(0, (DERIVED, "possible leak: " + leaks.describe(tr)))
        ins.cmdline = cmd
        ins.unavailable = dict(p.unavailable)
        if info:
            ins.evidence = [e for e in info.evidence if e[1]] + ins.evidence
        elif not ins.error:
            ins.evidence.insert(0, (HINT, "no known runtime recognised"))
        return ins

    def _add_wsl_guest(self, ins: Inspection, p: ProcessMem) -> None:
        from memtaskman import wslhost
        from memtaskman.fmt import fmt_bytes

        guest, why = wslhost.guest_memory()
        if guest is None:
            ins.evidence.append((HINT, f"guest view unavailable: {why}"))
            return
        ins.guest = guest
        if ins.error and "access denied" in ins.error:
            ins.error = None  # expected for the VM process; the guest view below is what matters
            ins.evidence.append((MEASURED, "VM process address space is not inspectable; showing the guest's view"))
        used, cache = guest.get("used"), guest.get("reclaimable_cache")
        ins.evidence.append((MEASURED, f"guest {guest['distro']}: {fmt_bytes(used)} used, "
                                       f"{fmt_bytes(guest.get('cache'))} page cache, {fmt_bytes(guest.get('free'))} free "
                                       f"(of {fmt_bytes(guest.get('total'))})"))
        if used is not None and p.resident > used:
            ins.evidence.append((DERIVED, f"Windows holds {fmt_bytes(p.resident)} for the VM but the guest only uses "
                                          f"{fmt_bytes(used)}: the other {fmt_bytes(p.resident - used)} is guest cache / "
                                          f"freed pages not yet returned"))
        cfg = wslhost.read_wslconfig()
        limit = cfg.get("wsl2.memory")
        ins.evidence.append((HINT, f".wslconfig memory={limit} caps the VM" if limit else
                             "no memory= limit in .wslconfig: the VM may grow to half of RAM by default"))
        reclaim = cfg.get("experimental.automemoryreclaim") or cfg.get("wsl2.automemoryreclaim")
        if reclaim:
            ins.evidence.append((HINT, f"autoMemoryReclaim={reclaim} is set"))
        else:
            ins.evidence.append((HINT, "autoMemoryReclaim=gradual in .wslconfig returns idle cache to Windows"))
        if cache:
            ins.evidence.append((HINT, f"free {fmt_bytes(cache)} of cache now: "
                                       "wsl -u root -e sh -c \"echo 1 > /proc/sys/vm/drop_caches\""))

    def _add_policy(self, ins: Inspection, p: ProcessMem) -> None:
        pol = native.process_policy(p.pid)
        if not pol:
            return
        mp = pol.get("memory_priority")
        if mp is not None:
            note = "" if mp == 5 else ": its pages go to lower-priority standby and are reused sooner"
            ins.evidence.append((MEASURED, f"memory priority {mp} ({native.MEMORY_PRIORITIES.get(mp, '?')}){note}"))
        if pol.get("ecoqos"):
            mode = "Efficiency mode" if pol.get("idle_priority") else "EcoQoS"
            ins.evidence.append((MEASURED, f"{mode} on: throttled for power efficiency"))
        if pol.get("in_job"):
            ins.evidence.append((MEASURED, "runs inside a job object (its memory limits, if any, are only "
                                           "readable by the job's owner)"))

    def _add_models(self, ins: Inspection, p: ProcessMem) -> None:
        """Name memory-mapped model files and, for Ollama, report its RAM / VRAM split."""
        from memtaskman import models
        from memtaskman.fmt import fmt_bytes

        for f in ins.top_files:
            if not models.looks_like_model(f.path):
                continue
            meta = models.gguf_info(os.path.expandvars(f.path.replace("%SystemRoot%", "%SYSTEMROOT%")))
            if not meta:
                continue
            size = meta["file_size"]
            res = f.resident or 0
            ins.evidence.insert(0, (IDENTIFIED, f"model file {models.describe_model(meta)}: {fmt_bytes(res)} of "
                                                f"{fmt_bytes(size)} resident ({100 * res / max(size, 1):.0f}%)"))
        if rt.stem(p.name) in ("ollama", "ollama_llama_server", "ollama app"):
            loaded, why = models.ollama_loaded()
            if loaded is None:
                ins.evidence.append((HINT, why))
            elif not loaded:
                ins.evidence.append((MEASURED, "Ollama: no model loaded (GET /api/ps)"))
            for m in loaded or []:
                extra = " ".join(x for x in (m["params"], m["quant"]) if x)
                ins.evidence.insert(0, (MEASURED, f"Ollama {m['name']} {extra}: {fmt_bytes(m['ram'])} in RAM, "
                                                  f"{fmt_bytes(m['vram'])} in VRAM (of {fmt_bytes(m['size'])})"))

    def close(self) -> None:
        if self._pdh:
            self._pdh.close()
        if self._pws:
            self._pws.close()


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
    "uss": lambda p: p.uss or 0,
    "growth": lambda p: p.growth_ps or 0,
    "faults": lambda p: p.faults_ps or 0,
    "name": lambda p: p.name.lower(),
    "pid": lambda p: p.pid,
    "count": lambda p: p.count,
    "extra": lambda p: ((p.paged_pool or 0) + (p.nonpaged_pool or 0)) if p.paged_pool is not None else (p.swapped or 0),
    "runtime": lambda p: (p.runtime is None, f"{p.runtime or ''} {p.runtime_detail or ''}".lower()),
}
ASCENDING = {"name", "pid", "runtime"}  # natural order is A-Z / low-high; everything else largest first


def _other_user(pid: int) -> bool:
    try:
        import os

        return os.stat(f"/proc/{pid}").st_uid != os.getuid()
    except (OSError, AttributeError):
        return False


def matches(p: ProcessMem, text: str) -> bool:
    """Case-insensitive filter on name, runtime label or exact PID."""
    t = text.strip().lower()
    if not t:
        return True
    if t.isdigit() and int(t) == p.pid:
        return True
    return t in p.name.lower() or t in f"{p.runtime or ''} {p.runtime_detail or ''}".lower()


def sort_procs(procs: list[ProcessMem], key: str, invert: bool = False) -> list[ProcessMem]:
    """Sort by a SORTS key in its natural direction; invert=True flips it."""
    descending = key not in ASCENDING
    return sorted(procs, key=SORTS[key], reverse=descending != invert)
