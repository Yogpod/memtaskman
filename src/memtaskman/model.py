"""Plain data types shared by collectors, the UI and reports.

Every number is in bytes (or events per second for *_ps fields). ``None`` means
"this platform/privilege level could not measure it" and is never silently
turned into zero.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

# Evidence levels, strongest first. Shown next to every inspector claim.
MEASURED = "measured"  # read straight from an OS counter
DERIVED = "derived"  # computed by us from OS data (e.g. page-by-page working-set walk)
IDENTIFIED = "identified"  # runtime recognised from loaded modules / executable
HINT = "hint"  # configuration from the command line; a limit, not usage


@dataclass
class SystemMemory:
    total: int
    available: int
    used: int  # total - available
    free: int | None = None  # free + zeroed pages (Win) / MemFree (Linux)
    standby: int | None = None  # Windows standby list (cache that is instantly reclaimable)
    modified: int | None = None  # Windows modified list (dirty, must be written before reuse)
    cached: int | None = None  # file cache (Win system cache WS / Linux Cached+Buffers)
    compressed: int | None = None  # Windows compression store WS / Linux zswap pool
    commit_used: int | None = None
    commit_limit: int | None = None
    swap_total: int | None = None
    swap_used: int | None = None
    kernel_paged: int | None = None  # Win paged pool / Linux reclaimable slab
    kernel_nonpaged: int | None = None  # Win nonpaged pool / Linux unreclaimable slab
    page_faults_ps: float | None = None
    hard_faults_ps: float | None = None  # pages read from disk per second
    pressure_some: float | None = None  # Linux PSI: % of time some task stalled on memory (avg10)
    pressure_full: float | None = None  # Linux PSI: % of time all tasks stalled on memory (avg10)
    pressure_level: str | None = None  # macOS: normal / warn / critical (kern.memorystatus_vm_pressure_level)
    extra: dict[str, int] = field(default_factory=dict)  # platform-specific labelled values
    vm_note: str | None = None  # e.g. "this is a WSL2 VM" when running inside one
    source: str = "psutil"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProcessMem:
    pid: int
    name: str
    ppid: int
    create_time: float
    resident: int  # working set (Win) / RSS (Linux, macOS)
    private: int | None  # private commit (Win) / anonymous resident (Linux) / None
    shared: int | None = None  # resident file-backed + shmem (Linux)
    swapped: int | None = None  # VmSwap (Linux)
    pss: int | None = None  # proportional set size: shared pages split between sharers (Linux)
    uss: int | None = None  # unique set size: freed if the process exits (Linux)
    peak: int | None = None  # peak working set / VmHWM
    paged_pool: int | None = None  # Windows kernel pool charged to the process
    nonpaged_pool: int | None = None
    faults_ps: float | None = None
    growth_ps: float | None = None  # smoothed private-bytes growth rate, B/s
    runtime: str | None = None
    runtime_detail: str | None = None
    count: int = 1  # >1 when this row aggregates several processes (group-by-app view)
    leak: str | None = None  # description when growth has been steady for minutes (see leaks.py)
    cgroup: str | None = None  # Linux cgroup path (per process) or the group's path (cgroup rows)
    cgroup_stats: dict | None = None  # kernel accounting for cgroup rows (memory.current, stat, limits)

    @property
    def key(self) -> tuple[int, float]:
        return (self.pid, self.create_time)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Snapshot:
    time: float
    platform: str
    system: SystemMemory | None
    processes: list[ProcessMem]
    private_label: str = "Private"  # what "private" means on this platform
    cgroups: list[ProcessMem] | None = None  # Linux: one row per cgroup, from kernel accounting

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": 1,
            "time": self.time,
            "platform": self.platform,
            "private_label": self.private_label,
            "system": self.system.to_dict() if self.system else None,
            "processes": [p.to_dict() for p in self.processes],
            "cgroups": [g.to_dict() for g in self.cgroups] if self.cgroups is not None else None,
        }


@dataclass
class Category:
    """One slice of a process's address space."""

    name: str
    mapped: int = 0  # committed (Win) / mapped size (Linux)
    resident: int | None = None
    resident_shared: int | None = None
    swapped: int | None = None
    regions: int = 0


@dataclass
class FileMapping:
    path: str
    kind: str  # "image" or "mapped"
    mapped: int = 0
    resident: int | None = None


@dataclass
class Inspection:
    pid: int
    name: str
    categories: list[Category] = field(default_factory=list)
    top_files: list[FileMapping] = field(default_factory=list)
    reserved: int | None = None  # address space reserved but not committed (Win)
    evidence: list[tuple[str, str]] = field(default_factory=list)  # (level, text)
    cmdline: list[str] = field(default_factory=list)
    guest: dict | None = None  # vmmemWSL: the WSL2 guest's own memory view (wslhost.guest_memory)
    error: str | None = None
    elapsed: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# Fixed category names so Windows and Linux line up in the UI.
CAT_IMAGE = "Images (exe/dll/.so)"
CAT_MAPPED = "Mapped files"
CAT_SHM = "Shared memory"
CAT_HEAP = "Private (heap/anon)"
CAT_STACK = "Stacks"
CAT_OTHER = "Other"
CAT_GPU = "Graphics / GPU"  # macOS: IOKit, IOSurface, IOAccelerator, CoreAnimation, CoreGraphics
CAT_JIT = "JIT / JavaScript"  # macOS: JavaScriptCore heap and JIT code
CATEGORY_ORDER = [CAT_HEAP, CAT_JIT, CAT_GPU, CAT_STACK, CAT_IMAGE, CAT_MAPPED, CAT_SHM, CAT_OTHER]
