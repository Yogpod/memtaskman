"""Windows memory sources via ctypes (no extra dependencies).

* PDH ``\\Memory\\*`` counters: standby / modified / free lists, pools, fault rates.
* ``GetPerformanceInfo``: commit charge and limit.
* ``VirtualQueryEx`` walk: committed bytes per region type (image / mapped / private).
* ``QueryWorkingSet``: which of those pages are resident right now, and shared or not.
* ``EnumProcessModulesEx``: loaded DLL names for runtime identification.

Everything degrades to ``None`` when access is denied (elevated or protected
processes when running unelevated).
"""

from __future__ import annotations

import bisect
import ctypes
import mmap
import os
import string
import sys
import time
from ctypes import wintypes as wt

from memtaskman.model import (
    CAT_HEAP,
    CAT_IMAGE,
    CAT_MAPPED,
    CAT_SHM,
    CAT_STACK,
    DERIVED,
    MEASURED,
    Category,
    FileMapping,
    Inspection,
)

assert sys.platform == "win32"

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
pdh = ctypes.WinDLL("pdh")

PAGE_SIZE = mmap.PAGESIZE

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
MEM_IMAGE = 0x1000000
MEM_MAPPED = 0x40000
MEM_PRIVATE = 0x20000
PAGE_GUARD = 0x100
ERROR_BAD_LENGTH = 24
LIST_MODULES_ALL = 0x03

kernel32.OpenProcess.restype = wt.HANDLE
kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.CloseHandle.argtypes = [wt.HANDLE]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wt.DWORD),
        ("PartitionId", wt.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
    ]


kernel32.VirtualQueryEx.restype = ctypes.c_size_t
kernel32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]
kernel32.K32GetMappedFileNameW.restype = wt.DWORD
kernel32.K32GetMappedFileNameW.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.LPWSTR, wt.DWORD]
kernel32.K32QueryWorkingSet.restype = wt.BOOL
kernel32.K32QueryWorkingSet.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD]
kernel32.K32EnumProcessModulesEx.restype = wt.BOOL
kernel32.K32EnumProcessModulesEx.argtypes = [wt.HANDLE, ctypes.POINTER(wt.HMODULE), wt.DWORD, ctypes.POINTER(wt.DWORD), wt.DWORD]
kernel32.K32GetModuleBaseNameW.restype = wt.DWORD
kernel32.K32GetModuleBaseNameW.argtypes = [wt.HANDLE, wt.HMODULE, wt.LPWSTR, wt.DWORD]
kernel32.QueryDosDeviceW.restype = wt.DWORD
kernel32.QueryDosDeviceW.argtypes = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD]


class PERFORMANCE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("cb", wt.DWORD),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", wt.DWORD),
        ("ProcessCount", wt.DWORD),
        ("ThreadCount", wt.DWORD),
    ]


kernel32.K32GetPerformanceInfo.restype = wt.BOOL
kernel32.K32GetPerformanceInfo.argtypes = [ctypes.POINTER(PERFORMANCE_INFORMATION), wt.DWORD]


ntdll = ctypes.WinDLL("ntdll")
ntdll.NtQuerySystemInformation.restype = ctypes.c_long
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.POINTER(ctypes.c_ulong)]
SystemPageFileInformation = 18
STATUS_INFO_LENGTH_MISMATCH = ctypes.c_long(0xC0000004).value


class UNICODE_STRING(ctypes.Structure):
    _fields_ = [("Length", wt.USHORT), ("MaximumLength", wt.USHORT), ("Buffer", ctypes.c_void_p)]


class SYSTEM_PAGEFILE_INFORMATION(ctypes.Structure):
    _fields_ = [("NextEntryOffset", wt.ULONG), ("TotalSize", wt.ULONG), ("TotalInUse", wt.ULONG),
                ("PeakUsage", wt.ULONG), ("PageFileName", UNICODE_STRING)]


def pagefiles() -> list[dict] | None:
    """Every pagefile: path, size, in use and peak (bytes). None when the query is refused."""
    size = 4096
    for _ in range(4):
        buf = ctypes.create_string_buffer(size)
        ret = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(SystemPageFileInformation, buf, size, ctypes.byref(ret))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size = max(size * 2, ret.value + 256)
            continue
        if status != 0:
            return None
        break
    else:
        return None
    out, offset = [], 0
    if ret.value == 0:
        return []  # no pagefile configured
    base = ctypes.addressof(buf)
    while True:
        info = SYSTEM_PAGEFILE_INFORMATION.from_address(base + offset)
        name = ctypes.wstring_at(info.PageFileName.Buffer, info.PageFileName.Length // 2) if info.PageFileName.Buffer else ""
        if name.startswith("\\??\\"):
            name = name[4:]
        out.append({"path": name, "size": info.TotalSize * PAGE_SIZE, "used": info.TotalInUse * PAGE_SIZE,
                    "peak": info.PeakUsage * PAGE_SIZE})
        if not info.NextEntryOffset:
            break
        offset += info.NextEntryOffset
    return out


kernel32.CreateMemoryResourceNotification.restype = wt.HANDLE
kernel32.CreateMemoryResourceNotification.argtypes = [ctypes.c_int]
kernel32.QueryMemoryResourceNotification.restype = wt.BOOL
kernel32.QueryMemoryResourceNotification.argtypes = [wt.HANDLE, ctypes.POINTER(wt.BOOL)]
_low_memory_handle = None


class SYSTEM_POOLTAG(ctypes.Structure):
    _fields_ = [("Tag", ctypes.c_char * 4), ("PagedAllocs", wt.ULONG), ("PagedFrees", wt.ULONG),
                ("PagedUsed", ctypes.c_size_t), ("NonPagedAllocs", wt.ULONG), ("NonPagedFrees", wt.ULONG),
                ("NonPagedUsed", ctypes.c_size_t)]


SystemPoolTagInformation = 22


def decode_tag(raw: bytes) -> str:
    """Pool tags are 4 bytes, usually ASCII and space-padded; show anything else as hex."""
    text = raw.decode("latin-1")
    return text.rstrip(" \x00") if all(32 <= b < 127 or b == 0 for b in raw) else raw.hex()


def pool_tags() -> dict[str, tuple[int, int]] | None:
    """tag -> (nonpaged bytes, paged bytes) for every kernel pool tag (like poolmon). ~0.2 ms."""
    size = 256 * 1024
    for _ in range(5):
        buf = ctypes.create_string_buffer(size)
        ret = ctypes.c_ulong(0)
        status = ntdll.NtQuerySystemInformation(SystemPoolTagInformation, buf, size, ctypes.byref(ret))
        if status == STATUS_INFO_LENGTH_MISMATCH:
            size = ret.value + 64 * 1024
            continue
        if status != 0:
            return None
        break
    else:
        return None
    count = ctypes.c_ulong.from_buffer(buf).value
    offset = ctypes.sizeof(ctypes.c_size_t)  # Count, padded to pointer alignment
    if offset + count * ctypes.sizeof(SYSTEM_POOLTAG) > ret.value:
        return None
    tags = (SYSTEM_POOLTAG * count).from_buffer(buf, offset)
    out: dict[str, tuple[int, int]] = {}
    for t in tags:
        name = decode_tag(bytes(t.Tag))
        np_, pg = out.get(name, (0, 0))
        out[name] = (np_ + t.NonPagedUsed, pg + t.PagedUsed)
    return out


def low_memory() -> bool | None:
    """Windows' own low-physical-memory signal (the one apps use to drop caches)."""
    global _low_memory_handle
    if _low_memory_handle is None:
        _low_memory_handle = kernel32.CreateMemoryResourceNotification(0) or 0  # LowMemoryResourceNotification
    if not _low_memory_handle:
        return None
    state = wt.BOOL()
    if not kernel32.QueryMemoryResourceNotification(_low_memory_handle, ctypes.byref(state)):
        return None
    return bool(state.value)


kernel32.GetProcessInformation.restype = wt.BOOL
kernel32.GetProcessInformation.argtypes = [wt.HANDLE, ctypes.c_int, ctypes.c_void_p, wt.DWORD]
kernel32.IsProcessInJob.restype = wt.BOOL
kernel32.IsProcessInJob.argtypes = [wt.HANDLE, wt.HANDLE, ctypes.POINTER(wt.BOOL)]
kernel32.GetPriorityClass.restype = wt.DWORD
kernel32.GetPriorityClass.argtypes = [wt.HANDLE]
ProcessMemoryPriority, ProcessPowerThrottling = 0, 4
MEMORY_PRIORITIES = {1: "very low", 2: "low", 3: "medium", 4: "below normal", 5: "normal"}
IDLE_PRIORITY_CLASS = 0x40


class PROCESS_POWER_THROTTLING_STATE(ctypes.Structure):
    _fields_ = [("Version", wt.ULONG), ("ControlMask", wt.ULONG), ("StateMask", wt.ULONG)]


def process_policy(pid: int) -> dict | None:
    """Memory priority, Efficiency Mode (EcoQoS) and job membership. None if the process can't be opened."""
    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        out: dict = {}
        prio = wt.ULONG()
        if kernel32.GetProcessInformation(h, ProcessMemoryPriority, ctypes.byref(prio), ctypes.sizeof(prio)):
            out["memory_priority"] = prio.value
        st = PROCESS_POWER_THROTTLING_STATE(Version=1)
        if kernel32.GetProcessInformation(h, ProcessPowerThrottling, ctypes.byref(st), ctypes.sizeof(st)):
            # Execution-speed throttling explicitly on = EcoQoS; Task Manager's Efficiency mode
            # also drops the priority class to Idle.
            out["ecoqos"] = bool(st.ControlMask & 1 and st.StateMask & 1)
        pc = kernel32.GetPriorityClass(h)
        if pc:
            out["idle_priority"] = pc == IDLE_PRIORITY_CLASS
        in_job = wt.BOOL()
        if kernel32.IsProcessInJob(h, None, ctypes.byref(in_job)):
            out["in_job"] = bool(in_job.value)
        return out
    finally:
        kernel32.CloseHandle(h)


def performance_info() -> dict[str, int] | None:
    pi = PERFORMANCE_INFORMATION()
    pi.cb = ctypes.sizeof(pi)
    if not kernel32.K32GetPerformanceInfo(ctypes.byref(pi), pi.cb):
        return None
    ps = pi.PageSize
    return {
        "commit_total": pi.CommitTotal * ps,
        "commit_limit": pi.CommitLimit * ps,
        "commit_peak": pi.CommitPeak * ps,
        "physical_total": pi.PhysicalTotal * ps,
        "physical_available": pi.PhysicalAvailable * ps,
        "system_cache": pi.SystemCache * ps,
        "kernel_paged": pi.KernelPaged * ps,
        "kernel_nonpaged": pi.KernelNonpaged * ps,
    }


# --------------------------------------------------------------------------- PDH


class _PdhValue(ctypes.Union):
    _fields_ = [("longValue", ctypes.c_long), ("doubleValue", ctypes.c_double), ("largeValue", ctypes.c_longlong)]


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    _fields_ = [("CStatus", wt.DWORD), ("u", _PdhValue)]


PDH_FMT_DOUBLE = 0x00000200
PDH_FMT_NOCAP100 = 0x00008000
pdh.PdhOpenQueryW.restype = ctypes.c_long
pdh.PdhOpenQueryW.argtypes = [wt.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wt.HANDLE)]
pdh.PdhAddEnglishCounterW.restype = ctypes.c_long
pdh.PdhAddEnglishCounterW.argtypes = [wt.HANDLE, wt.LPCWSTR, ctypes.c_size_t, ctypes.POINTER(wt.HANDLE)]
pdh.PdhCollectQueryData.restype = ctypes.c_long
pdh.PdhCollectQueryData.argtypes = [wt.HANDLE]
pdh.PdhGetFormattedCounterValue.restype = ctypes.c_long
pdh.PdhGetFormattedCounterValue.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(PDH_FMT_COUNTERVALUE)]
pdh.PdhCloseQuery.argtypes = [wt.HANDLE]

MEMORY_COUNTERS = {
    "standby_core": r"\Memory\Standby Cache Core Bytes",
    "standby_normal": r"\Memory\Standby Cache Normal Priority Bytes",
    "standby_reserve": r"\Memory\Standby Cache Reserve Bytes",
    "modified": r"\Memory\Modified Page List Bytes",
    "free_zero": r"\Memory\Free & Zero Page List Bytes",
    "cache": r"\Memory\Cache Bytes",
    "pool_paged": r"\Memory\Pool Paged Bytes",
    "pool_nonpaged": r"\Memory\Pool Nonpaged Bytes",
    "driver_resident": r"\Memory\System Driver Resident Bytes",
    "code_resident": r"\Memory\System Code Resident Bytes",
    "page_faults_ps": r"\Memory\Page Faults/sec",
    "pages_input_ps": r"\Memory\Pages Input/sec",
    "pages_output_ps": r"\Memory\Pages Output/sec",
    "pagefile_pct": r"\Paging File(_Total)\% Usage",
}


class PdhQuery:
    """A small wrapper that keeps one PDH query open across samples."""

    def __init__(self, counters: dict[str, str] = MEMORY_COUNTERS):
        self.handle = wt.HANDLE()
        self.counters: dict[str, wt.HANDLE] = {}
        if pdh.PdhOpenQueryW(None, 0, ctypes.byref(self.handle)) != 0:
            self.handle = None
            return
        for key, path in counters.items():
            h = wt.HANDLE()
            if pdh.PdhAddEnglishCounterW(self.handle, path, 0, ctypes.byref(h)) == 0:
                self.counters[key] = h
        pdh.PdhCollectQueryData(self.handle)  # prime rate counters

    def sample(self) -> dict[str, float]:
        out: dict[str, float] = {}
        if not self.handle or pdh.PdhCollectQueryData(self.handle) != 0:
            return out
        val = PDH_FMT_COUNTERVALUE()
        for key, h in self.counters.items():
            if pdh.PdhGetFormattedCounterValue(h, PDH_FMT_DOUBLE | PDH_FMT_NOCAP100, None, ctypes.byref(val)) == 0:
                out[key] = val.u.doubleValue
        return out

    def close(self) -> None:
        if self.handle:
            pdh.PdhCloseQuery(self.handle)
            self.handle = None


class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", wt.LPWSTR), ("FmtValue", PDH_FMT_COUNTERVALUE)]


PDH_FMT_LARGE = 0x00000400
PDH_MORE_DATA = 0x800007D2
pdh.PdhGetFormattedCounterArrayW.restype = ctypes.c_ulong
pdh.PdhGetFormattedCounterArrayW.argtypes = [wt.HANDLE, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.POINTER(wt.DWORD), ctypes.c_void_p]


def _counter_array(counter, fmt: int = PDH_FMT_LARGE) -> dict[str, int]:
    """Instance name -> value for a wildcard counter."""
    size, count = wt.DWORD(0), wt.DWORD(0)
    status = pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), None)
    if status != PDH_MORE_DATA or not size.value:
        return {}
    buf = ctypes.create_string_buffer(size.value)
    if pdh.PdhGetFormattedCounterArrayW(counter, fmt, ctypes.byref(size), ctypes.byref(count), buf) != 0:
        return {}
    items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W))
    out = {}
    for i in range(count.value):
        item = items[i]
        if item.FmtValue.CStatus in (0, 1):  # PDH_CSTATUS_VALID_DATA / NEW_DATA
            out[item.szName] = item.FmtValue.u.largeValue
    return out


class PrivateWorkingSet:
    """Private working set (Task Manager's "Memory" column) for every process in one query.

    Prefers the ``Process V2`` counter set (Windows 11 / Server 2022+), whose instances are
    named ``name:pid``. Falls back to the classic ``Process`` set, pairing instances with
    ``ID Process`` because its names are ambiguous (``chrome#12``).
    """

    def __init__(self):
        self.handle = wt.HANDLE()
        self.v2 = False
        self.ws = self.ids = None
        if pdh.PdhOpenQueryW(None, 0, ctypes.byref(self.handle)) != 0:
            self.handle = None
            return
        h = wt.HANDLE()
        if pdh.PdhAddEnglishCounterW(self.handle, r"\Process V2(*)\Working Set - Private", 0, ctypes.byref(h)) == 0:
            self.ws, self.v2 = h, True
        else:
            h2 = wt.HANDLE()
            ok1 = pdh.PdhAddEnglishCounterW(self.handle, r"\Process(*)\Working Set - Private", 0, ctypes.byref(h)) == 0
            ok2 = pdh.PdhAddEnglishCounterW(self.handle, r"\Process(*)\ID Process", 0, ctypes.byref(h2)) == 0
            if ok1 and ok2:
                self.ws, self.ids = h, h2
        if self.ws is None:
            self.close()

    @property
    def source(self) -> str:
        return r"\Process V2(*)" if self.v2 else r"\Process(*)"

    def sample(self) -> dict[int, int]:
        """PID -> private working set bytes. Empty when unavailable."""
        if not self.handle or pdh.PdhCollectQueryData(self.handle) != 0:
            return {}
        values = _counter_array(self.ws)
        out: dict[int, int] = {}
        if self.v2:
            for name, v in values.items():
                _, sep, pid = name.rpartition(":")
                if sep and pid.isdigit():
                    out[int(pid)] = v
        else:
            ids = _counter_array(self.ids)
            for name, v in values.items():
                pid = ids.get(name)
                if pid is not None and name != "_Total":
                    out[int(pid)] = v
        out.pop(0, None)  # Idle / _Total
        return out

    def close(self) -> None:
        if self.handle:
            pdh.PdhCloseQuery(self.handle)
            self.handle = None


# --------------------------------------------------------------------------- processes


def _open(pid: int, access: int) -> int | None:
    h = kernel32.OpenProcess(access, False, pid)
    return h or None


def module_names(pid: int) -> list[str] | None:
    """Basenames of loaded modules, or None when the process cannot be opened."""
    h = _open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    if not h:
        return None
    try:
        count = 512
        while True:
            arr = (wt.HMODULE * count)()
            needed = wt.DWORD()
            if not kernel32.K32EnumProcessModulesEx(h, arr, ctypes.sizeof(arr), ctypes.byref(needed), LIST_MODULES_ALL):
                return None
            n = needed.value // ctypes.sizeof(wt.HMODULE)
            if n <= count:
                break
            count = n + 64
        buf = ctypes.create_unicode_buffer(260)
        names = []
        for i in range(n):
            if kernel32.K32GetModuleBaseNameW(h, arr[i], buf, 260):
                names.append(buf.value)
        return names
    finally:
        kernel32.CloseHandle(h)


_device_map: list[tuple[str, str]] | None = None


def _dos_devices() -> list[tuple[str, str]]:
    global _device_map
    if _device_map is None:
        m = []
        buf = ctypes.create_unicode_buffer(1024)
        for letter in string.ascii_uppercase:
            if kernel32.QueryDosDeviceW(f"{letter}:", buf, 1024):
                m.append((buf.value + "\\", f"{letter}:\\"))
        _device_map = m
    return _device_map


def device_to_dos(path: str) -> str:
    for dev, drive in _dos_devices():
        if path.startswith(dev):
            return drive + path[len(dev):]
    return path


def _walk_regions(h) -> list[tuple[int, int, int, int, int, int]]:
    """(base, size, state, type, protect, allocation_base) for every region."""
    regions = []
    mbi = MEMORY_BASIC_INFORMATION()
    addr = 0
    sz = ctypes.sizeof(mbi)
    limit = 1 << 47 if ctypes.sizeof(ctypes.c_void_p) == 8 else 1 << 31
    while addr < limit:
        if not kernel32.VirtualQueryEx(h, ctypes.c_void_p(addr), ctypes.byref(mbi), sz):
            break
        base = mbi.BaseAddress or 0
        size = mbi.RegionSize
        regions.append((base, size, mbi.State, mbi.Type, mbi.Protect, mbi.AllocationBase or 0))
        nxt = base + size
        if nxt <= addr:
            break
        addr = nxt
    return regions


def _working_set(h) -> list[int] | None:
    """Raw PSAPI_WORKING_SET_BLOCK values, or None on failure."""
    count = 4096
    for _ in range(6):
        buf = (ctypes.c_size_t * (count + 1))()
        if kernel32.K32QueryWorkingSet(h, buf, ctypes.sizeof(buf)):
            n = buf[0]
            return list(buf[1 : 1 + n])
        if ctypes.get_last_error() != ERROR_BAD_LENGTH:
            return None
        count = int(buf[0] * 1.25) + 4096
    return None


def inspect(pid: int, name: str, *, top_files: int = 12) -> Inspection:
    t0 = time.perf_counter()
    ins = Inspection(pid=pid, name=name)
    h = _open(pid, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)
    if not h:
        ins.error = "access denied (run elevated to inspect this process)"
        return ins
    try:
        regions = _walk_regions(h)
        name_buf = ctypes.create_unicode_buffer(1024)
        file_of_alloc: dict[int, str | None] = {}

        cats = {c: Category(c) for c in (CAT_HEAP, CAT_STACK, CAT_IMAGE, CAT_MAPPED, CAT_SHM)}
        files: dict[str, FileMapping] = {}
        reserved = 0
        # Committed regions only, in address order, for page attribution.
        starts: list[int] = []
        spans: list[tuple[int, str, str | None]] = []  # (end, category, file path)

        # Thread stacks: a private allocation that contains a PAGE_GUARD region.
        stack_allocs = {ab for (_b, _s, st, ty, pr, ab) in regions if st == MEM_COMMIT and ty == MEM_PRIVATE and pr & PAGE_GUARD}

        for base, size, state, typ, _prot, alloc in regions:
            if state == MEM_RESERVE:
                reserved += size
                continue
            if state != MEM_COMMIT:
                continue
            path = None
            if typ == MEM_PRIVATE:
                cat = CAT_STACK if alloc in stack_allocs else CAT_HEAP
            else:
                if alloc not in file_of_alloc:
                    n = kernel32.K32GetMappedFileNameW(h, ctypes.c_void_p(base), name_buf, 1024)
                    file_of_alloc[alloc] = device_to_dos(name_buf.value) if n else None
                path = file_of_alloc[alloc]
                if typ == MEM_IMAGE:
                    cat = CAT_IMAGE
                elif path:
                    cat = CAT_MAPPED
                else:
                    cat = CAT_SHM  # pagefile-backed section: shared memory
            c = cats[cat]
            c.mapped += size
            c.regions += 1
            if path:
                fm = files.get(path)
                if fm is None:
                    fm = files[path] = FileMapping(path, "image" if typ == MEM_IMAGE else "mapped")
                fm.mapped += size
            starts.append(base)
            spans.append((base + size, cat, path))

        ins.reserved = reserved
        ins.evidence.append((MEASURED, f"{len(regions)} regions walked with VirtualQueryEx"))

        ws = _working_set(h)
        if ws is not None:
            for c in cats.values():
                c.resident = 0
                c.resident_shared = 0
            for fm in files.values():
                fm.resident = 0
            unattributed = 0
            for entry in ws:
                va = (entry >> 12) << 12
                i = bisect.bisect_right(starts, va) - 1
                if i < 0 or va >= spans[i][0]:
                    unattributed += 1
                    continue
                _end, cat, path = spans[i]
                c = cats[cat]
                c.resident += PAGE_SIZE
                if entry & 0x100:
                    c.resident_shared += PAGE_SIZE
                if path:
                    files[path].resident += PAGE_SIZE
            ins.evidence.append((DERIVED, f"{len(ws):,} resident pages attributed via QueryWorkingSet"))
            if unattributed:
                ins.evidence.append((DERIVED, f"{unattributed:,} resident pages are page tables / outside user regions"))
        else:
            ins.evidence.append((MEASURED, "working set detail unavailable; showing committed sizes only"))

        ins.categories = [c for c in cats.values() if c.mapped]
        key = (lambda f: f.resident or 0) if ws is not None else (lambda f: f.mapped)
        ins.top_files = sorted(files.values(), key=key, reverse=True)[:top_files]
        for f in ins.top_files:
            f.path = _short_path(f.path)
    finally:
        kernel32.CloseHandle(h)
    ins.elapsed = time.perf_counter() - t0
    return ins


def _short_path(p: str) -> str:
    win = os.environ.get("SystemRoot", r"C:\Windows")
    if p.lower().startswith(win.lower()):
        return "%SystemRoot%" + p[len(win):]
    return p
