"""macOS memory sources via ctypes on libSystem (no extra dependencies).

* ``host_statistics64(HOST_VM_INFO64)``: free / active / inactive / wired / compressed /
  purgeable / file-backed vs anonymous pages, fault and page-in counters.
* ``sysctl``: ``vm.pagesize``, ``kern.memorystatus_vm_pressure_level``.
* ``proc_pid_rusage(RUSAGE_INFO_V4)``: physical footprint (Activity Monitor's "Memory"),
  lifetime peak footprint, page-ins.
* ``proc_pidinfo(PROC_PIDTASKINFO)``: fault counter.
* ``proc_pidinfo(PROC_PIDREGIONPATHINFO)``: the per-region walk ``vmmap`` does, with the
  allocation tag (malloc, stack, IOKit, CoreAnimation, JavaScriptCore …), share mode,
  resident / shared / swapped-out pages and the backing file.

Nothing here needs debugger entitlements or ``task_for_pid``. Other users' processes
return EPERM unless run as root; those values stay ``None``.

Struct layouts and category rules are plain Python so they're unit-tested on every OS.
The live calls are exercised by CI on macos-latest and by tools/smoke.py.
"""

from __future__ import annotations

import ctypes
import os
import sys
import time
from ctypes import c_int, c_int32, c_uint8, c_uint16, c_uint32, c_uint64, c_void_p

from memtaskman.model import (
    CAT_GPU,
    CAT_HEAP,
    CAT_JIT,
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


# ---------------------------------------------------------------------- structs (any OS)


class vm_statistics64(ctypes.Structure):
    _fields_ = [
        ("free_count", c_uint32), ("active_count", c_uint32), ("inactive_count", c_uint32), ("wire_count", c_uint32),
        ("zero_fill_count", c_uint64), ("reactivations", c_uint64), ("pageins", c_uint64), ("pageouts", c_uint64),
        ("faults", c_uint64), ("cow_faults", c_uint64), ("lookups", c_uint64), ("hits", c_uint64), ("purges", c_uint64),
        ("purgeable_count", c_uint32), ("speculative_count", c_uint32),
        ("decompressions", c_uint64), ("compressions", c_uint64), ("swapins", c_uint64), ("swapouts", c_uint64),
        ("compressor_page_count", c_uint32), ("throttled_count", c_uint32),
        ("external_page_count", c_uint32), ("internal_page_count", c_uint32),
        ("total_uncompressed_pages_in_compressor", c_uint64),
    ]


HOST_VM_INFO64 = 4
HOST_VM_INFO64_COUNT = ctypes.sizeof(vm_statistics64) // 4


class rusage_info_v4(ctypes.Structure):
    _fields_ = [("ri_uuid", c_uint8 * 16)] + [(n, c_uint64) for n in (
        "ri_user_time", "ri_system_time", "ri_pkg_idle_wkups", "ri_interrupt_wkups", "ri_pageins",
        "ri_wired_size", "ri_resident_size", "ri_phys_footprint", "ri_proc_start_abstime", "ri_proc_exit_abstime",
        "ri_child_user_time", "ri_child_system_time", "ri_child_pkg_idle_wkups", "ri_child_interrupt_wkups",
        "ri_child_pageins", "ri_child_elapsed_abstime", "ri_diskio_bytesread", "ri_diskio_byteswritten",
        "ri_cpu_time_qos_default", "ri_cpu_time_qos_maintenance", "ri_cpu_time_qos_background",
        "ri_cpu_time_qos_utility", "ri_cpu_time_qos_legacy", "ri_cpu_time_qos_user_initiated",
        "ri_cpu_time_qos_user_interactive", "ri_billed_system_time", "ri_serviced_system_time",
        "ri_logical_writes", "ri_lifetime_max_phys_footprint", "ri_instructions", "ri_cycles",
        "ri_billed_energy", "ri_serviced_energy", "ri_interval_max_phys_footprint", "ri_runnable_time",
    )]


RUSAGE_INFO_V4 = 4


class proc_taskinfo(ctypes.Structure):
    _fields_ = [
        ("pti_virtual_size", c_uint64), ("pti_resident_size", c_uint64), ("pti_total_user", c_uint64),
        ("pti_total_system", c_uint64), ("pti_threads_user", c_uint64), ("pti_threads_system", c_uint64),
        ("pti_policy", c_int32), ("pti_faults", c_int32), ("pti_pageins", c_int32), ("pti_cow_faults", c_int32),
        ("pti_messages_sent", c_int32), ("pti_messages_received", c_int32), ("pti_syscalls_mach", c_int32),
        ("pti_syscalls_unix", c_int32), ("pti_csw", c_int32), ("pti_threadnum", c_int32),
        ("pti_numrunning", c_int32), ("pti_priority", c_int32),
    ]


PROC_PIDTASKINFO = 4


class proc_regioninfo(ctypes.Structure):
    _fields_ = [
        ("pri_protection", c_uint32), ("pri_max_protection", c_uint32), ("pri_inheritance", c_uint32),
        ("pri_flags", c_uint32), ("pri_offset", c_uint64), ("pri_behavior", c_uint32),
        ("pri_user_wired_count", c_uint32), ("pri_user_tag", c_uint32), ("pri_pages_resident", c_uint32),
        ("pri_pages_shared_now_private", c_uint32), ("pri_pages_swapped_out", c_uint32),
        ("pri_pages_dirtied", c_uint32), ("pri_ref_count", c_uint32), ("pri_shadow_depth", c_uint32),
        ("pri_share_mode", c_uint32), ("pri_private_pages_resident", c_uint32),
        ("pri_shared_pages_resident", c_uint32), ("pri_obj_id", c_uint32), ("pri_depth", c_uint32),
        ("pri_address", c_uint64), ("pri_size", c_uint64),
    ]


class vinfo_stat(ctypes.Structure):
    _fields_ = [
        ("vst_dev", c_uint32), ("vst_mode", c_uint16), ("vst_nlink", c_uint16), ("vst_ino", c_uint64),
        ("vst_uid", c_uint32), ("vst_gid", c_uint32),
        ("vst_atime", ctypes.c_int64), ("vst_atimensec", ctypes.c_int64),
        ("vst_mtime", ctypes.c_int64), ("vst_mtimensec", ctypes.c_int64),
        ("vst_ctime", ctypes.c_int64), ("vst_ctimensec", ctypes.c_int64),
        ("vst_birthtime", ctypes.c_int64), ("vst_birthtimensec", ctypes.c_int64),
        ("vst_size", ctypes.c_int64), ("vst_blocks", ctypes.c_int64), ("vst_blksize", c_int32),
        ("vst_flags", c_uint32), ("vst_gen", c_uint32), ("vst_rdev", c_uint32), ("vst_qspare", ctypes.c_int64 * 2),
    ]


class vnode_info(ctypes.Structure):
    _fields_ = [("vi_stat", vinfo_stat), ("vi_type", c_int), ("vi_pad", c_int), ("vi_fsid", c_int32 * 2)]


class vnode_info_path(ctypes.Structure):
    _fields_ = [("vip_vi", vnode_info), ("vip_path", ctypes.c_char * 1024)]


class proc_regionwithpathinfo(ctypes.Structure):
    _fields_ = [("prp_prinfo", proc_regioninfo), ("prp_vip", vnode_info_path)]


PROC_PIDREGIONPATHINFO = 8

# ---------------------------------------------------------------------- pure rules

# Share modes (mach/vm_region.h)
SM_COW, SM_PRIVATE, SM_EMPTY, SM_SHARED, SM_TRUESHARED, SM_PRIVATE_ALIASED, SM_SHARED_ALIASED = 1, 2, 3, 4, 5, 6, 7
VM_PROT_EXECUTE = 4

# Allocation tags (mach/vm_statistics.h, VM_MEMORY_*)
TAG_MALLOC = {1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 53, 61}  # malloc zones, sbrk, realloc, tcmalloc, dyld malloc
TAG_STACK = {30}
TAG_GUARD = {31}
TAG_GPU = {
    21,  # IOKit
    42, 51, 52, 54, 55, 56, 57, 58,  # CoreGraphics, CoreAnimation (LayerKit), CGImage, CG data/shared/fb/backing/xalloc
    66, 67, 68,  # GLSL, OpenCL, CoreImage
    88,  # IOSurface
    100,  # IOAccelerator (GPU, Apple silicon unified memory)
}
TAG_JIT = {63, 64, 65}  # JavaScriptCore heap, JIT executable allocator, JIT register file
TAG_NAMES = {
    1: "malloc", 2: "malloc small", 3: "malloc large", 4: "malloc huge", 7: "malloc tiny", 11: "malloc nano",
    12: "malloc medium", 21: "IOKit", 30: "stack", 33: "dylib", 51: "CoreAnimation", 52: "CGImage",
    60: "dyld", 63: "JavaScriptCore", 64: "JIT code", 88: "IOSurface", 100: "IOAccelerator (GPU)",
}


def is_shared_cache(path: str) -> bool:
    return "dyld_shared_cache" in path


def categorize_region(tag: int, share_mode: int, path: str, protection: int) -> str:
    """Category for one region, using the allocation tag first, then backing file and share mode."""
    if tag in TAG_STACK:
        return CAT_STACK
    if tag in TAG_GUARD:
        return CAT_OTHER
    if tag in TAG_GPU:
        return CAT_GPU
    if tag in TAG_JIT:
        return CAT_JIT
    if tag in TAG_MALLOC:
        return CAT_HEAP
    if path:
        if is_shared_cache(path) or protection & VM_PROT_EXECUTE or path.endswith((".dylib", ".so")) \
                or ".framework/" in path or tag == 33:
            return CAT_IMAGE
        return CAT_MAPPED
    if share_mode in (SM_SHARED, SM_TRUESHARED, SM_SHARED_ALIASED):
        return CAT_SHM
    return CAT_HEAP  # anonymous private memory without a recognised tag


def vm_breakdown(v: dict[str, int], page: int) -> dict[str, int]:
    """Activity Monitor's categories from vm_statistics64 page counts."""
    app = max(0, v["internal_page_count"] - v["purgeable_count"]) * page
    wired = v["wire_count"] * page
    compressed = v["compressor_page_count"] * page
    cached = (v["external_page_count"] + v["purgeable_count"]) * page
    free = (v["free_count"] + v.get("speculative_count", 0)) * page
    return {
        "app": app,
        "wired": wired,
        "compressed": compressed,
        "cached": cached,
        "free": free,
        "used": app + wired + compressed,  # Activity Monitor "Memory Used"
        "compressed_original": v.get("total_uncompressed_pages_in_compressor", 0) * page,
        "purgeable": v["purgeable_count"] * page,
    }


PRESSURE_LEVELS = {1: "normal", 2: "warn", 4: "critical"}


def pressure_name(level: int | None) -> str | None:
    if level is None:
        return None
    return PRESSURE_LEVELS.get(level, f"level {level}")


def module_basename(path: str) -> str:
    """'…/Electron Framework.framework/Versions/A/Electron Framework' -> 'Electron Framework'."""
    return path.rstrip("/").rsplit("/", 1)[-1]


# ---------------------------------------------------------------------- live calls (macOS only)

_lib = None


def _libsystem():
    global _lib
    if _lib is None:
        if sys.platform != "darwin":
            raise OSError("macOS only")
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        lib.mach_host_self.restype = c_uint32
        lib.host_statistics64.argtypes = [c_uint32, c_int, c_void_p, ctypes.POINTER(c_uint32)]
        lib.host_statistics64.restype = c_int
        lib.sysctlbyname.argtypes = [ctypes.c_char_p, c_void_p, ctypes.POINTER(ctypes.c_size_t), c_void_p, ctypes.c_size_t]
        lib.sysctlbyname.restype = c_int
        lib.proc_pid_rusage.argtypes = [c_int, c_int, c_void_p]
        lib.proc_pid_rusage.restype = c_int
        lib.proc_pidinfo.argtypes = [c_int, c_int, c_uint64, c_void_p, c_int]
        lib.proc_pidinfo.restype = c_int
        _lib = lib
    return _lib


def sysctl_int(name: str) -> int | None:
    lib = _libsystem()
    val = ctypes.c_int64(0)
    size = ctypes.c_size_t(ctypes.sizeof(val))
    if lib.sysctlbyname(name.encode(), ctypes.byref(val), ctypes.byref(size), None, 0) != 0:
        return None
    if size.value == 4:
        return ctypes.c_int32.from_buffer_copy(bytes(val)[:4]).value
    return val.value


_page = None


def page_size() -> int:
    global _page
    if _page is None:
        _page = sysctl_int("vm.pagesize") or os.sysconf("SC_PAGE_SIZE")
    return _page


def vm_stats() -> dict[str, int] | None:
    lib = _libsystem()
    st = vm_statistics64()
    count = c_uint32(HOST_VM_INFO64_COUNT)
    if lib.host_statistics64(lib.mach_host_self(), HOST_VM_INFO64, ctypes.byref(st), ctypes.byref(count)) != 0:
        return None
    return {name: getattr(st, name) for name, _ in vm_statistics64._fields_}


def pressure_level() -> str | None:
    return pressure_name(sysctl_int("kern.memorystatus_vm_pressure_level"))


def rusage(pid: int) -> dict[str, int] | None:
    """Footprint numbers for one process; None when not permitted (other users without root)."""
    ri = rusage_info_v4()
    if _libsystem().proc_pid_rusage(pid, RUSAGE_INFO_V4, ctypes.byref(ri)) != 0:
        return None
    return {"footprint": ri.ri_phys_footprint, "peak": ri.ri_lifetime_max_phys_footprint,
            "resident": ri.ri_resident_size, "pageins": ri.ri_pageins}


def task_faults(pid: int) -> int | None:
    ti = proc_taskinfo()
    n = _libsystem().proc_pidinfo(pid, PROC_PIDTASKINFO, 0, ctypes.byref(ti), ctypes.sizeof(ti))
    return ti.pti_faults if n == ctypes.sizeof(ti) else None


def regions(pid: int, limit: int = 200_000):
    """Yield (address, size, regioninfo, path) for every region, like vmmap."""
    lib = _libsystem()
    info = proc_regionwithpathinfo()
    size = ctypes.sizeof(info)
    addr = 0
    for _ in range(limit):
        n = lib.proc_pidinfo(pid, PROC_PIDREGIONPATHINFO, addr, ctypes.byref(info), size)
        if n <= 0:
            return
        r = info.prp_prinfo
        path = info.prp_vip.vip_path.decode("utf-8", errors="replace") if info.prp_vip.vip_path else ""
        yield r.pri_address, r.pri_size, r, path
        nxt = r.pri_address + r.pri_size
        if nxt <= addr:
            return
        addr = nxt


def module_names(pid: int) -> list[str] | None:
    """Basenames of mapped libraries, frameworks and executables (for runtime identification)."""
    names = set()
    try:
        for _a, _s, r, path in regions(pid, limit=20_000):
            if path and not is_shared_cache(path) and (r.pri_protection & VM_PROT_EXECUTE or path.endswith(".dylib")):
                names.add(module_basename(path))
    except OSError:
        return None
    return sorted(names) if names else None


def inspect(pid: int, name: str, *, top_files: int = 12) -> Inspection:
    t0 = time.perf_counter()
    ins = Inspection(pid=pid, name=name)
    page = page_size()
    cats: dict[str, Category] = {}
    files: dict[str, FileMapping] = {}
    tags: dict[int, int] = {}
    count = 0
    for _addr, size, r, path in regions(pid):
        count += 1
        cat = categorize_region(r.pri_user_tag, r.pri_share_mode, path, r.pri_protection)
        c = cats.setdefault(cat, Category(cat, resident=0, resident_shared=0, swapped=0))
        res = r.pri_pages_resident * page
        c.mapped += size
        c.resident += res
        c.resident_shared += r.pri_shared_pages_resident * page
        c.swapped += r.pri_pages_swapped_out * page
        c.regions += 1
        if res and r.pri_user_tag:
            tags[r.pri_user_tag] = tags.get(r.pri_user_tag, 0) + res
        if path and cat in (CAT_IMAGE, CAT_MAPPED):
            key = "dyld shared cache" if is_shared_cache(path) else path
            f = files.setdefault(key, FileMapping(key, "image" if cat == CAT_IMAGE else "mapped", 0, 0))
            f.mapped += size
            f.resident += res
    if count == 0:
        ins.error = "cannot read regions: process exited, or owned by another user (run with sudo)"
        return ins
    ins.categories = list(cats.values())
    ins.top_files = sorted(files.values(), key=lambda f: f.resident or 0, reverse=True)[:top_files]
    ins.evidence.append((MEASURED, f"{count} regions walked with proc_pidinfo(PROC_PIDREGIONPATHINFO)"))
    ru = rusage(pid)
    if ru:
        from memtaskman.fmt import fmt_bytes

        ins.evidence.append((MEASURED, f"footprint {fmt_bytes(ru['footprint'])} (Activity Monitor's Memory), "
                                       f"peak {fmt_bytes(ru['peak'])}"))
    top_tags = sorted(tags.items(), key=lambda kv: -kv[1])[:4]
    if top_tags:
        from memtaskman.fmt import fmt_bytes

        desc = ", ".join(f"{TAG_NAMES.get(t, f'tag {t}')} {fmt_bytes(b)}" for t, b in top_tags)
        ins.evidence.append((MEASURED, f"largest allocation tags (resident): {desc}"))
    ins.evidence.append((DERIVED, "Swapped column = pages compressed or swapped out"))
    ins.elapsed = time.perf_counter() - t0
    return ins
