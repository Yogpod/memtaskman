"""Plain-text and JSON output for --once / --json / inspect."""

from __future__ import annotations

import json

from memtaskman.fmt import fmt_bytes, fmt_count_rate, fmt_rate, pct
from memtaskman.model import Inspection, Snapshot, SystemMemory


def system_lines(sm: SystemMemory) -> list[str]:
    lines = []
    up = pct(sm.used, sm.total)
    lines.append(f"RAM      {fmt_bytes(sm.used)} / {fmt_bytes(sm.total)} used ({up:.0f}%), {fmt_bytes(sm.available)} available")
    parts = []
    if sm.modified is not None:
        parts.append(f"modified {fmt_bytes(sm.modified)}")
    if sm.standby is not None:
        parts.append(f"standby {fmt_bytes(sm.standby)}")
    if sm.free is not None:
        parts.append(f"free {fmt_bytes(sm.free)}")
    if sm.cached is not None:
        parts.append(f"file cache {fmt_bytes(sm.cached)}")
    if sm.compressed is not None:
        parts.append(f"compressed {fmt_bytes(sm.compressed)}")
    if parts:
        lines.append("         " + ", ".join(parts))
    if sm.commit_used is not None and sm.commit_limit:
        lines.append(f"Commit   {fmt_bytes(sm.commit_used)} / {fmt_bytes(sm.commit_limit)} ({pct(sm.commit_used, sm.commit_limit):.0f}%)")
    if sm.swap_total:
        lines.append(f"Swap     {fmt_bytes(sm.swap_used)} / {fmt_bytes(sm.swap_total)}")
    if sm.kernel_paged is not None:
        lines.append(f"Kernel   paged/reclaimable {fmt_bytes(sm.kernel_paged)}, nonpaged/unreclaimable {fmt_bytes(sm.kernel_nonpaged)}")
    if sm.page_faults_ps is not None:
        lines.append(f"Faults   {fmt_count_rate(sm.page_faults_ps)}/s, hard {fmt_count_rate(sm.hard_faults_ps)}/s")
    for k, v in sm.extra.items():
        lines.append(f"         {k}: {fmt_bytes(v)}")
    if sm.pressure_level:
        lines.append(f"Pressure {sm.pressure_level}")
    if sm.pressure_some is not None:
        lines.append(f"Pressure some {sm.pressure_some:.1f}%, full {sm.pressure_full or 0:.1f}% (PSI avg10)")
    if sm.vm_note:
        lines.append(f"Note     {sm.vm_note}")
    return lines


def render_text(snap: Snapshot, *, top: int | None = 25) -> str:
    out: list[str] = []
    if snap.system:
        out += system_lines(snap.system)
        out.append("")
    procs = sorted(snap.processes, key=lambda p: p.resident, reverse=True)
    if top:
        procs = procs[:top]
    pl = snap.private_label
    from memtaskman.collector import unique_column

    uniq = unique_column()
    has_pss = uniq is not None and any(getattr(p, uniq[1]) is not None for p in procs)
    pss_h = f" {uniq[0]:>9}" if has_pss else ""
    out.append(f"{'PID':>7}  {'Name':<28} {'Resident':>9}{pss_h} {pl:>9} {'Growth':>10} {'Faults/s':>8}  Runtime")
    for p in procs:
        rt = f"{p.runtime or ''} {p.runtime_detail or ''}".strip()
        pss = f" {fmt_bytes(getattr(p, uniq[1])):>9}" if has_pss else ""
        out.append(
            f"{p.pid:>7}  {p.name[:28]:<28} {fmt_bytes(p.resident):>9}{pss} {fmt_bytes(p.private):>9} "
            f"{fmt_rate(p.growth_ps):>10} {fmt_count_rate(p.faults_ps):>8}  {rt}"
        )
    return "\n".join(out)


def render_inspection(ins: Inspection) -> str:
    out = [f"{ins.name} (pid {ins.pid})"]
    if ins.error:
        out.append(f"  error: {ins.error}")
    if ins.categories:
        out.append(f"  {'Category':<22} {'Mapped':>9} {'Resident':>9} {'Shared':>9}")
        for c in ins.categories:
            out.append(f"  {c.name:<22} {fmt_bytes(c.mapped):>9} {fmt_bytes(c.resident):>9} {fmt_bytes(c.resident_shared):>9}")
        if ins.reserved:
            out.append(f"  {'Reserved (uncommitted)':<22} {fmt_bytes(ins.reserved):>9}")
    if ins.guest:
        g = ins.guest
        out.append(f"  Inside the WSL2 VM ({g['distro']}):")
        for label, key in (("used by Linux", "used"), ("anonymous", "anon"), ("page cache", "cache"),
                           ("tmpfs", "shmem"), ("free", "free"), ("VM size", "total")):
            if g.get(key) is not None:
                out.append(f"    {label:<14} {fmt_bytes(g[key]):>9}")
    if ins.top_files:
        out.append("  Top files:")
        for f in ins.top_files:
            out.append(f"    {fmt_bytes(f.resident):>9} res {fmt_bytes(f.mapped):>9} map  {f.path}")
    for level, text in ins.evidence:
        out.append(f"  [{level}] {text}")
    if ins.cmdline:
        out.append("  cmd: " + " ".join(ins.cmdline)[:400])
    return "\n".join(out)


def to_json(obj) -> str:
    return json.dumps(obj.to_dict() if hasattr(obj, "to_dict") else obj, indent=2)
