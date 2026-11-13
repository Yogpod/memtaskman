"""Compare two --json snapshots: what grew, what appeared, what went away."""

from __future__ import annotations

from collections import defaultdict

from memtaskman.fmt import fmt_bytes

_SYSTEM_FIELDS = ["used", "available", "standby", "modified", "cached", "compressed", "commit_used",
                  "swap_used", "kernel_paged", "kernel_nonpaged"]


def _signed(n: int) -> str:
    return ("+" if n > 0 else "") + fmt_bytes(n)


def diff_snapshots(a: dict, b: dict, *, top: int = 20) -> str:
    out = []
    dt = b.get("time", 0) - a.get("time", 0)
    out.append(f"Δt = {dt:.0f}s")
    sa, sb = a.get("system") or {}, b.get("system") or {}
    rows = []
    for f in _SYSTEM_FIELDS:
        va, vb = sa.get(f), sb.get(f)
        if va is not None and vb is not None and va != vb:
            rows.append(f"  {f:<16} {fmt_bytes(va):>9} -> {fmt_bytes(vb):>9}  ({_signed(vb - va)})")
    if rows:
        out.append("System:")
        out += rows

    def by_name(snap: dict) -> dict[str, dict]:
        agg: dict[str, dict] = defaultdict(lambda: {"resident": 0, "private": 0, "count": 0})
        for p in snap.get("processes", []):
            g = agg[p["name"].lower()]
            g["name"] = p["name"]
            g["resident"] += p.get("resident") or 0
            g["private"] += p.get("private") or 0
            g["count"] += 1
        return agg

    ga, gb = by_name(a), by_name(b)
    changes = []
    for k in set(ga) | set(gb):
        pa, pb = ga.get(k), gb.get(k)
        name = (pb or pa)["name"]
        ra, rb = (pa or {}).get("resident", 0), (pb or {}).get("resident", 0)
        qa, qb = (pa or {}).get("private", 0), (pb or {}).get("private", 0)
        tag = "new" if pa is None else "gone" if pb is None else ""
        changes.append((abs(qb - qa) + abs(rb - ra), name, ra, rb, qa, qb, tag,
                        (pa or {}).get("count", 0), (pb or {}).get("count", 0)))
    changes.sort(reverse=True)
    out.append(f"Processes (grouped by name, top {top} by change):")
    out.append(f"  {'Name':<28} {'Resident Δ':>11} {'Private Δ':>11}  {'now':>9}  count")
    for _w, name, ra, rb, qa, qb, tag, ca, cb in changes[:top]:
        if ra == rb and qa == qb and not tag:
            continue
        out.append(f"  {name[:28]:<28} {_signed(rb - ra):>11} {_signed(qb - qa):>11}  {fmt_bytes(rb):>9}  {ca}->{cb} {tag}")
    return "\n".join(out)
