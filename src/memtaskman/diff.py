"""Compare two --json snapshots: what grew, shrank, appeared, went away or restarted.

Processes are paired by PID *and* start time, so a reused PID is never mistaken for
the same process. Unmatched processes whose name is unique on both sides are paired
as "restarted". When a snapshot was trimmed to the top N, a missing process is
reported as "not listed" rather than "gone".
"""

from __future__ import annotations

from collections import Counter, defaultdict

from memtaskman.fmt import fmt_bytes

DEFAULT_THRESHOLD = 16 * 1024 * 1024
_SYSTEM_FIELDS = ["used", "available", "standby", "modified", "cached", "compressed", "commit_used",
                  "swap_used", "kernel_paged", "kernel_nonpaged"]


def _signed(n: int) -> str:
    return ("+" if n > 0 else "") + fmt_bytes(n)


def _key(p: dict) -> tuple[int, float]:
    return (p["pid"], round(p.get("create_time") or 0.0, 1))


def _size(p: dict | None, field: str) -> int:
    return (p or {}).get(field) or 0


def pair_processes(a: dict, b: dict) -> list[dict]:
    """One entry per process with a status: changed, restarted, new, gone, not listed."""
    pa = {_key(p): p for p in a.get("processes", [])}
    pb = {_key(p): p for p in b.get("processes", [])}
    out: list[dict] = []
    for k in pa.keys() & pb.keys():
        out.append({"status": "changed", "a": pa[k], "b": pb[k]})
    only_a = [pa[k] for k in pa.keys() - pb.keys()]
    only_b = [pb[k] for k in pb.keys() - pa.keys()]

    # Same app, new PID: pair when the name is unique among the leftovers on both sides.
    ca = Counter(p["name"].lower() for p in only_a)
    cb = Counter(p["name"].lower() for p in only_b)
    restarted = {n for n in ca if ca[n] == 1 and cb.get(n) == 1}
    by_name_b = {p["name"].lower(): p for p in only_b if p["name"].lower() in restarted}
    for p in list(only_a):
        n = p["name"].lower()
        if n in restarted:
            out.append({"status": "restarted", "a": p, "b": by_name_b[n]})
            only_a.remove(p)
            only_b.remove(by_name_b[n])

    trunc_a, trunc_b = bool(a.get("truncated")), bool(b.get("truncated"))
    for p in only_a:
        out.append({"status": "not listed" if trunc_b else "gone", "a": p, "b": None})
    for p in only_b:
        out.append({"status": "not listed before" if trunc_a else "new", "a": None, "b": p})

    for e in out:
        e["name"] = (e["b"] or e["a"])["name"]
        e["pid_a"] = e["a"]["pid"] if e["a"] else None
        e["pid_b"] = e["b"]["pid"] if e["b"] else None
        for f in ("resident", "private"):
            e[f"{f}_a"] = (e["a"] or {}).get(f) if e["a"] else None
            e[f"{f}_b"] = (e["b"] or {}).get(f) if e["b"] else None
            e[f"{f}_delta"] = None if e["status"].startswith("not listed") else _size(e["b"], f) - _size(e["a"], f)
        e["weight"] = max(abs(e["resident_delta"] or 0), abs(e["private_delta"] or 0),
                          _size(e["a"], "resident") if e["status"] == "gone" else 0,
                          _size(e["b"], "resident") if e["status"] == "new" else 0)
        del e["a"], e["b"]
    out.sort(key=lambda e: e["weight"], reverse=True)
    return out


def diff_data(a: dict, b: dict, *, threshold: int = DEFAULT_THRESHOLD) -> dict:
    sa, sb = a.get("system") or {}, b.get("system") or {}
    system = {}
    for f in _SYSTEM_FIELDS:
        va, vb = sa.get(f), sb.get(f)
        if va is not None and vb is not None:
            system[f] = {"a": va, "b": vb, "delta": vb - va}
    warnings = []
    if a.get("truncated") or b.get("truncated"):
        warnings.append("a snapshot was limited to the top N processes; take both with --all for a full comparison")
    if a.get("platform") and b.get("platform") and a["platform"] != b["platform"]:
        warnings.append(f"snapshots come from different platforms ({a['platform']} vs {b['platform']})")
    return {
        "dt": b.get("time", 0) - a.get("time", 0),
        "threshold": threshold,
        "warnings": warnings,
        "system": system,
        "processes": pair_processes(a, b),
    }


def render(d: dict, *, top: int = 20) -> str:
    out = [f"Δt = {d['dt']:.0f}s"]
    for w in d["warnings"]:
        out.append(f"warning: {w}")
    rows = [(f, v) for f, v in d["system"].items() if v["delta"]]
    if rows:
        out.append("System:")
        for f, v in rows:
            out.append(f"  {f:<16} {fmt_bytes(v['a']):>9} -> {fmt_bytes(v['b']):>9}  ({_signed(v['delta'])})")
    thr = d["threshold"]
    shown = [e for e in d["processes"] if e["weight"] >= thr]
    hidden = len(d["processes"]) - len(shown)
    out.append(f"Processes (top {top} by change, hiding changes under {fmt_bytes(thr)}):")
    out.append(f"  {'PID':>13}  {'Name':<26} {'Resident Δ':>11} {'Private Δ':>11} {'now':>9}  status")
    for e in shown[:top]:
        pid = f"{e['pid_a']}->{e['pid_b']}" if e["status"] == "restarted" else str(e["pid_b"] or e["pid_a"])
        rd = "-" if e["resident_delta"] is None else _signed(e["resident_delta"])
        pd = "-" if e["private_delta"] is None else _signed(e["private_delta"])
        now = fmt_bytes(e["resident_b"]) if e["resident_b"] is not None else "-"
        status = "" if e["status"] == "changed" else e["status"]
        out.append(f"  {pid:>13}  {e['name'][:26]:<26} {rd:>11} {pd:>11} {now:>9}  {status}")
    if hidden:
        out.append(f"  ({hidden} smaller change(s) hidden; --threshold 0 shows all, --json has everything)")
    return "\n".join(out)


def by_name(a: dict, b: dict, *, top: int = 20) -> str:
    """Older summary: totals per executable name (useful for many short-lived processes)."""
    def agg(snap: dict) -> dict[str, dict]:
        g: dict[str, dict] = defaultdict(lambda: {"resident": 0, "private": 0, "count": 0})
        for p in snap.get("processes", []):
            x = g[p["name"].lower()]
            x["name"] = p["name"]
            x["resident"] += p.get("resident") or 0
            x["private"] += p.get("private") or 0
            x["count"] += 1
        return g

    ga, gb = agg(a), agg(b)
    rows = []
    for k in set(ga) | set(gb):
        xa, xb = ga.get(k, {}), gb.get(k, {})
        name = (xb or xa)["name"]
        rows.append((abs(xb.get("private", 0) - xa.get("private", 0)) + abs(xb.get("resident", 0) - xa.get("resident", 0)),
                     name, xa, xb))
    rows.sort(key=lambda r: r[0], reverse=True)
    out = [f"  {'Name':<28} {'Resident Δ':>11} {'Private Δ':>11}  count"]
    for _w, name, xa, xb in rows[:top]:
        out.append(f"  {name[:28]:<28} {_signed(xb.get('resident', 0) - xa.get('resident', 0)):>11} "
                   f"{_signed(xb.get('private', 0) - xa.get('private', 0)):>11}  {xa.get('count', 0)}->{xb.get('count', 0)}")
    return "\n".join(out)


def diff_snapshots(a: dict, b: dict, *, top: int = 20, threshold: int = DEFAULT_THRESHOLD) -> str:
    return render(diff_data(a, b, threshold=threshold), top=top)
