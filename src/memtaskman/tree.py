"""Process tree view: parent/child structure from ppid (pure functions)."""

from __future__ import annotations

from dataclasses import dataclass, replace

from memtaskman.model import ProcessMem

AUTO_COLLAPSE = 8  # nodes with more children than this start collapsed (e.g. services.exe -> svchost)


@dataclass
class TreeRow:
    proc: ProcessMem  # display copy: subtree totals when collapsed
    depth: int
    prefix: str  # tree drawing, e.g. "│  ├─ "
    children: int  # direct children
    descendants: int
    collapsed: bool


def build_children(procs: list[ProcessMem]) -> tuple[list[ProcessMem], dict[tuple, list[ProcessMem]]]:
    """(roots, children by parent key). A parent that started after its child is a reused PID: not a parent."""
    by_pid = {p.pid: p for p in procs}
    children: dict[tuple, list[ProcessMem]] = {}
    roots = []
    for p in procs:
        parent = by_pid.get(p.ppid)
        if parent is None or parent is p or (parent.create_time and p.create_time
                                             and parent.create_time > p.create_time + 1.0):
            roots.append(p)
        else:
            children.setdefault(parent.key, []).append(p)
    return roots, children


def _subtree(p: ProcessMem, children: dict, seen: set) -> list[ProcessMem]:
    out, stack = [], [p]
    while stack:
        q = stack.pop()
        if q.key in seen:
            continue  # defensive: ppid cycles
        seen.add(q.key)
        out.append(q)
        stack.extend(children.get(q.key, []))
    return out


def subtree_total(members: list[ProcessMem], root: ProcessMem) -> ProcessMem:
    """Collapsed row: private bytes summed (no overlap); resident summed (an upper bound)."""
    def total(attr):
        vals = [getattr(m, attr) for m in members if getattr(m, attr) is not None]
        return sum(vals) if vals else None

    return replace(root, resident=sum(m.resident for m in members), private=total("private"), uss=total("uss"),
                   pss=total("pss"), swapped=total("swapped"), growth_ps=total("growth_ps"),
                   faults_ps=total("faults_ps"), count=len(members))


def _auto(kids: list[ProcessMem], depth: int, limit: int) -> bool:
    """Start collapsed? Only crowded nodes: below the top level, or whose children are mostly one
    program (services.exe -> svchost x100). Top-level launchers like systemd or explorer stay open."""
    if len(kids) <= limit:
        return False
    if depth > 0:
        return True
    names = {}
    for k in kids:
        names[k.name.lower()] = names.get(k.name.lower(), 0) + 1
    return max(names.values()) * 2 >= len(kids)


def flatten(procs: list[ProcessMem], sort, *, collapsed: set, expanded: set,
            auto_collapse: int = AUTO_COLLAPSE) -> list[TreeRow]:
    """Depth-first rows. `sort(list) -> list` orders siblings (roots by their subtree's size).

    collapsed / expanded are explicit user choices by process key; otherwise nodes with more
    than auto_collapse children start collapsed.
    """
    roots, children = build_children(procs)
    rows: list[TreeRow] = []
    sizes: dict[tuple, list[ProcessMem]] = {}

    def members(p):
        if p.key not in sizes:
            sizes[p.key] = _subtree(p, children, set())
        return sizes[p.key]

    def visit(p: ProcessMem, depth: int, lead: str, last: bool, seen: set):
        if p.key in seen:
            return
        seen.add(p.key)
        kids = children.get(p.key, [])
        is_collapsed = bool(kids) and (p.key in collapsed or (p.key not in expanded and _auto(kids, depth, auto_collapse)))
        sub = members(p)
        shown = subtree_total(sub, p) if is_collapsed else p
        branch = "" if depth == 0 else lead + ("└─ " if last else "├─ ")
        rows.append(TreeRow(shown, depth, branch, len(kids), len(sub) - 1, is_collapsed))
        if is_collapsed:
            seen.update(m.key for m in sub)  # hidden inside this row, not lost
            return
        ordered = sort(kids)
        child_lead = "" if depth == 0 else lead + ("   " if last else "│  ")
        for i, k in enumerate(ordered):
            visit(k, depth + 1, child_lead, i == len(ordered) - 1, seen)

    # Roots are ordered by their whole subtree, so a small launcher with huge children ranks high.
    root_totals = {r.key: subtree_total(members(r), r) for r in roots}
    ordered_roots = [r for r in roots]
    by_total = sort([root_totals[r.key] for r in ordered_roots])
    key_order = {t.key: i for i, t in enumerate(by_total)}
    ordered_roots.sort(key=lambda r: key_order[r.key])
    seen: set = set()
    for r in ordered_roots:
        visit(r, 0, "", True, seen)
    for p in sort([p for p in procs if p.key not in seen]):  # ppid cycles: nobody reached them
        if p.key not in seen:
            visit(p, 0, "", True, seen)
    return rows
