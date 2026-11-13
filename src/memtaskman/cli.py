"""Command-line entry point: `memtaskman` / `mtm`."""

from __future__ import annotations

import argparse
import json
import sys
import time

from memtaskman import __version__


def _snapshot(args, collector=None):
    from memtaskman.collector import Collector, sort_procs

    c = collector or Collector(system=not args.no_system)
    c.sample()
    time.sleep(args.interval)
    snap = c.sample()
    top = sort_procs(snap.processes, "resident")
    c.resolve_runtimes(top[:40], time_budget=2.0)
    c.refresh_pss(top if args.all else top[: args.top], time_budget=2.0)
    snap = c.sample()
    return c, snap


def cmd_main(args) -> int:
    if args.once or args.json:
        from memtaskman import report

        c, snap = _snapshot(args)
        c.close()
        if not args.all:
            snap.processes = sorted(snap.processes, key=lambda p: p.resident, reverse=True)[: args.top]
        print(report.to_json(snap) if args.json else report.render_text(snap, top=None))
        return 0
    from memtaskman.app import MemTaskManApp

    MemTaskManApp(interval=args.interval, system=not args.no_system, wsl_guest=not args.no_host).run()
    return 0


def cmd_inspect(args) -> int:
    import psutil

    from memtaskman import report
    from memtaskman.collector import Collector

    c = Collector(system=False, wsl_guest=not args.no_host)
    snap = c.sample()
    p = next((p for p in snap.processes if p.pid == args.pid), None)
    if p is None:
        try:
            psutil.Process(args.pid)
            print(f"pid {args.pid}: access denied", file=sys.stderr)
        except psutil.NoSuchProcess:
            print(f"pid {args.pid}: no such process", file=sys.stderr)
        return 1
    ins = c.inspect(p)
    print(report.to_json(ins) if args.json else report.render_inspection(ins))
    return 0 if not ins.error else 2


def cmd_diff(args) -> int:
    from memtaskman.diff import diff_snapshots

    with open(args.a, encoding="utf-8") as fa, open(args.b, encoding="utf-8") as fb:
        a, b = json.load(fa), json.load(fb)
    print(diff_snapshots(a, b, top=args.top))
    return 0


def cmd_record(args) -> int:
    from memtaskman.collector import Collector

    c = Collector(system=not args.no_system)
    c.sample()
    n = 0
    try:
        with open(args.out, "a", encoding="utf-8") as f:
            deadline = time.monotonic() + args.duration if args.duration else None
            while (args.count == 0 or n < args.count) and (deadline is None or time.monotonic() < deadline):
                time.sleep(args.interval)
                snap = c.sample()
                if not args.all:
                    snap.processes = sorted(snap.processes, key=lambda p: p.resident, reverse=True)[: args.top]
                f.write(json.dumps(snap.to_dict(), separators=(",", ":")) + "\n")
                f.flush()
                n += 1
                print(f"\rrecorded {n} snapshot(s) to {args.out}", end="", file=sys.stderr)
    except KeyboardInterrupt:
        pass
    finally:
        c.close()
        print(file=sys.stderr)
    return 0


def cmd_summary(args) -> int:
    from memtaskman.fmt import fmt_bytes
    from memtaskman.leaks import rank, read_jsonl, summarize

    snaps, skipped = read_jsonl(args.file)
    if not snaps:
        print(f"{args.file}: no snapshots", file=sys.stderr)
        return 1
    rows = list(rank(summarize(snaps)))
    span = snaps[-1].get("time", 0) - snaps[0].get("time", 0)
    if args.json:
        out = {
            "snapshots": len(snaps), "skipped_lines": skipped, "span_s": span,
            "processes": [
                {"pid": r.pid, "name": r.name, "create_time": r.start_time, "first": r.first, "last": r.last,
                 "peak": r.peak, "delta": r.delta,
                 "slope_bps": r.trend.slope if r.trend else None, "r2": r.trend.r2 if r.trend else None,
                 "leak": bool(r.trend and r.trend.is_leak)}
                for r in rows[: args.top]
            ],
        }
        print(json.dumps(out, indent=2))
        return 0
    print(f"{len(snaps)} snapshots over {span / 60:.1f} min" + (f" ({skipped} unreadable line(s) skipped)" if skipped else ""))
    print(f"{'':2}{'PID':>7}  {'Name':<26} {'First':>9} {'Last':>9} {'Peak':>9} {'Δ':>10} {'Rate/h':>10} {'R²':>5}")
    for r in rows[: args.top]:
        tr = r.trend
        flag = "▲ " if tr and tr.is_leak else "  "
        rate = (("+" if tr.slope > 0 else "-") + fmt_bytes(abs(tr.slope) * 3600)) if tr else "-"
        sign = "+" if r.delta > 0 else ""
        print(f"{flag}{r.pid:>7}  {r.name[:26]:<26} {fmt_bytes(r.first):>9} {fmt_bytes(r.last):>9} "
              f"{fmt_bytes(r.peak):>9} {sign + fmt_bytes(r.delta):>10} {rate:>10} {(f'{tr.r2:.2f}' if tr else '-'):>5}")
    n = sum(1 for r in rows if r.trend and r.trend.is_leak)
    print(f"\n{n} suspected leak(s) (▲): steady straight-line growth of private bytes.")
    return 0


def parse_duration(text: str) -> float:
    """'90', '90s', '30m', '2h' -> seconds."""
    t = text.strip().lower()
    mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(t[-1:], None)
    try:
        return float(t[:-1]) * mult if mult else float(t)
    except ValueError:
        raise argparse.ArgumentTypeError(f"bad duration: {text!r} (use e.g. 90s, 30m, 2h)") from None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="memtaskman", description="An htop for what's inside your RAM, not just how full it is.")
    p.add_argument("--version", action="version", version=f"memtaskman {__version__}")
    p.add_argument("-i", "--interval", type=float, default=1.0, help="sample interval in seconds (default 1)")
    p.add_argument("--once", action="store_true", help="print one text report and exit")
    p.add_argument("--json", action="store_true", help="print one JSON snapshot and exit")
    p.add_argument("--top", type=int, default=25, help="processes in --once/--json/record output (default 25)")
    p.add_argument("--all", action="store_true", help="include every process in --once/--json/record output")
    p.add_argument("--no-system", action="store_true", help="skip system-wide counters")
    p.add_argument("--no-host", action="store_true",
                   help="Windows: don't read the WSL2 guest's memory when inspecting vmmemWSL")
    sub = p.add_subparsers(dest="cmd")

    ins = sub.add_parser("inspect", help="break down one process's address space")
    ins.add_argument("pid", type=int)
    ins.add_argument("--json", action="store_true")
    ins.add_argument("--no-host", action="store_true", help="don't read the WSL2 guest's memory for vmmemWSL")
    ins.set_defaults(func=cmd_inspect)

    d = sub.add_parser("diff", help="compare two --json snapshots")
    d.add_argument("a")
    d.add_argument("b")
    d.add_argument("--top", type=int, default=20)
    d.set_defaults(func=cmd_diff)

    r = sub.add_parser("record", help="append snapshots to a JSON Lines file")
    r.add_argument("out")
    r.add_argument("-i", "--interval", type=float, default=5.0)
    r.add_argument("-n", "--count", type=int, default=0, help="stop after N snapshots (0 = until Ctrl+C)")
    r.add_argument("--duration", type=parse_duration, default=None, help="stop after this long, e.g. 30m, 2h")
    r.add_argument("--top", type=int, default=50)
    r.add_argument("--all", action="store_true")
    r.add_argument("--no-system", action="store_true")
    r.set_defaults(func=cmd_record)

    sm = sub.add_parser("summary", help="find steadily growing processes in a `record` file")
    sm.add_argument("file")
    sm.add_argument("--top", type=int, default=20)
    sm.add_argument("--json", action="store_true")
    sm.set_defaults(func=cmd_summary)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "func", None):
        return args.func(args)
    return cmd_main(args)
