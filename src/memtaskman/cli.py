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

    MemTaskManApp(interval=args.interval, system=not args.no_system).run()
    return 0


def cmd_inspect(args) -> int:
    import psutil

    from memtaskman import report
    from memtaskman.collector import Collector

    c = Collector(system=False)
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
            while args.count == 0 or n < args.count:
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


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="memtaskman", description="An htop for what's inside your RAM, not just how full it is.")
    p.add_argument("--version", action="version", version=f"memtaskman {__version__}")
    p.add_argument("-i", "--interval", type=float, default=1.0, help="sample interval in seconds (default 1)")
    p.add_argument("--once", action="store_true", help="print one text report and exit")
    p.add_argument("--json", action="store_true", help="print one JSON snapshot and exit")
    p.add_argument("--top", type=int, default=25, help="processes in --once/--json/record output (default 25)")
    p.add_argument("--all", action="store_true", help="include every process in --once/--json/record output")
    p.add_argument("--no-system", action="store_true", help="skip system-wide counters")
    sub = p.add_subparsers(dest="cmd")

    ins = sub.add_parser("inspect", help="break down one process's address space")
    ins.add_argument("pid", type=int)
    ins.add_argument("--json", action="store_true")
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
    r.add_argument("--top", type=int, default=50)
    r.add_argument("--all", action="store_true")
    r.add_argument("--no-system", action="store_true")
    r.set_defaults(func=cmd_record)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "func", None):
        return args.func(args)
    return cmd_main(args)
