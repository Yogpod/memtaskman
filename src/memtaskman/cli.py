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


def cmd_self_test() -> int:
    """Run the real TUI headlessly for a few seconds (used to verify portable builds)."""
    import asyncio

    from memtaskman.app import MemTaskManApp

    async def run() -> int:
        app = MemTaskManApp(interval=0.5)
        async with app.run_test(size=(160, 48)) as pilot:
            await pilot.pause(3.0)
            rows = app.query_one("#procs").row_count
            await pilot.press("down", "g", "question_mark", "escape", "slash", "a", "escape", "m")
            await pilot.pause(1.0)
        print(f"self-test: {rows} rows, inspector {'ok' if app.inspection else 'missing'}")
        return 0 if rows > 0 else 1

    return asyncio.run(run())


def cmd_main(args) -> int:
    if args.self_test:
        return cmd_self_test()
    if args.once or args.json:
        from memtaskman import report

        args.top = args.top or 25  # the config file's 'top' is for the TUI

        c, snap = _snapshot(args)
        c.close()
        if args.filter:
            from memtaskman.collector import matches

            snap.processes = [p for p in snap.processes if matches(p, args.filter)]
        if not args.all:
            snap.truncated = len(snap.processes) > args.top
            snap.processes = sorted(snap.processes, key=lambda p: p.resident, reverse=True)[: args.top]
        print(report.to_json(snap) if args.json else report.render_text(snap, top=None))
        return 0
    from memtaskman.app import MemTaskManApp

    MemTaskManApp(interval=args.interval, system=not args.no_system, wsl_guest=not args.no_host,
                  privacy=args.privacy, settings=getattr(args, "settings", None)).run()
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
    from memtaskman.diff import by_name, diff_data, render

    with open(args.a, encoding="utf-8") as fa, open(args.b, encoding="utf-8") as fb:
        a, b = json.load(fa), json.load(fb)
    if args.by_name:
        print(by_name(a, b, top=args.top))
        return 0
    d = diff_data(a, b, threshold=args.threshold)
    print(json.dumps(d, indent=2) if args.json else render(d, top=args.top))
    return 0


def _size_arg(text: str) -> int:
    from memtaskman.fmt import parse_size

    v = parse_size(text)
    if v is None:
        raise argparse.ArgumentTypeError(f"bad size: {text!r} (use e.g. 0, 512k, 16m, 1g)")
    return v


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
                if args.filter:
                    from memtaskman.collector import matches

                    snap.processes = [p for p in snap.processes if matches(p, args.filter)]
                if not args.all:
                    snap.truncated = len(snap.processes) > args.top
                    snap.processes = sorted(snap.processes, key=lambda p: p.resident, reverse=True)[: args.top]
                f.write(json.dumps(snap.to_dict(compact=args.compact), separators=(",", ":")) + "\n")
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
    p.add_argument("-i", "--interval", type=float, default=None, help="sample interval in seconds (default 1)")
    p.add_argument("--once", action="store_true", help="print one text report and exit")
    p.add_argument("--json", action="store_true", help="print one JSON snapshot and exit")
    p.add_argument("--top", type=int, default=None,
                   help="rows: in the TUI (default 50) or in --once/--json output (default 25)")
    p.add_argument("--all", action="store_true", help="include every process in --once/--json/record output")
    p.add_argument("--no-system", action="store_true", help="skip system-wide counters")
    p.add_argument("--sort", choices=["resident", "pss", "uss", "private", "growth", "faults", "name", "pid"],
                   help="initial sort column")
    p.add_argument("--group", choices=["none", "app", "cgroup"], help="initial grouping")
    p.add_argument("--tree", action="store_true", help="start in the process tree view")
    p.add_argument("--slim", action="store_true", help="start in slim mode")
    p.add_argument("--read-only", action="store_true", help="disable ending processes (the k key)")
    p.add_argument("--print-config", action="store_true",
                   help="show the effective settings (config file + flags) as TOML and exit")
    p.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    p.add_argument("--units", choices=["binary", "decimal"], default=None,
                   help="binary: 1G = 1 GiB (default, like OS counters); decimal: 1G = 1 GB (like Explorer)")
    p.add_argument("--filter", metavar="TEXT", help="only processes whose name, runtime or PID matches TEXT")
    p.add_argument("--privacy", action="store_true",
                   help="hide command lines and home-directory paths (for screenshots and screen sharing)")
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
    d.add_argument("--json", action="store_true", help="machine-readable output with every change")
    d.add_argument("--threshold", type=_size_arg, default=16 * 1024 * 1024,
                   help="hide changes smaller than this in text output (default 16m)")
    d.add_argument("--by-name", action="store_true", help="totals per executable name instead of per process")
    d.set_defaults(func=cmd_diff)

    r = sub.add_parser("record", help="append snapshots to a JSON Lines file")
    r.add_argument("out")
    r.add_argument("-i", "--interval", type=float, default=5.0)
    r.add_argument("-n", "--count", type=int, default=0, help="stop after N snapshots (0 = until Ctrl+C)")
    r.add_argument("--duration", type=parse_duration, default=None, help="stop after this long, e.g. 30m, 2h")
    r.add_argument("--top", type=int, default=50)
    r.add_argument("--all", action="store_true")
    r.add_argument("--no-system", action="store_true")
    r.add_argument("--filter", metavar="TEXT", help="only record matching processes")
    r.add_argument("--compact", action="store_true",
                   help="store only the fields diff/summary use (about 2.5x smaller)")
    r.set_defaults(func=cmd_record)

    sm = sub.add_parser("summary", help="find steadily growing processes in a `record` file")
    sm.add_argument("file")
    sm.add_argument("--top", type=int, default=20)
    sm.add_argument("--json", action="store_true")
    sm.set_defaults(func=cmd_summary)
    return p


def apply_config(args) -> tuple[dict, dict, list[str]]:
    """Merge the config file under the command-line flags; flags win."""
    from memtaskman import config

    file_settings, warnings = config.load()
    cli = {
        "interval": args.interval,
        "units": args.units,
        "sort": getattr(args, "sort", None),
        "group": getattr(args, "group", None),
        "tree": True if getattr(args, "tree", False) else None,
        "slim": True if getattr(args, "slim", False) else None,
        "all": True if args.all else None,
        "top": args.top,
        "privacy": True if args.privacy else None,
        "system": False if args.no_system else None,
        "wsl_guest": False if args.no_host else None,
        "read_only": True if getattr(args, "read_only", False) else None,
    }
    eff, src = config.resolve(cli, file_settings)
    return eff, src, warnings


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from memtaskman import config
    from memtaskman.fmt import set_units

    if getattr(args, "func", None):  # subcommands: only units come from the config file
        file_settings, _warnings = config.load()
        set_units(getattr(args, "units", None) or file_settings.get("units", "binary"))
        return args.func(args)
    eff, src, warnings = apply_config(args)
    for w in warnings:
        print(f"memtaskman: config: {w}", file=sys.stderr)
    if args.print_config:
        print(config.render(eff, src, config.config_path()))
        return 0
    set_units(eff["units"])
    args.interval = eff["interval"]
    args.no_system = not eff["system"]
    args.no_host = not eff["wsl_guest"]
    args.privacy = eff["privacy"]
    args.settings = eff
    return cmd_main(args)
