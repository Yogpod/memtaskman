"""End-to-end smoke test against the live machine (used by CI on every OS).

Unlike tests/, this touches real OS counters: it samples, inspects its own
process, drives the TUI headlessly and runs every CLI subcommand.

    uv run python tools/smoke.py
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from memtaskman.collector import LINUX, WINDOWS, Collector, sort_procs

FAILURES: list[str] = []


def check(cond: bool, what: str) -> None:
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        FAILURES.append(what)


def collector_checks() -> None:
    c = Collector()
    c.sample()
    time.sleep(1.0)
    snap = c.sample()
    check(len(snap.processes) > 5, f"sampled {len(snap.processes)} processes")
    me = next((p for p in snap.processes if p.pid == os.getpid()), None)
    check(me is not None and me.resident > 0, "own process present with resident bytes")
    sm = snap.system
    check(sm is not None and sm.total > 0 and 0 < sm.available <= sm.total, "system total/available sane")
    if WINDOWS or LINUX:
        check(sm.commit_used is not None and sm.commit_limit, "commit charge reported")
        check(sm.page_faults_ps is not None, "system fault rate reported")
        check(me.private is not None, "own private bytes reported")
    if WINDOWS:
        check(sm.standby is not None and sm.modified is not None, "standby/modified lists via PDH")
        check(any(k.startswith("Standby: ") for k in sm.extra), "standby split by priority")
        with_ws = sum(1 for p in snap.processes if p.uss is not None)
        check(me.uss is not None and 0 < me.uss <= me.resident, "own private working set via PDH")
        check(with_ws > len(snap.processes) // 2, f"private working set for {with_ws}/{len(snap.processes)} processes")
    n = c.resolve_runtimes(sort_procs(snap.processes, "resident")[:30], time_budget=5.0)
    check(n > 0, f"runtime identification ran for {n} processes")
    if LINUX:
        c.refresh_pss([me], time_budget=2.0)
        check(me.pss is not None and me.pss > 0, "own PSS from smaps_rollup")

    ins = c.inspect(me)
    if WINDOWS or LINUX:
        check(ins.error is None, f"inspect self: {ins.error or 'no error'}")
        check(len(ins.categories) >= 3, f"inspect self: {len(ins.categories)} categories")
        check(any(c.resident for c in ins.categories), "inspect self: resident bytes attributed")
        py = c.runtime_of(me.key)[0]
        check(py is not None and py.name.startswith("Python"), f"self identified as {py and py.label}")
    else:
        check(ins.error is not None, "inspect reports unsupported platform cleanly")
    c.close()


async def tui_checks() -> None:
    from memtaskman.app import MemTaskManApp

    app = MemTaskManApp(interval=0.5)
    async with app.run_test(size=(160, 48)) as pilot:
        await pilot.pause(2.5)
        table = app.query_one("#procs")
        check(table.row_count > 0, f"TUI table has {table.row_count} rows")
        await pilot.press("down")
        await pilot.pause(3.0)
        check(app.inspection is not None, "TUI inspected the selected process")
        for key in "sgacmp":
            await pilot.press(key)
            await pilot.pause(0.6)
        check(app.grouped and app.show_all and app.paused, "TUI toggles respond")
        await pilot.press("question_mark")
        await pilot.pause(0.3)
        await pilot.press("escape")
        await pilot.pause(0.3)
        check(app.screen is not None, "help screen opens and closes")


def run(*args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONUTF8="1")
    return subprocess.run([sys.executable, "-m", "memtaskman", *args], capture_output=True, text=True,
                          encoding="utf-8", env=env, timeout=120)


def cli_checks() -> None:
    r = run("--once", "--top", "5", "-i", "0.5")
    check(r.returncode == 0 and "Resident" in r.stdout, "mtm --once")
    with tempfile.TemporaryDirectory() as d:
        a, b, rec = Path(d, "a.json"), Path(d, "b.json"), Path(d, "r.jsonl")
        for path in (a, b):
            r = run("--json", "--all", "-i", "0.5")
            check(r.returncode == 0, f"mtm --json -> {path.name}")
            path.write_text(r.stdout, encoding="utf-8")
            data = json.loads(r.stdout)
            check(data["version"] == 1 and data["processes"], f"{path.name} parses with processes")
        r = run("diff", str(a), str(b))
        check(r.returncode == 0 and "Processes" in r.stdout, "mtm diff")
        r = run("record", str(rec), "-i", "0.5", "-n", "2")
        lines = rec.read_text(encoding="utf-8").splitlines() if rec.exists() else []
        check(r.returncode == 0 and len(lines) == 2, "mtm record wrote 2 snapshots")
    r = run("inspect", str(os.getpid()))
    expected = 0 if (WINDOWS or LINUX) else 2
    check(r.returncode == expected, f"mtm inspect <self> exit {r.returncode}")


def main() -> int:
    print(f"platform {sys.platform}, python {sys.version.split()[0]}")
    collector_checks()
    asyncio.run(tui_checks())
    cli_checks()
    print(f"\n{len(FAILURES)} failure(s)")
    return 1 if FAILURES else 0


if __name__ == "__main__":
    raise SystemExit(main())
