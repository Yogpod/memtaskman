"""Regenerate the README screenshots from the live machine.

    uv run python tools/capture_screenshots.py [--out docs/screenshots]

Runs the TUI headlessly in privacy mode (no command lines, home directories shown
as ~) and saves SVGs. After capturing, it scans the files for the current
username and refuses to keep any that contain it.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import os
import re
from pathlib import Path

from memtaskman.app import MemTaskManApp

SIZE = (180, 50)
BROWSERS = {"Chrome", "Edge", "Brave", "Electron", "Firefox", "WebView2", "Opera", "Vivaldi", "Chromium", "Arc"}


async def wait_for(pilot, cond, timeout=15.0):
    waited = 0.0
    while not cond() and waited < timeout:
        await pilot.pause(0.5)
        waited += 0.5
    return cond()


def select_row(app, predicate) -> bool:
    table = app.query_one("#procs")
    for i, key in enumerate(app.rows):
        if predicate(app.rows[key]):
            table.move_cursor(row=i, animate=False)
            return True
    return False


async def capture(out: Path) -> list[Path]:
    saved: list[Path] = []
    app = MemTaskManApp(interval=1.0, privacy=True)
    async with app.run_test(size=SIZE) as pilot:
        await wait_for(pilot, lambda: app.snapshot is not None)
        await pilot.pause(12)  # let the charts collect some history and runtimes resolve

        def shot(name: str):
            app.save_screenshot(f"{name}.svg", path=str(out))
            saved.append(out / f"{name}.svg")
            print("saved", out / f"{name}.svg")

        # 1. Dashboard + inspector on the biggest browser / Electron process.
        await pilot.pause(1)
        picked = select_row(app, lambda p: p.runtime in BROWSERS) or select_row(app, lambda p: p.private)
        await wait_for(pilot, lambda: app.inspection is not None and app.inspection.categories)
        await pilot.pause(1)
        app.paused = True
        await pilot.pause(0.5)
        shot("dashboard" if picked else "dashboard-generic")

        # 2. Grouped by app.
        app.paused = False
        await pilot.press("g")
        await pilot.pause(2.5)
        app.paused = True
        await pilot.pause(0.5)
        shot("grouped")

        # 3. Help screen.
        await pilot.press("question_mark")
        await pilot.pause(0.8)
        shot("help")
        await pilot.press("escape")
        await pilot.pause(0.3)

        # 4. Slim mode.
        app.paused = False
        await pilot.press("g")
        if app.group_mode != "none":
            await pilot.press("g")
        await pilot.press("m")
        await pilot.pause(2.5)
        app.paused = True
        await pilot.pause(0.5)
        shot("slim")
    return saved


def leaks_identity(path: Path, needles: list[str]) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace").lower()
    return [n for n in needles if n and n.lower() in text]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="docs/screenshots")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    saved = asyncio.run(capture(out))

    user = getpass.getuser()
    needles = [user, os.path.basename(os.path.expanduser("~"))]
    needles = [n for n in dict.fromkeys(needles) if n and len(n) >= 3 and not re.fullmatch(r"(?i)user|root|admin", n)]
    bad = 0
    for path in saved:
        found = leaks_identity(path, needles)
        if found:
            bad += 1
            path.unlink()
            print(f"REMOVED {path}: contains {found}")
    print(f"{len(saved) - bad} screenshot(s) kept")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
