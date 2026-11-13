"""Leak detection: sustained, steady growth rather than an instantaneous rate.

Pure functions over (time, bytes) series, shared by the live TUI and
``mtm summary``. A leak looks like a straight line going up: a least-squares fit
with a high R² and a meaningful total increase. Garbage-collected runtimes grow
and drop in a sawtooth, which fits a line badly (low R²) and is not flagged.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable, Iterator

MIN_SPAN_S = 120.0  # need at least 2 minutes of data
MIN_POINTS = 12
MIN_R2 = 0.85  # how straight the line must be
MIN_GROWTH = 16 * 1024 * 1024  # fitted growth over the window must exceed 16 MiB ...
MIN_REL_GROWTH = 0.05  # ... and 5% of the starting size


@dataclass
class Trend:
    slope: float  # bytes per second
    r2: float
    span: float  # seconds covered
    start: float  # fitted value at the first sample
    points: int

    @property
    def growth(self) -> float:
        return self.slope * self.span

    @property
    def is_leak(self) -> bool:
        return (
            self.span >= MIN_SPAN_S
            and self.points >= MIN_POINTS
            and self.slope > 0
            and self.r2 >= MIN_R2
            and self.growth >= MIN_GROWTH
            and self.growth >= MIN_REL_GROWTH * max(self.start, 1.0)
        )


def fit(series: list[tuple[float, float]]) -> Trend | None:
    """Least-squares line through (t, v). None when there is too little data."""
    n = len(series)
    if n < 3:
        return None
    t0 = series[0][0]
    xs = [t - t0 for t, _ in series]
    ys = [v for _, v in series]
    mx = sum(xs) / n
    my = sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return None
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    syy = sum((y - my) ** 2 for y in ys)
    slope = sxy / sxx
    r2 = (sxy * sxy) / (sxx * syy) if syy > 0 else 0.0
    return Trend(slope=slope, r2=r2, span=xs[-1], start=my - slope * mx, points=n)


def describe(tr: Trend) -> str:
    from memtaskman.fmt import fmt_bytes

    per_hour = tr.slope * 3600
    return (f"steady growth {fmt_bytes(tr.growth)} over {tr.span / 60:.0f} min "
            f"({fmt_bytes(per_hour)}/h, R² {tr.r2:.2f})")


# ---------------------------------------------------------------------- recordings


def read_jsonl(path: str) -> tuple[list[dict], int]:
    """Snapshots from a `mtm record` file, skipping torn or corrupt lines. Returns (snapshots, skipped)."""
    snaps, skipped = [], 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1  # typically the last line of an interrupted recording
                continue
            if isinstance(obj, dict) and "processes" in obj:
                snaps.append(obj)
            else:
                skipped += 1
    return snaps, skipped


@dataclass
class SeriesSummary:
    pid: int
    name: str
    start_time: float
    first: int
    last: int
    peak: int
    trend: Trend | None

    @property
    def delta(self) -> int:
        return self.last - self.first


def summarize(snaps: Iterable[dict]) -> list[SeriesSummary]:
    """Per process (PID + start time), the private-bytes series and its trend."""
    series: dict[tuple[int, float], list[tuple[float, float]]] = {}
    names: dict[tuple[int, float], str] = {}
    for s in snaps:
        t = s.get("time", 0.0)
        for p in s.get("processes", []):
            v = p.get("private")
            if v is None:
                v = p.get("resident")
            if v is None:
                continue
            key = (p["pid"], p.get("create_time", 0.0))
            series.setdefault(key, []).append((t, float(v)))
            names[key] = p.get("name", "?")
    out = []
    for key, pts in series.items():
        pts.sort()
        vals = [v for _, v in pts]
        out.append(SeriesSummary(pid=key[0], name=names[key], start_time=key[1], first=int(vals[0]),
                                 last=int(vals[-1]), peak=int(max(vals)), trend=fit(pts)))
    return out


def rank(summaries: list[SeriesSummary]) -> Iterator[SeriesSummary]:
    """Suspected leaks first (by fitted growth), then everything else by growth."""
    def score(s: SeriesSummary):
        tr = s.trend
        return (tr.is_leak if tr else False, tr.growth * tr.r2 if tr else 0.0)
    return iter(sorted(summaries, key=score, reverse=True))
