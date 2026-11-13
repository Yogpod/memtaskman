"""Human-readable formatting helpers (pure, no I/O)."""

from __future__ import annotations

import re

_UNITS = ["B", "K", "M", "G", "T", "P"]
_base = 1024  # 1024: binary (KiB, MiB, GiB), 1000: decimal (kB, MB, GB)


def set_units(mode: str) -> None:
    """'binary' (default; what OS memory counters use) or 'decimal' (what disk vendors and Explorer use)."""
    global _base
    if mode not in ("binary", "decimal"):
        raise ValueError(f"units must be 'binary' or 'decimal', not {mode!r}")
    _base = 1024 if mode == "binary" else 1000


def units() -> str:
    return "binary" if _base == 1024 else "decimal"


def units_legend() -> str:
    """Spelled out, so a bare 'G' is never ambiguous."""
    return "K/M/G = KiB/MiB/GiB (binary)" if _base == 1024 else "K/M/G = kB/MB/GB (decimal)"


def fmt_bytes(n: float | int | None, *, long: bool = False) -> str:
    """Format a byte count compactly: 0, 512B, 1.5K, 12M, 3.40G (binary units unless set_units('decimal'))."""
    if n is None:
        return "-"
    neg = n < 0
    v = float(abs(n))
    i = 0
    while v >= _base and i < len(_UNITS) - 1:
        v /= _base
        i += 1
    if i == 0:
        s = f"{int(v)}B"
    elif v >= 100:
        s = f"{v:.0f}{_UNITS[i]}"
    elif v >= 10:
        s = f"{v:.1f}{_UNITS[i]}"
    else:
        s = f"{v:.2f}{_UNITS[i]}"
    if long and i > 0:
        s += "iB" if _base == 1024 else "B"
    return ("-" if neg else "") + s


def fmt_rate(bps: float | None) -> str:
    """Format a signed byte rate, e.g. +1.20M/s. Near-zero rates render as a dot."""
    if bps is None:
        return "-"
    if abs(bps) < 1024:
        return "0"
    sign = "+" if bps > 0 else "-"
    return f"{sign}{fmt_bytes(abs(bps))}/s"


def fmt_count_rate(n: float | None) -> str:
    if n is None:
        return "-"
    if n < 1:
        return "0"
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 10_000:
        return f"{n / 1000:.0f}k"
    if n >= 1000:
        return f"{n / 1000:.1f}k"
    return f"{n:.0f}"


def pct(part: float | None, whole: float | None) -> float | None:
    if part is None or not whole:
        return None
    return 100.0 * part / whole


_HOME_PATTERNS = [
    (re.compile(r"(?i)\b[a-z]:\\users\\[^\\/\s]+"), "~"),
    (re.compile(r"(?i)\b[a-z]:/users/[^\\/\s]+"), "~"),
    (re.compile(r"/(?:home|Users)/[^/\s]+"), "~"),
]


def redact(text: str) -> str:
    """Replace user home directories (which contain the username) with ~."""
    for pat, repl in _HOME_PATTERNS:
        text = pat.sub(repl, text)
    return text


def parse_size(text: str) -> int | None:
    """Parse sizes as used on command lines: 4g, 512m, 2048k, 1024 (bytes), 4GB, 1.5G."""
    t = text.strip().lower().rstrip("b")
    if not t:
        return None
    mult = 1
    if t[-1] in "kmgt":
        mult = 1024 ** ("kmgt".index(t[-1]) + 1)
        t = t[:-1]
    try:
        return int(float(t) * mult)
    except ValueError:
        return None
