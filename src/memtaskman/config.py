"""User configuration: defaults from a TOML file, overridden by command-line flags.

    Windows  %APPDATA%\\memtaskman\\config.toml
    Linux    $XDG_CONFIG_HOME/memtaskman/config.toml  (default ~/.config)
    macOS    ~/Library/Application Support/memtaskman/config.toml

`mtm --print-config` shows the effective settings and where each came from.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path

# name -> (default, type, choices or None, description)
SETTINGS: dict[str, tuple] = {
    "interval": (1.0, float, None, "seconds between samples"),
    "sort": ("resident", str, ("resident", "pss", "uss", "private", "growth", "faults", "name", "pid"),
             "initial sort column"),
    "group": ("none", str, ("none", "app", "cgroup"), "initial grouping"),
    "tree": (False, bool, None, "start in the process tree view"),
    "top": (50, int, None, "rows shown in the TUI unless 'all' is on"),
    "all": (False, bool, None, "show every process instead of the top N"),
    "slim": (False, bool, None, "start in slim mode (bars and table only)"),
    "units": ("binary", str, ("binary", "decimal"), "binary: 1G = 1 GiB; decimal: 1G = 1 GB"),
    "privacy": (False, bool, None, "hide command lines and home-directory paths"),
    "wsl_guest": (True, bool, None, "Windows: read the WSL2 guest's memory when inspecting vmmemWSL"),
    "system": (True, bool, None, "sample system-wide counters"),
    "read_only": (False, bool, None, "disable ending processes (the k key)"),
}


def config_path() -> Path:
    override = os.environ.get("MEMTASKMAN_CONFIG")
    if override:
        return Path(override)
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA") or Path.home() / "AppData" / "Roaming")
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config")
    return base / "memtaskman" / "config.toml"


class ConfigError(ValueError):
    pass


def validate(raw: dict) -> tuple[dict, list[str]]:
    """Known, well-typed keys only. Returns (settings, warnings)."""
    out, warnings = {}, []
    for key, value in raw.items():
        k = key.replace("-", "_")
        if k not in SETTINGS:
            warnings.append(f"unknown setting '{key}' ignored")
            continue
        default, typ, choices, _ = SETTINGS[k]
        if typ is float and isinstance(value, int) and not isinstance(value, bool):
            value = float(value)
        if not isinstance(value, typ) or (typ is int and isinstance(value, bool)):
            warnings.append(f"'{key}' should be {typ.__name__}, got {value!r}; using default {default!r}")
            continue
        if choices and value not in choices:
            warnings.append(f"'{key}' must be one of {', '.join(choices)}; got {value!r}")
            continue
        if k == "interval" and value < 0.25:
            warnings.append("'interval' below 0.25 s; using 0.25")
            value = 0.25
        if k == "top" and value < 1:
            warnings.append("'top' must be at least 1")
            continue
        out[k] = value
    return out, warnings


def load(path: Path | None = None) -> tuple[dict, list[str]]:
    """(settings from the file, warnings). Missing file -> ({}, [])."""
    p = path or config_path()
    try:
        text = p.read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}, []
    except OSError as e:
        return {}, [f"cannot read {p}: {e}"]
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        return {}, [f"{p} is not valid TOML ({e}); using defaults"]
    section = raw.get("memtaskman", raw)  # allow an optional [memtaskman] table
    return validate(section)


def resolve(cli: dict, file_settings: dict) -> tuple[dict, dict]:
    """Effective settings and the source of each ('flag', 'config' or 'default').

    `cli` holds only flags the user actually gave (None / absent = not given).
    """
    eff, src = {}, {}
    for k, (default, *_rest) in SETTINGS.items():
        if cli.get(k) is not None:
            eff[k], src[k] = cli[k], "flag"
        elif k in file_settings:
            eff[k], src[k] = file_settings[k], "config"
        else:
            eff[k], src[k] = default, "default"
    return eff, src


def render(eff: dict, src: dict, path: Path) -> str:
    """Effective settings as TOML, ready to paste into the config file."""
    def toml(v):
        if isinstance(v, bool):
            return "true" if v else "false"
        if isinstance(v, str):
            return f'"{v}"'
        return repr(v)

    lines = [f"# memtaskman settings ({'found' if path.exists() else 'not created yet'}: {path})", ""]
    for k, (default, _typ, choices, desc) in SETTINGS.items():
        hint = f" ({' | '.join(choices)})" if choices else ""
        lines.append(f"# {desc}{hint}; from {src[k]}")
        lines.append(f"{k} = {toml(eff[k])}")
    return "\n".join(lines)
