"""memtaskman: an htop for what's inside your RAM, not just how full it is."""

from importlib import metadata

try:
    __version__ = metadata.version("memtaskman")  # single source of truth: pyproject.toml
except metadata.PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
