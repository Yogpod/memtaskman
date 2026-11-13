# memtaskman

[![CI](https://github.com/Yogpod/memtaskman/actions/workflows/ci.yml/badge.svg)](https://github.com/Yogpod/memtaskman/actions/workflows/ci.yml)

An `htop` for what's **inside** your RAM, not just how full it is.

Task Manager tells you Chrome uses 5 GB. memtaskman tells you which of those bytes are
heap, which are DLL code shared with every other process, which are memory-mapped files
(fonts, caches, model weights), which are thread stacks, and how much is actually resident
versus merely committed. It also shows *where* the rest of your RAM is: standby cache,
modified pages, the compression store, kernel pools and commit charge.

Inspired by [gputaskman](https://github.com/shanselman/gputaskman), which does the same for VRAM.

> Early, experimental software. Windows is the primary target, Linux is supported (tested on Ubuntu under WSL2), macOS
> gets the basic psutil view without the address-space inspector.

## What you get

- **System bar**: RAM split into *In use / Modified / Standby / Free* (Windows) or
  *In use / Cache / Free* (Linux), plus commit charge and swap/pagefile bars.
- **Eight history charts**: RAM in use, commit, standby/cache, compressed, swap,
  kernel pools, page faults/s and hard faults/s. `c` cycles to a single large chart.
- **System panel**: available memory, modified/dirty, standby/page cache, kernel paged
  and nonpaged pools (slab on Linux), compression store, driver-resident bytes, commit peak.
- **Process table**: resident (working set / RSS), private commit (Windows) or anonymous
  resident (Linux), a smoothed **growth rate** (a steadily positive number is what a leak
  looks like), page faults/s, kernel pool or swap, and the identified **runtime**.
  On Linux there is also a **PSS** column (resident memory with shared pages split fairly
  between the processes sharing them, so the column sums to real RAM use), read from
  `smaps_rollup` for the visible rows only. Other users' processes show `-` unless you run as root.
- **Group by app** (`g`): every `chrome.exe`/`brave.exe`/`Discord.exe` summed into one row.
- **Inspector** for the selected process, built from a page-level walk of its address space:

  | Category            | Meaning                                                           |
  |---------------------|-------------------------------------------------------------------|
  | Private (heap/anon) | heaps, GC heaps, JIT code, anonymous mmap — memory only it owns   |
  | Stacks              | thread stacks                                                     |
  | Images              | exe / DLL / .so pages, mostly shared with other processes         |
  | Mapped files        | memory-mapped files: font caches, databases, mmap'd model weights |
  | Shared memory       | pagefile-backed sections, `/dev/shm`, memfd                       |

  For each: bytes committed/mapped, bytes resident, and how many resident bytes are shared,
  plus the largest file-backed mappings and the address space that is only reserved.

### Runtime identification

Runtimes are recognised from loaded modules, the executable and the command line, and every
claim is tagged with how strong the evidence is: **measured** (OS counter), **derived**
(computed by memtaskman), **identified** (from loaded modules), **hint** (a configured limit
such as `-Xmx` or `--max-old-space-size`, which is not usage).

Recognised: Chromium browsers and their process types (Chrome, Edge, Brave, Opera, Vivaldi,
WebView2, Electron apps: renderer / gpu / utility:network …), Firefox, Java, .NET and
.NET Framework (including chocolatey shims), Node.js / Bun / Deno, CPython (version from
the DLL, PyTorch detection), local LLM servers (Ollama, llama.cpp, LM Studio, vLLM,
Foundry Local), databases (SQL Server, PostgreSQL, MySQL, Redis, MongoDB …), hypervisor
hosts (`vmmem`/`vmmemWSL`, QEMU, VMware, VirtualBox) and the Windows compression store.

## Install & run

```bash
uv tool install .         # from a clone; or: pipx install .
memtaskman                # or: mtm
```

Without installing:

```bash
uv run mtm
```

Run from an elevated terminal (or as root on Linux) to inspect processes owned by other users
and services; otherwise those show "access denied" in the inspector but still appear in the table.

## Keys

| Key        | Action                                   |
|------------|------------------------------------------|
| ↑ / ↓      | select a process and inspect it          |
| `s`        | cycle sort: resident, PSS (Linux), private, growth, faults, name, pid |
| `g`        | group processes by executable            |
| `a`        | top 50 / all processes                   |
| `c`        | cycle charts (all, or one metric)        |
| `m`        | slim mode (table only)                   |
| `p`        | pause / resume                           |
| `?`        | explanations of every counter            |
| `q`        | quit                                     |

## Command line

```text
mtm                         interactive TUI
mtm -i 2                    sample every 2 seconds
mtm --once [--top N|--all]  print a text report and exit
mtm --json [--top N|--all]  print a JSON snapshot and exit
mtm --no-system             skip system-wide counters
mtm inspect PID [--json]    address-space breakdown of one process
mtm record out.jsonl [-i 5] [-n COUNT] [--all]   append snapshots (JSON Lines)
mtm diff a.json b.json      what grew, appeared or went away between snapshots
```

Tip: take both snapshots with `--all` before using `diff`, otherwise processes outside the
top N look like they appeared or vanished.

## How it measures

| Source | Platform | Used for |
|--------|----------|----------|
| PDH `\Memory\*` counters | Windows | standby (3 priorities), modified, free+zero, cache, pools, fault rates |
| `GetPerformanceInfo` | Windows | commit charge / limit / peak |
| `GetProcessMemoryInfo` (via psutil) | Windows | working set, private commit, pools, fault counts |
| `VirtualQueryEx` | Windows | every region: committed vs reserved, image / mapped / private, stacks (guard pages) |
| `GetMappedFileName` | Windows | which file backs each image/mapped region |
| `QueryWorkingSet` | Windows | every resident page and its shared bit, attributed back to regions |
| `EnumProcessModulesEx` | Windows | loaded DLLs for runtime identification |
| `/proc/meminfo`, `/proc/vmstat` | Linux | cache, dirty, slab, zswap, commit, fault rates |
| `/proc/<pid>/status`, `stat` | Linux | RssAnon / RssFile / RssShmem, VmSwap, VmHWM, faults |
| `/proc/<pid>/smaps_rollup` | Linux | PSS and USS (private clean + dirty) for visible rows, refreshed every 2 s at most |
| `/proc/<pid>/smaps`, `maps` | Linux | per-mapping Rss / Shared / Swap, loaded libraries |

Nothing reads the *contents* of another process's memory; only metadata about its pages.

Caveats:

- Resident totals in group mode double count pages shared between members (DLLs, shared
  memory). Private totals do not overlap.
- On Windows, *Private* is commit charge: it can exceed the working set when pages are
  paged out or compressed.
- The compression store is reported as the working set of the `MemCompression` process.
- The inspector walk takes ~0.1-1 s for very large processes; it runs in the background and
  refreshes every 5 seconds.

## Development

```bash
uv sync
uv run python -m unittest discover -s tests -v   # hardware-independent unit tests
uv run python tools/smoke.py                      # live check: counters, inspector, TUI, every CLI command
uv build
```

CI (`.github/workflows/ci.yml`) runs the unit tests and the smoke test on Windows, Linux and
macOS with Python 3.11 and 3.14, then builds the wheel and runs it. To release, bump `version`
in `pyproject.toml`, then push a matching tag (`git tag v0.2.0 && git push main v0.2.0`). The release
workflow tests, builds and attaches the sdist and wheel to a GitHub release.

Layout:

```
src/memtaskman/
  app.py        Textual TUI
  cli.py        argument parsing, --once / --json / inspect / record / diff
  collector.py  sampling, growth & fault rates, runtime cache, group-by-app
  win32.py      ctypes: PDH, GetPerformanceInfo, VirtualQueryEx, QueryWorkingSet, modules
  linux.py      /proc parsers (pure) and readers
  runtime.py    runtime identification from modules + command line (pure)
  model.py      dataclasses shared by everything
  report.py     text / JSON output
  diff.py       snapshot comparison
  fmt.py        byte & rate formatting
tests/          hardware-independent unit tests
tools/smoke.py  end-to-end check against the live machine (used by CI)
```

## License

MIT
