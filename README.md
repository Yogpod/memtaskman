# memtaskman

[![CI](https://github.com/Yogpod/memtaskman/actions/workflows/ci.yml/badge.svg)](https://github.com/Yogpod/memtaskman/actions/workflows/ci.yml)

An `htop` for what's **inside** your RAM, not just how full it is.

Task Manager tells you Chrome uses 5 GB. memtaskman tells you which of those bytes are
heap, which are DLL code shared with every other process, which are memory-mapped files
(fonts, caches, model weights), which are thread stacks, and how much is actually resident
versus merely committed. It also shows *where* the rest of your RAM is: standby cache,
modified pages, the compression store, kernel pools and commit charge.

Inspired by [gputaskman](https://github.com/shanselman/gputaskman), which does the same for VRAM.

> Early, experimental software. Windows is the primary target, Linux is supported (tested on Ubuntu under WSL2).
> macOS support (footprint, compression, memory pressure, and a vmmap-style inspector) is new and
> **not yet validated on a real Mac**; it's checked by CI on Apple silicon runners.

![memtaskman dashboard: RAM, commit and swap bars, eight history charts, the process table and the inspector breaking a Steam web helper process into heap, stacks, DLLs and mapped files](docs/screenshots/dashboard.svg)

<details>
<summary>More screenshots: grouped by app, slim mode, help</summary>

**Grouped by app** (`g`): every process of the same executable summed into one row.

![Processes grouped by executable, with process counts](docs/screenshots/grouped.svg)

**Slim mode** (`m`): just the bars and the table.

![Slim mode showing only the memory bars and process table](docs/screenshots/slim.svg)

**Help** (`?`): what every counter means.

![Help screen explaining each counter](docs/screenshots/help.svg)

</details>

Screenshots are captured with `tools/capture_screenshots.py` in privacy mode: no command lines, and
home directories are shown as `~`.

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
  On Windows a **PrivWS** column shows the private working set, which is Task Manager's "Memory"
  number, for every process from a single PDH query.
  On Linux there is also a **PSS** column (resident memory with shared pages split fairly
  between the processes sharing them, so the column sums to real RAM use), read from
  `smaps_rollup` for the visible rows only. Other users' processes show `-` unless you run as root.
- **Leak watch**: rows marked **▲** have private bytes that rose in a straight line (least-squares
  R² ≥ 0.85, at least 16 MiB and 5%) over at least 2 of the last 10 minutes. Garbage-collector
  sawtooth patterns aren't flagged. For hours-long hunts, `mtm record` then `mtm summary`.
- **What's inside `vmmemWSL`** (Windows): select the `vmmemWSL` row (or `mtm inspect <pid>`) to see
  the WSL2 guest's own view: used, page cache, tmpfs and free, versus what Windows holds for
  the VM, plus `.wslconfig` limit and reclaim hints. It's read on demand and only when a distro
  is already running, because polling would keep WSL from shutting down when idle. Disable it
  with `--no-host`. Inside WSL, the Linux view notes that its RAM is really `vmmemWSL` on the host.
- **macOS**: an Activity Monitor-style RAM bar (App / Wired / Compressed / Cached files / Free),
  memory pressure level (normal / warn / critical), a **Footprint** column (Activity Monitor's
  "Memory", which includes compressed memory and, on Apple silicon, GPU memory), and an inspector
  that walks regions like `vmmap`. It splits malloc heaps, stacks, **Graphics / GPU** (IOKit,
  IOSurface, IOAccelerator, CoreAnimation), **JIT / JavaScript**, dylibs plus the dyld shared
  cache (counted once), and mapped files.
- **Group by app** (`g`): every `chrome.exe`/`brave.exe`/`Discord.exe` summed into one row.
- **Group by cgroup** (`g` again, Linux): one row per systemd service, container, pod or login
  session, sized by the kernel's own cgroup accounting (`memory.current`, so shared pages are
  counted once), with anon / file / shmem / kernel breakdown, `memory.max` limits, OOM kills and
  per-cgroup memory pressure in the inspector.
- **Memory pressure** (Linux PSI): the percentage of time tasks stalled waiting for memory,
  shown in the status line and as a chart. It's a better out-of-memory signal than "% used".
- **Standby by priority** (Windows): the standby cache split into reserve, normal and core,
  in the order Windows reuses them.
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
| `/`        | filter by name, runtime or PID (Enter keeps it, Esc clears) |
| `s`        | cycle sort: resident, PSS (Linux), private, growth, faults, name, pid |
| `g`        | cycle grouping: per process, by app, by cgroup (Linux) |
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
mtm --once --filter brave   only processes matching a name, runtime or PID (also --json, record)
mtm --no-host               don't read the WSL2 guest's memory when inspecting vmmemWSL
mtm inspect PID [--json]    address-space breakdown of one process
mtm record out.jsonl [-i 5] [-n COUNT] [--duration 2h] [--all]   append snapshots (JSON Lines)
mtm summary out.jsonl [--top N] [--json]   steadily growing processes in a recording (leak finder)
mtm diff a.json b.json      what grew, appeared or went away between snapshots
```

Recording size: about 19 KB per snapshot with the default `--top 50` (~14 MB/hour at the default
5 s interval) and about 120 KB with `--all` (~85 MB/hour). An interrupted recording can be
appended to; a half-written last line is skipped when reading.

Tip: take both snapshots with `--all` before using `diff`, otherwise processes outside the
top N look like they appeared or vanished.

## How it measures

| Source | Platform | Used for |
|--------|----------|----------|
| PDH `\Memory\*` counters | Windows | standby (3 priorities), modified, free+zero, cache, pools, fault rates |
| PDH `\Process V2(*)\Working Set - Private` | Windows | private working set for every process (falls back to `\Process(*)`) |
| `GetPerformanceInfo` | Windows | commit charge / limit / peak |
| `GetProcessMemoryInfo` (via psutil) | Windows | working set, private commit, pools, fault counts |
| `VirtualQueryEx` | Windows | every region: committed vs reserved, image / mapped / private, stacks (guard pages) |
| `GetMappedFileName` | Windows | which file backs each image/mapped region |
| `QueryWorkingSet` | Windows | every resident page and its shared bit, attributed back to regions |
| `EnumProcessModulesEx` | Windows | loaded DLLs for runtime identification |
| `host_statistics64(HOST_VM_INFO64)` | macOS | app / wired / compressed / cached / free pages, faults, page-ins |
| `sysctl` `vm.pagesize`, `kern.memorystatus_vm_pressure_level` | macOS | page size (16 KB on Apple silicon), memory pressure |
| `proc_pid_rusage(RUSAGE_INFO_V4)` | macOS | physical footprint and lifetime peak per process |
| `proc_pidinfo(PROC_PIDTASKINFO / PROC_PIDREGIONPATHINFO)` | macOS | fault counts; per-region tag, share mode, resident / shared / swapped pages, backing file |
| `/proc/meminfo`, `/proc/vmstat` | Linux | cache, dirty, slab, zswap, commit, fault rates |
| `/proc/<pid>/status`, `stat` | Linux | RssAnon / RssFile / RssShmem, VmSwap, VmHWM, faults |
| `/proc/pressure/memory` | Linux | memory pressure stall information (PSI) |
| `/proc/<pid>/cgroup`, `/sys/fs/cgroup/**/memory.*` | Linux | cgroup membership, `memory.current`, `memory.stat`, limits, events, per-cgroup pressure (v2; v1 basic) |
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
workflow tests, builds, attaches the sdist and wheel to a GitHub release and publishes them
to PyPI.

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
