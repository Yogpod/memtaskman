# AGENTS.md

Guidance for people and coding agents changing memtaskman.

## Evidence rules

memtaskman's value is that its numbers can be trusted. Every change must keep these rules:

1. **Never invent a zero.** If a value can't be measured, it's `None` in Python, `null` in JSON,
   and `-` in the UI, and the reason goes into the `unavailable` map
   (`ProcessMem.unavailable` / `SystemMemory.unavailable`).
2. **Label how a claim was obtained.** Inspector evidence uses one of four levels
   (`model.py`):
   - `measured`: read directly from an OS counter or API.
   - `derived`: computed by memtaskman from measured data (page attribution, trends).
   - `identified`: recognised from loaded modules, executable names or file headers.
   - `hint`: configuration such as `-Xmx` or `.wslconfig memory=`. It's a limit, not usage.
3. **Read metadata, never contents.** No reading another process's memory. Model files are
   read up to their GGUF header only.
4. **Don't change what you observe.** No polling that keeps WSL awake, no starting services,
   no network beyond documented localhost GETs (Ollama `/api/ps`).
5. **Shared pages are double counted in per-process sums.** Say so wherever totals are shown
   (group-by-app). Prefer kernel accounting (cgroup `memory.current`, PSS, private working set).

## Module map

| Module | Role |
|---|---|
| `collector.py` | sampling loop, rates, leak series, runtime cache, cgroup rows, `unavailable` reasons |
| `win32.py` | Windows: PDH, `GetPerformanceInfo`, `VirtualQueryEx`, `QueryWorkingSet`, modules |
| `linux.py` | Linux: pure `/proc` and cgroup parsers, plus readers |
| `macos.py` | macOS: ctypes structs (unit-tested layouts), region rules, libSystem calls |
| `wslhost.py` | the WSL2 guest's memory, read from Windows on demand |
| `models.py` | GGUF header parser, Ollama `/api/ps` |
| `runtime.py` | runtime identification from modules and command line (pure) |
| `leaks.py` | trend fitting, leak rule, recording reader and summary (pure) |
| `diff.py` | snapshot comparison (pure) |
| `app.py` | Textual TUI |
| `cli.py`, `report.py` | command line, text and JSON output |
| `model.py`, `fmt.py` | data types, formatting, redaction |

Keep platform code behind the same small interface (`inspect`, `module_names`, system and
process readers) so `collector.py` stays platform-neutral. Put parsing in pure functions that
take text or bytes, so they can be tested on every OS.

## Verifying a change

```bash
uv run python -m unittest discover -s tests -v   # pure tests, every OS
uv run python tools/smoke.py                      # live machine: counters, inspector, TUI, every command
```

CI runs both on Windows, Linux and macOS (Python 3.11 and 3.14). For UI changes, also check
small terminals (`tools/smoke.py` covers 80×24) and regenerate screenshots with
`tools/capture_screenshots.py` (privacy mode; it deletes any capture containing your username).

Linux can be tested from Windows with WSL. macOS live code is exercised only by CI and real
Macs, so keep struct layouts covered by `tests/test_macos.py`.

## Releasing

1. Bump `version` in `pyproject.toml`.
2. Merge to `master` with CI green.
3. `git tag vX.Y.Z && git push <remote> vX.Y.Z`. The release workflow checks that the tag matches
   the version, tests, builds, creates the GitHub release and publishes to PyPI via trusted
   publishing.
