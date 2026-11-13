"""Textual TUI."""

from __future__ import annotations

import time
from collections import deque
from pathlib import PureWindowsPath

from rich.console import Group
from rich.table import Table
from rich.text import Text
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Grid, Horizontal, Vertical, VerticalScroll
from textual.css.query import NoMatches
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Input, Sparkline, Static

from memtaskman.collector import (
    ASCENDING,
    LINUX,
    MACOS,
    SORTS,
    WINDOWS,
    Collector,
    group_by_app,
    matches,
    sort_procs,
    unique_column,
)

UNIQUE = unique_column()
from memtaskman import killer
from memtaskman import tree as ptree
from memtaskman.fmt import fmt_bytes, fmt_count_rate, fmt_rate, pct, redact, set_units, units, units_legend
from memtaskman.model import (
    DERIVED,
    FIELD_LABELS,
    HINT,
    IDENTIFIED,
    MEASURED,
    Inspection,
    ProcessMem,
    Snapshot,
    SystemMemory,
)

HISTORY = 120
SIDE_W = 65  # side panel width incl. border
NARROW_W = 150  # below this the side panel moves under the table
# Column tiers chosen from the width left for the table (cells include 2 columns of padding):
FULL_COLS_W = 128  # tier 0: all columns
MID_COLS_W = 104  # tier 1: drop Faults/s and Pool/Swap, shorter Runtime
SMALL_COLS_W = 92  # tier 2: also shorter Name and Runtime; below (tier 3): also drop PSS/PrivWS
SHORT_H = 36  # below this the charts are hidden
TOP_N = 50
INSPECT_EVERY = 5.0

C_USED = "#4e9af1"
C_MOD = "#e5a50a"
C_STANDBY = "#57a773"
C_FREE = "#3a3f4b"
C_COMMIT = "#b48ead"
C_SWAP = "#d08770"

CHARTS = [
    ("used", "RAM in use", "bytes"),
    ("commit", "Commit charge", "bytes"),
    ("cache", "Standby / cache", "bytes"),
    ("compressed", "Compressed", "bytes"),
    ("swap", "Swap / pagefile used", "bytes"),
    ("kernel", "Kernel pools", "bytes"),
    ("faults", "Page faults/s", "rate"),
    ("hard", "Hard faults/s (disk)", "rate"),
]
if LINUX:  # zswap is often off; memory pressure (PSI) is the better Linux signal
    CHARTS[3] = ("pressure", "Memory pressure (PSI some %)", "pct")
if MACOS:  # macOS has no commit charge; wired memory is the more useful series
    CHARTS[1] = ("wired", "Wired", "bytes")
GROUP_MODES = ["none", "app"] + (["cgroup"] if LINUX else [])

LEVEL_STYLE = {MEASURED: "green", DERIVED: "cyan", IDENTIFIED: "magenta", HINT: "yellow"}

HELP = f"""\
[b]memtaskman[/b] — what is inside your RAM

[b]System bar[/b]
  [{C_USED}]■ In use[/]     pages owned by processes, the kernel and drivers
  [{C_MOD}]■ Modified[/]   dirty pages that must be written to disk before reuse
  [{C_STANDBY}]■ Standby/cache[/]  file cache; instantly reusable, so it is "available"
  [{C_FREE}]■ Free[/]       zeroed / free pages (Linux: MemFree)
  Commit      memory promised to processes (RAM + pagefile); hitting the limit = out of memory
              (status line warns above 90%; LOW MEMORY = Windows' own low-memory signal)
  Compressed  Windows compression store / Linux zswap pool

[b]Process columns[/b]
  Resident    working set / RSS: this process's pages in RAM right now (shared pages counted in every sharer)
  Private     Windows: private commit (heap, stacks; may be partly paged out)
  Anon        Linux: resident anonymous memory (RssAnon)
  PSS         Linux: resident, with each shared page split between its sharers; sums to real RAM use
              (read from smaps_rollup for visible rows; blank for other users' processes unless run as root)
  PrivWS      Windows: private working set, Task Manager's "Memory" column. Pages only this process
              can use; slightly below tools that count shared-but-unshared pages as unique
  Growth      smoothed change of Private per second — a steadily positive value is how leaks look
  ▲ name      possible leak: private bytes rose in a straight line (R² ≥ 0.85) by ≥ 16 MiB and ≥ 5%
              over at least 2 minutes of the last 10. GC sawtooth patterns are not flagged.
              For long runs: mtm record out.jsonl, then mtm summary out.jsonl
  Faults/s    page faults per second (soft + hard)
  Footprint   macOS: Activity Monitor's "Memory". Private memory incl. compressed pages and,
              on Apple silicon, GPU allocations, so it can exceed Resident
  Pool/Swap   Windows: kernel pool charged to the process / Linux: swapped-out bytes

[b]macOS system bar[/b] App (anonymous) / Wired (kernel, can't be paged or compressed) /
  Compressed (compressor pool) / Cached files (reclaimable) / Free.
  Memory pressure normal / warn / critical is the kernel's own verdict, the same as
  Activity Monitor's pressure graph.

[b]Inspector[/b] walks the selected process's address space:
  Images      exe/DLL/.so code+data, mostly shared with other processes
  Mapped      memory-mapped files (fonts, caches, model weights loaded with mmap)
  Shared mem  pagefile-backed sections, /dev/shm, memfd
  Private     heap, GC heaps, JIT code, anonymous mmap
  Mapped = committed (Win) / mapped (Linux); Resident = in RAM; Shared = resident pages shared with others
  Evidence: [green]measured[/] OS counter · [cyan]derived[/] computed by memtaskman ·
            [magenta]identified[/] from loaded modules · [yellow]hint[/] a configured limit, not usage

[b]Grouping[/b] (g cycles)
  by app      every process with the same executable summed (resident double counts shared pages)
  by cgroup   Linux: one row per systemd service / container / session, sized by the kernel's
              cgroup accounting (memory.current), with limits, OOM kills and per-cgroup pressure

[b]Memory pressure[/b] (Linux PSI) % of the last 10 s in which some / all tasks were stalled
  waiting for memory. A better out-of-memory signal than % used, since page cache fills RAM on purpose.

[b]Units[/b] sizes use binary units by default (1G = 1 GiB = 1024³ bytes), like the OS counters.
  u switches to decimal (1G = 1 GB = 10⁹ bytes), as used by Explorer and disk vendors.

[b]Tree[/b] (t) parents with their children. Enter collapses / expands a node; a collapsed node shows
  its subtree's totals (+N = hidden descendants). Nodes with many children start collapsed.

[b]Ending processes[/b] (k) type the name to confirm. The first k asks politely (like closing its
  windows / SIGTERM); if it's still running, k again force-kills it after a second confirmation.
  Critical system processes are refused; --read-only (or read_only = true) disables k entirely.

[b]Keys[/b]  k end process  t tree  u units  ↑/↓ select  / filter  s sort (or click a header; again to reverse)  g group (app/cgroup)  a top/all  c charts  m slim  p pause  ? help  q quit
[dim]Esc to close[/dim]"""


def ui_callback(method):
    """For updates posted from worker threads: skip them once the app is shutting down.

    A sample or inspection can finish just after the user quits; its widgets are gone by
    then, and drawing into them must not turn a clean exit into a traceback.
    """
    import functools

    @functools.wraps(method)
    def wrapper(self, *args, **kwargs):
        if self._shutting_down:
            return None
        try:
            return method(self, *args, **kwargs)
        except NoMatches:
            if self._shutting_down or not self.is_running or not self.query("#procs"):
                return None  # widgets already torn down: the app is exiting
            raise

    return wrapper


class KillScreen(ModalScreen):
    """Type the process name to confirm. Returns True / False via dismiss."""

    AUTO_FOCUS = "#kill-name"
    BINDINGS = [Binding("escape", "cancel", "Cancel")]

    def __init__(self, proc: ProcessMem, force: bool):
        super().__init__()
        self.proc = proc
        self.force = force

    def compose(self) -> ComposeResult:
        p = self.proc
        verb = "FORCE-KILL" if self.force else "End"
        how = ("It gets no chance to save anything (TerminateProcess / SIGKILL)." if self.force else
               "It is asked to close, as if you closed its windows (taskkill without /F / SIGTERM).")
        with Vertical(id="kill"):
            yield Static(f"[b]{verb} {p.name}[/b]  (pid {p.pid}, {fmt_bytes(p.resident)} resident)\n\n{how}\n\n"
                         f"Type [b]{p.name}[/b] and press Enter to confirm, or Esc to cancel.")
            yield Input(placeholder=p.name, id="kill-name")
            yield Static("", id="kill-error")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.value.strip().lower() == self.proc.name.lower():
            self.dismiss(True)
        else:
            self.query_one("#kill-error", Static).update(Text("name doesn't match", style="red"))

    def action_cancel(self) -> None:
        self.dismiss(False)


class HelpScreen(ModalScreen):
    BINDINGS = [Binding("escape,question_mark,q", "app.pop_screen", "Close")]

    def compose(self) -> ComposeResult:
        with VerticalScroll(id="help"):
            yield Static(HELP)


def stacked_bar(segments: list[tuple[str, int, str]], total: int, width: int) -> Text:
    t = Text()
    width = max(10, width)
    used_cells = 0
    for i, (_label, value, color) in enumerate(segments):
        if i == len(segments) - 1:
            cells = width - used_cells
        else:
            cells = round(width * max(0, value) / total) if total else 0
            cells = min(cells, width - used_cells)
        t.append("█" * cells, style=color)
        used_cells += cells
    return t


def ram_segments(sm: SystemMemory) -> list[tuple[str, int, str]]:
    if "App memory" in sm.extra:  # macOS, Activity Monitor's split
        used = sm.extra["App memory"] + sm.extra.get("Wired", 0) + (sm.compressed or 0)
        cached = min(sm.cached or 0, max(0, sm.total - used))
        free = max(0, sm.total - used - cached)
        return [("App", sm.extra["App memory"], C_USED), ("Wired", sm.extra.get("Wired", 0), C_MOD),
                ("Compressed", sm.compressed or 0, C_COMMIT), ("Cached files", cached, C_STANDBY), ("Free", free, C_FREE)]
    if sm.standby is not None:  # Windows
        mod = sm.modified or 0
        in_use = max(0, sm.used - mod)
        free = sm.free if sm.free is not None else max(0, sm.total - in_use - mod - sm.standby)
        return [("In use", in_use, C_USED), ("Modified", mod, C_MOD), ("Standby", sm.standby, C_STANDBY), ("Free", free, C_FREE)]
    if sm.cached is not None and sm.free is not None:  # Linux
        in_use = max(0, sm.total - sm.free - sm.cached)
        return [("In use", in_use, C_USED), ("Cache", sm.cached, C_STANDBY), ("Free", sm.free, C_FREE)]
    return [("Used", sm.used, C_USED), ("Available", sm.available, C_FREE)]


class MemTaskManApp(App):
    TITLE = "memtaskman"
    AUTO_FOCUS = "#procs"  # never the (hidden) filter input, or it would swallow every key
    CSS = """
    Screen { layout: vertical; }
    #top { height: auto; padding: 0 1; }
    #charts { grid-size: 4 2; grid-gutter: 0 2; height: 8; padding: 0 1; }
    #charts.single { grid-size: 1 1; height: 10; }
    .chart { height: 4; }
    #charts.single .chart { height: 10; }
    .chart Sparkline { height: 1fr; }
    .chart .label { height: 1; color: $text-muted; }
    #body { height: 1fr; }
    #procs { width: 1fr; }
    #side { width: 64; border-left: tall $panel; }
    #system { height: auto; padding: 0 1; }
    #inspector { height: 1fr; padding: 0 1; }
    .slim #charts, .slim #side { display: none; }
    .narrow #body { layout: vertical; }
    .narrow #procs { height: 1fr; }
    .narrow #side { width: 1fr; height: 45%; border-left: none; border-top: tall $panel; }
    .narrow #charts { grid-size: 2 4; height: 16; }
    .short #charts { display: none; }
    #filter { display: none; height: 3; margin: 0 1; }
    #filter.visible { display: block; }
    HelpScreen { align: center middle; }
    KillScreen { align: center middle; }
    #kill { width: 76; max-width: 95%; height: auto; border: heavy $error; background: $surface; padding: 1 2; }
    #kill-error { height: 1; }
    #help { width: 100; max-width: 95%; height: 80%; border: round $accent; background: $surface; padding: 1 2; }
    """
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("s", "sort", "Sort"),
        Binding("g", "group", "Group"),
        Binding("a", "toggle_all", "Top/All"),
        Binding("c", "charts", "Charts"),
        Binding("m", "mode", "Slim"),
        Binding("p", "pause", "Pause"),
        Binding("slash", "filter", "Filter", key_display="/"),
        Binding("u", "units", "Units", show=False),
        Binding("t", "tree", "Tree"),
        Binding("k", "kill", "End process"),
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("escape", "clear_filter", "Clear filter", show=False),
    ]

    def __init__(self, interval: float = 1.0, system: bool = True, wsl_guest: bool = True,
                 privacy: bool = False, settings: dict | None = None):
        super().__init__()
        settings = settings or {}
        self.privacy = privacy  # hide command lines and home-directory paths (screenshots, demos)
        self.interval = max(0.25, interval)
        self.collector = Collector(system=system, wsl_guest=wsl_guest)
        self.history: dict[str, deque[float]] = {k: deque(maxlen=HISTORY) for k, _, _ in CHARTS}
        self.sort_keys = ["resident"] + ([UNIQUE[1]] if UNIQUE else []) + ["private", "growth", "faults", "name", "pid"]
        self.sort_key = "resident"
        if settings.get("sort") in self.sort_keys:
            self.sort_key = settings["sort"]
        self.sort_invert = False  # second click on the same header reverses the order
        self.tree_mode = bool(settings.get("tree", False))
        self.top_n = int(settings.get("top", TOP_N))
        self.start_slim = bool(settings.get("slim", False))
        self.read_only = bool(settings.get("read_only", False))
        self.polite_sent: dict[tuple, float] = {}  # process key -> when a polite close was requested
        self.tree_collapsed: set = set()  # explicit user choices, by process key
        self.tree_expanded: set = set()
        self.tree_rows: dict[str, ptree.TreeRow] = {}
        self.col_labels: dict[str, str] = {}
        self.show_all = bool(settings.get("all", False))
        self.group_mode = settings.get("group", "none")  # none | app | cgroup (Linux)
        if self.group_mode not in GROUP_MODES:
            self.group_mode = "none"
        self.filter_text = ""
        self.compact_cols = 0  # column tier, see _column_tier
        self.paused = False
        self.chart_mode = -1  # -1 = all charts, else index into CHARTS
        self.snapshot: Snapshot | None = None
        self.rows: dict[str, ProcessMem] = {}
        self.selected: str | None = None
        self.last_inspect = 0.0
        self.inspection: Inspection | None = None
        self._shutting_down = False

    # ------------------------------------------------------------------ layout
    @property
    def grouped(self) -> bool:
        return self.group_mode != "none"

    def compose(self) -> ComposeResult:
        yield Static(id="top")
        with Grid(id="charts"):
            for key, label, _ in CHARTS:
                with Vertical(classes="chart", id=f"chart-{key}"):
                    yield Static(label, classes="label", id=f"label-{key}")
                    yield Sparkline([], summary_function=max, id=f"spark-{key}")
        with Horizontal(id="body"):
            yield DataTable(id="procs", cursor_type="row", zebra_stripes=True)
            with Vertical(id="side"):
                yield Static(id="system")
                with VerticalScroll(id="inspector"):
                    yield Static("Select a process to see what its memory is made of.", id="inspect-body")
        yield Input(placeholder="filter by name, runtime or PID   (Enter keeps it, Esc clears)", id="filter")
        yield Footer()

    def on_resize(self, event) -> None:
        self._apply_size(event.size.width, event.size.height)

    def _column_tier(self, width: int) -> int:
        slim = self.screen.has_class("slim")
        narrow = width < NARROW_W
        table_w = width if (slim or narrow) else width - SIDE_W
        if table_w >= FULL_COLS_W:
            return 0
        return 1 if table_w >= MID_COLS_W else 2 if table_w >= SMALL_COLS_W else 3

    def _apply_size(self, width: int, height: int) -> None:
        self.screen.set_class(width < NARROW_W, "narrow")
        self.screen.set_class(height < SHORT_H, "short")
        compact = self._column_tier(width)
        if compact != self.compact_cols:
            self.compact_cols = compact
            self._setup_columns()
            if self.snapshot:
                self.render_table()

    def on_mount(self) -> None:
        if self.start_slim:
            self.screen.add_class("slim")
        self.compact_cols = self._column_tier(self.size.width)
        self._apply_size(self.size.width, self.size.height)
        self._setup_columns()
        self.set_interval(self.interval, self.tick)
        self.call_after_refresh(self.tick)  # first sample once the widgets are on screen

    def _setup_columns(self) -> None:
        t = self.query_one("#procs", DataTable)
        t.clear(columns=True)
        pl = self.collector_private_label()
        last = "Pool" if WINDOWS else "Swap"
        first = "Procs" if self.grouped else "PID"
        t.add_column(first, key="pid", width=7)
        t.add_column("Name", key="name", width=18 if self.compact_cols >= 2 else 26)
        t.add_column("Resident", key="resident", width=9)
        if UNIQUE and self.compact_cols < 3:
            t.add_column(UNIQUE[0], key=UNIQUE[1], width=9)
        t.add_column(pl, key="private", width=9)
        t.add_column("Growth", key="growth", width=10)
        if not self.compact_cols:
            t.add_column("Faults/s", key="faults", width=8)
            t.add_column(last, key="extra", width=7)
        t.add_column("Runtime", key="runtime", width=(24, 18, 14, 14)[self.compact_cols])
        self.col_labels = {str(k.value): str(c.label) for k, c in t.columns.items()}
        self._update_header_arrows()

    def _sort_for_column(self, column_key: str) -> str:
        return "count" if column_key == "pid" and self.grouped else column_key

    def _update_header_arrows(self) -> None:
        t = self.query_one("#procs", DataTable)
        descending = (self.sort_key not in ASCENDING) != self.sort_invert
        for key, col in t.columns.items():
            base = self.col_labels.get(str(key.value), str(col.label))
            if self._sort_for_column(str(key.value)) == self.sort_key:
                col.label = Text(f"{base} {'▼' if descending else '▲'}", style="bold")
            else:
                col.label = Text(base)
        t.refresh()

    def on_data_table_header_selected(self, event: DataTable.HeaderSelected) -> None:
        key = self._sort_for_column(str(event.column_key.value))
        if key not in SORTS:
            return
        if key == self.sort_key:
            self.sort_invert = not self.sort_invert
        else:
            self.sort_key, self.sort_invert = key, False
        self._update_header_arrows()
        self._refresh_now()

    def collector_private_label(self) -> str:
        from memtaskman.collector import private_label

        return private_label()

    # ------------------------------------------------------------------ sampling
    def tick(self) -> None:
        if not self.paused:
            self.sample()

    @work(thread=True, exclusive=True, group="sample")
    def sample(self) -> None:
        snap = self.collector.sample()
        visible = sort_procs(snap.processes, "resident")[: self.top_n if not self.show_all else None]
        if self.group_mode == "none":
            visible = self._ordered(snap)[: self.top_n if not self.show_all else None]
        self.collector.resolve_runtimes(visible + sort_procs(snap.processes, "resident"), time_budget=0.3)
        self.collector.refresh_pss(visible, time_budget=0.2)
        self.call_from_thread(self.apply, snap)

    @ui_callback
    def apply(self, snap: Snapshot) -> None:
        self.snapshot = snap
        if snap.system:
            self._push_history(snap.system)
        self.render_top()
        self.render_charts()
        self.render_system()
        self.render_table()
        if self.selected and time.monotonic() - self.last_inspect > INSPECT_EVERY:
            self._inspect_selected()

    def _push_history(self, sm: SystemMemory) -> None:
        vals = {
            "used": sm.used,
            "commit": sm.commit_used,
            "cache": sm.standby if sm.standby is not None else sm.cached,
            "compressed": sm.compressed,
            "pressure": sm.pressure_some,
            "wired": sm.kernel_nonpaged,
            "swap": sm.swap_used,
            "kernel": (sm.kernel_paged or 0) + (sm.kernel_nonpaged or 0) if sm.kernel_paged is not None else None,
            "faults": sm.page_faults_ps,
            "hard": sm.hard_faults_ps,
        }
        for k, v in vals.items():
            if v is not None and k in self.history:  # only series that have a chart on this platform
                self.history[k].append(float(v))

    # ------------------------------------------------------------------ rendering
    def render_top(self) -> None:
        snap = self.snapshot
        top = self.query_one("#top", Static)
        width = max(20, top.size.width - 2 if top.size.width else 100)
        lines: list[Text] = []
        status = Text()
        status.append("memtaskman", style="bold")
        mode = {"none": "tree" if self.tree_mode else "per process", "app": "grouped by app",
                "cgroup": "grouped by cgroup"}[self.group_mode]
        status.append(f"  sort:{self.sort_key}  {mode}"
                      f"  {'all' if self.show_all else f'top {self.top_n}'}  {len(snap.processes)} processes", style="dim")
        sm0 = snap.system
        if sm0 and sm0.pressure_some is not None:
            full = sm0.pressure_full or 0.0
            style = "bold red" if full >= 5 else "yellow" if sm0.pressure_some >= 5 else "dim"
            status.append(f"  pressure some {sm0.pressure_some:.1f}% full {full:.1f}%", style=style)
        if sm0 and sm0.low_memory:
            status.append("  LOW MEMORY", style="bold red")
        if sm0 and sm0.commit_used and sm0.commit_limit and sm0.commit_used >= 0.9 * sm0.commit_limit:
            status.append(f"  commit {100 * sm0.commit_used / sm0.commit_limit:.0f}% of limit", style="bold red")
        if sm0 and sm0.pressure_level:
            style = {"warn": "bold yellow", "critical": "bold red"}.get(sm0.pressure_level, "dim")
            status.append(f"  memory pressure: {sm0.pressure_level}", style=style)
        status.append(f"  {'GiB' if units() == 'binary' else 'GB'}", style="dim")
        if self.filter_text:
            status.append(f'  filter "{self.filter_text}"', style="bold cyan")
        if self.paused:
            status.append("  PAUSED", style="bold yellow")
        lines.append(status)
        sm = snap.system
        if sm:
            bar_w = width - 30
            segs = ram_segments(sm)
            line = Text(f"{'RAM':<7}")
            line.append_text(stacked_bar(segs, sm.total, bar_w))
            line.append(f" {fmt_bytes(sm.used)}/{fmt_bytes(sm.total)} {pct(sm.used, sm.total):.0f}%")
            lines.append(line)
            legend = Text(" " * 7)
            for label, value, color in segs:
                legend.append("■ ", style=color)
                legend.append(f"{label} {fmt_bytes(value)}   ")
            if sm.compressed is not None:
                legend.append(f"Compressed {fmt_bytes(sm.compressed)}   ", style="dim")
            lines.append(legend)
            if sm.commit_used is not None and sm.commit_limit:
                line = Text(f"{'Commit':<7}")
                line.append_text(stacked_bar([("c", sm.commit_used, C_COMMIT), ("r", sm.commit_limit - sm.commit_used, C_FREE)],
                                             sm.commit_limit, bar_w))
                line.append(f" {fmt_bytes(sm.commit_used)}/{fmt_bytes(sm.commit_limit)} {pct(sm.commit_used, sm.commit_limit):.0f}%")
                lines.append(line)
            if sm.swap_total:
                line = Text(f"{'Swap':<7}")
                line.append_text(stacked_bar([("s", sm.swap_used or 0, C_SWAP), ("f", sm.swap_total - (sm.swap_used or 0), C_FREE)],
                                             sm.swap_total, bar_w))
                line.append(f" {fmt_bytes(sm.swap_used)}/{fmt_bytes(sm.swap_total)}")
                lines.append(line)
        top.update(Text("\n").join(lines))

    def render_charts(self) -> None:
        for i, (key, label, kind) in enumerate(CHARTS):
            data = list(self.history[key])
            cell = self.query_one(f"#chart-{key}")
            cell.display = self.chart_mode in (-1, i)
            if not cell.display:
                continue
            cur = data[-1] if data else None
            if kind == "bytes":
                val = fmt_bytes(cur)
                rng = f"  [{fmt_bytes(min(data))}-{fmt_bytes(max(data))}]" if len(data) > 1 else ""
            elif kind == "pct":
                val = f"{cur:.1f}%" if cur is not None else "-"
                rng = f"  [peak {max(data):.1f}%]" if data else ""
            else:
                val = fmt_count_rate(cur)
                rng = f"  [peak {fmt_count_rate(max(data))}]" if data else ""
            self.query_one(f"#label-{key}", Static).update(f"{label}: [b]{val}[/b][dim]{rng}[/dim]")
            self.query_one(f"#spark-{key}", Sparkline).data = data or [0]

    def render_system(self) -> None:
        sm = self.snapshot.system if self.snapshot else None
        w = self.query_one("#system", Static)
        if not sm:
            w.update("[dim]system counters disabled[/dim]")
            return
        note = Text(sm.vm_note, style="yellow") if sm.vm_note else None
        t = Table.grid(padding=(0, 1))
        t.add_column(style="dim")
        t.add_column(justify="right")
        t.add_column(style="dim")
        rows = [
            ("Available", sm.available, "free + reclaimable cache"),
            ("Modified" if WINDOWS else "Dirty", sm.modified, "waiting to be written"),
            ("Standby" if WINDOWS else "Page cache", sm.standby if WINDOWS else sm.cached, "cached file data"),
            ("Kernel paged" if WINDOWS else "Slab reclaim", sm.kernel_paged, ""),
            ("Kernel nonpaged" if WINDOWS else "Slab unreclaim", sm.kernel_nonpaged, "can't be paged out"),
            ("Compressed", sm.compressed, "compression store" if WINDOWS else "zswap pool"),
        ]
        rows += [(k, v, "") for k, v in sm.extra.items()]
        why = [(FIELD_LABELS.get(k, k), r) for k, r in sm.unavailable.items() if k != "page_faults_ps"]
        for label, value, note in rows:
            if value is not None:
                t.add_row(label, fmt_bytes(value), note)
        extra = []
        for pf in sm.pagefiles or []:
            line = Text(f"Pagefile {pf['path']}", style="dim")
            line.append(f"  {fmt_bytes(pf['used'])} of {fmt_bytes(pf['size'])} used, peak {fmt_bytes(pf['peak'])}")
            extra.append(line)
        if sm.pagefiles == []:
            extra.append(Text("No pagefile: commit limit = RAM", style="yellow"))
        if why:
            extra.append(Text("Unavailable", style="bold dim"))
            for label, reason in why:
                extra.append(Text(f"  {label}: {reason}", style="dim"))
        w.update(Group(Text("System", style="bold"), t, *([note] if note else []), *extra))

    def _ordered(self, snap: Snapshot) -> list[ProcessMem]:
        if self.group_mode == "cgroup" and snap.cgroups is not None:
            procs = snap.cgroups
        elif self.group_mode == "app":
            procs = group_by_app(snap.processes)
        else:
            procs = snap.processes
        if self.filter_text:
            procs = [p for p in procs if matches(p, self.filter_text)]
        if self.tree_mode and self.group_mode == "none":
            rows = ptree.flatten(procs, lambda ps: sort_procs(ps, self.sort_key, self.sort_invert),
                                 collapsed=self.tree_collapsed, expanded=self.tree_expanded)
            self.tree_rows = {self._row_key(r.proc): r for r in rows}
            return [r.proc for r in rows]
        self.tree_rows = {}
        return sort_procs(procs, self.sort_key, self.sort_invert)

    def _row_key(self, p: ProcessMem) -> str:
        if self.group_mode == "cgroup":
            return f"c:{p.cgroup}"
        return f"g:{p.name.lower()}" if self.group_mode == "app" else f"p:{p.pid}:{p.create_time}"

    def render_table(self) -> None:
        t = self.query_one("#procs", DataTable)
        procs = self._ordered(self.snapshot)
        if not self.show_all:
            procs = procs[: self.top_n]
        if self.selected and not any(self._row_key(p) == self.selected for p in procs):
            # Keep the selected process visible even when it drops out of the top N.
            sel = next((p for p in self._ordered(self.snapshot) if self._row_key(p) == self.selected), None)
            if sel:
                procs.append(sel)
        scroll_y = t.scroll_y
        t.clear()
        self.rows = {}
        for p in procs:
            k = self._row_key(p)
            self.rows[k] = p
            growth = Text(fmt_rate(p.growth_ps), justify="right")
            if p.growth_ps and p.growth_ps > 1024 * 1024:
                growth.stylize("bold red")
            elif p.growth_ps and p.growth_ps > 64 * 1024:
                growth.stylize("yellow")
            elif p.growth_ps and p.growth_ps < -64 * 1024:
                growth.stylize("green")
            extra = (p.paged_pool or 0) + (p.nonpaged_pool or 0) if WINDOWS and p.paged_pool is not None else p.swapped
            rt = f"{p.runtime or ''} {p.runtime_detail or ''}".strip()
            if p.cgroup_stats is not None:
                cs = p.cgroup_stats
                bits = []
                if cs.get("max") is not None:
                    bits.append(f"limit {fmt_bytes(cs['max'])}")
                if cs.get("oom_kill"):
                    bits.append(f"{cs['oom_kill']} OOM kill(s)")
                rt = " · ".join(bits) or rt
            name = Text(p.name)
            if p.leak:
                name = Text("▲ ", style="bold red").append(p.name, style="red")
            tr = self.tree_rows.get(k)
            if tr is not None:
                marker = ("▸ " if tr.collapsed else "▾ ") if tr.children else "  "
                name = Text(tr.prefix, style="dim").append(marker, style="cyan").append_text(name)
                if tr.collapsed:
                    name.append(f" +{tr.descendants}", style="dim")
            cells = [
                Text(f"×{p.count}" if self.grouped else str(p.pid), justify="right"),
                name,
                Text(fmt_bytes(p.resident), justify="right"),
            ]
            if UNIQUE and self.compact_cols < 3:
                cells.append(Text(fmt_bytes(getattr(p, UNIQUE[1])), justify="right"))
            cells += [Text(fmt_bytes(p.private), justify="right"), growth]
            if not self.compact_cols:
                cells += [Text(fmt_count_rate(p.faults_ps), justify="right"),
                          Text(fmt_bytes(extra) if extra is not None else "-", justify="right")]
            cells.append(Text(rt, style="magenta" if p.runtime else ""))
            t.add_row(*cells, key=k)
        if self.selected in self.rows:
            t.move_cursor(row=t.get_row_index(self.selected), animate=False, scroll=False)
        t.scroll_to(y=scroll_y, animate=False)

    # ------------------------------------------------------------------ inspector
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        t = event.data_table
        key = event.row_key.value if event.row_key else None
        # Ignore stale events from clear()/rebuild: only the row under the cursor counts.
        try:
            current = t.coordinate_to_cell_key(t.cursor_coordinate).row_key.value
        except Exception:  # noqa: BLE001 - empty table
            return
        if key != current or key == self.selected:
            return
        self.selected = key
        self.query_one("#inspect-body", Static).update(Text(f"Inspecting {self.rows[key].name} …", style="dim"))
        self._inspect_selected()

    def _inspect_selected(self) -> None:
        if not self.selected or not self.snapshot:
            return
        p = self.rows.get(self.selected)
        if p is None:
            return
        if self.group_mode == "cgroup":
            self.last_inspect = time.monotonic()
            self.show_cgroup(p)
            return
        if self.grouped:
            members = [q for q in self.snapshot.processes if q.name.lower() == p.name.lower()]
            if not members:
                return
            target = max(members, key=lambda q: q.resident)
        else:
            target = p
        self.last_inspect = time.monotonic()
        self.inspect_worker(target, 1 if self.tree_mode else p.count)

    @ui_callback
    def show_cgroup(self, row: ProcessMem) -> None:
        parts: list = []
        head = Text()
        head.append(row.name, style="bold")
        head.append(f"  cgroup  ×{row.count} processes", style="dim")
        parts.append(head)
        parts.append(Text(row.cgroup.partition(":")[2] if row.cgroup else "", style="dim"))
        cs = row.cgroup_stats
        if cs is None:
            parts.append(Text("No memory accounting for this cgroup (root cgroup, or the memory controller is not "
                              "enabled here). Sizes are sums of member processes: an upper bound.", style="yellow"))
        else:
            t = Table(box=None, padding=(0, 1), show_edge=False, show_header=False)
            t.add_column(style="dim")
            t.add_column(justify="right")
            t.add_column(style="dim")
            total = cs["current"] or 1
            for label, key, note in (("Charged", "current", "memory.current"), ("Anonymous", "anon", "heap, stacks"),
                                     ("File cache", "file", "reclaimable"), ("Shmem", "shmem", "tmpfs / shared"),
                                     ("Kernel", "kernel", "slab, page tables"), ("Sockets", "sock", "network buffers"),
                                     ("Swap", "swap", "")):
                v = cs.get(key)
                if v is not None:
                    note_t = Text(note + " ")
                    if key != "current":
                        note_t.append("█" * round(8 * v / total), style=C_USED)
                    t.add_row(label, fmt_bytes(v), note_t)
            parts.append(t)
            lim = Text("\nLimits  ", style="bold")
            lim.append(f"max {fmt_bytes(cs['max']) if cs.get('max') is not None else 'unlimited'}   ")
            lim.append(f"high {fmt_bytes(cs['high']) if cs.get('high') is not None else 'unlimited'}")
            if cs.get("max"):
                lim.append(f"   ({100 * cs['current'] / cs['max']:.0f}% used)", style="dim")
            parts.append(lim)
            oom = cs.get("oom")
            kills = cs.get("oom_kill")
            ev = Text("Events  ", style="bold")
            ev.append(f"oom {'-' if oom is None else oom}   oom_kill {'-' if kills is None else kills}")
            parts.append(ev)
            psi = cs.get("pressure")
            if psi:
                parts.append(Text(f"Pressure  some {psi.get('some', {}).get('avg10', 0):.1f}%  "
                                  f"full {psi.get('full', {}).get('avg10', 0):.1f}% (avg10)", style="bold"))
        members = sorted((q for q in self.snapshot.processes if q.cgroup == row.cgroup), key=lambda q: -q.resident)
        if members:
            parts.append(Text("\nMembers (by resident)", style="bold"))
            mt = Table(box=None, padding=(0, 1), show_edge=False, show_header=False)
            mt.add_column(justify="right", style="dim")
            mt.add_column()
            mt.add_column(justify="right")
            for q in members[:10]:
                mt.add_row(str(q.pid), q.name, fmt_bytes(q.resident))
            parts.append(mt)
        parts.append(Text("\nmeasured: kernel cgroup accounting; shared pages are charged once, to the cgroup "
                          "that first used them", style="dim"))
        self.query_one("#inspect-body", Static).update(Group(*parts))

    @work(thread=True, exclusive=True, group="inspect")
    def inspect_worker(self, p: ProcessMem, group_count: int) -> None:
        ins = self.collector.inspect(p)
        self.call_from_thread(self.show_inspection, ins, group_count)

    @ui_callback
    def show_inspection(self, ins: Inspection, group_count: int = 1) -> None:
        self.inspection = ins
        parts: list = []
        head = Text()
        head.append(f"{ins.name}", style="bold")
        head.append(f"  pid {ins.pid}", style="dim")
        if group_count > 1:
            head.append(f"  (largest of {group_count})", style="dim")
        parts.append(head)
        if ins.error:
            parts.append(Text(ins.error, style="red"))
        if ins.guest:
            g = ins.guest
            parts.append(Text(f"\nInside the WSL2 VM ({g['distro']})", style="bold"))
            gt = Table(box=None, padding=(0, 1), show_edge=False, show_header=False)
            gt.add_column(style="dim")
            gt.add_column(justify="right")
            gt.add_column()
            total = g.get("total") or 1
            for label, key, color in (("Used by Linux", "used", C_USED), ("  anonymous", "anon", C_USED),
                                      ("Page cache", "cache", C_STANDBY), ("  of which tmpfs", "shmem", C_MOD),
                                      ("Free", "free", C_FREE), ("VM size", "total", "")):
                v = g.get(key)
                if v is not None:
                    bar = Text("█" * round(16 * v / total), style=color) if color else Text("")
                    gt.add_row(label, fmt_bytes(v), bar)
            parts.append(gt)
            parts.append(Text("read on demand while this row is selected; WSL is never started",
                              style="dim"))
        if ins.categories:
            total_res = sum(c.resident or 0 for c in ins.categories) or 1
            t = Table(box=None, padding=(0, 1), show_edge=False, header_style="bold dim")
            t.add_column("What", no_wrap=True)
            t.add_column("Mapped", justify="right")
            t.add_column("Resident", justify="right")
            t.add_column("Shared", justify="right")
            t.add_column("", width=8, no_wrap=True)
            for c in ins.categories:
                share = (c.resident or 0) / total_res
                bar = Text("█" * max(0, round(share * 8)), style=C_USED)
                t.add_row(c.name, fmt_bytes(c.mapped), fmt_bytes(c.resident), fmt_bytes(c.resident_shared), bar)
            if ins.reserved:
                t.add_row(Text("Reserved only", style="dim"), Text(fmt_bytes(ins.reserved), style="dim"), "", "", "")
            parts.append(t)
        if ins.top_files:
            parts.append(Text("\nLargest file-backed pages", style="bold"))
            ft = Table(box=None, padding=(0, 1), show_edge=False, show_header=False)
            ft.add_column(justify="right")
            ft.add_column(no_wrap=True, overflow="ellipsis")
            for f in ins.top_files:
                pp = PureWindowsPath(redact(f.path) if self.privacy else f.path)
                label = Text(pp.name)
                parent = str(pp.parent)
                label.append("  " + (parent if len(parent) <= 30 else "…" + parent[-29:]), style="dim")
                ft.add_row(fmt_bytes(f.resident if f.resident is not None else f.mapped), label)
            parts.append(ft)
        if ins.evidence:
            parts.append(Text("\nEvidence", style="bold"))
            for level, text in ins.evidence:
                text = redact(text) if self.privacy else text
                line = Text()
                line.append(f"{level:<11}", style=LEVEL_STYLE.get(level, ""))
                line.append(text)
                parts.append(line)
        missing = {k: r for k, r in ins.unavailable.items() if k not in ("growth_ps", "faults_ps") or r != "needs two samples"}
        if missing:
            parts.append(Text("\nWhy some values show -", style="bold"))
            for k, r in missing.items():
                parts.append(Text(f"  {FIELD_LABELS.get(k, k)}: {r}", style="dim"))
        if ins.cmdline and not self.privacy:
            parts.append(Text("\n" + " ".join(ins.cmdline)[:300], style="dim"))
        parts.append(Text(f"\ninspected in {ins.elapsed * 1000:.0f} ms, refreshes every {INSPECT_EVERY:.0f}s", style="dim"))
        self.query_one("#inspect-body", Static).update(Group(*parts))

    # ------------------------------------------------------------------ actions
    def _refresh_now(self) -> None:
        if self.snapshot:
            self.render_top()
            self.render_table()

    def action_sort(self) -> None:
        i = self.sort_keys.index(self.sort_key) if self.sort_key in self.sort_keys else -1
        self.sort_key, self.sort_invert = self.sort_keys[(i + 1) % len(self.sort_keys)], False
        self.notify(f"sort: {self.sort_key}", timeout=1.5)
        self._update_header_arrows()
        self._refresh_now()

    def check_action(self, action: str, parameters) -> bool | None:
        if action == "kill" and self.read_only:
            return False  # hidden from the footer and inert
        return True

    def _selected_process(self) -> ProcessMem | None:
        """The real process under the cursor (not a tree subtree total or a group)."""
        row = self.rows.get(self.selected) if self.selected else None
        if row is None or self.snapshot is None or self.group_mode != "none":
            return row
        return next((q for q in self.snapshot.processes if q.key == row.key), row)

    def action_kill(self) -> None:
        p = self._selected_process()
        if p is None:
            self.notify("select a process first", severity="warning")
            return
        why = killer.refuse_reason(p)
        if why:
            self.notify(f"won't end it: {why}", severity="warning", timeout=4)
            return
        force = time.monotonic() - self.polite_sent.get(p.key, -1e9) < 120

        def done(confirmed: bool | None) -> None:
            if confirmed:
                self.kill_worker(p, force)

        self.push_screen(KillScreen(p, force), done)

    @work(thread=True, group="kill")
    def kill_worker(self, p: ProcessMem, force: bool) -> None:
        sent, msg = killer.end_process(p, force=force)
        if not force and not sent and "polite" in msg:
            self.polite_sent[p.key] = time.monotonic()  # next k forces
        self.call_from_thread(self.notify, msg, severity="information" if sent else "warning", timeout=4)
        if sent and not force:
            self.polite_sent[p.key] = time.monotonic()
            time.sleep(3)
            if isinstance(killer.verify(p), killer.psutil.Process):
                self.call_from_thread(self.notify, f"{p.name} is still running; press k again to force it",
                                      severity="warning", timeout=6)

    def action_tree(self) -> None:
        self.tree_mode = not self.tree_mode
        if self.tree_mode and self.group_mode != "none":
            self.group_mode = "none"
            self._setup_columns()
        self.notify("tree view: Enter collapses / expands" if self.tree_mode else "flat view", timeout=1.5)
        self._refresh_now()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        """Enter on a tree row collapses or expands it."""
        key = event.row_key.value if event.row_key else None
        tr = self.tree_rows.get(key) if key else None
        if not self.tree_mode or tr is None or not tr.children:
            return
        pk = tr.proc.key
        if tr.collapsed:
            self.tree_collapsed.discard(pk)
            self.tree_expanded.add(pk)
        else:
            self.tree_expanded.discard(pk)
            self.tree_collapsed.add(pk)
        self._refresh_now()

    def action_group(self) -> None:
        if self.tree_mode:
            self.tree_mode = False
        modes = list(GROUP_MODES)
        if self.snapshot is not None and self.snapshot.cgroups is None and "cgroup" in modes:
            modes.remove("cgroup")
        self.group_mode = modes[(modes.index(self.group_mode) + 1) % len(modes)] if self.group_mode in modes else "none"
        if self.group_mode == "cgroup":
            self.notify("grouped by cgroup: sizes are the kernel's cgroup accounting", timeout=2)
        self.selected = None
        self._setup_columns()
        self._refresh_now()

    def action_toggle_all(self) -> None:
        self.show_all = not self.show_all
        self._refresh_now()

    def action_charts(self) -> None:
        self.chart_mode = self.chart_mode + 1 if self.chart_mode + 1 < len(CHARTS) else -1
        self.query_one("#charts").set_class(self.chart_mode >= 0, "single")
        self.render_charts()

    def action_mode(self) -> None:
        self.screen.toggle_class("slim")
        self._apply_size(self.size.width, self.size.height)  # slim frees the side panel's width

    def action_pause(self) -> None:
        self.paused = not self.paused
        self._refresh_now()

    def action_units(self) -> None:
        set_units("decimal" if units() == "binary" else "binary")
        self.notify(units_legend(), timeout=2)
        self.render_charts()
        self.render_system()
        self._refresh_now()
        if self.inspection:
            self.show_inspection(self.inspection)

    def action_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        inp.add_class("visible")
        inp.focus()

    def action_clear_filter(self) -> None:
        inp = self.query_one("#filter", Input)
        if not inp.has_class("visible") and not self.filter_text:
            return
        inp.value = ""
        inp.remove_class("visible")
        self.filter_text = ""
        self.query_one("#procs", DataTable).focus()
        self._refresh_now()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter":
            self.filter_text = event.value.strip()
            self._refresh_now()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "filter":
            if not self.filter_text:
                event.input.remove_class("visible")
            self.query_one("#procs", DataTable).focus()

    def action_help(self) -> None:
        self.push_screen(HelpScreen())

    def on_unmount(self) -> None:
        self._shutting_down = True
        self.collector.close()
