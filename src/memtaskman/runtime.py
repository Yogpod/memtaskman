"""Identify what kind of runtime owns a process, from evidence only.

Pure functions: input is the executable name, loaded module basenames and the
command line; output is a label plus evidence lines. Nothing here touches the OS,
so it is fully unit-testable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Iterable

from memtaskman.fmt import fmt_bytes, parse_size
from memtaskman.model import HINT, IDENTIFIED, MEASURED


@dataclass
class RuntimeInfo:
    name: str
    detail: str = ""
    evidence: list[tuple[str, str]] = field(default_factory=list)

    @property
    def label(self) -> str:
        return f"{self.name} {self.detail}".strip()


_BROWSERS = {
    "chrome": "Chrome",
    "msedge": "Edge",
    "msedgewebview2": "WebView2",
    "brave": "Brave",
    "opera": "Opera",
    "vivaldi": "Vivaldi",
    "chromium": "Chromium",
    "arc": "Arc",
}

_VM_HOSTS = {
    "vmmem": "Hyper-V / WSL2 guest RAM",
    "vmmemwsl": "WSL2 guest RAM",
    "vmwp": "Hyper-V worker",
    "qemu-system-x86_64": "QEMU guest RAM",
    "qemu-system-aarch64": "QEMU guest RAM",
    "vmware-vmx": "VMware guest RAM",
    "virtualboxvm": "VirtualBox guest RAM",
}

_DATABASES = {
    "sqlservr": "SQL Server",
    "postgres": "PostgreSQL",
    "mysqld": "MySQL",
    "mariadbd": "MariaDB",
    "redis-server": "Redis",
    "mongod": "MongoDB",
    "memcached": "memcached",
    "clickhouse": "ClickHouse",
    "elasticsearch": "Elasticsearch",
}

_LLM = {
    "ollama": "Ollama",
    "ollama_llama_server": "Ollama",
    "llama-server": "llama.cpp",
    "llama-cli": "llama.cpp",
    "lm studio": "LM Studio",
    "lms": "LM Studio",
    "foundry": "Foundry Local",
    "vllm": "vLLM",
}


def stem(name: str) -> str:
    """Lowercase basename without a trailing .exe."""
    base = PurePath(name.replace("\\", "/")).name.lower()
    return base[:-4] if base.endswith(".exe") else base


def _flag(cmdline: list[str], *names: str) -> str | None:
    """Value of --name=value / --name value / -Xname style flags."""
    for i, arg in enumerate(cmdline):
        for n in names:
            if arg == n and i + 1 < len(cmdline):
                return cmdline[i + 1]
            if arg.startswith(n + "="):
                return arg[len(n) + 1 :]
    return None


def _has_module(mods: set[str], *patterns: str) -> str | None:
    for m in mods:
        for p in patterns:
            if re.fullmatch(p, m):
                return m
    return None


def detect(exe: str, modules: Iterable[str] = (), cmdline: Iterable[str] = ()) -> RuntimeInfo | None:
    name = stem(exe)
    mods = {m.lower() for m in modules}
    args = list(cmdline)

    # --- Hypervisors: one process standing in for an entire guest OS ---------------
    if name in _VM_HOSTS:
        ev = [(IDENTIFIED, f"{exe} hosts a virtual machine; its memory is the guest's RAM")]
        if name in {"vmmem", "vmmemwsl"}:
            ev.append((HINT, "WSL2: cap it with [wsl2] memory=... in %UserProfile%\\.wslconfig"))
        return RuntimeInfo("VM", _VM_HOSTS[name], ev)
    if name in {"memory compression", "memcompression"}:
        return RuntimeInfo("Kernel", "compression store",
                           [(MEASURED, "Windows keeps compressed pages from all processes here")])
    if name in {"system", "registry", "secure system", "kernel_task", "kthreadd"}:
        return RuntimeInfo("Kernel", "", [(IDENTIFIED, "kernel / system process")])

    # --- Browsers & Electron (Chromium multi-process model) -------------------------
    ptype = _flag(args, "--type")
    chromium_mod = _has_module(mods, r"chrome_elf\.dll", r"chrome\.dll", r"msedge\.dll", r"libcef\.(dll|so)",
                               r"msedge_elf\.dll", r"electron.*")
    if ptype or chromium_mod or name in _BROWSERS:
        brand = _BROWSERS.get(name)
        if brand is None:
            brand = "Electron" if (ptype or chromium_mod) else "Chromium"
        sub = _flag(args, "--utility-sub-type")
        detail = ptype or "browser"
        if detail == "gpu-process":
            detail = "gpu"
        if sub:
            detail += ":" + sub.split(".")[-1].replace("Service", "").lower()
        ev = [(IDENTIFIED, f"Chromium process type '{ptype or 'browser'}'"
               + (f" (module {chromium_mod})" if chromium_mod else ""))]
        js = _flag(args, "--js-flags")
        if js:
            m = re.search(r"--max-old-space-size=(\d+)", js)
            if m:
                ev.append((HINT, f"V8 heap limit {fmt_bytes(int(m.group(1)) * 1024 * 1024)} (--js-flags)"))
        if ptype == "renderer":
            ev.append((HINT, "renderers hold one or more tabs/frames; V8 heap + DOM + images"))
        return RuntimeInfo(brand, detail, ev)

    # --- Firefox ---------------------------------------------------------------------
    if name in {"firefox", "librewolf", "waterfox"} or _has_module(mods, r"xul\.dll", r"libxul\.so"):
        detail = "content" if "-contentproc" in args else "parent"
        if "-contentproc" in args and args:
            last = args[-1]
            if last in {"tab", "gpu", "socket", "rdd", "utility", "gmplugin"}:
                detail = last
        return RuntimeInfo("Firefox", detail, [(IDENTIFIED, "Gecko (xul) process")])

    # --- Managed runtimes -------------------------------------------------------------
    jvm = _has_module(mods, r"jvm\.dll", r"libjvm\.(so|dylib)")
    if jvm or name in {"java", "javaw"}:
        ev = [(IDENTIFIED, f"JVM ({jvm or exe})")]
        for a in args:
            if a.startswith("-Xmx"):
                size = parse_size(a[4:])
                ev.append((HINT, f"max heap {fmt_bytes(size)} (-Xmx)" if size else f"max heap {a[4:]} (-Xmx)"))
            elif a.startswith("-XX:MaxRAMPercentage="):
                ev.append((HINT, f"max heap {a.split('=', 1)[1]}% of RAM"))
        main = next((a for a in args if a.endswith(".jar")), "")
        return RuntimeInfo("Java", PurePath(main.replace("\\", "/")).name if main else "", ev)

    clr = _has_module(mods, r"coreclr\.dll", r"libcoreclr\.(so|dylib)", r"clr\.dll", r"mscorwks\.dll")
    if clr:
        flavour = ".NET" if "coreclr" in clr else ".NET Framework"
        ev = [(IDENTIFIED, f"CLR loaded ({clr}); private bytes include the GC heap")]
        if _has_module(mods, r"wpfgfx.*\.dll", r"presentationcore.*"):
            ev.append((IDENTIFIED, "WPF UI"))
        return RuntimeInfo(flavour, "", ev)

    node = _has_module(mods, r"libnode\.(dll|so.*|dylib)", r"node\.dll")
    if node or name in {"node", "bun", "deno"}:
        label = {"bun": "Bun", "deno": "Deno"}.get(name, "Node.js")
        ev = [(IDENTIFIED, f"{label} ({node or exe})")]
        v = _flag(args, "--max-old-space-size")
        if v and v.isdigit():
            ev.append((HINT, f"V8 heap limit {fmt_bytes(int(v) * 1024 * 1024)}"))
        script = next((a for a in args[1:] if not a.startswith("-")), "")
        return RuntimeInfo(label, PurePath(script.replace("\\", "/")).name if script else "", ev)

    py = _has_module(mods, r"python3\d*\.dll", r"libpython3[\d.]*\.(so.*|dylib)")
    if py or re.fullmatch(r"pythonw?(3(\.\d+)?)?", name):
        ver = ""
        if py:
            m = re.search(r"python(\d)\.?(\d+)", py)
            if m:
                ver = f"{m.group(1)}.{m.group(2)}"
        script = next((a for a in args[1:] if not a.startswith("-")), "")
        if "-m" in args:
            i = args.index("-m")
            if i + 1 < len(args):
                script = args[i + 1]
        ev = [(IDENTIFIED, f"CPython {ver}".strip() + (f" ({py})" if py else ""))]
        if _has_module(mods, r"torch_cpu\.dll", r"libtorch_cpu\.so", r"c10\.dll"):
            ev.append((IDENTIFIED, "PyTorch loaded (tensors on CPU count as private bytes)"))
        return RuntimeInfo(f"Python {ver}".strip(), PurePath(script.replace("\\", "/")).name if script else "", ev)

    # --- Local LLM servers (CPU-offloaded weights live in RAM) -------------------------
    for key, label in _LLM.items():
        if name == key or name.startswith(key + "-"):
            ev = [(IDENTIFIED, f"{label} server")]
            model = _flag(args, "-m", "--model")
            if model:
                ev.append((HINT, f"model {PurePath(model.replace(chr(92), '/')).name}"))
            if _flag(args, "--mlock") is not None or "--mlock" in args:
                ev.append((HINT, "--mlock: weights pinned in RAM"))
            if "--no-mmap" in args:
                ev.append((HINT, "--no-mmap: weights copied into private memory"))
            else:
                ev.append((HINT, "weights are usually mmap'd: they appear under Mapped files"))
            return RuntimeInfo("LLM", label, ev)

    # --- Databases ----------------------------------------------------------------------
    if name in _DATABASES:
        ev = [(IDENTIFIED, _DATABASES[name])]
        mm = _flag(args, "--maxmemory")
        if mm:
            ev.append((HINT, f"maxmemory {mm}"))
        if name == "sqlservr":
            ev.append((HINT, "SQL Server grows its buffer pool to 'max server memory'"))
        return RuntimeInfo("DB", _DATABASES[name], ev)

    return None
