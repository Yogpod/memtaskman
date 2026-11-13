"""Build a portable memtaskman (no Python needed) for the current OS and CPU.

    uv run --with pyinstaller python tools/build_portable.py

Produces dist/portable/memtaskman-<version>-<os>-<arch>.(zip|tar.gz) plus a .sha256 file.
PyInstaller does not cross-compile: run this on each target (CI does, per runner).
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from importlib import metadata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "dist" / "portable"
WORK = ROOT / "build" / "portable"
BUNDLED = ["memtaskman", "textual", "rich", "psutil", "pygments", "markdown-it-py", "mdurl",
           "platformdirs", "typing_extensions", "linkify-it-py", "uc-micro-py", "mdit-py-plugins"]


def target() -> str:
    os_name = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux")
    arch = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(arch, arch)
    return f"{os_name}-{arch}"


def version() -> str:
    with open(ROOT / "pyproject.toml", "rb") as f:
        return tomllib.load(f)["project"]["version"]


def collect_licenses(dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy(ROOT / "LICENSE", dest / "memtaskman.LICENSE")
    for name in BUNDLED[1:]:
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue
        files = [f for f in (dist.files or []) if "licen" in f.name.lower() or "copying" in f.name.lower()]
        for f in files:
            src = Path(dist.locate_file(f))
            if src.is_file():
                shutil.copy(src, dest / f"{dist.metadata['Name']}.{src.name}")
    (dest / "python.LICENSE").write_text(
        "This bundle includes the CPython runtime, licensed under the PSF License Agreement:\n"
        "https://docs.python.org/3/license.html\n", encoding="utf-8")


def build() -> Path:
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    entry = WORK / "mtm_entry.py"
    entry.write_text("from memtaskman.cli import main\nraise SystemExit(main())\n", encoding="utf-8")
    subprocess.run([
        sys.executable, "-m", "PyInstaller", str(entry), "--name", "mtm", "--onedir", "--console", "--noconfirm",
        "--clean", "--distpath", str(WORK / "dist"), "--workpath", str(WORK / "work"), "--specpath", str(WORK),
        "--collect-all", "textual", "--collect-submodules", "memtaskman", "--copy-metadata", "memtaskman",
    ], check=True, cwd=ROOT)
    app_dir = WORK / "dist" / "mtm"
    shutil.copy(ROOT / "README.md", app_dir / "README.md")
    collect_licenses(app_dir / "licenses")
    return app_dir


def smoke(app_dir: Path) -> None:
    exe = app_dir / ("mtm.exe" if sys.platform == "win32" else "mtm")
    for args in (["--version"], ["--once", "--top", "3", "-i", "0.5"], ["--self-test"]):
        r = subprocess.run([str(exe), *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=120)
        print(r.stdout.strip()[-600:])
        if r.returncode != 0:
            raise SystemExit(f"portable smoke test failed: {args}\n{r.stderr}")


def package(app_dir: Path) -> Path:
    OUT.mkdir(parents=True, exist_ok=True)
    stem = f"memtaskman-{version()}-{target()}"
    if sys.platform == "win32":
        archive = OUT / f"{stem}.zip"
        with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
            for f in sorted(app_dir.rglob("*")):
                z.write(f, Path(stem) / f.relative_to(app_dir))
    else:
        archive = OUT / f"{stem}.tar.gz"
        with tarfile.open(archive, "w:gz") as t:
            t.add(app_dir, arcname=stem)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (OUT / f"{archive.name}.sha256").write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    print(f"{archive}  {archive.stat().st_size / 2**20:.1f} MiB  sha256 {digest[:16]}…")
    return archive


if __name__ == "__main__":
    d = build()
    smoke(d)
    package(d)
