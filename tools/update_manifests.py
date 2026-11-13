"""Update the Scoop and winget manifests for a published release.

    uv run python tools/update_manifests.py 0.3.0

Reads the checksums from the release's .sha256 assets on GitHub (the release workflow
must have finished), rewrites bucket/memtaskman.json and writes the winget manifests to
packaging/winget/manifests/y/Yogpod/memtaskman/<version>/.
"""

from __future__ import annotations

import json
import re
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "Yogpod/memtaskman"
ARCHES = {"64bit": ("x64", "windows-x64"), "arm64": ("arm64", "windows-arm64")}
WINGET = ROOT / "packaging" / "winget" / "manifests" / "y" / "Yogpod" / "memtaskman"


def asset_url(version: str, target: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/memtaskman-{version}-{target}.zip"


def sha256_of(version: str, target: str) -> str:
    with urllib.request.urlopen(asset_url(version, target) + ".sha256", timeout=30) as r:
        digest = r.read().decode().split()[0]
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit(f"bad checksum file for {target}: {digest!r}")
    return digest


def update_scoop(version: str, hashes: dict[str, str]) -> Path:
    path = ROOT / "bucket" / "memtaskman.json"
    man = json.loads(path.read_text(encoding="utf-8"))
    man["version"] = version
    for scoop_arch, (_w, target) in ARCHES.items():
        a = man["architecture"][scoop_arch]
        a["url"] = asset_url(version, target)
        a["hash"] = hashes[target]
        a["extract_dir"] = f"memtaskman-{version}-{target}"
    path.write_text(json.dumps(man, indent=4) + "\n", encoding="utf-8")
    return path


def update_winget(version: str, hashes: dict[str, str]) -> Path:
    versions = sorted((p for p in WINGET.iterdir() if p.is_dir()), key=lambda p: [int(x) for x in p.name.split(".")])
    template = versions[-1]
    out = WINGET / version
    out.mkdir(parents=True, exist_ok=True)
    old = template.name
    for src in template.glob("*.yaml"):
        text = src.read_text(encoding="utf-8").replace(old, version)
        if src.name.endswith(".installer.yaml"):
            for _s, (_w, target) in ARCHES.items():
                text = re.sub(rf"(InstallerUrl: \S*-{target}\.zip\n\s+InstallerSha256: )[0-9A-Fa-f]{{64}}",
                              lambda m, t=target: m.group(1) + hashes[t].upper(), text)
            text = re.sub(r"ReleaseDate: \S+", f"ReleaseDate: {date.today().isoformat()}", text)
        (out / src.name).write_text(text, encoding="utf-8")
    return out


def main() -> int:
    if len(sys.argv) != 2 or not re.fullmatch(r"\d+\.\d+\.\d+", sys.argv[1]):
        print(__doc__)
        return 2
    version = sys.argv[1]
    hashes = {target: sha256_of(version, target) for _s, (_w, target) in ARCHES.items()}
    print("scoop :", update_scoop(version, hashes).relative_to(ROOT))
    print("winget:", update_winget(version, hashes).relative_to(ROOT))
    print("Next: winget validate --manifest <winget dir>, commit, and open a PR to microsoft/winget-pkgs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
