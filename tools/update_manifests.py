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
import time
import urllib.error
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = "Yogpod/memtaskman"
ARCHES = {"64bit": ("x64", "windows-x64"), "arm64": ("arm64", "windows-arm64")}
WINGET = ROOT / "packaging" / "winget" / "manifests" / "y" / "Yogpod" / "memtaskman"


def asset_url(version: str, target: str) -> str:
    return f"https://github.com/{REPO}/releases/download/v{version}/memtaskman-{version}-{target}.zip"


class ManifestError(Exception):
    pass


def _get(url: str, *, tries: int = 4, wait: float = 10.0) -> bytes:
    """GET with retries: right after a release, downloads can 404 for a few minutes."""
    req = urllib.request.Request(url, headers={"User-Agent": "memtaskman-update-manifests",
                                               "Accept": "application/vnd.github+json"})
    for attempt in range(1, tries + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code != 404 or attempt == tries:
                raise
            print(f"  {url.rsplit('/', 1)[-1]}: not available yet, retrying in {wait:.0f}s ({attempt}/{tries - 1})")
            time.sleep(wait)
    raise AssertionError("unreachable")


def release_assets(version: str) -> set[str]:
    """Asset names on the GitHub release, from the API (authoritative, not CDN-cached)."""
    url = f"https://api.github.com/repos/{REPO}/releases/tags/v{version}"
    try:
        data = json.loads(_get(url, tries=1))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise ManifestError(f"there is no GitHub release v{version} yet. Push the tag and let the "
                                "release workflow finish first.") from None
        raise ManifestError(f"GitHub API error {e.code} for {url}") from None
    return {a["name"] for a in data.get("assets", [])}


def sha256_of(version: str, target: str) -> str:
    try:
        digest = _get(asset_url(version, target) + ".sha256").decode().split()[0]
    except urllib.error.HTTPError as e:
        raise ManifestError(f"couldn't download the checksum for {target} (HTTP {e.code}); the release "
                            "assets may still be uploading, try again in a few minutes") from None
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ManifestError(f"bad checksum file for {target}: {digest!r}")
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
    arg = sys.argv[1].strip().lstrip("vV") if len(sys.argv) == 2 else ""
    if not re.fullmatch(r"\d+\.\d+\.\d+", arg):
        print(__doc__)
        print("error: give the released version, e.g. 0.2.2 (a leading v is fine)", file=sys.stderr)
        return 2
    version = arg
    try:
        assets = release_assets(version)
        wanted = [f"memtaskman-{version}-{t}.zip{ext}" for _s, (_w, t) in ARCHES.items() for ext in ("", ".sha256")]
        missing = [w for w in wanted if w not in assets]
        if missing:
            raise ManifestError(f"release v{version} is missing {', '.join(missing)}. Is the release "
                                "workflow still running? Check the Actions tab, then try again.")
        hashes = {target: sha256_of(version, target) for _s, (_w, target) in ARCHES.items()}
    except ManifestError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print("scoop :", update_scoop(version, hashes).relative_to(ROOT))
    print("winget:", update_winget(version, hashes).relative_to(ROOT))
    print("Next: winget validate --manifest <winget dir>, commit, and open a PR to microsoft/winget-pkgs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
