# Packaging

## After each release

Once the release workflow has finished (the portable zips and `.sha256` files are on the
GitHub release):

```bash
uv run python tools/update_manifests.py X.Y.Z
winget validate --manifest packaging/winget/manifests/y/Yogpod/memtaskman/X.Y.Z
git add bucket packaging && git commit -m "Packaging: X.Y.Z manifests"
```

This updates the Scoop manifest (`bucket/memtaskman.json`) and writes winget manifests for
the new version, using the checksums published with the release.

## Scoop

This repository is its own Scoop bucket, so users can install with:

```powershell
scoop bucket add memtaskman https://github.com/Yogpod/memtaskman
scoop install memtaskman
```

The manifest has `checkver` / `autoupdate`, so `scoop update` picks up new versions as soon as
the manifest is committed.

## winget

winget packages live in [microsoft/winget-pkgs](https://github.com/microsoft/winget-pkgs) and
are submitted by pull request. They're reviewed and automatically tested there, usually within
a few days:

1. Fork `microsoft/winget-pkgs`.
2. Copy `packaging/winget/manifests/y/Yogpod/memtaskman/X.Y.Z/` to the same path in the fork.
3. Open a PR titled `New package: Yogpod.memtaskman version X.Y.Z` (or `New version: ...` later).

Alternatively, `wingetcreate submit packaging/winget/manifests/y/Yogpod/memtaskman/X.Y.Z`
does steps 1–3 for you.

The first submission may get questions about the unsigned binary. Once merged, users install
with `winget install Yogpod.memtaskman`.

## Not yet

- **Nix flake**: not written yet, since it couldn't be tested here (see issue #13).
- **Code signing**: the Windows builds are unsigned, so SmartScreen may warn once.
