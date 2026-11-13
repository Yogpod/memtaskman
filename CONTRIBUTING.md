# Contributing

Thanks for helping. Short version:

1. Read [AGENTS.md](AGENTS.md). Its evidence rules (never invent zeros, label every claim,
   read metadata only) apply to every change.
2. `uv sync`, make the change, and add tests:
   - parsing goes in pure functions with unit tests in `tests/`, runnable on any OS;
   - anything that touches the live machine gets a check in `tools/smoke.py`.
3. Run `uv run python -m unittest discover -s tests` and `uv run python tools/smoke.py`.
4. Open a pull request. CI runs everything on Windows, Linux and macOS.

Hardware or OS coverage you can test that CI can't (a real Mac, other Linux distributions,
ARM Windows, very large machines) is especially welcome. Just describe what you ran it on.

Issues are labelled by platform (`windows`, `linux`, `macos`, `cross-platform`) and by
`priority: high / medium / low`.
