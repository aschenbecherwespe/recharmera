# recharmera
Firmware reverse engineering notes and tooling for the KODAK CHARMERA (Generalplus GPCV)

## Setup

Deps are declared in `pyproject.toml` and pinned in `uv.lock`; [uv](https://docs.astral.sh/uv/)
creates and drives the venv, so there is no manual `venv`/`pip` step:

```
uv sync                      # build .venv from the lock
uv run scripts/find_xrefs.py # run a tool without activating anything
```

`uv add <pkg>` (not bare `pip install`) keeps `pyproject.toml` and `uv.lock` in sync.
See `REVERSE_ENGINEERING_NOTES.md` §7 for details.
