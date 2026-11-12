# AGENTS.md

devenv runs AI coding agents in a bubblewrap sandbox. It is security
software: when correctness and convenience conflict, choose correctness and
say so.

## Layout

- `src/devenv/plan.py`: builds the bwrap argv. Pure; mount order matters.
- `src/devenv/protect.py`: protected paths and post-session quarantine.
- `src/devenv/config.py`: strict TOML policy; defaults in `defaults.toml`.
- `src/devenv/seccomp.py`, `landlock.py`: kernel hardening.
- `src/devenv/cli.py`: the only module that starts processes.
- `DESIGN.md` explains why things are the way they are. Read it before
  changing mount order, protections or the threat model.

## Commands

```sh
pip install -e '.[dev]'
ruff format . && ruff check .   # all rules enabled
mypy                            # strict
pytest                          # integration tests need a working bwrap
```

All four must pass before a change is done.

## Rules

- Python 3.13+. Use modern idioms: `type` aliases, `match`, `pathlib`, and
  frozen/slotted/kw-only dataclasses.
- Every function, class, module and module/class-level variable has a
  docstring.
- Keep `plan.py`, `config.py`, `protect.analyse` and `seccomp.py` free of
  side effects. I/O belongs in `cli.py`.
- Never follow a symlink found in an agent-writable area when mounting.
- Never mount anything after the protections in `plan.build()`.
- New config keys: add them to the dataclass, `parse()`, `defaults.toml`
  (commented) and the tests. Unknown keys must stay errors.
- Every security behaviour gets a test, and an integration test when bwrap
  is involved.
- Don't weaken a check to make a test pass. Fix the test or ask.
- Update `README.md` "Known limits" when you find or close a gap.
