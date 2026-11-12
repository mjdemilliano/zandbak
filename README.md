# devenv

*devenv* is Dutch for sandbox. It runs AI coding agents (Claude Code, Gemini CLI, Goose, ...) inside a
[bubblewrap](https://github.com/containers/bubblewrap) sandbox. The agent can
write to the project directory you start it in, and to nothing else you
haven't listed.

A Python rewrite of [umago/bubblewrap-ai](https://github.com/umago/bubblewrap-ai)
that fixes the issues from its security review. [DESIGN.md](DESIGN.md)
explains how it works and why.

## Requirements

Linux, Python 3.13+, `bwrap` (`dnf install bubblewrap` / `apt install bubblewrap`).
Linux 6.12+ is recommended (see *Abstract sockets* below).

## Install

```sh
pipx install git+https://example.invalid/you/devenv   # or: pipx install .
```

Install it somewhere the sandbox can't write (pipx's default is fine, as
long as you don't make `~/.local` writable). devenv refuses to start if its
own code, its config, Python or bwrap would be writable inside the sandbox.

## Usage

```sh
cd ~/src/my-project
devenv                          # sandboxed bash shell with a [🫧] prompt
devenv -c claude                # run an agent directly
devenv -c goose -- session -r   # arguments after -- are passed through as-is
devenv --ro-dir ../shared-lib   # expose another folder read-only (repeatable)
devenv --no-network             # cut the network for this run
devenv --allow-git-writes       # let the agent change .git/config and hooks
devenv --dry-run                # print the bwrap command
```

## What the sandbox sees

| Area | Access |
|---|---|
| Project directory (cwd) | read-write, minus protected paths |
| `/usr`, `/etc`, `/opt`, `/sys` | read-only |
| `/tmp`, `/var/tmp`, `/run`, `/dev/shm` | private, empty, discarded on exit |
| `$HOME` | empty; only `[home]` allowlisted paths are mounted |
| Environment | cleared; only `env_allow` variables are copied |
| Network | shared by default; `--no-network` isolates it |
| Processes, IPC, hostname | separate namespaces; no capabilities |

devenv refuses to start in `$HOME`, `/`, any parent of `$HOME`, or a
dot-directory, and refuses `--ro-dir` paths that would expose those.

## Configuration

`~/.config/devenv/config.toml` (or `--config FILE`). Start from the defaults:

```sh
mkdir -p ~/.config/devenv && devenv --dump-config > ~/.config/devenv/config.toml
```

The default file is commented. Keys you set replace the default (lists are
not merged). Unknown keys and bad values are errors, never silently ignored.

`[home]` has four lists, all relative to `$HOME`:

- `ro` read-only, `rw` read-write;
- `ephemeral` a private copy that's discarded on exit (used for
  `~/.claude.json`, which Claude rewrites constantly but which can also
  define MCP servers that run on your host);
- `protect` paths inside `rw` folders that stay read-only.

`[project] protect` lists the same kind of paths inside the project:
`.git/config`, `.git/hooks`, `.git/modules`, agent settings, `.mcp.json`,
`.envrc`, `.vscode`.

## How protection works

Protected paths are things your host *runs* later without you choosing to:
git hooks and `core.fsmonitor`, agent hooks and MCP servers, direnv.

- **Existing** protected paths are mounted read-only, and their parent
  folders are pinned (mount points can't be renamed or deleted, so the agent
  can't swap `.git` for a copy it controls).
- **Missing** ones are watched. If the agent creates one (say
  `.claude/settings.json` with a hook), devenv renames it to
  `*.devenv-quarantine-<time>` after the session and tells you.
- **Symlinks** are never followed when mounting (a link planted in an earlier
  session could otherwise pull any host file into the sandbox). They're
  watched instead.

Two other protections:

- **Terminal injection** (`TIOCSTI`/`TIOCLINUX`, CVE-2017-5226) is blocked
  with a seccomp filter. It compares only the low 32 bits of the ioctl
  command, which avoids the CVE-2019-10063 bypass. Unlike `--new-session`,
  Ctrl-C still works normally.
- **Abstract sockets.** With a shared network, the host's abstract UNIX
  sockets are reachable, including the X11 display, which on many desktops
  accepts any process running as your user. On Linux 6.12+ devenv blocks them
  with Landlock scoping. On older kernels it warns, and `--no-network` is
  the fix.

## Known limits

Read these before you trust it with something important.

- **The project is the agent's output.** It can change any code in it, and
  `make`, `npm test`, build scripts and Claude hook scripts *referenced by* a
  protected settings file will run that code on your host. Review changes
  before running them.
- **Nested git repositories.** The agent can create `sub/.git` with a hostile
  `core.fsmonitor`. A shell prompt that runs `git status` when you `cd sub`
  would execute it. Only the project's top-level `.git` is protected.
- **The agent's own data is exposed.** Everything under `~/.claude` stays
  readable: API/OAuth credentials, and transcripts and prompt history from
  *all* your projects (`~/.claude/projects`, `history.jsonl`). The same goes
  for the other agents' folders.
- **Network.** With the default shared network the agent can reach services
  on localhost (databases, Docker's TCP API, Jupyter, ...) and send data
  anywhere. Use `--no-network` for untrusted code.
- **Quarantine runs when devenv exits.** If devenv is killed with SIGKILL the
  check doesn't run, and a host tool running *during* the session could load
  a just-planted file. Files you create yourself during a session (e.g.
  VS Code making `.vscode`) are quarantined too. Restore them by renaming.
- **Rejected writes.** Agents can't save permission choices into protected
  files (e.g. Claude's "always allow" in `.claude/settings.local.json`).
  `~/.claude.json` changes (such as folder trust) are discarded, so Claude
  may ask again.
- **Terminal escape sequences** the agent prints go to your real terminal.
  Use a current terminal emulator.
- **`/etc` and `/sys`** are visible read-only.
- **Setuid `bwrap`** (some older distros) disables the Landlock protection,
  because Landlock needs `no_new_privs`.

## Development

```sh
pip install -e '.[dev]'
ruff format . && ruff check . && mypy && pytest
```

Ruff runs with every rule enabled and mypy runs in strict mode. See
[AGENTS.md](AGENTS.md) for the project rules.

`tests/test_integration.py` runs the real `bwrap` and is skipped where
bwrap can't run. It covers hidden secrets, read-only git files, quarantine,
the TIOCSTI block, Landlock and `--no-network`. The seccomp program is
checked with a small BPF interpreter, including the 64-bit ioctl bypass and
the 32-bit/x32 syscall paths.
