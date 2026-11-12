# zandbak design

zandbak starts a process inside a
[bubblewrap](https://github.com/containers/bubblewrap) sandbox. The agent may
change the project it was started in and nothing else, and it must not be able
to plant anything that the host later runs on its own.

This document explains the components, how they fit together, and why the
less obvious decisions were made. For usage see `README.md`.

## Threat model

**Assumed hostile:** the agent and everything it runs. A prompt injection in a
dependency's README is enough to turn a helpful agent into an attacker, so
zandbak assumes it will read every file it can reach, open network
connections, and plant files designed to be executed later.

**Trusted:** the user, the kernel, `bwrap`, the Python interpreter, and
zandbak's own code and config. zandbak checks that the last four are out of
the agent's reach.

**Goals**

1. Secrets outside the allowlist cannot be read.
2. Nothing outside the project and allowlisted folders can be changed.
3. The agent cannot get code run on the host *without the user choosing to
   run it*: no git hooks, no agent hooks or MCP servers, no keystrokes typed
   into the user's terminal or desktop.
4. The agent cannot weaken the sandbox for a later run.

**Non-goals.** Making code the agent wrote in the project safe to run. The
project is the agent's output; the user reviews it like any other change.
Network exfiltration is also out of scope while the network is shared
(`--no-network` turns it off).

## Components

```
cli.py ──► config.py ──► plan.py ──► (bwrap) ──► protect.quarantine()
                           │  ├── protect.analyse()
                           │  ├── seccomp.build_filter()
                           │  └── landlock.usable()
                           └── Plan: argv + fds + protections + warnings
```

| Module | Role | Side effects |
|---|---|---|
| `cli.py` | Parses arguments, gathers the environment into a `Request`, launches bwrap, runs the quarantine check | Starts processes, opens descriptors, renames files |
| `config.py` | Loads and validates `config.toml` on top of `defaults.toml` | Reads one file |
| `plan.py` | Turns a `Request` into a `Plan`: the bwrap arguments and what the launcher must prepare | Reads the filesystem only |
| `protect.py` | Decides how each protected path is enforced; renames changed paths after the session | `quarantine()` renames |
| `seccomp.py` | Assembles the terminal-injection BPF filter | None |
| `landlock.py` | Detects and applies Landlock scoping | `restrict_self()` restricts the calling process |

The split keeps every decision in pure code (`config`, `plan`, `protect.analyse`,
`seccomp`). Those can be tested thoroughly without bwrap, and the code with
side effects (`cli`) stays small.

### config.py

The config *is* the security policy, so parsing is strict. Unknown keys are
errors, because a typo such as `protcet = [...]` must not silently fall back
to defaults. Types are checked, and every path is normalised and must stay
relative (no `/`, no `..`). A config that fails to load stops zandbak instead
of being replaced by the defaults.

Rules spanning several fields live in `_validate`. The most important one:
nothing in `ro` or `ephemeral` may sit *inside* an `rw` entry. The agent can
create symlinks in `rw` folders, and zandbak follows host symlinks when
mounting, so a nested entry could be turned into a path to any host file in
the next session. The safe tool for "read-only part of a writable folder" is
`protect`, which never follows symlinks.

Keys the user sets replace the defaults rather than merging with them. That
keeps the effective policy readable from one file (`--dump-config` produces
it).

### plan.py

`build()` produces the command line in a fixed order, because a later bwrap
mount covers an earlier one:

1. **Namespaces:** `--unshare-all` (user, PID, IPC, UTS, cgroup, network),
   `--share-net` unless disabled, `--die-with-parent`, `--cap-drop ALL`.
2. **Environment:** `--clearenv`, then only `env_allow`.
3. **System:** read-only `/usr`, `/etc`, `/opt`, `/sys`; private tmpfs for
   `/tmp`, `/var/tmp`, `/run` and `/dev/shm` (`/run` hides the D-Bus, Docker
   and Wayland sockets; `/dev/shm` stops sharing memory with host programs);
   DNS files re-exposed from `/run`.
4. **Home:** an empty tmpfs, then allowlist entries sorted parents-first.
5. **Project:** `--ro-dir` folders that *contain* the project, the project
   read-write, then the remaining `--ro-dir` folders.
6. **`bwrap_extra_args`** from the config.
7. **Protections**, last, so neither the config nor the project mount can
   cover them.
8. **Terminal filter**, working directory, and the command after `--`, so a
   command starting with `-` can't be read as a bwrap option.

Before step 6, `_check_self` refuses to run if zandbak's own code, its config
path (even if the file doesn't exist yet), the Python interpreter or bwrap
lies inside a writable area. Otherwise the agent could switch the
protections off for the next run.

Descriptors (the seccomp program, the prompt script, ephemeral files) are
represented in the plan as `FdRef` placeholders, and the launcher opens them.
This keeps `build()` free of side effects and makes `--dry-run` exact.

**Project and `--ro-dir` checks.** A project directory may not contain
`$HOME` (that would make home writable) or sit inside a home dot-directory
(those are governed by the allowlist). `--ro-dir` paths may not contain
`$HOME` or sit inside a dot-directory either. Also refused: a path that is
inside the project lexically but resolves outside it, which is the shape of
a symlink planted by the agent in an earlier session.

### protect.py

Some files in writable areas are executed by the host without the user
asking: `.git/config` (`core.fsmonitor` runs on every `git status`), git
hooks, agent settings that define hooks and MCP servers, `.envrc`. For each
protected path, `analyse()` walks its components:

| Found | Action | Why |
|---|---|---|
| Existing directory on the way | Bind it onto itself ("pin") | Mount points can't be renamed or removed, so `mv .git .old; mkdir .git` fails |
| Existing final component, or a non-directory on the way | Read-only bind | A worktree's `.git` *file* could otherwise be repointed |
| Symlink anywhere | Watch, don't mount | Mounting follows the link, so a planted link would expose any host file |
| Missing component | Watch | There is nothing to mount; the agent could create it |

After bwrap exits, `quarantine()` compares watched paths with their startup
`Identity` (device, inode, type, link target). Changed or new ones are
renamed to `<name>.zandbak-quarantine-<time>`. The rename acts on the path
itself, never on a symlink's target. Parents of a watched path were pinned
and could not be swapped. The PID namespace guarantees every sandboxed
process is dead by then, so nothing can race the check.

*Alternative rejected:* creating placeholder files for missing paths and
mounting them read-only. Empty `settings.json` files are invalid JSON and
break the tools, and the placeholders would litter every project.

**Home protections.** `~/.claude` is often a symlink into a dotfiles repo.
Protections are analysed from the *resolved* folder and mounted at the path
the sandbox sees, so they still apply.

### seccomp.py

The sandbox shares the terminal, so `ioctl(TIOCSTI)` could push keystrokes
into the parent shell (CVE-2017-5226). bwrap's `--new-session` fixes this,
but it detaches the sandbox from job control: Ctrl-C would end the whole
sandbox instead of the running command. A small BPF filter blocks only
`TIOCSTI` and `TIOCLINUX`:

* it compares the **low 32 bits** of the ioctl command, since the kernel
  ignores the high bits (CVE-2019-10063 bypassed a 64-bit comparison);
* it checks every syscall ABI the kernel accepts on that machine (i386 on
  x86_64, arm on aarch64) and refuses all x32 syscalls;
* it refuses syscalls from unknown ABIs.

On other architectures zandbak falls back to `--new-session` and warns.

### landlock.py

With a shared network, the sandbox shares the host's *abstract* UNIX socket
namespace. The X11 server listens there, and desktops that allow
`SI:localuser` accept any process of the user's uid, which means keylogging,
screenshots and fake input. Landlock ABI 6 (Linux 6.12+) can scope abstract
sockets and signals. `restrict_self()` runs between fork and exec of bwrap,
so the whole sandbox inherits it. It needs `no_new_privs`, which would break
a setuid bwrap, so `usable()` turns it off in that case. Without Landlock,
zandbak warns and recommends `--no-network`.

### cli.py

`main()` loads the config, builds the plan, prints warnings, opens the
descriptors and runs bwrap. Signals:

* **SIGINT/SIGQUIT** get a no-op handler while bwrap runs. The terminal sends
  them to the whole foreground process group, and the sandbox should handle
  them. A handler, unlike `SIG_IGN`, is reset by `exec`, so bwrap still
  receives them normally.
* **SIGTERM/SIGHUP** are forwarded so the sandbox ends and the quarantine
  check still runs (for example, when the terminal window is closed).

The quarantine check sits in a `finally` block and runs even when the launch
fails half-way.

### Ephemeral files

`~/.claude.json` is rewritten constantly by Claude Code, but it can also
define MCP servers that run on the host. It is copied in with `--file FD`, so
it becomes a regular file in the home tmpfs. Atomic rename-over still works
inside the sandbox, and nothing is written back.

## Testing

* **Unit tests** cover config validation, every plan rule (ordering, refusals,
  warnings) and protect's analysis and quarantine, including symlink attacks.
* **The seccomp program** runs in a small BPF interpreter in
  `tests/test_seccomp.py` against x86_64, i386, x32, aarch64 and arm inputs.
* **Integration tests** run real bwrap and are skipped where it can't run.
  They cover hidden secrets, read-only git files, quarantine, ephemeral
  copies, TIOCSTI, Landlock against a live abstract socket, `--no-network`,
  argument passing and exit codes.

## Known limits

See "Known limits" in `README.md`. In short: code in the project is untrusted
output; nested git repositories inside the project aren't protected; the
agent can read its own credentials and transcripts from all projects;
quarantine doesn't run if zandbak is SIGKILLed; and a shared network
reaches localhost services.
