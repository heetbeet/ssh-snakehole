# ssh-snakehole

Temporary SSH access through a one-use invitation. Both computers connect outward,
then try UDP hole punching with ICE. SSH uses a reliable WebRTC data channel when
that works and a relay otherwise. No port forwarding or SSH daemon is required.

This is a work in progress. Install from GitHub or a checkout; public PyPI releases
will wait until the remaining edge cases are resolved. Requires CPython 3.11-3.14;
interactive Windows hosts use ConPTY on Windows 10 1809 or later.

```sh
python -m pip install git+https://github.com/heetbeet/ssh-snakehole.git
# Or from a downloaded or cloned checkout:
python -m pip install .
```

## Open a remote shell

On the computer being assisted:

```sh
python -m ssh_snakehole open
```

Read its one-use CODE to the operator and leave that terminal open. The operator runs:

```sh
python -m ssh_snakehole connect CODE
```

This opens the remote account's shell: PowerShell on Windows, the user's shell on
Unix. Its prompt, working directory, variables, interactive Python, colors and
terminal resizing work through a real SSH PTY. Ctrl+C reaches the remote program.
Type `exit` to disconnect. Host Ctrl+C revokes access immediately.

Before opening the shell, `connect` prints a reconnection token. Keep it if you want
to reconnect later. The invitation CODE is consumed; the new token unlocks encrypted
credentials saved on the operator's computer. Neither CODE nor token is stored as plaintext.

## Agent commands

Exchange CODE without opening a terminal, then use the returned token:

```sh
python -m ssh_snakehole pair CODE
# Prints: snake1_<token>
python -m ssh_snakehole exec --token TOKEN "COMMAND"
python -m ssh_snakehole resume --token TOKEN
python -m ssh_snakehole put --token TOKEN local-file remote-file
python -m ssh_snakehole get --token TOKEN remote-file local-file
python -m ssh_snakehole close --token TOKEN
```

`exec` streams stdout, stderr and piped stdin, and returns the remote shell's exit
status. Each `exec` starts a separate shell; use `resume` or the Python API's
`terminal()` for persistent shell state. Transfers refuse overwrites unless
`--overwrite` is supplied. `close` revokes every controller sharing this host session
and removes the local ticket. Separate `open` sessions are independent.

CODE can be passed directly on the command line. It cannot be reused after pairing,
but someone who obtains it before redemption could connect first. The reconnection
token stays usable while access is open, so arguments containing it can be a risk
in shell history, process listings or tool logs. Omit CODE or `--token` for hidden
input, or use `--code-stdin` / `--token-stdin` from a trusted runner. A token line
on stdin may be followed by command input for `exec`.

`status --token TOKEN` shows saved host information; it does not check online
availability. `forget --token TOKEN` deletes the local ticket without closing the
host. Another operator computer needs both token and encrypted ticket.

## Long-running work

Commands, open interactive shells and open file transfers pause the inactivity
timer. A fresh 30 minutes starts after the last operation finishes or disconnects,
including nonzero exits. A quiet Python REPL or long command stays connected.
Idle SSH connections without active work and automatic transport keepalives do
not renew access.

Between agent commands, an owned foreground subprocess can renew access every
20 minutes:

```sh
python -m ssh_snakehole keepalive --token TOKEN --interval 1200
```

Stop it when finished. `keepalive` without an interval sends one renewal.
`exec --timeout SECONDS` opts into a command limit. Host `open --lifetime SECONDS`
sets a hard limit which can interrupt active work. Neither limit is imposed by default.
Invitations expire after ten minutes; first SSH authentication must follow pairing
within two minutes, including when using `pair`.

## Python API

The API keeps credentials in memory and needs no saved ticket or token:

```python
from ssh_snakehole import connect


async def assist(code):
    async with connect(code) as session:
        result = await session.run("COMMAND")
        result.check_returncode()
        print(result.stdout.decode(errors="replace"))
        await session.run_argv(["python", "--version"])
        await session.close_host()
```

Reuse the same `Session` for repeated commands and transfers. `session.exec()`
exposes byte streams for input and output. `session.terminal()` opens the remote
shell with a PTY; pass a command to run an interactive program instead. Its process
supports `send(bytes)`, `stdout.read(32768)`, `resize(columns, rows)` and `wait()`.
PTY stdout and stderr are combined by the operating system, as with normal SSH.
Terminal input is UTF-8 on Windows. Use a UTF-8 locale on Unix when connecting
from Windows. SSH carries bytes rather than negotiating an encoding; the API's
Unix PTYs and every platform's `exec` streams preserve bytes, including Latin-1.
Colors and full-screen programs use your terminal's VT support and `TERM` value.
Use a current terminal, such as Windows Terminal. Fonts still determine which
Unicode characters can be displayed.
Captured `run()` output defaults to 8 MiB. Retain `session.ticket` for reconnection;
`await session.keepalive()` renews inactivity without a shell command.

## Routing and recovery

The connection displays `direct-udp` or `relay`. Some NATs and firewalls prevent
UDP punching; relay fallback remains available. A reachable Transit relay is
required for initial negotiation even when SSH later travels directly. Setup can
take several seconds; reuse a Python Session for repeated work.

Secure relays verify against certifi's Mozilla CA bundle. Set `SSL_CERT_FILE`
for an explicitly trusted private CA bundle; certificate verification stays enabled.

Default STUN is `stun.l.google.com:19302`. Before the subcommand, use
`--stun stun:HOST:PORT` to select another server or `--stun none` for local candidates.

If first SSH setup fails after pairing, use `resume --token TOKEN` with the token
already printed. `pair` saves the ticket and prints its token without dialing SSH.
The API attaches accepted tickets to `ConnectTimeout` and `RelayUnavailable`.

An interrupted session does not switch transports or replay commands. Reconnect
with the token or retained ticket; each new connection tries ICE again.
`OutcomeUnknown` means no exit status was confirmed. Inspect effects before retrying;
file publication and remote close can also remain unconfirmed after a lost reply.
Upgrade both peers to 0.5.0 and open a fresh invitation for terminal support.

The package installs no service and edits no PATH or global SSH settings. AsyncSSH
owns SSH and SFTP; aiortc owns the reliable ICE transport; ptyprocess and pywinpty
supply native terminals. Encrypted tickets protect against file copying, but cannot
protect credentials from malware controlling your account. Intentional software
and file changes remain after close. This has not received an independent security audit.

See [the command matrix, native SSH and offline installation](docs/usage.html) and
[test evidence and boundaries](docs/implementation.html).

Development checks:

```sh
python -m pip install -e . -r requirements-dev.txt
npm ci
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m mypy --platform linux
python -m build
python -m unittest discover -s tests -v
python tools/audit_runtime.py
```

Node and Textual are test dependencies only. The terminal tests use xterm's
parser to check cursor replies, a full-screen editor, Unicode paste and resizing.
