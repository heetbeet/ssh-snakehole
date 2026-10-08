# ssh-snakehole

Temporary SSH command and file access for people, Python programs and agents.
Both computers connect outward through Magic Wormhole relays. No port forwarding
or SSH daemon is needed.

This is a work in progress. Public PyPI releases will wait until the edge cases
are resolved and we are happy with the library.

Requires CPython 3.11-3.14. Install from GitHub with Git available:

```sh
python -m pip install git+https://github.com/heetbeet/ssh-snakehole.git
```

Or, from a downloaded or cloned checkout:

```sh
python -m pip install .
```

## Open access

On the computer being assisted:

```sh
python -m ssh_snakehole open
```

Read its one-use code to the operator and leave the terminal open. On the
operator's computer:

```sh
python -m ssh_snakehole connect
```

Enter CODE at the hidden prompt. The connection opens a command prompt and shows:

```text
Connected to HOST as USER.

Reconnection token: snake1_<token>
Keep this private if you want to reconnect later. It unlocks the saved credentials here.

Access expires after 30 minutes of inactivity.
Type close to revoke access; exit disconnects this client.
```

Type remote commands at `snakehole>`. Each runs independently through PowerShell
on Windows or /bin/sh on Unix. Working-directory and environment changes do not
carry between commands. This prompt executes commands without a PTY.

Use `close` when finished. It revokes access for everyone sharing this host session.
`exit`, EOF or operator Ctrl+C disconnects this client and leaves time to reconnect.
Host Ctrl+C revokes access immediately.

## Follow-up commands

These ask for the reconnection token through hidden input:

```sh
python -m ssh_snakehole resume
python -m ssh_snakehole exec "COMMAND"
python -m ssh_snakehole put local-file remote-file
python -m ssh_snakehole get remote-file local-file
python -m ssh_snakehole close
```

The original CODE is consumed. The independently generated token selects exactly
one session and unlocks its encrypted local credentials. Neither secret is saved.
You need both the token and encrypted ticket to reconnect from another computer.
Keep the token out of shell arguments, history, logs and the clipboard.

File transfers refuse overwrites unless `--overwrite` is supplied. `status` shows
saved information without checking online availability; `forget` deletes saved
credentials without revoking remote access.

## Long-running work

Commands and open file transfers pause the host's inactivity timer. A fresh full
30 minutes starts after the last concurrent operation finishes, including commands
with nonzero exits. A quiet command lasting more than 30 minutes is not disconnected
for inactivity. Commands have no default time limit; `exec --timeout SECONDS` opts in.

To keep access open between operations, run this in a foreground subprocess:

```sh
python -m ssh_snakehole keepalive --interval 1200
```

Enter the token once. The process holds it in memory and renews access every
20 minutes. Stop that process when finished; an agent must own and clean up its
keepalive subprocess. `keepalive` without an interval sends one renewal. Normal
authenticated commands such as `echo keepalive` also renew access. Idle SSH sockets
and automatic transport keepalives do not renew it.

An explicit host `open --lifetime SECONDS` sets a hard limit which can interrupt
active work. There is no default hard limit. Unredeemed invitations expire after
ten minutes; first SSH authentication must follow pairing within two minutes.

## Agents and the Python API

The API keeps credentials in memory and needs neither saved tickets nor tokens:

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

Supply `code` from a trusted secret provider. Keep the same `Session` for repeated
commands and transfers. `session.exec()` exposes byte streams for sending input
and receiving output; captured `run()` output defaults to 8 MiB. Retain
`session.ticket` for reconnection. Lost commands are never replayed.
`await session.keepalive()` renews inactivity without launching a command.

For separate CLI processes, use `connect --code-stdin --detach`. Supply CODE through
a dedicated stdin pipe. It prints only the new token on stdout. Follow-up commands
accept `--token-stdin`; the trusted runner supplies the token from memory through
stdin. Do not construct `echo TOKEN | ...` or put a secret literal in a tool call.
The runner must not log secret input or token output.

The package installs no service and makes no PATH edits. It uses AsyncSSH,
cryptography, PyNaCl, spake2 and bcrypt. Encrypted files protect against file copying;
they cannot protect live credentials from malware controlling your account or
reading permitted process memory. Deliberate file/software changes remain after
close. This library has not received an independent security audit.

See [the command matrix, native SSH and offline installation](docs/usage.html) or
[test evidence and boundaries](docs/implementation.html).

Development checks:

```sh
python -m pip install -e . -r requirements-dev.txt
python -m ruff check .
python -m ruff format --check .
python -m mypy
python -m build
python -m unittest discover -s tests -v
python tools/audit_runtime.py
```
