# ssh-snakehole

Temporary SSH access for Python programs and agents. Run a host, share its code,
execute commands or transfer files, then close access. Both computers connect
outward through Magic Wormhole relays. No port forwarding is needed.

This is a work in progress. We will release on public PyPI once the edge cases
are resolved and we are happy with the library.

Requires CPython 3.11-3.14. For now, install from GitHub:

```sh
python -m pip install git+https://github.com/heetbeet/ssh-snakehole.git
```

This requires Git. Alternatively, from a downloaded or cloned checkout:

```sh
python -m pip install .
```

The current 0.2.1 interface is below. The proposed replacement is described afterward.

On the computer being assisted:

```sh
python -m ssh_snakehole open
```

Read the printed code, such as `42-adroitness-aardvark-adviser-absurd`, to the operator
and leave the terminal open. On the operator's computer:

```sh
python -m ssh_snakehole connect CODE
python -m ssh_snakehole exec ID "COMMAND"
python -m ssh_snakehole close ID
```

`CODE` is the one-use code printed by the host. `connect` asks for a passphrase,
saves an encrypted ticket on the operator's computer and prints its `ID`. Use that
ID for subsequent commands. The passphrase protects the saved ticket locally.
Agents can supply `SSH_SNAKEHOLE_PASSPHRASE` through their secret environment.

The importable API keeps credentials in memory and needs no vault passphrase:

```python
import asyncio
from getpass import getpass
from ssh_snakehole import connect


async def assist(code):
    async with connect(code) as session:
        result = await session.run("COMMAND")
        result.check_returncode()
        print(result.stdout.decode(errors="replace"))
        await session.close_host()


asyncio.run(assist(getpass("Code: ")))
```

`run_argv()` executes an argument list without shell parsing. `put()` and `get()`
transfer files without overwriting by default. Retain `session.ticket` to reconnect
until expiry. Commands interrupted by a lost connection are never replayed.

The host runs as its current account and closes on Ctrl+C or after two hours.
Closing stops ordinary owned commands; intentional file and software changes remain.
Installation uses normal pip, with no service or PATH changes. SSH/SFTP use AsyncSSH;
crypto uses cryptography, PyNaCl and spake2. This is an early library, not independently
security audited. Native macOS and protected admin operation still need validation.

See [the command matrix and offline installation](docs/usage.html) or
[test evidence and limits](docs/implementation.html).

## Proposed connection flow

This is not implemented yet. `connect` will ask for the host's code through hidden
input and keep a foreground connection open for commands. No additional passphrase
will be required. The connection message will read:

```text
Connected to HOST as USER.
Reconnection token: snake1_<token>
Keep this private if you want to reconnect later. It unlocks the saved credentials here.
Access expires after 30 minutes without a completed operation or an explicit keepalive.
Type close to revoke access for everyone on this session; exit disconnects this client.
```

Immediate work uses credentials in memory. An independently generated 256-bit token
will protect the saved credentials for follow-up commands. Neither the token nor
the original pairing code will be saved. Tokens will be supplied through hidden
input or a trusted stdin pipe, rather than command-line arguments or the clipboard.

Agents can already keep the Python `Session` above open, send commands and receive
results without an interactive prompt or saved credentials. `session.exec()` also
provides byte streams for sending input and reading output. The proposed CLI will
support token-based reconnection for separate processes. Agents must select their
session explicitly when using separate CLI commands.

The proposed inactivity policy counts authenticated operation completion, including
nonzero command exits. Long-running operations will send application heartbeats
while their controller is alive; an idle prompt or automatic SSH transport
keepalives will not renew access. Explicit application keepalives will support
longer gaps between commands, within the host's absolute lifetime limit. Host
expiry revokes access for all connections to that session.

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
