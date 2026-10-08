# ssh-snakehole

Temporary SSH access for Python programs and agents. Run a host, share its code,
execute commands or transfer files, then close access. Both computers connect
outward through Magic Wormhole relays. No port forwarding is needed.

Requires CPython 3.11-3.14. Install from GitHub in your usual Python environment:

```sh
python -m pip install https://github.com/heetbeet/ssh-snakehole/archive/refs/heads/master.zip
```

This downloads the current source and installs its dependencies. Git is not required.
The package is not published on public PyPI.

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
from ssh_snakehole import connect


async def assist(code):
    async with connect(code) as session:
        result = await session.run("COMMAND")
        result.check_returncode()
        print(result.stdout.decode(errors="replace"))
        await session.close_host()


asyncio.run(assist(input("Code: ")))
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
