ssh-snakehole 0.1.0

Temporary SSH access as an importable Python package. A foreground host shows
a code; an operator redeems it, runs commands and transfers files using actual
SSH/SFTP, and closes access when finished. Both connect outward through Magic
Wormhole's mailbox and Transit relay. The default opens no incoming port and
creates no service, SSH daemon, router change or firewall rule.

Requires existing CPython 3.12.14 or newer, through 3.14. Extra runtime imports are source-only
wsproto 1.3.2 and h11 0.16.0. Crypto and SSH operations are Python code. Windows
process/security calls use ctypes and built-in OS APIs. No native crypto
package, transport executable or SSH client is required.

Experimental: Python crypto is not constant-time; the new SSH implementation
has not had an independent security audit. Windows x64/Python 3.12 and Linux
x64/WSL/Python 3.12 have been exercised locally. macOS and other Python/CPU
cells await CI and native evidence. See docs/implementation.html.

Run from source:
  python -m pip install .
  ssh-snakehole open

Run without permanent installation:
  python ssh-snakehole.pyz open

Operator:
  python ssh-snakehole.pyz connect CODE
  python ssh-snakehole.pyz exec TICKET-ID "COMMAND"
  python ssh-snakehole.pyz put TICKET-ID local-file remote-file
  python ssh-snakehole.pyz get TICKET-ID remote-file local-file
  python ssh-snakehole.pyz close TICKET-ID

connect asks for a passphrase and saves the encrypted accepted ticket BEFORE
trying SSH, so a failed first connection can be retried by ticket ID. The
SSH_SNAKEHOLE_PASSPHRASE environment variable supplies it to an agent. The
library keeps tickets in memory unless explicitly saved. connect CODE --memory
provides a foreground command prompt without saving credentials.

Python API:
  import asyncio
  from ssh_snakehole import open_host, connect

  async def host():
      async with open_host() as access:
          print(access.code, flush=True)
          await access.wait_closed()

  async def operator(code):
      async with connect(code) as session:
          result = await session.run("COMMAND")
          print(result.stdout.decode(errors="replace"))
          await session.close_host()

Session context exit disconnects its SSH connection. Host context exit revokes
access and terminates owned commands. A retained session.ticket reconnects
until the host expires. Commands are never replayed automatically after loss.
Command text uses PowerShell on Windows and /bin/sh on Unix. run_argv() passes
arguments directly. SFTP has account-wide access; put/get use sibling temporary
files and do not overwrite by default. Intentional remote software/file changes
remain after access closes.

Offline and permanent installation:
  Extract ssh-snakehole-0.1.0-offline.zip.
  python offline-install.py
  # Or: python ssh-snakehole.pyz open --install
  # Remove later: ssh-snakehole remove

Installation copies one Python archive and creates the full command name.
Windows updates the user's PATH; open a new terminal. On Unix ensure ~/.local/bin
is on PATH. Existing Python remains required. No background tasks are added.
Removal preserves encrypted tickets; close/forget manages those explicitly.

Normal mode refuses an elevated interpreter. --admin requires an elevated
terminal, Python -I and protected installation: Python/package under Program Files or
Windows on Windows; root-owned and not group/public-writable on Unix. The
convenience per-user installer is for normal user assistance. Unix commands use
a temporary Python pipe watcher for host-death cleanup; macOS native evidence
is still pending. POSIX process groups are not a sandbox against a hostile
same-account operator.

Optional self-hosting:
  python -m ssh_snakehole.relay --bind 127.0.0.1 --state relay.sqlite
  ssh-snakehole --mailbox ws://127.0.0.1:4000/v1 --relay tcp://127.0.0.1:4001 open
Use TLS for internet mailbox deployment. Binary WebSocket Transit is at /transit;
--cert/--key enables TLS on the WebSocket server. Default public Transit uses
TCP port 4001. Networks blocking that port need an explicitly supplied WebSocket
relay. No unverified 443 fallback is selected. Direct listeners are not included.

Build and test:
  python -m unittest discover -s tests -v
  python tools/build.py
Native SSH/SFTP tests use independent clients when available. Reference crypto
and SSH checks in tools/ require requirements-dev.txt, never runtime deps.

Root boot.ps1/boot.sh target a future heetbeet/ssh-snakehole GitHub release.
Those download URLs are NOT published yet. Use the local bundle/source commands
until a release is available. Bootstraps do not download Python or elevate.

See docs/usage.html for the command matrix and docs/implementation.html for
evidence and limits. Specifications start at docs/index.html. Disposable
research remains in ignored docs/temp/.
