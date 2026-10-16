# Connecting to a remote computer

When given a Snakehole invitation CODE to assist another computer, use this
workflow. Run these commands on the operator computer where your tools run.

1. Run `python -m ssh_snakehole pair CODE` once. Capture stdout. On success it
   contains one new secret, `snake1_...`. Do not use `connect` for command automation;
   that opens an interactive terminal.
2. Retain the exact returned token in your private session context or your runner's
   secret store. Keep it available across tool calls. Shell variables disappear
   when a tool starts a fresh shell. Do not save the token in repository files,
   logs or plaintext temporary files. Snakehole saves the encrypted ticket, not
   the token, and cannot recover a lost token.
3. Run the first command within two minutes of pairing:
   `python -m ssh_snakehole exec --token TOKEN "COMMAND"`.
   Replace TOKEN with the returned `snake1_...` secret, never the invitation CODE.
4. Use that same token for every subsequent `exec`, `put`, `get`, `keepalive` and
   `close`. Run them under the same operator account on the same computer, where
   the encrypted ticket was saved. Each `exec` starts a fresh remote shell, so use
   explicit working directories or combine commands when they share shell state.
5. When the assistance is finished, run
   `python -m ssh_snakehole close --token TOKEN` to revoke access and delete the
   local ticket. Discard the token after successful closure.

The invitation CODE is consumed by pairing. Do not try it again or pass it to
follow-up commands. If pairing succeeded but SSH setup fails, retry a safe command
with the token. Do not replay a command whose effects are unknown without checking
the remote state first. If the token is lost, a fresh host invitation is required.

For a trusted runner, prefer `--token-stdin` and send the token plus a newline on
stdin, instead of exposing it in command arguments. `exec` accepts command input
after that first line. Do not print the token in progress reports or final answers.

Active commands and terminals pause the 30-minute inactivity timer. For long gaps
between commands, own a foreground
`python -m ssh_snakehole keepalive --token TOKEN --interval 1200` process and stop
it when finished. No keepalive is needed while a long command is still running.

If using the Python API instead of the CLI, retain a single `Session` from
`connect(CODE)` in memory and reuse it. This API path needs no CLI token.
