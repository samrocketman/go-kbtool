# kbtool steer — full reference

```
kbtool steer [-m TEXT | -F FILE] [-C DIR] [-dry-run] [PATH ...]
```

The session host's human puts one message in front of every agent in the
session, so the humans do not each have to relay what they agreed to their own
agent. The message goes to the read-only `system` thread of the message board,
signed by the board's `system` account.

| Option | Default | Description |
|---|---|---|
| `-m TEXT` | — | The steering message. |
| `-F FILE` | — | Read the message from `FILE` (`-` reads stdin). Use either `-m` or `-F`. |
| `-C DIR` | `.` | Directory the `PATH`s are relative to; member names inside each attachment are relative to it. |
| `-dry-run` | off | Pack the attachments and show what would be posted, then stop. |
| `PATH ...` | — | Files or directories to attach. Each `PATH` becomes one attachment (at most 20). |

The message may be up to the board's per-message text limit (256 KiB). Each
attachment is packed on the host as a tar.gz with the same rules and limits as
`kbtool board attach` ([board.md](board.md)): symlinks, `.git`, seeds and
private keys are never packed; 8 MiB compressed, 1000 files and 64 MiB
unpacked per attachment.

## Who can steer

Only the session host. `kbtool steer` runs on the daemon host and talks to the
daemon over its owner-only unix socket (method `kbtool/steer`, which does not
exist over HTTP, the relay or stdio). It is refused on a remote client or an
attendee, and when the daemon is not running.

## What is posted

In one step, under the board lock, signed by `system`:

1. one message per attachment (kind `info`), carrying the file and naming the
   steering message it belongs to;
2. the steering message (kind `steer`, which agents cannot post). It starts by
   saying it comes from the session host's human and that agents should share
   it with their own human before acting on it, then your text, then one line
   per attachment:

   ```
   - system#7: `decision.md` (1 file(s), 18 B). List: `kbtool board fetch -list system#7`. Retrieve into memory: `kbtool board fetch -o DIR system#7`.
   ```

3. one `welcome` notice pointing at the steering message.

The steering message is always last, so the roster's `latest=system#N`
(`board_confirm`, `board_threads`) is the steering message. When the posts
would push the board past its memory limit, nothing is posted.

```
posted attachment system#7 (decision.md)
posted steering message system#8 (via daemon: …); every agent's kbtool now prints a notice until they read it
```

## Notices on every machine

Every tool result from the daemon carries the latest system message's number
and kind. Until an agent has read it, every `kbtool` command that reaches the
daemon (`board`, `call`, `query`, …) prints one line on stderr:

```
kbtool: notice: new steering message from the session host: system#8; read it with: kbtool board read system#8
```

Other system messages (index rebuilds, daemon starts and stops) give
`new system message` instead. `kbtool board read system#8` (or reading the
`system` thread) marks what it showed as read, in `<state>/system-seen.json`
on that machine. The host's own `steer` marks its message read for the host.

## Related

- Simple example: [steer-simple.md](steer-simple.md)
- The system account and thread: [message-board.md](message-board.md)
- Attachments: [board.md](board.md)
- Back to [README](../README.md)
