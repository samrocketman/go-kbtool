# kbtool kbx — full reference

```
kbtool kbx rekey [-db-key-env NAME | -db-key-file PATH] [-new-key-env NAME | -new-key-file PATH] [FILE]
```

`kbtool kbx rekey` re-encrypts KBX files under a new key. Only the outer
layer is re-encrypted: an encrypted session archive is rewritten record by
record without unpacking it, and the encrypted `kb.db` inside it is left
alone (see below).

| Option | Default | Description |
|---|---|---|
| `-db-key-env NAME` | `$KBTOOL_SECRET` | The current key from environment variable `NAME`. |
| `-db-key-file PATH` | — | The current key from a file (surrounding whitespace trimmed). |
| `-new-key-env NAME` | — | The new key from environment variable `NAME`. |
| `-new-key-file PATH` | — | The new key from a file. |

Without a current key source kbtool asks for it on a terminal; without a new
key source it asks for the new key twice. Without a terminal, a missing key
is an error. The new key must differ from the current one.

## The state dir (no FILE)

Every encrypted file of the state dir shares one key, so they are rekeyed
together:

- `<state>/kb.db`, when it is an encrypted store;
- every finished session, `<state>/sessions/<random>.kbx`.

All of them get one new salt. `kb.db` is rewritten in place. Every session
archive is written under a **new random name** (32 lowercase hex characters)
and the old file is removed once the new one is complete, verified and in
place, so after a rekey no session file keeps its old name. A session's
identity is in its encrypted head, so the names carry nothing.

A rekey that was interrupted can simply be run again with the same keys:

- a file that already opens with the new key is skipped;
- an old-key archive whose head an already rekeyed archive carries is the
  leftover of an interrupted rename and is removed, not rekeyed twice;
- a file that opens with neither key stops the run.

Refused while a session is active or the daemon is running: the daemon holds
the current key in memory and would keep writing with it. Run
`kbtool collaborate finish` (or `kbtool daemon stop`) first. Afterwards,
export `KBTOOL_SECRET` with the new key.

### Inner kb.db

A session archive remembers the key of the encrypted `kb.db` inside it. A
rekey keeps that record, so the inner `kb.db` stays under the key it had.
When the session is resumed, kbtool re-encrypts that `kb.db` with the
current key as it moves it to `<state>/kb.db`, and the remembered key is
never written to disk.

## One file (FILE)

Rekeys one KBX file (an encrypted store or bundle, or a session archive)
outside the state dir, in place under its own name, keeping its file mode. A file inside the
state dir is refused, because the state dir has one key for all its files:

```
kbx rekey: /home/sam/.config/kbtool/sessions/3f9c0e5a7b1d4c2e8a6f0b9d1e7c5a3b.kbx is in the kbtool data dir /home/sam/.config/kbtool, whose files share one key; rekey them all with: kbtool kbx rekey
```

## Related

- Simple example: [kbx-simple.md](kbx-simple.md)
- Encrypted sessions: [collaborate.md](collaborate.md)
- Formats and keys: [cryptography.md](cryptography.md)
- Back to [README](../README.md)
