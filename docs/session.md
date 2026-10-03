# kbtool session — full reference

```
kbtool session ls [-a]
kbtool session validate [-id ID] [-db-key-env NAME | -db-key-file PATH]
kbtool session about [-summary "TWO OR THREE WORDS"] [-participant NAME]... [-clear-participants]
```

`sessions` is accepted for `session`, and `list` for `ls`. Sessions are
created by `kbtool collaborate host|attend` ([collaborate.md](collaborate.md)).

## `session ls`

Lists every session in `<state>/sessions/`, most recently used first: plain
directories and encrypted `.kbx` files. Of an encrypted session only the
head record is decrypted (its `meta.json` and `about.json`); the rest of the
archive, including the board seed, is never decrypted or unpacked. The file
names are random and ignored: the session ID, role, dates, summary and
participants all come from the encrypted head. A `.kbx` whose head cannot be
read is listed with `?` as its ID and the reason as its summary.

`session ls` fails without `$KBTOOL_SECRET` in an encrypted state dir, and
whenever `sessions/` holds a `.kbx`. Heads are read through a catalog that
loads on first use, so the first listing takes longer; with the host daemon
running, its catalog answers ([collaborate.md](collaborate.md)).

| Column | Source |
|---|---|
| marker | `*` for the current session (`session.json`). |
| `SESSION` | The session ID: the directory name, or the ID in an encrypted head (`?` when the head cannot be read). |
| `LAST USED` | `meta.json` `last_used` (updated by host, attend, resume and finish), in local time; the ID's timestamp when `meta.json` is unreadable. |
| `ROLE` | `host` or `attendee` from `meta.json`, for an encrypted session the one in its head (`?` when unreadable). |
| `STATE` | `active` for the current, active session; `finished, encrypted` for a `.kbx`; else `finished`. |
| `SUMMARY` | `about.json` `summary`, or `(no summary)`. |
| `PARTICIPANTS` | `about.json` `participants`: the first 3, then `+N more`; `-` when empty. |

| Option | Description |
|---|---|
| `-a` | List every participant instead of the first 3. |

When a list was cut off, a note after the table names `-a`.

## `session about`

Shows the active session's summary and participants (`about.json`, read by
`session ls`) and changes them, so agents never edit `about.json` by path.

| Option | Description |
|---|---|
| `-summary TEXT` | Set the summary; runs of spaces become one space. |
| `-participant NAME` | Add a human taking part (repeatable). A name already listed, compared without case, is not added again. |
| `-clear-participants` | Remove every participant before adding. |

It prints `summary:` and `participants:`, then one `to fix:` line per rule
the result still breaks (the rules are listed under `session validate`).
Changes are written even when something is left to fix.

## `session validate`

Checks the files `session ls` reads, for the current session or `-id ID`
(the ID may also be given as the only argument). The active session needs no
key. For an encrypted session (the `.kbx` whose head names the ID) it checks
the head's `meta.json` and `about.json` and needs the key (`$KBTOOL_SECRET`,
`-db-key-env` or `-db-key-file`). Prints
`session ID: ok`, or every problem followed by the path of `about.json`, and
exits 1 when there are problems. It also notes when `consensus/goals.md` is
not written yet (not a failure).

Checked:

- the session ID format and that its directory exists;
- `meta.json` (written by kbtool) parses and describes this session;
- `memory/`, `consensus/` and `deliverables/` exist;
- `about.json`, strictly:
  - exactly the fields `summary` and `participants` (unknown fields and
    trailing data are errors);
  - `summary`: 2 or 3 words separated by single spaces, each at most 32
    characters, no control characters;
  - `participants`: 1 to 100 names of the humans taking part, each at most 64
    characters, no leading or trailing spaces, no control characters, no
    duplicates (case-insensitive).

`collaborate finish` runs the same check and warns about problems.

### After an unclean shutdown

When the host daemon of an encrypted state dir died without sealing the
active session (see "Unclean shutdown" in [collaborate.md](collaborate.md)),
every other command refuses and `session validate` does more. It needs
`$KBTOOL_SECRET` (or `-db-key-env NAME` / `-db-key-file PATH`) and:

1. removes leftovers of interrupted work: `sessions/*.kbx.tmp` and
   `*.rekey` files, `.<id>.extract` directories, and the stale `daemon` and
   `mcp` pid files and sockets;
2. if an archive whose head names the session exists, verifies, and no
   state is loose (finish
   was interrupted after sealing), removes the plain directory and marks the
   session finished;
3. otherwise checks the session files as above (problems are printed as
   warnings, since `finish` seals regardless) and the state, which must be
   sound to seal:
   - `kb.db` is encrypted (KBX1), opens with the key, and its index and
     message board parse;
   - no plain `board.bin` is left;
   - `config.json` parses and the certificates parse;
   - neither an archive of this session nor `sessions/<id>/state/` exists
     yet;
4. on failure prints every problem, leaves everything as it was and exits 1;
5. on success seals the session like `kbtool collaborate finish`, so it is no
   longer active, and prints how to resume it:

```
session 20261002T184700Z_3fa9c1: ok; sealed into /home/sam/.config/kbtool/sessions/3f9c0e5a7b1d4c2e8a6f0b9d1e7c5a3b.kbx
resume it with:
  cd /home/sam/work && kbtool collaborate resume -id 20261002T184700Z_3fa9c1
```

## Related

- Simple example: [session-simple.md](session-simple.md)
- Sessions and their files: [collaborate.md](collaborate.md)
- Back to [README](../README.md)
