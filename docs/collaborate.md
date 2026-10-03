# kbtool collaborate — full reference

`kbtool collaborate` runs a session end to end: the session directory,
indexing (host), mTLS, the daemon (host) or enrollment (attendee), putting
sessions away between working days (encrypted when the state dir is), and
`AGENTS_COLLABORATION.md`, the rules the agents follow.

A host's session runs in one of three modes (see [`collaborate host`](#collaborate-host)):

- **local**: no enabled relay. The index and the message board serve only
  this machine, and the board is the agent's own session memory;
- **self-hosted relay**: the daemon hosts its own relay, for a LAN or VPN
  (`kbtool relay self-host start`, [relay.md](relay.md#self-hosted-relay-relay-self-host-startstop-daemon-host));
- **remote relay**: collaborators reach the session through a joined relay
  (`kbtool relay join`, [relay.md](relay.md#joined-relays-relay-join-ls-move-enabledisable-leave-daemon-host)).

A session does not assume other people: enabling a relay and resuming opens
a local session to collaborators later.

```
kbtool collaborate host [-yes] [-encrypt] [-db-key-env NAME | -db-key-file PATH] [-expire 24h]
kbtool collaborate attend [-yes] kb1TOKEN
kbtool collaborate resume [-yes] [-id ID] [-db-key-env NAME | -db-key-file PATH] [-expire 24h] [-relay URL] [kb1TOKEN]
kbtool collaborate finish
```

One session is active at a time: `host`, `attend`, and `resume` of another
session refuse while one is active and ask for `kbtool collaborate finish`.

## Sessions

A session lives in `<state>/sessions/<id>/` (the state dir is
`~/.config/kbtool` unless `KBTOOL_DIR` is set). The ID is the UTC start time
in ISO-8601 basic format plus six random hex characters, for example
`20261002T184700Z_3fa9c1`.

All session files live there, never in the working directory: only
`AGENTS_COLLABORATION.md` is written to the working directory. A session is
refused when the state dir is not absolute (a relative `KBTOOL_DIR`, or no
home directory). `AGENTS_COLLABORATION.md` names no session ID and no path
in the state dir: agents reach the session's files only through kbtool
(`kbtool memory`, `kbtool consensus`, `kbtool deliverables`,
`kbtool session about`, and the board commands, which use the session's seed).
The table is for humans.

| Path | Written by | Purpose |
|---|---|---|
| `.kbtool-seed` | `kbtool board signup` | The agent's board seed (0600, never printed). It sits outside `memory/`, so no memory command can read, export or attach it. |
| `memory/` | the agent, through `kbtool memory` | Private agent memory ([memory.md](memory.md)). |
| `consensus/` | kbtool, from accepted proposals | Documents everyone agrees on, starting with `goals.md` ([memory.md](memory.md#voting-kbtool-consensus-propose--review--vote--status)). |
| `deliverables/` | kbtool, from accepted proposals | The session's results. |
| `consensus.sha256`, `deliverables.sha256` | kbtool | Checksum lists of the two shared directories, regenerated after each background update. |
| `about.json` | the agents, through `kbtool session about` | `{"summary": "two or three words", "participants": ["Human", …]}` for `kbtool session ls`. Checked by `kbtool session validate`. |
| `meta.json` | kbtool | ID, role (`host` or `attendee`), created, last used, finished, working directory, and the host's certificate arguments (reused on renewal). |
| `state/` | `finish` | The session's kbtool state while the session is not running (0700). |
| `previous-state-*.tar.gz` | `host`, `attend`, `resume` | kbtool state found outside any session when the session started, archived instead of deleted. |

`<state>/session.json` names the current session, whether it is active, and
whether the state dir is encrypted. It, `relay.json` and `sessions/` are the
only entries in the state dir that outlive a session: `finish` moves
everything else (`config.json`, certificates and keys, `kb.db`, `board.bin`,
`client.json`, logs, …) into the session's `state/` and `resume` moves it
back.

A session belongs to the working directory it was started in (`meta.json`
`workdir`), where its `AGENTS_COLLABORATION.md` is. `resume` from anywhere
else fails and prints the command to run, for example:

```
collaborate resume: session 20261002T184700Z_3fa9c1 belongs to /home/sam/work (its AGENTS_COLLABORATION.md and the agents' instructions are there); run:
  cd /home/sam/work && kbtool collaborate resume -id 20261002T184700Z_3fa9c1
```

## Encrypted state dir

`kbtool collaborate host -encrypt` keys the whole state dir with one key, and
from then on session.json has `"encrypt": true`:

```json
{"version":1,"current":"20261002T184700Z_3fa9c1","active":true,"encrypt":true}
```

With two finished sessions and one active session, the state dir holds:

| Path | Shape |
|---|---|
| `kb.db` | Encrypted store: the index and the message board ([cryptography.md](cryptography.md)). |
| `sessions/<active id>/` | The active session, plain, for the agents. |
| `sessions/<random>.kbx` | A finished session, encrypted (KBX2), under a random name (32 lowercase hex characters). Its ID, role and the rest come only from its encrypted head. |

- **The key** comes from `-db-key-env NAME`, `-db-key-file PATH` or
  `$KBTOOL_SECRET`. Only `host -encrypt` in a plain state dir may ask for it
  (twice, on a terminal). In an encrypted state dir nothing prompts: `host`,
  `attend`, `resume`, `finish` and `kbtool session ls` fail without a key.
  Commands that only
  talk to the daemon (`board`, `call`, `query`, `status`,
  `session validate` of the active session) need no key, so agents never
  need it.
- **Switching on** cautions that the whole session history is about to be
  encrypted and needs confirmation (`-yes`). Every finished plain session is
  encrypted then: its plain `kb.db` and `board.bin` become one encrypted
  `kb.db`, and the session directory becomes a randomly named
  `sessions/<random>.kbx`.
- **`finish`** moves the state into `state/`, then seals the session directory
  (paths relative to it, as with `tar -C sessions/<id>`) into
  a new randomly named `sessions/<random>.kbx`, reads it back, and removes
  the plain directory.
- **`resume`** finds the archive whose head names the session ID (two
  archives with the same ID are an error), reads its head (the working
  directory check needs only that), extracts it into `sessions/<id>/`, deletes the `.kbx`, and moves
  `state/` back. The archive remembers the key of its inner `kb.db`; when the
  state dir was rekeyed since, the `kb.db` is re-encrypted with the current
  key as it moves into place.
- **`kbtool session ls`** decrypts only the head of each `.kbx`
  ([session.md](session.md)).
- **Session catalog.** Finding a session by ID means reading heads, so
  kbtool keeps a catalog of every archive's head, by file name, size and
  modification time. It loads on first use (one pass over all archives: the
  first `session ls`, `session validate` or `resume` pays that delay) and
  then decrypts only new or changed files. The host daemon keeps its catalog
  for its lifetime and serves it on its unix socket (`kbtool/sessions`) to a
  caller that proves it holds the key with
  `HMAC-SHA256(key, "kbtool session list v1")`; the key itself is never
  sent. Without a daemon, or when it refuses, the command uses its own.
- **Rekeying** is `kbtool kbx rekey` ([kbx.md](kbx.md)). It gives every
  session archive a new random name.
- **Unclean shutdown:** a host daemon that dies without finishing (SIGKILL,
  a crash, power loss) leaves the active session and the state plain on
  disk. While that holds (encrypted state dir, an active host session whose
  plain directory exists, no daemon running), every command except
  `kbtool session validate`, `help` and `version` does nothing and prints:

  ```
  warning: an unclean shutdown left the active encrypted session 20261002T184700Z_3fa9c1 plain in /home/sam/.config/kbtool/sessions/20261002T184700Z_3fa9c1 while the daemon is not running.
  Nothing was done. Check and seal it with:
    kbtool session validate
  ```

  `session validate` (with the key) then checks the session thoroughly and,
  on success, seals it like `finish` and prints how to resume it
  ([session.md](session.md)).

While a session is active, `kbtool board` commands default `-seed-file` to
its `.kbtool-seed`, and `kbtool call board_*` fills in a missing
`"seed"` from it ([board.md](board.md), [call.md](call.md)).

## Confirmation

`host` and `attend` start a new session. They ask first when:

- `AGENTS_COLLABORATION.md` exists in the working directory (it is replaced);
- the state dir holds kbtool state outside any session (it is archived into
  the new session as `previous-state-*.tar.gz`);
- `host -encrypt` is about to encrypt the state dir and its session history.

`resume` asks when `AGENTS_COLLABORATION.md` exists but was not written by
kbtool, and when it would archive loose state. A doc kbtool wrote is
replaced without asking.

`-yes` confirms. On a terminal kbtool asks `continue? [y/N]`; without a
terminal (scripts, agents) and without `-yes` it refuses and exits 1.

## `collaborate host`

| Option | Default | Description |
|---|---|---|
| `-yes` | — | Confirm replacing or encrypting (see above). |
| `-encrypt` | off | Encrypt the whole state dir with one key (see [Encrypted state dir](#encrypted-state-dir)). |
| `-db-key-env NAME`, `-db-key-file PATH` | `$KBTOOL_SECRET` | Where the key comes from. In a plain state dir they need `-encrypt`. |
| `-expire D` | `24h` | Certificate lifetime of a relayed session ([relay.md](relay.md#certificates-in-relay-mode)). |

1. Refuses while a session is active, or a daemon runs in the state dir. With `-encrypt` (or in an encrypted state dir) it gets the key first,
   and the build and the daemon use it.
2. Creates the session and makes it current and active.
3. **Indexes the working directory:**
   - it is a git checkout (`.git` exists): only it;
   - else, if any direct child directory is a git checkout: every child
     directory, git or not (hidden directories and symlinks are skipped);
   - else the working directory itself.

   The sources are recorded in `config.json`, so a bare `kbtool build`
   rebuilds them later and the running daemon picks the new index up without
   a restart ([build.md](build.md)).
4. **Network** ([relay.md](relay.md#certificates-in-relay-mode)), one of:
   - **self-hosted relay**: relays are enabled and self-hosting is on
     (`kbtool relay self-host start`): relay-mode mTLS through the relay the
     daemon hosts in memory, for a LAN or VPN; no joined relay is tried;
   - **remote relay**: relays are enabled and at least one is joined
     (`kbtool relay join`, [relay.md](relay.md)): relay-mode mTLS. The
     daemon tries the joined relays round robin and the session sticks to
     the first that accepts it;
   - **local**: neither (or relays disabled): no certificates, no TCP port,
     no relay connectivity needed.

   The message board is turned on in every case.
5. Starts the daemon. With a relay it prints the enrollment lines as
   `kbtool collaborate attend kb1…`: with a self-hosted relay one per
   address of this machine, each ending in `# via HOST:PORT`; else a single
   line for the relay the session started on. Humans pass a line on
   out of band; agents never post it. A local session prints how to open it
   to collaborators later.
6. Writes `AGENTS_COLLABORATION.md` in the working directory (naming the
   session's relay). A local session's file tells the agent that nobody else
   takes part and that the board is its session memory.

## `collaborate attend`

Takes the `kb1…` line the host's daemon printed: a relay token that names
the relay, the session and the bundle key.

1. Refuses while a session is active; in an encrypted state dir it needs the
   key (so `finish` can encrypt the session). Confirms (see above).
2. Creates the session (role `attendee`), current and active.
3. Enrolls through the relay named in the token: downloads and decrypts the
   bundle, checks the daemon certificate, writes `client.json` and
   `relay.json` ([relay.md](relay.md#clients-1)).
4. Writes `AGENTS_COLLABORATION.md` in the working directory.

If enrollment fails, the new session is removed and any earlier state is
restored.

## `collaborate resume`

Continues the current session, or the one named by `-id` (see
`kbtool session ls`).

| Option | Description |
|---|---|
| `-yes` | Confirm replacing (see above). |
| `-id ID` | Session to resume (default: the current one). |
| `-db-key-env NAME`, `-db-key-file PATH` | Encrypted state dir: where the key comes from (default `$KBTOOL_SECRET`). |
| `-expire D` | Host: lifetime of renewed certificates (default: as when hosting started). |
| `-relay URL` | Host: move the session to this joined relay (see `kbtool relay ls`; the daemon must be stopped, so `finish` first). Attendees need the new enrollment line. |
| `kb1TOKEN` | Attendee: a new enrollment line after the host renewed its certificates. |

1. Refuses while another session is active, and outside the session's working
   directory (printing the `cd … &&` command). When the session is not
   active: decrypts it if it is a `.kbx`, archives loose state, and moves the
   session's `state/` back into the state dir.
2. **Host:** when the daemon is running, nothing else happens (if relays
   were enabled that the session does not use yet, it says to finish and
   resume). Otherwise, before starting the daemon:
   - relays are enabled and the session has no relay session yet (a local
     session, or one hosted before `relay join`/`enable`): kbtool sets up
     relay-mode mTLS, opening the session to collaborators. The daemon picks
     the relay round robin (or uses `-relay`). The board, memory and shared
     files stay;
   - `-relay URL`: the session moves to that joined relay. It keeps its ID
     when the certificates cover the relay host, else it gets new
     certificates and a new session there
     ([relay.md](relay.md#moving-a-session-manual));
   - the session has certificates and the server certificate expires within
     10 minutes: kbtool issues new certificates with the session's original
     `-expire` (a new CA, and a new relay session that stays on its sticky
     relay). After a renewal attendees need
     the new enrollment line. With
     the relay disabled since, it warns instead and the session stays
     local;
   - self-hosting is on and the certificates cover none of this machine's
     addresses (the session was hosted on a remote relay): kbtool issues new
     certificates; the session's remote `relay_url` is kept for when
     self-hosting stops, and attendees need the new enrollment line;
   - a local session with no enabled relay just starts the daemon.
3. **Attendee:** with an enrollment line, enrolls again. Without one, an
   expired client certificate is an error that asks for the new line;
   otherwise kbtool checks the connection (an unreachable host is only a
   warning: the host may not have resumed yet).
4. Rewrites `AGENTS_COLLABORATION.md` in the working directory.

## `collaborate finish`

Also accepted as `collaborate finished`.

1. Stops the daemon, if running. On the host the
   daemon finishes the session itself as it stops (below).
2. Moves the session's state into its `state/`, leaving `relay.json`,
   `session.json` and `sessions/` in the state dir.
3. Marks the session finished. In an encrypted state dir it seals the session
   into a new randomly named `sessions/<random>.kbx` and removes the plain
   directory.
4. Warns when `about.json` does not validate, so the session lists properly.

Stopping the host's daemon any other graceful way (`kbtool daemon stop`,
SIGTERM, SIGINT, an operating system shutdown) finishes the session the same
way, so the session is not left decrypted. `kbtool daemon stop` waits up to two
minutes for that. A crash or power loss cannot finish it; the next `resume`
continues from the plain directory.

With no active session it prints `collaborate: no active session` and exits 0.

## `AGENTS_COLLABORATION.md`

Rendered from a template compiled into kbtool. It gives the agent:

- the session's files (`memory/`, `consensus/`, `deliverables/`, the seed,
  the summary) and the kbtool commands for each, with the path rules. It
  names no session ID and no path in the kbtool state dir;
- first steps: check the connection, `kbtool board signup`, read `system#0`,
  catch up on system messages, introduce itself, `kbtool session about`;
- the stderr notices (system and steering messages, background updates,
  votes awaited) and how to ask for an index rebuild (a human action on the
  host: through the humans' call, or the board's `index` thread);
- goals: agreed first, by everyone, as `consensus/goals.md`;
- agreeing on files: drafting in memory, `kbtool consensus propose`,
  `review`, `vote`, the voting rules and `-host-accepted`;
- the communication protocol between humans and agents, board conventions,
  confirmation rules, secrets;
- for the host only, what is indexed, how rebuild requests reach the host's
  human, and that its agent is the session host's agent.

Its first line starts with `<!-- kbtool collaboration session`, which is how
`resume` and new sessions tell a doc kbtool wrote from someone else's file.

## Related

- Simple example: [collaborate-simple.md](collaborate-simple.md)
- Listing and validating sessions: [session.md](session.md)
- Rekeying an encrypted state dir: [kbx.md](kbx.md)
- Relays: [relay.md](relay.md)
- The message board: [message-board.md](message-board.md), [board.md](board.md)
- State dir files: [client-server-config.md](client-server-config.md)
- Back to [README](../README.md)
