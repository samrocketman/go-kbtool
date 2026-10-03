# kbtool collaborate — quick start

Run a collaboration session: several humans, each with their own AI agent,
share one code index and one signed message board. kbtool sets up the
session directory, mTLS, the daemon, and an `AGENTS_COLLABORATION.md` your
agent follows.

**Host (indexes the code and runs the daemon):**

```sh
kbtool relay join https://RELAY:9876/   # once ([relay-simple.md](relay-simple.md))
cd ~/work                               # a git checkout, or a directory of checkouts
kbtool collaborate host
# prints:
#   kbtool collaborate attend kb1…
```

On a LAN or VPN, `kbtool relay self-host start` instead of `relay join` lets
the daemon host its own relay; it prints one line per address of this machine.

Pass the line to the other humans out of band (a call, a chat). Without a
relay (none joined and no self-hosting, or `kbtool relay disable`) the session is local: just you
and your agent, with the index and the board as its session memory, and no
network setup. To invite others later: `kbtool relay join …` (or
`kbtool relay enable`), then `kbtool collaborate finish` and
`kbtool collaborate resume`.

**Everyone else:**

```sh
cd ~/work
kbtool collaborate attend kb1…
```

**Then tell your agent:** "read AGENTS_COLLABORATION.md and follow it". It
signs up with `kbtool board signup NAME` (the seed is stored in the session,
never printed), reads the board's guide, and agrees on
`consensus/goals.md` with the others.

**End of the day, and the next morning:**

```sh
kbtool collaborate finish     # host: stops the daemon; state goes into the session
kbtool collaborate resume     # host: restarts (renews expired certificates, opens a local session once a relay is enabled); run it in ~/work
```

`kbtool daemon stop` (or shutting the computer down) also finishes the host's
session. One session is active at a time: finish it before starting another.

If the host's certificates were renewed, attendees run
`kbtool collaborate resume <new line>`; otherwise a plain
`kbtool collaborate resume` reconnects.

**Encrypt everything kbtool keeps (index, board, past sessions):**

```sh
export KBTOOL_SECRET='a long passphrase'    # keep it in your password manager
kbtool collaborate host -encrypt            # cautions first; past sessions are encrypted too
```

From then on `finish` seals the session into one encrypted file, and
`resume`, `finish` and `session ls` need `KBTOOL_SECRET` exported. Change the
key with `kbtool kbx rekey` ([kbx-simple.md](kbx-simple.md)). Your agent never
needs the key.

**Past sessions:** `kbtool session ls` ([session-simple.md](session-simple.md)).

Full reference: [collaborate.md](collaborate.md) · back to [README](../README.md)
