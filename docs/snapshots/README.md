# kbtool snapshot builds

Applies to snapshot builds only (`make release-snapshot` or `go build`).
**All documentation in `docs/snapshots/` is for unreleased debug builds.**
Release builds refuse every command and option described here; what a
release does is documented in [../](../) and the
[top-level README](../../README.md).

Releases work through collaboration sessions only: local, through a
self-hosted relay, or through a public relay. Sessions issue and renew
certificates, start the daemon and index the working directory, so nobody
manages mTLS by hand. Snapshot builds keep the lower-level pieces that
sessions are built from, for developing and debugging kbtool itself:

- index any directories without a session, with every build option
  (including git history);
- run the daemon (or the socket MCP service) without a session;
- issue the mTLS PKI by hand and enroll clients directly;
- run **direct sessions**, where the daemon serves mTLS on all interfaces
  with no relay in between;
- benchmark query latency.

## Getting a snapshot build

```sh
go build -o kbtool .          # every plain go build is a snapshot build
make release-snapshot         # goreleaser snapshot: dist/, for every platform
```

Release binaries are built by goreleaser with `-X main.preRelease=false`.
A release refuses snapshot-only commands with a hint toward the session
equivalent, for example:

```
kbtool: `kbtool mtls` issues certificates by hand; sessions issue and renew them (kbtool collaborate host, kbtool collaborate resume) (snapshot builds only; not in release 0.1.0)
```

`kbtool -h` in a snapshot build prints the release help followed by a
"Snapshot builds only" section.

## A tour without sessions

Index, serve and query on one machine:

```sh
kbtool build -git ./repoA ./repoB    # index two repos, with git history
kbtool daemon start                  # serve the index on the unix socket
kbtool query "token refresh" -kind commit
kbtool daemon stop
```

Share the daemon directly over mTLS (no relay, no session):

```sh
kbtool mtls                          # CA + server + client certificates
kbtool daemon start -http -mtls      # HTTPS on all interfaces (:9876)
# prints:  kbtool client -import https://HOST:PORT/ kb1…
```

Another machine runs the printed line to enroll:

```sh
kbtool client -import https://HOST:PORT/ kb1…
kbtool status
```

Or do the same as a direct session, which keeps the session layout
(`AGENTS_COLLABORATION.md`, memory, consensus, deliverables) without a
relay:

```sh
kbtool collaborate host -ip 192.168.1.10
kbtool collaborate attend https://192.168.1.10:9876/ kb1…   # on the other machine
```

## Commands

Snapshot-only commands:

- [`bench`](bench-simple.md): in-process query benchmark (min/p50/p95/max) against a built index (full options: [bench.md](bench.md))
- [`mtls`](mtls-simple.md): issue the mTLS PKI (CA, server and client certificates) by hand, also in relay mode (full options: [mtls.md](mtls.md))
- [`client`](client-simple.md): enroll this machine with a direct or relayed daemon without a session (full options: [client.md](client.md))

What snapshot builds add to commands that releases also have:

- [`build`](build.md): index directories without a session, with every option (`-git`, chunking, `-kwpath`, `-db`, `-encrypt`)
- [`daemon`](daemon.md): `daemon run | start` without a session, with `-http`, `-mtls`, `-bind`, CRL and `-live` options
- [`mcp`](mcp.md): `mcp serve | start | stop | status`, the daemon as a socket MCP service
- [`collaborate`](collaborate.md): direct sessions (`host -ip/-dns`, `attend`/`resume` with an `https://` address)
- [`relay`](relay.md): relay mode without a session: `mtls` in relay mode, a sessionless daemon behind a relay, `client -import kb1…`
- [`query`](query.md): `-kind commit | diff` over indexed git history
- [`board`](board.md): the board against a sessionless daemon: seed files, `attach -C` / `fetch -o` on ordinary directories, board storage flags

Related: [cryptography in snapshot builds](cryptography.md) (direct mTLS,
hand-issued certificates; everything else is in
[../cryptography.md](../cryptography.md)) ·
[configuration files in snapshot builds](client-server-config.md)
(`config.json` persistence and the `KBTOOL_DB`, `KBTOOL_SOCKET`,
`KBTOOL_BOARD` environment variables)
