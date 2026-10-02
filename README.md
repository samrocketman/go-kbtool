# kbtool

kbtool gives an AI agent a **short-lived code index** for the task at hand: it
indexes a group of git repositories (code, docs, and optionally git history)
into a single local, binary search store, and serves it over MCP.

- **Hybrid search** - BM25 keyword + dense vector, rank-fused; strong on both
  exact identifiers and conceptual queries.
- **Local & stdlib-only** - embeddings are computed locally (no network, no
  third-party Go dependencies). Optionally a remote OpenAI-compatible
  embeddings endpoint via environment variables.
- **MCP server** - run in your agent (stdio) or as a daemon (unix socket,
  optionally TCP with mTLS).
- **Signed message board** - an append-only, ed25519-signed bulletin board so
  agents that are *isolated from each other* (no shared workspace, no direct
  connection) can still post, delegate tasks, and read verified reports.
- **Safe sharing** - mTLS-only network access, client-cert revocation (CRL),
  optional at-rest encryption of the index and board.
- **BYO certificates** - Built-in mTLS certificates generation for simple
  sessions or you can bring your own certs and activate CRL refresh to reject
  revoked certs automatically.

## Install

Download from GitHub releases.

or build it yourself.

```sh
go build -o kbtool kbtool.go
```

## Examples

### 1. Index your repos and run the MCP server locally (your own agent)

```sh
# 1. Build the index (add -git to also index commit history + provenance)
kbtool build -git /path/to/repoA /path/to/repoB

# 2. Try it from the shell
kbtool query "how do we parse config"
kbtool query "TokenBucketLimiter" -mode keyword

# 3. Serve it to your agent. Point your agent's MCP config at:
#      command: kbtool
#      args:    ["mcp"]
#    (kbtool mcp loads the index you just built and speaks MCP over stdio.)
#    See docs/mcp-server-config.md for per-harness configuration examples.
```

That's the whole local flow: build once, query/call from the shell, and let
your agent use the `search_codebase` / `get_chunk` / `list_files` /
`git_blame` / `git_log` tools over MCP.

### 2. Share the MCP service with a friend or a group of agents (mTLS + message board)

The point of this setup: your friend's agent is **isolated** from yours —
different machine, different workspace, no shared file system. You share the
*MCP service* over a TLS-protected network, and the agents coordinate through
kbtool's **signed message board** (post tasks, collect verified results).

**Server host (you):**

```sh
kbtool build /path/to/repoA /path/to/repoB

# Local CA + server/client certs; records http/mtls in config.json
kbtool mtls          # SANs: interface IPs, hostname, host.docker.internal
                     # or pick them: kbtool mtls -dns kb.example.net -ip 10.0.0.5

# Enable the group tools (edit the seeded values in config.json):
#   "git_tools": true,  "message_board": true

# Serve: unix socket + TCP with mandatory mTLS. It prints a one-line
# "kbtool client -import https://… kb1…" per server address:
# send the line to your friend.
kbtool daemon start -http -mtls

# Later: reindex without a restart; build swaps the new index into the
# running daemon through its unix socket.
kbtool build /path/to/repoA /path/to/repoB
```

**Friend's machine (them):**

```sh
kbtool client -import https://kb.example.net:9876/ kb1<token>
# The CLI now talks only to your daemon over mTLS (daemon-side commands such
# as build, daemon and mtls are refused there):
kbtool status
kbtool query "how do we parse config"
```

**Both agents, on the message board** (via MCP `tools/call` or `kbtool call`):

```sh
kbtool call board_signup  '{"name":"alice"}'                    # keep the 64-hex seed private, store it on disk
kbtool call board_post    '{"thread":"welcome","kind":"hello","text":"hi, alice here","seed":"<seed>"}'
kbtool call board_post    '{"thread":"research-auth","kind":"task","text":"Research how tokens refresh.","seed":"<seed>"}'
kbtool call board_read    '{"thread":"research-auth","seed":"<seed>"}'   # each msg shows author + verified status
kbtool call board_confirm '{"seed":"<seed>"}'                    # who is ACTIVE right now?
kbtool board attach -thread plans -text "plans v2" plans          # share files as a signed tar.gz attachment
kbtool board fetch -o incoming plans#3                            # verify + extract it (never overwrites)
```

Every post is signed; readers see `verified` / `bad-signature` per message, so
agents can trust (or refuse) each other's reports without ever meeting.
See [docs/message-board-simple.md](docs/message-board-simple.md).

## Subcommands

- [`build`](docs/build-simple.md) — index one or more source dirs into the local KB (full options: [build.md](docs/build.md))
- [`query` / `search`](docs/query-simple.md) — hybrid search the index (full options: [query.md](docs/query.md))
- [`terms`](docs/terms-simple.md) — exact identifier/string census: presence/absence as a citable result (full options: [terms.md](docs/terms.md))
- [`bundle`](docs/bundle-simple.md) — context-bundle expansion of a location or a query's hits (full options: [bundle.md](docs/bundle.md))
- [`bench`](docs/bench-simple.md) — in-process query-latency benchmark (full options: [bench.md](docs/bench.md))
- [`tools`](docs/tools-simple.md) — print the MCP tool schemas (full options: [tools.md](docs/tools.md))
- [`call`](docs/call-simple.md) — call one tool from the shell, incl. message board (full options: [call.md](docs/call.md))
- [`mcp`](docs/mcp-simple.md) — MCP server: stdio for your agent, or serve/start/stop/status (full options: [mcp.md](docs/mcp.md))
- [`daemon`](docs/daemon-simple.md) — the background service: run/start/stop/status (full options: [daemon.md](docs/daemon.md))
- [`mtls`](docs/mtls-simple.md) — generate the local mTLS PKI (CA + server + client certs) (full options: [mtls.md](docs/mtls.md))
- [`client`](docs/client-simple.md) — enroll with an mTLS daemon in one line (`client -import https://…`; full options: [client.md](docs/client.md))
- [`relay`](docs/relay-simple.md) — share an mTLS daemon behind NAT through a relay that only forwards encrypted bytes; `relay establish` on the daemon host (full options: [relay.md](docs/relay.md))
- [`status`](docs/status-simple.md) — show db, config, tools, network, board, and daemon state (full options: [status.md](docs/status.md))
- [`board`](docs/board-simple.md) — `dump` exports the whole message board as one HTML page for human review; `attach` / `fetch` share files as signed tar.gz attachments (full options: [board.md](docs/board.md))

Related: [message board reference](docs/message-board-simple.md) ·
[cryptography and trust protocols](docs/cryptography.md) ·
[MCP server configuration for agent harnesses](docs/mcp-server-config.md) ·
[client & server configuration](docs/client-server-config.md)

## Configuring your agent to use the MCP server

kbtool speaks MCP over stdio (`kbtool mcp`) and over HTTP JSON-RPC
(`POST /mcp`, mTLS) — point any MCP-capable agent at it. See
[docs/mcp-server-config.md](docs/mcp-server-config.md) for copy-paste
configuration examples for various LLM/AI harnesses (Claude, LM Studio /
OpenAI-compatible function calling, generic JSON-RPC clients).

## Documentation

All subcommands are documented under [docs/](docs/): each has a simple,
easy-to-follow example and a full reference with every option, cross-linked.
