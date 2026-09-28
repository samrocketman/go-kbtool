# kbtool query — full reference

Search the local knowledge base. `query` and `search` are identical.

```
kbtool query "text" [-k N] [-min f] [-full] [-path sub] [-kind K]
                    [-mode hybrid|vector|keyword|weighted] [-kw-w F] [-vec-w F]
                    [-db PATH] [-db-key-env NAME | -db-key-file PATH]
```

All words after the flags form the query (joined with spaces).

## Options

| Option | Default | Description |
|---|---|---|
| `-k N` | 8 | Maximum number of results. |
| `-min f` | 0 | Minimum dense-vector score. Gates the **vector channel only**, never keyword. 0 = off. |
| `-full` | off | Print the full chunk text instead of a 300-char snippet. |
| `-path sub` | — | Filter to chunks whose path contains `sub`. |
| `-kind K` | — | Filter by chunk kind: `code` \| `doc` \| `text` \| `commit` \| `diff`. |
| `-mode M` | `hybrid` | `hybrid` = BM25 + vector rank fusion (RRF); `vector` = dense only; `keyword` = BM25 only; `weighted` = weighted fusion with `-kw-w` / `-vec-w`. |
| `-kw-w F` | 0.6 | Keyword weight for `-mode weighted`. |
| `-vec-w F` | 0.4 | Vector weight for `-mode weighted`. |
| `-db PATH` | config db, else `<state>/kb.db` | Db file (used when the daemon is down). |
| `-db-key-env NAME` | — | DB-at-rest key from `$NAME` (encrypted stores). |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH` (encrypted stores). |

## Behavior

- **Daemon first.** When a daemon/mcp service is running and reachable
  (socket or `client.json` endpoint), the query is executed as an MCP
  `search_codebase` call through that service — output is annotated with
  `(via daemon: <socket>)`. Otherwise the db file is opened in-process.
- **Message board is searchable.** Board messages are merged into the index
  (kind `board`) — with an encrypted store they come from the bundle.
- **Encrypted stores.** Key precedence: `-db-key-env` > `-db-key-file` >
  `$KBTOOL_DBKEY` > prompt (TTY). No key for an encrypted store fails
  closed.
- **Output.** Numbered: `path:start-end [kind] score=…` plus a snippet (or
  full text with `-full`). Chunks are 1-based line ranges; the same index
  can be fetched in full via the `get_chunk` tool (`kbtool call get_chunk
  '{"index":N}'`).

## Examples

```sh
kbtool query "how do we parse config"
kbtool query "TokenBucketLimiter" -mode keyword
kbtool query "how do we parse config" -mode vector
kbtool query "auth" -path pkg/auth -kind code -full -k 3
kbtool query "why was this refactored" -kind commit
```

## Related

- Simple example: [query-simple.md](query-simple.md)
- The same search as an MCP tool: `search_codebase` in [mcp-server-config.md](mcp-server-config.md)
- Benchmark search latency: [bench-simple.md](bench-simple.md)
- Back to [README](../README.md)
