# kbtool query — full reference

Search the session's index. `query` and `search` are identical.

```
kbtool query "text" [-k N] [-min f] [-full] [-path sub] [-kind K]
                    [-mode hybrid|vector|keyword|weighted] [-kw-w F] [-vec-w F] [-bundle]
```

All words after the flags form the query (joined with spaces).

## Options

| Option | Default | Description |
|---|---|---|
| `-k N` | 8 | Maximum number of results. |
| `-min f` | 0 | Minimum dense-vector score. Gates the **vector channel only**, never keyword. 0 = off. |
| `-full` | off | Print the full chunk text instead of a 300-char snippet. |
| `-path sub` | — | Filter to chunks whose path contains `sub`. |
| `-kind K` | — | Filter by chunk kind: `code` \| `doc` \| `text`. |
| `-mode M` | `hybrid` | `hybrid` = BM25 + vector rank fusion (RRF); `vector` = dense only; `keyword` = BM25 only; `weighted` = weighted fusion with `-kw-w` / `-vec-w`. |
| `-kw-w F` | 0.6 | Keyword weight for `-mode weighted`. |
| `-vec-w F` | 0.4 | Vector weight for `-mode weighted`. |

## Behavior

- **Through the session's daemon.** The query is an MCP `search_codebase`
  call to the session's daemon (the unix socket on the host, the
  `client.json` endpoint on an attendee's machine), annotated
  `(via daemon: <socket>)`. With no daemon running it fails (the host starts
  it with `kbtool collaborate resume`); it never opens the db itself.
- **Message board is searchable.** Board messages are merged into the index
  (kind `board`) — with an encrypted store they come from the bundle.
- **Encrypted stores** need no key here: the daemon holds it.
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
```

## Related

- Simple example: [query-simple.md](query-simple.md)
- The same search as an MCP tool: `search_codebase` in [mcp-server-config.md](mcp-server-config.md)
- Back to [README](../README.md)
