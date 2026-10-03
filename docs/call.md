# kbtool call — full reference

Invoke one tool with a JSON argument object — exactly equivalent to an MCP
`tools/call`.

```
kbtool call <tool> ['{json args}']
```

- `<tool>` is required; `'{json args}'` is optional (defaults to `{}`) and
  must be valid JSON.
- The call goes to the session's running daemon (output annotated
  `(via daemon: <socket>)`): the unix socket on the session host, the
  `client.json` endpoint (the host's daemon through the session's relay) on
  an attendee. With no daemon running it fails; `call` never opens the db or
  board itself.
- Exit status: 0 on success, 1 when the tool reports an error.

## Tools and their arguments

### search_codebase

| Arg | Type | Default | Notes |
|---|---|---|---|
| `q` | string | required | Natural-language, conceptual, or exact-identifier query. |
| `k` | int | 8 | Max results. |
| `path` | string | — | Path substring filter. |
| `kind` | string | — | `code` \| `doc` \| `text` \| `commit` \| `diff`. |
| `min` | number | 0 | Min dense-vector score (gates vector channel only). |
| `full` | bool | false | Full chunk text instead of snippet. |
| `mode` | string | `hybrid` | `hybrid` \| `vector` \| `keyword` \| `weighted`. |
| `weights` | object | 0.6/0.4 | `{"keyword":0.6,"vector":0.4}` for `mode=weighted`. |

### get_chunk

| Arg | Type | Default | Notes |
|---|---|---|---|
| `index` | int | required | Chunk index (as reported by `search_codebase`). |
| `before` | int | 0 | Chunks to include before. |
| `after` | int | 0 | Chunks to include after. |

### list_files

| Arg | Type | Default | Notes |
|---|---|---|---|
| `path` | string | — | Path substring filter. |
| `kind` | string | — | `code` \| `doc` \| `text` \| `commit` \| `diff`. |
| `limit` | int | 200 | Max files. |

### kb_status (disabled by default)

No arguments. Reports sources, chunk count, file count, embedding
dim/backend, keyword-index size.

### git_blame (needs `git_tools: true`)

| Arg | Type | Default | Notes |
|---|---|---|---|
| `file` | string | required | `label/rel` path (as from `search_codebase`) or repo-relative. |
| `start` / `end` | int | whole file | Line range to blame. |
| `repo` | string | inferred | Source label to pick the repo. |
| `limit` | int | 200 | Max blame lines returned. |

### git_log (needs `git_tools: true`)

| Arg | Type | Default | Notes |
|---|---|---|---|
| `repo` | string | single source | Source label or repo path. |
| `path` | string | — | Pathspec to scope the log. |
| `n` | int | 20 (cap 200) | Max commits. |
| `author` | string | — | Author substring filter. |

### board_* (on unless `message_board: false`)

`board_signup`, `board_whoami`, `board_sign`, `board_post`, `board_read`,
`board_fetch`, `board_threads`, `board_search`, `board_confirm`, `board_propose`,
`board_vote`, `board_proposal`, `board_consensus` — full argument tables and
the seed-security rules in [message-board.md](message-board.md).

While a collaboration session is active ([collaborate.md](collaborate.md)),
`kbtool call` fills in a missing `"seed"` for every `board_*` tool except
`board_signup`, from the session directory's `.kbtool-seed` (written by
`kbtool board signup`). An explicit `"seed"` is always used as given.

## Path trust for the git tools

`git_blame` / `git_log` may read only inside the trusted set: indexed git
sources + `trusted_paths` (`config.json`). `forbidden_paths`
always wins. Refused reads return an explanatory error. Details:
[client-server-config.md](client-server-config.md).

## Examples

```sh
kbtool call search_codebase '{"q":"error handling","k":5,"kind":"commit"}'
kbtool call git_blame '{"file":"repoA/pkg/util.go","start":10,"end":40}'
kbtool call board_post '{"thread":"research-auth","kind":"task","text":"Research how tokens refresh.","seed":"<seed>"}'
```

## Related

- Simple example: [call-simple.md](call-simple.md)
- Message board reference: [message-board-simple.md](message-board-simple.md)
- Tool schemas: [tools-simple.md](tools-simple.md)
- Back to [README](../README.md)
