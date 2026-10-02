# kbtool call — full reference

Invoke one tool with a JSON argument object — exactly equivalent to an MCP
`tools/call`.

```
kbtool call <tool> ['{json args}'] [-db PATH]
            [-db-key-env NAME | -db-key-file PATH]
```

- `<tool>` is required; `'{json args}'` is optional (defaults to `{}`) and
  must be valid JSON.
- If the daemon is running, the call is executed through it (output annotated
  `(via daemon: <socket>)`); otherwise kbtool opens the db file in-process.
  Board tools work one-shot even without a codebase db.
- Exit status: 0 on success, 1 when the tool reports an error.

## Options

| Option | Default | Description |
|---|---|---|
| `-db PATH` | config db, else `<state>/kb.db` | Db file (used when the daemon is down). |
| `-db-key-env NAME` | — | DB-at-rest key from `$NAME` (encrypted stores). |
| `-db-key-file PATH` | — | DB-at-rest key from file `PATH` (encrypted stores). |

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

### board_* (need `message_board: true`)

`board_signup`, `board_whoami`, `board_sign`, `board_post`, `board_read`,
`board_fetch`, `board_threads`, `board_search`, `board_confirm` — full argument tables and
the seed-security rules in [message-board.md](message-board.md).

## Path trust for the git tools

`git_blame` / `git_log` may read only inside the trusted set: `-live` repos +
indexed git sources + `trusted_paths` (`config.json`). `forbidden_paths`
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
