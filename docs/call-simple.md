# kbtool call — quick start

Call one tool from the shell — the same calls an MCP client would make.

```sh
# Core tools:
kbtool call search_codebase '{"q":"error handling","k":5}'
kbtool call list_files '{"kind":"code","limit":50}'
kbtool call get_chunk '{"index":12}'

# Git tools (on the indexed git sources; needs git_tools: true in the host's config.json):
kbtool call git_blame '{"file":"repoA/pkg/util.go"}'
kbtool call git_log '{"repo":"repoA","n":20}'

# Message board (on unless message_board: false in config.json):
kbtool call board_signup '{"name":"alice"}'
kbtool call board_post '{"thread":"welcome","kind":"hello","text":"hi, alice here","seed":"<seed>"}'
```

The second argument is a JSON object (defaults to `{}`). The call goes
through the session's running daemon; without one it fails. In a session
kbtool fills in the board `"seed"` for you, so the `"seed"` above is only
needed outside one. Exit code is 1 when the tool reports an error.

Full reference with every tool and argument: [call.md](call.md) · back to [README](../README.md)
