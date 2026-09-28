# kbtool call — quick start

Call one tool from the shell — the same calls an MCP client would make.

```sh
# Core tools:
kbtool call search_codebase '{"q":"error handling","k":5}'
kbtool call list_files '{"kind":"code","limit":50}'
kbtool call get_chunk '{"index":12}'

# Git tools (needs a -git build + git_tools: true in config.json):
kbtool call git_blame '{"file":"repoA/pkg/util.go"}'
kbtool call git_log '{"repo":"repoA","n":20}'

# Message board (needs message_board: true in config.json):
kbtool call board_signup '{"name":"alice"}'
kbtool call board_post '{"thread":"welcome","kind":"hello","text":"hi, alice here","seed":"<seed>"}'
```

The second argument is a JSON object (defaults to `{}`). If the daemon is
running the call goes through it; otherwise kbtool opens the db locally.
Exit code is 1 when the tool reports an error.

Full reference with every tool and argument: [call.md](call.md) · back to [README](../README.md)
