# kbtool status — quick start

Show the whole local state: db, config, tool options, path trust, network,
client endpoint, message board, and which services are running.

```sh
kbtool status
```

Example:

```
db: /home/you/.config/kbtool/kb.db (1520.3 KB)
config: /home/you/.config/kbtool/config.json
  sources=[/home/you/repos/repoA] git=true live=true liveRepos=[/home/you/repos/repoA]
  dim=1024 chunk=48 overlap=12 maxKB=512 kwPath=on db=… updated=…
tool options: git_tools=true message_board=true disable_tools=[kb_status, board_sign]
disabled tools: kb_status, board_sign
path trust:   trusted_paths=[]  forbidden_paths=[]
network:  http=true mtls=true insecure=false bind=kb.example.net:9876 crl=… (exists=false, refresh=false)
client:   https://kb.example.net:9876 (mtls)  (/home/you/.config/kbtool/client.json)
board:    3 threads, 12 messages, 2 agents
daemon: running (pid 12345), socket /home/you/.config/kbtool/daemon.sock
mcp: stopped
```

Useful for answering: *is my daemon up? which tools are enabled? where does
the CLI connect?*

Full reference: [status.md](status.md) · back to [README](../README.md)
