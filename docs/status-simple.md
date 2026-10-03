# kbtool status — quick start

Show the whole local state: db, config, tool options, path trust, network,
relay, message board, and whether the session's daemon is running.

```sh
kbtool status
```

Example (a session host using the self-hosted relay):

```
db: /home/you/.config/kbtool/kb.db (1520.3 KB)
config: /home/you/.config/kbtool/config.json
  sources=[/home/you/work/repoA] git=false live=false liveRepos=[]
  dim=1024 chunk=48 overlap=12 maxKB=512 kwPath=on db=… updated=…
tool options: git_tools=false message_board=true disable_tools=[kb_status, board_sign]
disabled tools: kb_status, board_sign, git_blame, git_log
path trust:   trusted_paths=[] (absent)  forbidden_paths=[] (absent)
network:  https=false mtls=true bind=:9876 crl=crl.pem (exists=false, refresh=false)
relay:    session 3f9c… on the self-hosted relay (relays enabled, 0 joined, self-hosting)
client:   this host's CLI uses the daemon's unix socket only (remote clients enroll with the line the daemon prints)
board:    3 threads, 12 messages, 2 agents
daemon: running (pid 12345), socket /home/you/.config/kbtool/daemon.sock
```

Useful for answering: *is my daemon up? which tools are enabled? which relay
does the session use?* On an attendee, status instead shows the host's
daemon it reaches through the session's relay, and that daemon's enabled
tools.

Full reference: [status.md](status.md) · back to [README](../README.md)
