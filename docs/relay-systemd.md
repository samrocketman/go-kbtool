# Running the relay under systemd

How to host `kbtool relay` as a systemd service: one unit file you rarely
change, and one environment file for your customizations. The relay keeps its
CA in memory and rotates it on its own, so the service needs no certificates
and almost no state (only its pid file).

## What the relay supports

- `kbtool relay run` stays in the foreground and logs to stderr, so journald
  picks up the logs.
- **Readiness:** when systemd sets `NOTIFY_SOCKET`, the relay reports
  `READY=1` once it is listening, a status line after every CA rotation, and
  `STOPPING=1` on shutdown. Use `Type=notify`.
- **Signals:** `SIGTERM` stops it gracefully; `SIGHUP` rotates the CA at once
  (or reloads the operator certificate from disk, see below), which is what
  `systemctl reload` sends.
- **Configuration from the environment.** Flags win over the environment, and
  the environment wins over `config.json`:

  | Variable | Default | Meaning |
  |---|---|---|
  | `KBTOOL_RELAY_PORT` | `9876` | Listen port on all interfaces. |
  | `KBTOOL_RELAY_BIND` | — | Full listen address `HOST:PORT`, e.g. `10.0.0.5:9876`. Wins over `KBTOOL_RELAY_PORT`. |
  | `KBTOOL_RELAY_TOKEN` | — (open) | Daemons must present this token to register. Keep it in the environment file, not on the command line. |
  | `KBTOOL_RELAY_ROTATE` | `12h` | How often the in-memory CA is replaced (Go duration). |
  | `KBTOOL_RELAY_CA_TTL` | `24h` | How long each CA is valid. Must be longer than the rotation interval. |
  | `KBTOOL_RELAY_MAX_SESSIONS` | `5000` | Most daemon sessions registered at once; more registrations get 503. Also config `relay_max_sessions`. |
  | `KBTOOL_RELAY_CONN_RATE` | `20` | New connections per second per source IP (burst 5×). `0` turns the limit off. |
  | `KBTOOL_RELAY_REGISTER_RATE` | `30` | Registrations per minute per source IP (burst 10). `0` turns the limit off. |
  | `KBTOOL_RELAY_CERT` | — | Serve this certificate chain (PEM) instead of the in-memory CA. Needs `KBTOOL_RELAY_KEY`. |
  | `KBTOOL_RELAY_KEY` | — | Private key (PEM) for `KBTOOL_RELAY_CERT`. |
  | `KBTOOL_DIR` | `~/.config/kbtool` | State dir; only the pid file is written there. |

  An invalid value stops the relay at startup with the variable named.

## 1. Install the binary

```sh
sudo install -m 0755 kbtool /usr/local/bin/kbtool
```

## 2. The environment file (your customizations)

`/etc/kbtool/relay.env`, readable by root only, because it holds the token:

```sh
sudo install -d -m 0755 /etc/kbtool
sudo install -m 0600 /dev/null /etc/kbtool/relay.env
sudoedit /etc/kbtool/relay.env
```

```sh
# /etc/kbtool/relay.env: kbtool relay settings (KEY=value, no quotes needed)

# Port on all interfaces (default 9876). Or pin an address with KBTOOL_RELAY_BIND.
KBTOOL_RELAY_PORT=9876
#KBTOOL_RELAY_BIND=10.0.0.5:9876

# Only daemons that know this token may register. Generate one with:
#   openssl rand -hex 24
KBTOOL_RELAY_TOKEN=change-me

# CA rotation (defaults shown).
#KBTOOL_RELAY_ROTATE=12h
#KBTOOL_RELAY_CA_TTL=24h

# Abuse limits (defaults shown; 0 turns a rate limit off).
#KBTOOL_RELAY_MAX_SESSIONS=5000
#KBTOOL_RELAY_CONN_RATE=20
#KBTOOL_RELAY_REGISTER_RATE=30
```

systemd reads this file as root before dropping privileges, so the service
user never needs to read it itself.

## 3. The unit file

`/etc/systemd/system/kbtool-relay.service`:

```ini
[Unit]
Description=kbtool relay
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/kbtool relay run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=2s

# Customizations live here; the leading "-" makes the file optional.
EnvironmentFile=-/etc/kbtool/relay.env

# A throwaway system user and a private state dir for the pid file.
DynamicUser=yes
StateDirectory=kbtool-relay
Environment=KBTOOL_DIR=%S/kbtool-relay

# Hardening: the relay needs the network and its state dir, nothing else.
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native

# Ports below 1024 (e.g. 443) need this capability:
#AmbientCapabilities=CAP_NET_BIND_SERVICE
#CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
```

`kbtool relay unit [-port N] [-bind HOST:PORT] [-name NAME]` prints this unit
with `ExecStart` set to the binary you run it with:

```sh
kbtool relay unit | sudo tee /etc/systemd/system/kbtool-relay.service
```

Keep the unit generic and put changes in the environment file. For anything
the environment cannot express, use a drop-in instead of editing the unit:
`sudo systemctl edit kbtool-relay` writes
`/etc/systemd/system/kbtool-relay.service.d/override.conf`, for example:

```ini
[Service]
# Listen on 443 instead: allow the low port.
Environment=KBTOOL_RELAY_PORT=443
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
```

### An operator certificate (optional)

On the internet, give the relay a real certificate (for example from your
ACME client) so daemons can verify it with `relay establish … -relay-ca
system` instead of trusting `/ca.crt`. The service user is dynamic, so hand
the files over as credentials in a drop-in:

```ini
[Service]
LoadCredential=relay.crt:/etc/letsencrypt/live/relay.example.net/fullchain.pem
LoadCredential=relay.key:/etc/letsencrypt/live/relay.example.net/privkey.pem
Environment=KBTOOL_RELAY_CERT=%d/relay.crt
Environment=KBTOOL_RELAY_KEY=%d/relay.key
```

After renewing the certificate, `sudo systemctl restart kbtool-relay`
(credentials are copied at start). With an operator certificate there is no
rotation, and `KBTOOL_RELAY_ROTATE` / `KBTOOL_RELAY_CA_TTL` must stay unset.

## 4. Start it

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now kbtool-relay
systemctl status kbtool-relay          # "active (running)" once READY=1 arrived
journalctl -u kbtool-relay -f          # serving on …, CA fingerprint, rotations
```

Open the port in the firewall, e.g. `sudo ufw allow 9876/tcp`.

## Day to day

| Task | Command |
|---|---|
| Change settings | Edit `/etc/kbtool/relay.env`, then `sudo systemctl restart kbtool-relay`. |
| Rotate the CA now | `sudo systemctl reload kbtool-relay` |
| Upgrade kbtool | Replace `/usr/local/bin/kbtool`, then `sudo systemctl restart kbtool-relay`. |
| Logs | `journalctl -u kbtool-relay` |

A restart, a reload or a scheduled rotation creates a new relay CA. Daemons
fetch the CA again on their own (at every registration, and after a failed
certificate check), so nothing needs to be redistributed. Established client
connections survive a rotation, and a restart only interrupts traffic for the
moment the relay is down. Daemons reconnect with jittered backoff and keep their
session ID, so enrolled clients keep working.

## Notes

- Do not run the relay in the same state dir as a kbtool daemon; with
  `StateDirectory=` it gets its own.
- Do not put a TLS-terminating proxy or load balancer in front of the relay:
  it routes client connections by their TLS server name without decrypting
  them. Pass TCP through unchanged.
- `RestrictAddressFamilies` keeps `AF_UNIX` because the readiness
  notification goes over a unix datagram socket.

## Related

- Relay reference: [relay.md](relay.md)
- Quick start: [relay-simple.md](relay-simple.md)
- Back to [README](../README.md)
