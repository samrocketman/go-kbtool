# Cryptography in kbtool

This document describes every piece of cryptography kbtool uses: the
algorithms and their parameters, which keys exist and where they live, the
file and token formats, and how each kind of connection is established and
trusted. It is written for people reviewing or operating kbtool, and it
follows the code in `kbtool.go` (standard library only; no third-party
crypto).

## 1. At a glance

| Purpose | Algorithm | Parameters | Go package |
|---|---|---|---|
| Certificates (team PKI, relay PKI) | ECDSA | P-256, random 159-bit serials | `crypto/ecdsa`, `crypto/x509` |
| Transport security | TLS | 1.2 minimum (1.3 negotiated when both sides can) | `crypto/tls` |
| Encrypted bundles (enrollment, store at rest) | AES-256-GCM | 12-byte random nonce, 16-byte tag | `crypto/aes`, `crypto/cipher` |
| Passphrase to key | PBKDF2-HMAC-SHA256 | 600,000 iterations, 16-byte random salt, 32-byte key | own RFC 2898 code over `crypto/hmac` |
| Message board signatures, relay session proof | Ed25519 | 32-byte seed, 64-byte signature | `crypto/ed25519` |
| Relay registration channel binding | TLS keying-material exporter | label `"kbtool relay register v1"`, 32 bytes (RFC 5705 / RFC 8446 §7.5) | `crypto/tls` |
| Bundle ID derivation | HMAC-SHA256 | key = enrollment key, message `"kbtool bundle id"`, truncated to 16 bytes | `crypto/hmac` |
| Fingerprints, digests, relay session ID | SHA-256 | CA fingerprint as 43-char base64url; attachment and index digests as hex; session ID = first 16 bytes | `crypto/sha256` |
| Secret comparison | constant time | bundle ID, relay token | `crypto/subtle` |
| Randomness | OS CSPRNG | all keys, salts, nonces, serials, session IDs, seeds | `crypto/rand` |

```mermaid
mindmap
  root((kbtool crypto))
    Transport
      TLS 1.2+
      mTLS client certificates
      CRL revocation
      Relay SNI routing
    PKI
      Team CA ECDSA P-256
      Relay CA in memory, rotating
    Bundles KBX1
      PBKDF2-HMAC-SHA256 600k
      AES-256-GCM
      Enrollment bundle
      Encrypted store
    Relay sessions
      Ed25519 session key
      ID from SHA-256 of key and CA expiry
      Signature bound to the TLS exporter
    Board
      Ed25519 identities
      Signed canonical messages
      SHA-256 attachment digests
    Integrity
      Index swap SHA-256
      CA fingerprints
```

## 2. Keys and secrets

Every secret kbtool handles, where it lives, and how long it lives:

| Secret | Created by | Stored | Lifetime |
|---|---|---|---|
| Team CA key `ca.key` | `kbtool mtls` | state dir, mode 0600 | until the next `kbtool mtls` (certificates default to 24h, `-expire`) |
| Server key `server.key` | `kbtool mtls` | state dir, 0600 | same |
| Client key `client.key` | `kbtool mtls` (host), `client -import` (remote) | state dir, 0600 | same as its certificate |
| Enrollment key (16 bytes) | daemon at every boot | memory only; printed inside the `kb1…` token and the daemon log (0600) | until the daemon restarts |
| Relay CA and leaf keys | relay at start and every rotation | memory only | `-ca-ttl` (24h), replaced every `-rotate` (12h) |
| Relay operator certificate key (optional) | operator (`-cert`/`-key`) | operator's file; read at start and on `SIGHUP` | operator-managed |
| Relay session key (Ed25519 seed) | `mtls -relay`, `relay establish` | daemon state dir `relay-session.key`, 0600 | until the next `mtls` (the session it proves expires with the team CA) |
| Relay registration token | operator | `config.json`, or `KBTOOL_RELAY_TOKEN` | operator-managed |
| Store passphrase | operator | memory only; supplied by prompt, `-db-key-env`, `-db-key-file` or `KBTOOL_DBKEY` | per process |
| Board seed (32 bytes) | `board_signup` | returned once to the agent; kbtool keeps only the public key | as long as the agent keeps it |
| Relay session ID (128 bits) | derived: SHA-256(label, session public key, CA expiry) | `config.json`, every client's `client.json` | until the team CA expires or the next `mtls -relay`; **not a secret** (it travels as SNI) |

```mermaid
flowchart TB
  subgraph host["Daemon host state dir"]
    CAK["ca.key (ECDSA P-256)"] -->|signs| SC["server.crt"]
    CAK -->|signs| CC["client.crt (shared by all clients)"]
    CAK -.->|signs CRLs you issue| CRL["crl.pem (optional)"]
  end
  subgraph mem["Daemon memory (per boot)"]
    EK["enrollment key, 16 bytes"] -->|HMAC-SHA256| BID["bundle ID"]
    EK -->|PBKDF2 600k| BK["AES-256 bundle key"]
    PP["store passphrase"] -->|PBKDF2 600k| SK["AES-256 store key"]
  end
  subgraph relay["Relay memory"]
    RCA["relay CA key (24h)"] -->|signs| RL["relay leaf"]
  end
  subgraph sess["Daemon host: relay session"]
    RSK["relay-session.key (Ed25519)"] -->|"SHA-256 with ca.crt NotAfter"| SID["session ID"]
    RSK -->|"signs each registration"| REG["registration proof"]
  end
  subgraph agent["Each agent"]
    SEED["board seed, 32 bytes"] -->|Ed25519| PUB["public key on the board"]
  end
  EK -. "kb1 token" .-> client(("remote client"))
  BK -. "decrypts bundle with ca.crt, client.crt, client.key" .-> client
```

## 3. Randomness

All secrets and unique values come from `crypto/rand` (the operating system's
CSPRNG): ECDSA keys, certificate serials (uniform below 2^159, as RFC 5280
allows), the 16-byte enrollment key, PBKDF2 salts, GCM nonces, relay session
keys, relay connection IDs, and board seeds. The only use of `math/rand` is
the jitter on the daemon's relay reconnect delay, which protects nothing.

## 4. The team PKI (`kbtool mtls`)

`kbtool mtls` creates a private certificate authority for one daemon and its
clients. Nothing is signed by a public CA.

```mermaid
flowchart LR
  A["kbtool mtls [-ip …] [-dns …] [-expire 24h]"] --> B["generate CA key (P-256)"]
  B --> C["self-sign CA certificate"]
  C --> D["generate server key, sign server.crt with SANs"]
  C --> E["generate client key, sign client.crt"]
  D --> F["verify every requested SAN is in server.crt"]
  F --> G["write ca.crt, ca.key, server.*, client.* (keys 0600)"]
  G --> H["config.json: mtls=true (http=true, or relay mode)"]
```

Certificate profiles:

| Field | CA | Server and client leaves |
|---|---|---|
| Key | ECDSA P-256 | ECDSA P-256 (one key each) |
| Signature | ECDSA with SHA-256 | ECDSA with SHA-256, by the CA |
| Serial | random, below 2^159 | random, below 2^159 |
| Subject | `CN=kbtool local CA, O=kbtool` (relay: `kbtool relay CA`) | `CN=<role>, O=kbtool` |
| Validity | 1 hour back-dated to `-expire` (default 24h) | same |
| Key usage | CertSign, CRLSign; `IsCA` | DigitalSignature |
| Extended key usage | — | ServerAuth **and** ClientAuth |
| SANs | — | server: the requested or default IPs and DNS names (relay mode: the relay host) |

Notes:

- **Default SANs:** every interface IP (not link-local), the host name, and
  `host.docker.internal`. Each requested SAN is checked in the issued
  certificate before anything is written.
- **One client certificate for everyone:** every enrolled client receives the
  same `client.crt` and `client.key`. TLS has no per-certificate uniqueness,
  and the CRL revokes that one shared identity (section 10).
- **The CA fingerprint** is SHA-256 over the CA certificate's DER bytes,
  written as unpadded base64url (43 characters). It is shown for humans and
  logs; no protocol depends on it.

## 5. Encrypted bundles (KBX1)

Two things use the same container format: the **enrollment bundle** a client
downloads, and the **encrypted store** (`kb.db` holding the index and the
message board).

### 5.1 Format

```mermaid
flowchart LR
  M["magic 'KBX1' (4 bytes)"] --> V["version u16 LE = 1 (2 bytes)"]
  V --> S["PBKDF2 salt (16 bytes)"]
  S --> N["GCM nonce (12 bytes)"]
  N --> CT["AES-256-GCM ciphertext of a tar.gz"]
  CT --> T["GCM tag (16 bytes)"]
```

- The plaintext is a deterministic tar.gz: the enrollment bundle holds
  `ca.crt`, `client.crt`, `client.key` and `client.json`; the store holds
  `kb.db` and, when present, `board.bin`.
- No associated data is used. The header is not authenticated separately:
  changing the salt or nonce makes GCM authentication fail.
- A wrong passphrase, a wrong token, or any tampering surfaces as a GCM
  authentication failure. Nothing is decrypted partially.

### 5.2 Key derivation

```mermaid
flowchart LR
  P["passphrase or 16-byte enrollment key"] --> K["PBKDF2-HMAC-SHA256"]
  SALT["16-byte random salt"] --> K
  K -->|"600,000 iterations"| KEY["32-byte AES-256 key"]
  KEY --> GCM["AES-256-GCM"]
  NONCE["fresh 12-byte nonce per seal"] --> GCM
```

PBKDF2 is implemented in kbtool itself (RFC 2898 over `crypto/hmac`),
because the standard library has no PBKDF2.

**Derive once, seal many.** A `bundleSealer` caches the derived key for its
salt:

- The daemon derives the enrollment bundle key **once at boot** and seals
  each download with that salt and a fresh nonce. A flood of bundle
  requests costs the server no PBKDF2 work.
- A store derives its key once when it is opened. Every later board or index
  save reuses it with a fresh nonce.
- Opening a bundle under a different salt costs one derivation; when it
  succeeds, that salt and key become the cached ones.
- The client pays the full 600,000 iterations once per enrollment. That cost
  is the brute-force barrier on a captured bundle.

```mermaid
sequenceDiagram
  autonumber
  participant D as Daemon (boot)
  participant S as bundleSealer
  participant C as Client
  D->>S: new sealer(enrollment key)
  S->>S: random salt, PBKDF2 600k (once)
  C->>D: GET /bundle/<id>
  D->>S: seal(tar.gz)
  S-->>D: KBX1 with same salt, fresh nonce
  D-->>C: bundle
  C->>C: PBKDF2 600k with the bundle's salt, then AES-GCM open
```

Bundles written before the iteration count rose from 100,000 do not open:
there is no version flag for the count, so they fail like a wrong key.

## 6. Encryption at rest (the store)

With a passphrase, `kb.db` becomes a KBX1 bundle that holds both the index
and the message board, so the two can never be out of step and the board is
never written in plaintext.

```mermaid
flowchart TB
  K1["build -encrypt (hidden prompt)"] --> R{"key source<br/>precedence"}
  K2["-db-key-env NAME"] --> R
  K3["-db-key-file PATH"] --> R
  K4["$KBTOOL_DBKEY"] --> R
  R --> ST["kbStore: key in memory, sealer"]
  ST -->|"save index or board"| W["tar.gz {kb.db, board.bin} then seal, atomic write 0600"]
  ST -->|"open"| O["decrypt; wrong key fails before serving"]
```

- **The key never touches disk.** It is not written to `config.json`, argv
  or any file kbtool owns. `daemon start` hands it to its child process
  through the `KBTOOL_DBKEY` environment variable.
- **Every save re-seals both parts** under the in-memory key. Saves run under
  the store lock (`kb.db.lock`), so concurrent board writers cannot lose each
  other's updates.
- **Live reindex.** `kbtool build` next to a running daemon builds the index
  in the client process and streams it over the unix socket. The daemon
  re-seals it with the current board under its own key and the store lock.
  The client never needs the passphrase, and no plaintext is written
  (section 11).
- **Mixed states are refused.** An encrypted `kb.db` next to a stray plain
  `board.bin`, or the reverse, stops the daemon.

## 7. The daemon's listeners

```mermaid
flowchart TB
  D(("daemon"))
  D --> U["unix socket daemon.sock<br/>mode 0600"]
  D --> T["TCP port (with -http)"]
  D --> RL["relay streams (relay mode)"]
  U -->|"config.json mtls=true"| UT["TLS 1.2+, client certificate required"]
  U -->|"otherwise"| UP["plain; owner-only file permission is the access control"]
  T --> DM{"first byte<br/>0x16?"}
  DM -->|"no: plain HTTP"| CA["GET /ca.crt only"]
  DM -->|"yes: TLS"| TL["TLS 1.2+, client certificate verified if given"]
  TL --> G{"route"}
  G -->|"/bundle/ID"| BUN["encrypted enrollment bundle, no certificate needed"]
  G -->|"anything else"| MT["requires a verified client chain (mTLS)"]
  RL --> TL
```

- **Unix socket.** The socket is created with umask 0177, so it is
  `srw-------`. With mTLS on, the socket also speaks TLS and requires the
  client certificate. The host's own CLI then presents the state dir's
  `client.crt`/`client.key` and expects the server certificate's first SAN.
- **TCP.** One port carries three protocols, split on the first byte (`0x16`
  starts a TLS handshake):
  - plain HTTP serves only the public team CA (`/ca.crt`);
  - TLS without a client certificate reaches only `/bundle/<id>`;
  - every API route requires a verified client chain.
- **Without enrollment** (no `client.crt`/`client.key` to hand out), TLS
  requires a client certificate at the handshake itself.
- **Plaintext guard.** A non-loopback TCP listener requires `-mtls` or the
  explicit `-http-allow-insecure` opt-in.

## 8. Direct mTLS connection

A remote client that has enrolled talks to the daemon over mutual TLS:

```mermaid
sequenceDiagram
  autonumber
  participant C as Remote client
  participant D as Daemon TCP port
  C->>D: TCP connect, ClientHello (SNI = dialed host)
  D-->>C: server.crt (signed by team CA)
  C->>C: verify chain to ca.crt and SAN matches the dialed host or IP
  D->>C: CertificateRequest
  C-->>D: client.crt + proof of possession of client.key
  D->>D: verify chain to ca.crt
  D->>D: CRL check of every certificate in the chain
  Note over C,D: ECDHE key exchange: the session has forward secrecy
  C->>D: POST /mcp (JSON-RPC)
  D->>D: route gate: verified chain present?
  D-->>C: result
```

- The client trusts **only** `ca.crt` from its state dir (no system roots).
- The client checks the server's **name**: the dialed host must be one of the
  server certificate's SANs. `client.json` lists every SAN, so a
  multi-homed server is reachable by each address.
- The server checks the client certificate against the same CA and the CRL.

## 9. Enrollment (`kbtool client -import`)

Enrollment gives a new machine the team's `ca.crt`, `client.crt` and
`client.key` with one pasted line, without trusting the network.

### 9.1 The token

```mermaid
flowchart LR
  P["'kb1' prefix"] --> F["flags (1 byte): host kind, port present, session present"]
  F --> H["relay host: IPv4 4B, IPv6 16B, or length + DNS name"]
  H --> PO["relay port u16 BE (only if not 9876)"]
  PO --> SE["relay session (16 bytes)"]
  SE --> K["enrollment key (16 bytes)"]
```

- Everything after `kb1` is unpadded base64url. A **direct** token carries
  only the flags byte and the key. The daemon URL is written in front of it:
  `kbtool client -import https://HOST:PORT/ kb1…`.
- A **relay** token also carries the relay host, port and session, so it is
  pasted alone.
- Parsing is strict: unknown flag bits, wrong lengths, an invalid host name,
  port 0 or trailing bytes are all refused.
- **The key is the only secret.** It is 128 random bits, generated at daemon
  boot and held in memory. A restart makes every old token useless.
- **Nothing else needs to travel.**
  - The bundle ID is derived from the key: `base64url(HMAC-SHA256(key,
    "kbtool bundle id")[:16])`. It cannot be found by scanning and reveals
    nothing about the key.
  - The team CA arrives inside the encrypted bundle, so no fingerprint is
    needed.

### 9.2 The protocol (direct)

```mermaid
sequenceDiagram
  autonumber
  actor U as User
  participant C as New client
  participant D as Daemon :9876
  U->>C: kbtool client -import https://kb.example.net:9876/ kb1…
  C->>C: parse token, id = HMAC-SHA256(key, "kbtool bundle id")[:16]
  C->>D: TLS (no verification yet), GET /bundle/<id>
  D->>D: constant-time compare id
  D-->>C: KBX1 bundle (sealed with the boot key's AES key)
  Note over C: remembers the server certificate seen on this connection
  C->>C: PBKDF2 600k + AES-GCM open (fails = wrong or stale token, or tampering)
  C->>C: extract only the 4 allowed files (1 MiB cap)
  C->>C: verify the seen server certificate chains to the bundled ca.crt and is valid for kb.example.net
  alt not valid
    C-->>U: refuse, write nothing (tampered connection?)
  else valid
    C->>C: write files (client.key 0600), client.json
    C->>D: mTLS GET /healthz with the new certificate
    D-->>C: 200 ok
    C-->>U: enrolled
  end
```

### 9.3 Why it is safe

```mermaid
flowchart TB
  A["Attacker on the network"] --> B{"Can it read the bundle?"}
  B -->|"no: AES-256-GCM under a key derived from the token"| X1["needs the 128-bit token key"]
  A --> C{"Can it swap in its own bundle?"}
  C -->|"no: GCM authenticates; a forged bundle does not open"| X2["refused"]
  A --> D{"Can it impersonate the daemon (MITM)?"}
  D -->|"no: the server certificate must chain to the CA inside the authentic bundle and match the host"| X3["refused before anything is written"]
  A --> E{"Can it find the bundle by probing?"}
  E -->|"no: 128-bit derived ID, constant-time compare, same 404 as any probe"| X4["404"]
```

The token is a **bearer secret** while its daemon runs: anyone who has it can
enroll. Daemon logs that contain it are mode 0600. Restarting the daemon
revokes all outstanding tokens; the CRL revokes the shared client
certificate itself (section 10).

## 10. Revocation (CRL)

```mermaid
flowchart TB
  F["crl.pem (PEM, one or more X509 CRL blocks)"] --> L["load"]
  L --> V{"signature verifies<br/>against the CA?"}
  V -->|"no"| DROP["dropped"]
  V -->|"yes"| STORE["in-memory CRL store"]
  H["each TLS handshake with a client certificate"] --> CH["for every certificate in the verified chain"]
  CH --> I{"CRL issuer = certificate issuer<br/>and NextUpdate in the future?"}
  I -->|"no"| SKIP["CRL ignored for this certificate"]
  I -->|"yes"| S{"serial listed?"}
  S -->|"yes"| REJ["handshake rejected"]
  S -->|"no"| OK["accepted"]
  STORE --> I
```

- **Refresh:** `crl_refresh=false` (the default) watches the file and
  reloads on change. `crl_refresh=true` reloads every `crl_interval`
  seconds.
- **Missing file:** no revocation data. Deleting the file clears the store.
- **Corrupt file:** the previous lists are kept, so a read hiccup never
  releases revocations.
- **Stale CRL** (NextUpdate in the past): ignored, so an old file can
  neither revoke nor deny service.

## 11. The host's unix socket and live reindex

On the daemon host the CLI reaches the daemon only through `daemon.sock`
(never TCP or the relay). Socket-only methods let `kbtool build` hand over a
new index:

```mermaid
sequenceDiagram
  autonumber
  participant B as kbtool build (host)
  participant S as daemon.sock (0600, TLS if mtls)
  participant D as Daemon
  B->>S: kbtool/index_info
  S-->>B: {db, encrypted}
  B->>B: build index in this process, sha = SHA-256(bytes)
  B->>S: {"method":"kbtool/index_swap","params":{"size":N,"sha256":sha}} + N raw bytes
  D->>D: size within 1..8 GiB, SHA-256 matches, bytes parse as an index
  D->>D: lock tools, board, store; persist (re-seal when encrypted)
  D-->>B: {chunks, db, encrypted}
```

- The SHA-256 here is an **integrity check** against truncation and
  corruption, not authentication. The socket's owner-only permission (and
  mTLS when enabled) decides who may swap.
- The swap methods do not exist over HTTP, the relay, or stdio.

## 12. The relay

A relay lets clients reach a daemon that cannot accept connections. The
daemon connects **out** to the relay; clients connect to the relay; the
relay copies bytes without decrypting the team's traffic.

### 12.1 Two layers of trust

```mermaid
flowchart TB
  subgraph outer["Relay TLS (low trust)"]
    direction LR
    DM["daemon"] -- "register session, accept streams" --> RY["relay"]
  end
  subgraph inner["Team TLS / mTLS (end to end, through the relay)"]
    direction LR
    CL["client"] -- "SNI = session ID; relay cannot decrypt" --> DM2["daemon"]
  end
  TA1["trust anchor: relay CA fetched over plain HTTP (default), or system roots / pinned CA (relay_ca)"] -.- outer
  TA3["who may register: holder of the session key (signature bound to the TLS connection)"] -.- outer
  TA2["trust anchor: team CA (from the enrollment bundle) and client certificates"] -.- inner
```

| Layer | Protects | Trust anchor |
|---|---|---|
| Relay TLS | the daemon's registration and its accept streams | by default the relay CA, fetched over plain HTTP from `/ca.crt`, host names not checked; with `relay_ca` the system roots or a pinned CA, host name checked |
| Session proof | that only the session's daemon registers it | the daemon's Ed25519 session key; the session ID commits to its public key |
| Team TLS / mTLS | everything that matters: the enrollment bundle and all MCP traffic | the team CA and the shared client certificate |

In the default mode the relay CA only keeps registrations private from
passive observers: an attacker who swaps the relay CA in transit could read
session IDs and the relay token, but never team traffic, and cannot enroll
or impersonate a daemon. Even that attacker cannot register a session: the
proof is signed over keying material of the TLS connection it travels on, so
it is useless on the attacker's own connection to the real relay. With
`relay_ca` set, the token is protected too. The registration token is
compared in constant time.

### 12.2 One port, routed by the first bytes

```mermaid
flowchart TB
  IN["connection to the relay port"] --> P{"first byte 0x16 (TLS)?"}
  P -->|"no"| HTTP["plain HTTP: GET /ca.crt (current relay CA), GET /healthz"]
  P -->|"yes"| SNI{"SNI in the ClientHello<br/>(peeked, not consumed)"}
  SNI -->|"live session ID"| PASS["passthrough: splice to that daemon, never terminated"]
  SNI -->|"session-shaped but unknown"| CLOSE["closed"]
  SNI -->|"anything else"| TERM["terminated by the relay: /healthz, POST /v1/register, POST /v1/accept/ID"]
```

### 12.3 Registration and a relayed client connection

```mermaid
sequenceDiagram
  autonumber
  participant D as Daemon
  participant R as Relay
  participant C as Client
  D->>R: plain HTTP GET /ca.crt (default trust mode only)
  R-->>D: current relay CA
  D->>R: TLS handshake (verify the relay certificate)
  D->>D: ekm = TLS exporter("kbtool relay register v1", 32 bytes)<br/>sig = Ed25519(session key, label, session, expiry, ekm)
  D->>R: POST /v1/register, Upgrade, X-Kbtool-Session, X-Kbtool-Session-Key, -Expires, -Sig, X-Kbtool-Relay-Token
  R->>R: per-IP rate, token (constant time), ID = SHA-256(key, expiry), same ekm, verify sig, not expired, under the cap, not already live
  R-->>D: 101 Switching Protocols: control stream (closed at expiry)
  loop every 30 s
    R->>D: ping
    D-->>R: pong
  end
  C->>R: TLS ClientHello with SNI = session ID
  R->>R: peek SNI, find session
  R->>D: control: "conn <random id>"
  D->>R: new relay TLS, POST /v1/accept/<id> (X-Kbtool-Session)
  R-->>D: 101: raw stream
  R->>R: splice client <-> daemon stream
  Note over C,D: Team TLS handshake runs end to end through the splice
  C->>D: (encrypted) client certificate, MCP calls
  D-->>C: (encrypted) results
```

Inside the splice:

- The daemon presents `server.crt` with the team CA appended to the chain.
- The client sends SNI = session (the relay's routing key). It still
  verifies the server certificate against the team CA **for the relay's host
  name**, which `mtls -relay` puts in the server certificate's SANs.
- The relay sees only TLS records. It learns metadata: session IDs, timing
  and byte counts.

### 12.4 The session proof

```mermaid
flowchart TB
  subgraph setup["mtls -relay (once)"]
    K["new Ed25519 key -> relay-session.key (0600)"]
    E["team CA NotAfter = expiry"]
    K --> H["SHA-256('kbtool relay session v1' || public key || expiry as 8-byte BE)"]
    E --> H
    H --> ID["first 16 bytes, hex = session ID (SNI)"]
  end
  subgraph reg["every registration"]
    T["TLS connection to the relay"] --> X["exporter: 32 bytes, same on both ends"]
    X --> M["message = 'kbtool relay register v1' NUL session NUL expiry NUL ekm"]
    M --> S["Ed25519 signature"]
  end
  subgraph check["relay (no stored state)"]
    C1{"ID = hash(key, expiry)?"} -->|"yes"| C2{"signature valid for this connection's ekm?"}
    C2 -->|"yes"| C3{"expiry in the future?"}
    C3 -->|"yes"| OK["session registered until expiry"]
    C1 -->|"no"| NO["403"]
    C2 -->|"no"| NO
    C3 -->|"no"| NO
  end
  ID --> check
  S --> check
```

- **No squatting.** A session ID is useless without its key; the relay
  refuses registrations without a proof (older daemons).
- **No replay.** The exporter output is unique to each TLS connection, so a
  captured registration fails on any other connection, including through a
  man in the middle who terminates the daemon's TLS.
- **Expiry.** The ID commits to the team CA's `NotAfter`. The relay refuses an
  expired session and closes a live one at that moment, so a session never
  outlives the certificates that make it useful.
- The daemon checks at start that `relay_session` matches its key and
  `ca.crt`, and refuses relay mode otherwise.

### 12.5 Abuse limits

| Limit | Default | Option |
|---|---|---|
| Registered sessions | 5000 (503 above) | `-max-sessions`, `KBTOOL_RELAY_MAX_SESSIONS`, `relay_max_sessions` |
| New connections per source IP | 20/s, burst 100 (closed at once) | `-conn-rate`, `KBTOOL_RELAY_CONN_RATE` |
| Registrations per source IP | 30/min, burst 10 (429) | `-register-rate`, `KBTOOL_RELAY_REGISTER_RATE` |
| Control line | 128 bytes, both ends | — |
| Streams per session / total | 64 / 1024 | — |

### 12.6 Enrollment through a relay

The same protocol as section 9.2, with these differences:

- the token carries the relay host, port and session;
- the bundle download uses SNI = session, so the relay routes it to the
  daemon unopened;
- the client verifies the server certificate it saw against the bundled CA
  for the relay host.

```mermaid
sequenceDiagram
  autonumber
  participant C as New client
  participant R as Relay
  participant D as Daemon
  C->>R: TLS (SNI = session), GET /bundle/<id>
  R->>D: conn <id> / accept / splice
  D-->>C: KBX1 bundle through the splice
  C->>C: PBKDF2 + AES-GCM open, verify server cert vs bundled CA for the relay host
  C->>R: mTLS (SNI = session) GET /healthz
  R->>D: splice
  D-->>C: 200 ok
```

### 12.7 The relay's certificate: in memory and rotating, or the operator's

```mermaid
stateDiagram-v2
  [*] --> Gen0: relay start
  Gen0: CA generation N (in memory, valid 24h)
  Gen0 --> GenNext: every 12h (-rotate) or SIGHUP
  GenNext: CA generation N+1
  GenNext --> GenNext: next rotation
  Gen0 --> [*]: stop (keys gone)
  GenNext --> [*]: stop (keys gone)
```

- At every start the relay generates a new CA and leaf (ECDSA P-256, valid
  `-ca-ttl`, 24h by default). It never writes them, and it deletes any
  `relay-ca.*`/`relay.*` files older versions left behind.
- **Rotation** swaps the CA served on `/ca.crt` and the leaf presented to
  new handshakes together. Established connections are untouched, because
  certificates are only checked at the handshake.
- **The CA lifetime is longer than the rotation interval**, so a CA stays
  valid for at least one interval after it is replaced.
- **Operator certificate.** With `-cert`/`-key` the relay serves that chain
  instead and never rotates; `SIGHUP` reads the files again. `/ca.crt` serves
  the chain's last certificate, so default-mode daemons keep working, and
  daemons with `relay_ca` (`system` or a file) verify it properly, host name
  included, without fetching anything over plain HTTP.

How a default-mode daemon follows a rotation (with `relay_ca` there is
nothing to fetch):

```mermaid
sequenceDiagram
  autonumber
  participant D as Daemon
  participant R as Relay
  Note over R: SIGHUP or 12h timer: new CA and leaf
  R->>D: control: conn <id>
  D->>R: TLS for /v1/accept with the cached old CA
  R-->>D: new leaf: verification fails
  D->>R: plain HTTP GET /ca.crt
  R-->>D: new CA (kept for later accepts)
  D->>R: TLS for /v1/accept with the new CA: succeeds
  R-->>D: 101: stream spliced to the client
```

**Reconnects.** If the control stream drops, or the relay is down, the daemon
re-registers the same session forever. It waits with jittered exponential
backoff: the ceiling doubles from 1 s to 30 s, and each wait is between half
the ceiling and the ceiling. In the default trust mode every attempt fetches
the CA again, so a restarted relay with a brand-new CA is picked up
automatically.

## 13. Message board signatures

Agents that cannot see each other's workspaces coordinate on a signed board.
Every message is signed with the author's Ed25519 key; readers see a
verification status on each message.

### 13.1 Identity

```mermaid
sequenceDiagram
  autonumber
  participant A as Agent
  participant B as Board (daemon)
  A->>B: board_signup {"name":"alice"}
  B->>B: seed = 32 random bytes, Ed25519 key from seed
  B->>B: under the board lock: bind name <-> public key permanently
  B-->>A: seed (64 hex) — shown once, kbtool keeps only the public key
  Note over A: the agent stores its seed privately (it is its identity)
```

A name is bound to one public key for the life of the board; a second
signup with the same name is refused.

### 13.2 Signing and verifying

The signature covers a **canonical string**: the fields joined with NUL
bytes, so no field can be re-split into another:

```text
agent \0 thread \0 seq \0 kind \0 task \0 sorted,refs \0 text [\0 attachment:sha256:<hex>]
```

```mermaid
flowchart TB
  subgraph post["board_post (author side, inside kbtool with the seed)"]
    S1["seed"] --> K1["Ed25519 private key"]
    M1["message fields"] --> CAN["canonical string"]
    ATT["attachment tar.gz (optional)"] --> D1["SHA-256 digest"] --> CAN
    K1 --> SIG["Ed25519 signature over the canonical string"]
    CAN --> SIG
  end
  subgraph read["every read"]
    R0{"author registered?"} -->|"no"| U["unknown-agent"]
    R0 -->|"yes"| R1{"message key = registered key?"}
    R1 -->|"no"| IMP["impersonation"]
    R1 -->|"yes"| R2{"Ed25519 verify?"}
    R2 -->|"no"| BAD["bad-signature"]
    R2 -->|"yes"| R3{"attachment bytes hash to the signed digest?"}
    R3 -->|"no"| BAD
    R3 -->|"yes or no attachment"| VER["verified"]
  end
  SIG --> read
```

- The seed is used to sign and then dropped; kbtool never stores it.
- **Attachments** are signed through their SHA-256 digest. Swapping the
  stored bytes turns the message into `bad-signature`, and `board fetch`
  refuses data whose digest differs from the signed one.
- **What signatures do not do:** they prove *who* wrote a message, not that
  the board is complete or fresh. Whoever controls the board file can delete
  or withhold messages. When the store is encrypted, the board is
  confidential at rest (section 6); otherwise `board.bin` is plaintext,
  protected by file permissions.

## 14. Threat model summary

```mermaid
flowchart LR
  subgraph who["Who"]
    N["network observer"]
    M["active MITM"]
    RO["relay operator"]
    TH["token holder"]
    LU["other local user on the host"]
    DT["disk thief"]
  end
  subgraph what["What they get"]
    N --> N1["TLS metadata; session IDs (SNI); the public team CA"]
    M --> M1["cannot enroll, read, or impersonate; can drop traffic"]
    RO --> RO1["metadata and byte counts; can drop traffic; never team plaintext"]
    TH --> TH1["can enroll while that daemon runs (bearer secret)"]
    LU --> LU1["no access to daemon.sock (0600) or keys (0600)"]
    DT --> DT1["encrypted store: needs the passphrase (PBKDF2 600k); plain store: everything"]
  end
```

| Asset | Protected by | Main residual risk |
|---|---|---|
| MCP traffic | TLS 1.2+ with ECDHE, mutual certificate authentication, CRL | a leaked shared client key; revoke it with the CRL |
| Enrollment | token-derived AES-256-GCM bundle, CA-inside-bundle server check | the token while its daemon runs |
| Relay registration | Ed25519 session proof bound to the TLS exporter, expiry with the team CA, constant-time token check, relay TLS (CA over plain HTTP, or `relay_ca`) | default mode: an active MITM on the CA download can see the token and session IDs (but cannot register) |
| Relay availability | session cap, per-IP connection and registration rates, stream limits, bounded control lines | a distributed flood from many addresses; one NAT shares a budget |
| Store at rest | AES-256-GCM with a PBKDF2 key | weak passphrases (PBKDF2 is not memory-hard) |
| Board authorship | Ed25519 signatures, permanent name-to-key binding | completeness and freshness are not guaranteed |
| Daemon socket | owner-only permission, mTLS when configured | any process running as the same user |

## 15. Limitations and deliberate choices

- **TLS 1.2 is the floor.** Go's defaults choose the cipher suites (AEAD
  suites with ECDHE only), and 1.3 is used when both ends support it.
- **Leaf certificates carry both ServerAuth and ClientAuth** (one profile
  for all leaves).
- **All clients share one client certificate.** Access is all-or-nothing per
  team, and revocation affects every holder. Re-run `kbtool mtls` and
  re-enroll to rotate it.
- **Certificates default to 24 hours** (`-expire`), so a long-lived team
  needs a longer expiry or a periodic `kbtool mtls`.
- **By default the relay CA is trusted on first fetch, every time.** This is
  intentional: the relay layer only adds privacy for registrations, and team
  security never depends on it; session ownership rests on the session key,
  not on the relay's certificate. Relay host names are not verified for the
  same reason. Set `relay_ca` (`-relay-ca system` or a CA file) for a relay on
  the internet with an operator certificate, so the token is protected too.
- **PBKDF2-HMAC-SHA256 with 600,000 iterations** follows current OWASP
  guidance for that function, but it is not memory-hard (unlike scrypt or
  Argon2, which are not in the standard library). The 128-bit enrollment key
  is random, so this only matters for human-chosen store passphrases.
- **No associated data in KBX1.** The magic and version are checked
  explicitly, and the salt and nonce feed the key and the GCM computation,
  so tampering with them still fails authentication.
- **SHA-256 on the index swap is integrity, not authentication.** The unix
  socket's permissions (and mTLS) are the authentication.
- **Fingerprints are informational.** The team CA fingerprint printed by
  `kbtool mtls` and the relay fingerprint printed by `relay establish` help
  humans compare; no protocol step depends on them.

## 16. Where to look in the code

| Topic | Functions in `kbtool.go` |
|---|---|
| Certificates | `cryptoGenerateCA`, `cryptoGenerateLeaf`, `cryptoRandomSerial`, `caFingerprint` |
| TLS configs | `cryptoServerTLSConfig`, `cryptoClientTLSConfig`, `bootstrapTLSConfig`, `hostSocketTLS` |
| CRL | `cryptoLoadCRLs`, `cryptoVerifyCRLs`, `cryptoCheckRevoked`, `cryptoMonitorCRL` |
| KBX1 bundles | `cryptoPbkdf2SHA256`, `cryptoBundleAEAD`, `bundleSealer.seal` / `.open` |
| Store at rest | `kbStore` (`writeBundle`, `saveBoard`, `saveDBBytes`, `lock`), `resolveKey` |
| Enrollment | `enrollToken.encode`, `parseEnrollToken`, `bundleIDFromKey`, `bootstrapState`, `bootstrapFetchBundle`, `bootstrapInstall` |
| Relay | `newRelayPKI`, `loadRelayOperatorPKI`, `relayServer` (`route`, `passthrough`, `handleRegister`), `verifyRegistration`, `ipLimiter`, `peekClientHelloSNI`, `relayConnector` (`run`, `once`, `accept`), `relaySessionID`, `relayRegisterMessage`, `relayEKM`, `relaySessionAuth`, `loadRelayAuth`, `relayTrust`, `relayFetchCA`, `relayVerifyCA`, `relaySNIConfig` |
| Board | `canonicalMsg`, `cryptoDeriveSeed`, `cryptoSignBoard`, `cryptoVerifyBoardMsg` |
| Live reindex | `handleHostMethod`, `Toolbox.swapIndex`, `swapIndexVia` |
