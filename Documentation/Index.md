# RustBalance — Documentation Index

> Exhaustive reference for every feature, check, balance, key variable, timing, order, schedule, and flow in the RustBalance codebase.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Module Map](#2-module-map)
3. [Startup Flow](#3-startup-flow)
4. [CLI Commands](#4-cli-commands)
5. [Configuration Reference](#5-configuration-reference)
6. [Cryptographic Operations](#6-cryptographic-operations)
7. [Tor Interaction](#7-tor-interaction)
8. [Coordination Layer](#8-coordination-layer)
9. [Election & Lease System](#9-election--lease-system)
10. [Peer Tracking & Gossip](#10-peer-tracking--gossip)
11. [Descriptor Publishing](#11-descriptor-publishing)
12. [Intro Point Management](#12-intro-point-management)
13. [Reverse Proxy](#13-reverse-proxy)
14. [Tor Bootstrap Channel (Join)](#14-tor-bootstrap-channel-join)
15. [Health Checking](#15-health-checking)
16. [Self-Repair](#16-self-repair)
17. [Scheduler Loops & Timings](#17-scheduler-loops--timings)
18. [State Model](#18-state-model)
19. [Utility Functions](#19-utility-functions)
20. [Key Constants & Defaults](#20-key-constants--defaults)
21. [Security Measures](#21-security-measures)
22. [Data Flow Diagrams](#22-data-flow-diagrams)

---

## 1. Architecture Overview

RustBalance is a Rust-based Tor v3 Hidden Service load balancer. Each node:

- **IS a hidden service** — runs Tor with the master identity key in `HiddenServiceDir`
- **Creates its own intro points** — Tor establishes 3 intro points per node by default
- **Accepts connections** — clients connect via any node's intro points
- **Reverse proxies** — forwards traffic through Tor SOCKS to the target `.onion` service
- **Coordinates** — nodes share intro points via WireGuard mesh, merge them into one descriptor

**Traffic flow:**
```
Client → Tor network → random intro point → RustBalance node → Tor SOCKS → target.onion
```

**Key insight:** The target service's intro points are irrelevant. RustBalance uses its OWN intro points from all nodes, published under the master address.

### Mode Detection

RustBalance auto-detects its mode:

| Condition | Mode | Behavior |
|-----------|------|----------|
| No active peers | Single-node | Tor auto-publishes; HSPOST also used for freshness |
| Active peers detected | Multi-node | Tor auto-publish disabled; merged descriptor via HSPOST |

Seamless transition — start with one node, add more without reconfiguration.

---

## 2. Module Map

```
src/
├── main.rs              — CLI dispatch, tokio runtime, run_daemon entry point
├── lib.rs               — Module declarations, VERSION constant, clippy allows
├── logging.rs           — tracing + EnvFilter log setup
│
├── config/
│   ├── mod.rs           — All config structs with defaults
│   ├── file.rs          — TOML loading, config search paths
│   └── validation.rs    — 5 validators (node, master, target, coordination, timing)
│
├── state/
│   ├── mod.rs           — Re-export
│   └── model.rs         — RuntimeState (role, intro points, lease, health flags)
│
├── balance/
│   ├── mod.rs           — Module re-exports
│   ├── backend.rs       — Backend struct, 5 health states
│   ├── health.rs        — HealthChecker: descriptor age checks, HTTP probe placeholder
│   ├── merge.rs         — DescriptorMerger: fair per-backend + random fill algorithm
│   ├── publish.rs       — Publisher: revision counter, dual time period HSPOST
│   ├── fetch.rs         — DescriptorFetcher: HSFETCH + cache + decrypt
│   ├── bootstrap.rs     — BootstrapClient: Tor SOCKS join via master.onion
│   ├── join_handler.rs  — JoinHandler: validates join requests, adds WireGuard peers
│   ├── onion_service.rs — OnionService: Tor HS setup, SOCKS5 reverse proxy, TLS, header rewriting
│   └── http_proxy.rs    — HttpProxy: reqwest-based reverse proxy (alternative implementation)
│
├── coord/
│   ├── mod.rs           — Coordinator: transport + election + peer tracker
│   ├── election.rs      — Election: priority-based publisher election
│   ├── lease.rs         — Lease + LeaseManager: time-based exclusivity
│   ├── messages.rs      — CoordMessage: 8 message types, JSON serialization, time validation
│   ├── peers.rs         — PeerTracker: peer lifecycle (Joining→Initializing→Healthy→Unhealthy→Dead)
│   ├── wireguard.rs     — WgTransport: UDP socket on tunnel_ip:51821, broadcast/receive
│   └── wg.rs            — WgInterface: CLI-based WireGuard setup (ip/wg commands)
│
├── crypto/
│   ├── mod.rs           — Re-exports
│   ├── keys.rs          — MasterIdentity: Ed25519 key loading, Tor key file I/O, onion address derivation
│   ├── blinding.rs      — Prop224 key blinding: time periods, subcredential, blinding factor
│   └── descriptor.rs    — DescriptorBuilder: inner/middle/outer layers, AES-256-CTR encryption, Ed25519 signing
│
├── tor/
│   ├── mod.rs           — Re-exports
│   ├── control.rs       — TorController: control port protocol, AUTHENTICATE, HSPOST, SETCONF, GETINFO
│   ├── descriptors.rs   — HsDescriptor + IntroductionPoint: v3 descriptor parsing, two-layer decryption
│   └── hsdir.rs         — HSDir index calculation, outer descriptor builder
│
├── repair/
│   ├── mod.rs           — Re-exports
│   ├── actions.rs       — RepairAction enum: RestartTor, ForceRepublish, StepDown, etc.
│   └── restart.rs       — Process restart: systemctl/service commands, Tor liveness check
│
├── scheduler/
│   ├── mod.rs           — Re-export
│   └── loops.rs         — Main orchestration: 6 concurrent loops + startup bootstrap
│
└── util/
    ├── mod.rs           — base64 encode/decode
    ├── rand.rs          — Jitter, backoff, random bytes
    └── time.rs          — Unix timestamps, time validation, duration formatting
```

---

## 3. Startup Flow

**Entry:** `main.rs::main()` → CLI parse → subcommand dispatch

### `run` subcommand (daemon mode)

```
main()
  → run_daemon(config_path)
    1. Load config from TOML
    2. Initialize logging (tracing + EnvFilter)
    3. Create RuntimeState (defaults)
    4. Connect TorController (authenticate: cookie or password)
    5. Create Coordinator (WgTransport or Tor fallback)
    6. scheduler::run(config, state, tor, coordinator)
```

### Scheduler startup (`scheduler/loops.rs::run()`)

```
run()
  1. Initialize election (node_id, priority, timeouts)
  2. Detect if joining node (has pre-configured WG peers)
  3. Load master identity key
  4. Write master key to HiddenServiceDir (hs_ed25519_secret_key, public_key, hostname)
  5. Create OnionService manager
  
  IF init node (no peers):
    6a. Configure Tor HS via SETCONF immediately
    6b. Wait 5s for Tor to create intro points
    6c. Verify hostname matches master address
    6d. Mark HS as running
  
  IF joining node (has peers):
    6a. Wait 30s for Tor circuits
    6b. initial_bootstrap() — 5 attempts × 15s delay, via Tor SOCKS to master.onion
    6c. Add responder as WireGuard peer
    6d. THEN configure Tor HS (prevents self-connection)
    6e. Wait 5s, verify hostname, mark HS running
  
  7. Create PeerTracker (heartbeat_interval, dead_threshold=3)
  8. Enable JoinHandler if join_secret configured
  9. Set initial election state (auto-publisher if no WG)
  
  10. Spawn 6 concurrent tasks:
      - heartbeat_loop (if WG configured)
      - receive_loop (if WG configured)
      - publish_loop (always)
      - intro_point_refresh_loop (always)
      - proxy (always, blocking)
      - background_bootstrap_loop (if joining node)
  
  11. tokio::select! — exit if any task fails
```

---

## 4. CLI Commands

| Command | Description | Source |
|---------|-------------|--------|
| `rustbalance run` | Start the daemon | `main.rs` |
| `rustbalance init` | Initialize first node (generate keys, config) | `main.rs` |
| `rustbalance join` | Join an existing cluster | `main.rs` |
| `rustbalance status` | Show node status | `main.rs` |
| `rustbalance backend` | Manage backends | `main.rs` |
| `rustbalance debug` | Debug commands | `main.rs` |

---

## 5. Configuration Reference

**File:** `src/config/mod.rs`

### `[node]` — NodeConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `id` | String | `""` | Unique node identifier |
| `priority` | u32 | `100` | Election priority (lower = higher priority) |
| `hidden_service_dir` | String | `"/var/lib/tor/rustbalance_node_hs"` | Path to Tor HiddenServiceDir |
| `clock_skew_tolerance_secs` | u64 | `5` | Max acceptable clock difference for messages |

### `[master]` — MasterConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `onion_address` | String | `""` | Master .onion address clients use |
| `identity_key_path` | String | `""` | Path to master Ed25519 secret key |

### `[tor]` — TorConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `control_host` | String | `"127.0.0.1"` | Tor control port host |
| `control_port` | u16 | `9051` | Tor control port |
| `control_password` | Option | `None` | Control port password |
| `socks_port` | u16 | `9050` | Tor SOCKS proxy port |

### `[publish]` — PublishConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `refresh_interval_secs` | u64 | `600` | How often to publish descriptor (10 min) |
| `takeover_grace_secs` | u64 | `90` | Grace period before publisher takeover |
| `max_intro_points` | usize | `20` | Max intro points per descriptor (Tor spec limit) |

### `[health]` — HealthConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `descriptor_max_age_secs` | u64 | `900` | Max descriptor age before stale (15 min) |
| `probe_interval_secs` | u64 | `60` | How often to probe backend health |
| `probe_path` | String | `"/health"` | HTTP path to probe |
| `probe_timeout_secs` | u64 | `5` | Probe timeout |

### `[coordination]` — CoordinationConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `heartbeat_interval_secs` | u64 | `10` | Heartbeat broadcast interval |
| `heartbeat_timeout_secs` | u64 | `30` | Seconds before peer considered unresponsive |
| `lease_duration_secs` | u64 | `60` | Publisher lease duration |
| `backoff_jitter_secs` | u64 | `15` | Random jitter for backoff |
| `cluster_token` | Option | `None` | Shared secret for peer authentication |
| `join_secret` | Option | `None` | Secret path for Tor Bootstrap Channel |

### `[wireguard]` — WireguardConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `private_key` | String | `""` | WG private key (base64) |
| `listen_port` | u16 | `51820` | WG listen port |
| `tunnel_ip` | Option | `None` | This node's tunnel IP (e.g., `10.200.200.1`) |
| `external_endpoint` | Option | `None` | This node's public IP:port |
| `public_key` | Option | `None` | This node's WG public key |
| `peers` | Vec | `[]` | Pre-configured WG peers |

### `[target]` — TargetConfig

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `onion_address` | String | `""` | Target .onion service address |
| `port` | u16 | `80` | Target port |
| `use_tls` | bool | `false` | Use TLS (HTTPS) when connecting to target |

### Top-level

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `local_port` | u16 | `8080` | Local port the reverse proxy listens on |

### Config Validation

**File:** `src/config/validation.rs` — 5 validators:

1. **`validate_node`** — Checks node ID is non-empty
2. **`validate_master`** — Checks onion_address is non-empty, key path exists
3. **`validate_target`** — Checks target address is non-empty
4. **`validate_coordination`** — Checks heartbeat_timeout > heartbeat_interval, lease_duration > heartbeat_interval
5. **`validate_timing`** — Checks refresh_interval >= 60, takeover_grace >= 30

---

## 6. Cryptographic Operations

### 6.1 Master Identity (`crypto/keys.rs`)

**`MasterIdentity`** struct fields:
- `signing_key` — Ed25519 SigningKey (from seed)
- `verifying_key` — Ed25519 VerifyingKey (public key)
- `private_scalar` — 32 bytes, clamped from expanded key bytes 0–31
- `prf_secret` — 32 bytes, from expanded key bytes 32–63

**Key loading (`load_identity_key`):**
- 32-byte seed → SHA-512 expand → clamp → `MasterIdentity::from_seed()`
- 96-byte Tor format → skip 32-byte header → 64-byte expanded key + separate `.pub` file → `from_expanded_with_pubkey()`
- 64-byte expanded format → requires companion `.pub` file

**Tor key file writing (`write_tor_key_files`):**
- Creates `hs_ed25519_secret_key` (32B header + 64B expanded key)
- Creates `hs_ed25519_public_key` (32B header + 32B pubkey)
- Creates `hostname` (the .onion address)
- Sets permissions 700 (dir), 600 (files), ownership to debian-tor/_tor/tor

**Onion address derivation:**
- `address = base32(pubkey || checksum || version)`
- `checksum = SHA3-256(".onion checksum" || pubkey || 0x03)[:2]`
- `version = 0x03`

### 6.2 Key Blinding (`crypto/blinding.rs`)

Per **Tor Proposal 224** (rend-spec-v3):

**Constants:**
- `TIME_PERIOD_LENGTH_MINUTES` = `1440` (24 hours)
- `TIME_PERIOD_ROTATION_OFFSET_MINUTES` = `720` (12 hours, so boundaries at 12:00 UTC)

**Blinding factor:**
```
h = SHA3-256("Derive temporary signing key\x00" || pubkey || basepoint_str || "key-blind" || period_num || period_length)
```

**Public key blinding:**
```
A' = clamp(h) * A    (EC scalar × point multiplication)
```

**Private key blinding:**
```
a' = clamp(h) * a mod l    (scalar multiplication)
```

**Subcredential derivation:**
```
credential = SHA3-256("credential" || pubkey)
subcredential = SHA3-256("subcredential" || credential || blinded_key)
```

**Time period calculation:**
```
period_num = (minutes_since_epoch - 720) / 1440
```

**Dual time periods:** Per rend-spec-v3 §2.2.1, descriptors published for BOTH current and next time period.

### 6.3 Descriptor Building (`crypto/descriptor.rs`)

**`DescriptorBuilder`** — builds a complete v3 descriptor per time period.

**Three-layer structure:**

| Layer | Content | Encryption | String Constant |
|-------|---------|------------|-----------------|
| Inner | Introduction points, `create2-formats 2` | AES-256-CTR | `"hsdir-encrypted-data"` |
| Middle | `desc-auth-type x25519`, 16 fake auth-clients, encrypted inner | AES-256-CTR | `"hsdir-superencrypted-data"` |
| Outer | `hs-descriptor 3`, signing cert, revision counter, encrypted middle, signature | — | — |

**Encryption scheme (per layer):**
```
SALT (16 random bytes) || ENCRYPTED || MAC (32 bytes)

Key derivation:
  secret_input = blinded_key || subcredential || INT_8(revision_counter)
  keys = SHAKE-256(secret_input || salt || string_constant, 80 bytes)
  SECRET_KEY = keys[0:32]     — AES-256 key
  SECRET_IV  = keys[32:48]    — CTR initialization vector
  MAC_KEY    = keys[48:80]    — Authentication key

MAC = SHA3-256(mac_key_len(8B) || MAC_KEY || salt_len(8B) || SALT || ENCRYPTED)
```

**Certificate types built:**

| Cert Type | Code | Purpose | Certified Key | Signed By |
|-----------|------|---------|---------------|-----------|
| Signing key cert | `0x08` | BLINDED_ID_V_SIGNING | desc_signing_pubkey | blinded private key |
| Auth key cert | `0x09` | HS_IP_V_SIGNING | intro auth key | desc_signing_key |
| Enc key cert | `0x0B` | NTOR_CC_V_SIGNING | intro auth key (NOT enc_key!) | desc_signing_key |

**Blinded signing algorithm:**
```
k' = SHA-512(prf_secret || "Derive temporary signing key hash input")[:32]
r = SHA-512(k' || message) mod l
R = r * G
challenge = SHA-512(R || blinded_pubkey || message)
s = r + challenge * blinded_scalar mod l
signature = (R, s)
```

### 6.4 Descriptor Decryption (`crypto/descriptor.rs::decrypt_layer`)

Reverse of encryption:
1. Extract SALT (16B), ENCRYPTED, MAC (32B) from ciphertext
2. Derive keys via SHAKE-256 (same as encryption)
3. Verify MAC BEFORE decrypting (timing attack protection)
4. Decrypt with AES-256-CTR
5. Return plaintext

---

## 7. Tor Interaction

### 7.1 Control Port (`tor/control.rs`)

**`TorController`** — async TCP client for Tor control protocol.

**Authentication methods (tried in order):**
1. Password (hex-encoded via `AUTHENTICATE <hex>`)
2. Cookie file (tried paths: `/run/tor/control.authcookie`, `/var/run/tor/control.authcookie`, `/var/lib/tor/control_auth_cookie`)
3. Null authentication (`AUTHENTICATE`)

**Commands used:**

| Command | Purpose | Used By |
|---------|---------|---------|
| `AUTHENTICATE` | Authenticate to control port | Startup |
| `SETCONF HiddenServiceDir=... HiddenServicePort=...` | Configure file-based hidden service | `OnionService::configure_tor_hs()` |
| `SETCONF PublishHidServDescriptors=0/1` | Enable/disable Tor's auto-publish | Publish loop |
| `GETINFO status/bootstrap-phase` | Check if Tor is bootstrapped | Health check |
| `GETINFO hs/service/desc/id/<addr>` | Get cached descriptor for our service | Intro point refresh |
| `GETINFO hs/client/desc/id/<addr>` | Get fetched descriptor for another service | Descriptor fetcher |
| `HSFETCH <addr>` | Trigger descriptor fetch from HSDirs | Descriptor fetcher |
| `+HSPOST HSADDRESS=<addr>\r\n<descriptor>\r\n.\r\n` | Upload descriptor to HSDirs | Publisher |
| `ADD_ONION ED25519-V3:<key> Port=...` | Create ephemeral hidden service | (Available, not primary path) |
| `DEL_ONION <id>` | Remove hidden service | Cleanup |

**Response parsing:**
- 10-second timeout per response line
- Multi-line data block support (`250+keyword=\r\n ... .\r\n 250 OK\r\n`)
- Error detection: `5XX` response codes

### 7.2 Descriptor Parsing (`tor/descriptors.rs`)

**`HsDescriptor::parse()`** — parses outer layer fields:
- `hs-descriptor 3` (version)
- `descriptor-lifetime` (default 180 min)
- `revision-counter`
- Ed25519 cert (extracts blinded key from extension 0x04)
- Encrypted body (BEGIN/END MESSAGE block)
- Signature

**`HsDescriptor::parse_and_decrypt_with_pubkey()`** — full decryption:
1. Parse outer layer → extract blinded key from cert
2. Derive subcredential from identity pubkey + blinded key
3. Decrypt outer (superencrypted) layer → middle plaintext
4. Extract inner encrypted blob from middle layer
5. Decrypt inner (encrypted) layer → intro point plaintext
6. Parse `introduction-point` entries with link specifiers, onion-key, auth-key, enc-key

**Certificate parsing (`extract_blinded_key_from_cert`):**
- Version 0x01, type 0x08 (HS_V3_DESC_SIGNING)
- Searches extension 0x04 (SIGNED_KEY) for blinded public key
- Falls back to CERTIFIED_KEY field if extension not found

### 7.3 Introduction Point Serialization

**`IntroductionPoint`** fields:
- `link_specifiers` — Vec of IPv4/IPv6/LegacyId/Ed25519Id
- `onion_key` — 32-byte ntor key
- `auth_key_cert` — Ed25519 certificate bytes
- `enc_key` — 32-byte encryption key
- `enc_key_cert` — Ed25519 certificate bytes

**Link specifier types:**

| Type | Code | Size | Content |
|------|------|------|---------|
| IPv4 | 0 | 6 | 4-byte addr + 2-byte port |
| IPv6 | 1 | 18 | 16-byte addr + 2-byte port |
| Legacy RSA ID | 2 | 20 | RSA fingerprint |
| Ed25519 ID | 3 | 32 | Ed25519 identity |

**Binary serialization format:**
```
NSPEC (1B) || [LSTYPE(1B) LSLEN(1B) LSDATA(LSLEN)]... || 
onion_key(32B) || auth_cert_len(2B) || auth_cert || 
enc_key(32B) || enc_cert_len(2B) || enc_cert
```

---

## 8. Coordination Layer

### 8.1 Coordinator (`coord/mod.rs`)

The `Coordinator` wraps:
- **Transport** — `WgTransport` (UDP over WireGuard) or Tor fallback
- **Election** — Publisher election logic
- **PeerTracker** — Peer state management

**Key methods:**
- `broadcast(msg)` — Send to all known peers
- `receive()` — Receive next message (with timeout)
- `process_message(msg)` — Update election + peer state
- `add_runtime_peer(id, pubkey, endpoint, tunnel_ip)` — Add WG peer at runtime
- `has_wg_peer(id)` — Check if peer is known
- `send_to_tunnel_ip(msg, ip)` — Direct send to specific peer

### 8.2 WireGuard Transport (`coord/wireguard.rs`)

**`WgTransport`** — UDP-based peer communication over WireGuard tunnel.

**Setup:**
1. Generate WG keypair if needed
2. Create `wg-rb` interface via `ip link add`
3. Set private key and listen port (51820)
4. Assign tunnel IP (e.g., `10.200.200.1/24`)
5. Add pre-configured peers with `wg set peer`
6. Bring interface up
7. Bind UDP socket on `tunnel_ip:51821`

**Constants:**
- WG interface name: `wg-rb`
- Coordination UDP port: `51821`
- Persistent keepalive: `25` seconds

**Broadcast:** Iterates all known peer tunnel IPs, sends JSON to `peer_ip:51821`

**Cleanup on Drop:** Brings interface down, deletes it.

### 8.3 Message Protocol (`coord/messages.rs`)

All messages are JSON-serialized `CoordMessage`:

```rust
CoordMessage {
    node_id: String,        // Sender's node ID
    timestamp: u64,         // Unix timestamp
    message: MessageType,   // Payload variant
}
```

**8 message types:**

| Type | Payload Fields | Purpose |
|------|---------------|---------|
| `Heartbeat` | `role`, `last_publish_ts`, `known_peers` (gossip), `intro_point_count` | Liveness + state sync |
| `LeaseClaim` | `priority` | Claim publisher role |
| `LeaseRelease` | *(none extra)* | Release publisher role |
| `BackendUnhealthy` | `backend_name`, `reason` | Report unhealthy backend |
| `PeerAnnounce` | `wg_pubkey`, `wg_endpoint`, `tunnel_ip`, `cluster_token` | Introduce self to cluster |
| `IntroPoints` | `intro_points: Vec<IntroPointData>` | Share serialized intro points |
| `JoinRequest` | `cluster_token`, `wg_pubkey`, `wg_endpoint`, `tunnel_ip`, `request_time` | Request cluster membership |
| `JoinResponse` | `success`, `error`, `responder_*`, `known_peers` | Join approval + peer info |

**Time validation:**
```rust
fn is_valid_time(tolerance_secs: u64) -> bool {
    |now - msg.timestamp| <= tolerance_secs
}
```
Default tolerance: 5 seconds.

---

## 9. Election & Lease System

### 9.1 Election (`coord/election.rs`)

**Priority-based, deterministic, no consensus needed.**

**`NodeRole` enum:** `Publisher` | `Standby`

**Election state per node:**
- `our_id`, `our_priority` — This node's identity
- `role` — Current role
- `known_nodes` — HashMap of `(node_id → (priority, last_heartbeat))`
- `heartbeat_timeout_secs`, `takeover_grace_secs`
- `suspect_since` — When current publisher became suspect

**Publisher determination (`is_highest_priority_candidate`):**
1. Filter alive nodes (heartbeat within `heartbeat_timeout_secs`)
2. Include self
3. Sort by priority (lower = higher priority)
4. Return whether we are the highest priority candidate

**Takeover logic (`should_take_over`):**
1. If no publisher exists → take over immediately
2. If publisher is unresponsive (heartbeat timeout) → mark as suspect
3. If suspect for longer than `takeover_grace_secs` → take over
4. Only take over if we are the highest priority candidate

**Methods:**
- `become_publisher()` — Set role to Publisher
- `become_standby()` — Set role to Standby
- `process_heartbeat(node_id, role, priority)` — Update known node state
- `is_publisher()` → bool

### 9.2 Lease (`coord/lease.rs`)

**`Lease`** struct:
- `holder` — Node ID holding the lease
- `acquired` — When acquired (Instant)
- `duration` — Lease duration (Duration)
- `expires` — Expiration time (Instant)

**`LeaseManager`** methods:
- `acquire(node_id, duration)` → Result — Acquire if free or same holder
- `release(node_id)` → bool — Release if holder matches
- `renew(node_id, duration)` → bool — Extend if holder matches
- `holder()` → Option<&str> — Current holder
- `is_expired()` → bool
- `is_held_by(node_id)` → bool

---

## 10. Peer Tracking & Gossip

### 10.1 Peer Lifecycle (`coord/peers.rs`)

```
Joining → Initializing → Healthy → Unhealthy → Dead
```

| State | Entry Condition | Eligible for Descriptor? |
|-------|-----------------|--------------------------|
| `Joining` | Just received JoinRequest, added to WG, no heartbeat yet | No |
| `Initializing` | Receiving heartbeats but `intro_point_count == 0` | No |
| `Healthy` | Heartbeats received AND `intro_point_count > 0` | **Yes** |
| `Unhealthy` | Was healthy, now missing heartbeats | No |
| `Dead` | Timed out completely | No |

### 10.2 PeerState Fields

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | String | Unique identifier |
| `wg_pubkey` | Option | WireGuard public key |
| `endpoint` | Option | WG endpoint (public IP:port) |
| `tunnel_ip` | Option | WG tunnel IP |
| `role` | NodeRole | Last known role |
| `last_heartbeat` | SystemTime | When last heartbeat received |
| `missed_heartbeats` | u32 | Count of missed heartbeats |
| `alive` | bool | Is the peer alive? |
| `intro_points` | Vec | Serialized intro point data |
| `lifecycle` | PeerLifecycle | Current lifecycle state |
| `last_intro_point_count` | usize | From last heartbeat |

### 10.3 PeerTracker

**`PeerTracker::new(heartbeat_interval, dead_threshold)`**

- `dead_threshold` = 3 (mark dead after 3 missed heartbeats)
- Timeout check: `since_last_heartbeat() > heartbeat_interval * 2`

**Key methods:**
- `process_heartbeat(msg)` — Update or create peer from heartbeat
- `process_gossip(info)` → bool — Add unknown peer from gossip
- `process_peer_announce(msg)` → bool — Add peer from announcement
- `update_intro_points(node_id, data)` — Store peer's intro points
- `find_unknown_peers(gossip)` → Vec — Find peers we don't know
- `collect_peer_intro_points()` → Vec — All intro points from alive peers
- `alive_count()` → usize
- `check_timeouts()` → Vec (dead peer IDs)
- `prune_dead()` → Vec (removed peer IDs)

### 10.4 Gossip Protocol

Every heartbeat includes `known_peers: Vec<KnownPeerInfo>` — all peers this node knows about.

**Gossip flow:**
1. Node A sends heartbeat with its `known_peers` list
2. Node B receives it, calls `find_unknown_peers()`
3. For each unknown peer: add to WireGuard + PeerTracker
4. Mesh self-heals regardless of join topology (chain → full mesh)

**`KnownPeerInfo`:**
```rust
{ node_id, wg_pubkey, wg_endpoint, tunnel_ip }
```

---

## 11. Descriptor Publishing

### 11.1 Publisher (`balance/publish.rs`)

**`Publisher`** fields:
- `identity` — MasterIdentity
- `revision_counter` — Monotonically increasing, initialized to `unix_timestamp() * 3`

**Revision counter strategy:**
- Initial value: `timestamp * 3` (high enough to override Tor's OPE-based counters)
- Incremented by 1 each publish cycle
- Ensures our HSPOST descriptor takes precedence over Tor's auto-published one

**Dual time period publishing:**
```rust
let (current_tp, next_tp) = current_and_next_time_periods();
// Build descriptor for current_tp → HSPOST
// Build descriptor for next_tp → HSPOST
```

Per rend-spec-v3 §2.2.1: "A service MUST generate and upload descriptors for the current and the following time period."

### 11.2 Publish Loop (`scheduler/loops.rs::publish_loop`)

**Timing:** Waits 90 seconds at startup (for HS + intro points to establish), then runs every `refresh_interval_secs` (default 600s = 10 min).

**Logic per tick:**

```
1. Check for active peers → determine mode
2. Check/perform publisher election
3. If not publisher → skip

SINGLE-NODE MODE (no active peers):
  - Re-enable Tor auto-publish if it was disabled
  - Collect own intro points
  - HSPOST descriptor for master address
  
MULTI-NODE MODE (active peers):
  - Disable Tor auto-publish (SETCONF PublishHidServDescriptors=0)
  - Collect own intro points
  - Collect + deserialize peer intro points (from PeerTracker)
  - Merge: own + peer, cap at 20
  - HSPOST merged descriptor for master address
```

### 11.3 HSPOST Command Format

```
+HSPOST HSADDRESS=<56-char-address>\r\n
<descriptor with CRLF line endings>\r\n
.\r\n
```

### 11.4 Descriptor Merging (`balance/merge.rs`)

**Strategy: Fair per-backend + random fill**

1. Calculate fair share: `max_intro_points / num_backends`
2. Take up to fair share from each backend
3. If under max, randomly fill from remaining intro points
4. Final shuffle for randomization

---

## 12. Intro Point Management

### 12.1 Intro Point Refresh Loop (`scheduler/loops.rs::intro_point_refresh_loop`)

**Timing:**
- Waits 60 seconds at startup
- Then checks every 30 seconds

**Flow:**
1. Connect to Tor control port
2. `GETINFO hs/service/desc/id/<master_address>` — get our cached descriptor
3. Parse and decrypt descriptor using master identity key
4. Extract introduction points
5. Serialize each intro point to base64 binary
6. Broadcast `IntroPoints` message to all peers (EVERY tick, not just on change)
7. Update `state.own_intro_points` if changed

**Why broadcast every tick:**
- A restarted peer needs to receive our intro points
- Messages may be lost if peer tracker doesn't have us yet
- Periodic broadcast ensures eventual consistency

### 12.2 Heartbeat Intro Point Piggyback

The heartbeat loop ALSO broadcasts intro points with every heartbeat:
```
heartbeat → broadcast intro points (redundant, ensures delivery)
```

---

## 13. Reverse Proxy

### 13.1 OnionService (`balance/onion_service.rs`)

**Listens on:** `127.0.0.1:<local_port>` (default 8080)

**Connection handling:**
1. Accept TCP connection from Tor
2. Peek at first bytes to check for join request (`POST /.rb/<secret>`)
3. If join request → handle via JoinHandler
4. Otherwise → proxy to target

**Proxy flow:**
1. Connect to Tor SOCKS5 at `127.0.0.1:<socks_port>`
2. SOCKS5 handshake (version 5, no auth)
3. SOCKS5 CONNECT to `target.onion:target_port`
4. If TLS enabled → wrap with rustls TLS (custom `OnionCertVerifier` skips cert validation for .onion)
5. Bidirectional proxy with header rewriting

### 13.2 Header Rewriting

**Request headers (client → target):**
- `Host:` → rewritten to target address

**Response headers (target → client):**
- `Location:` → target URLs converted to relative paths (e.g., `http://target.onion/path` → `/path`)
- `Set-Cookie:` → `Domain=` attribute stripped
- `Content-Security-Policy:` → target.onion references replaced with master.onion

### 13.3 Transfer Encoding Support

- **Fixed-length** bodies (Content-Length)
- **Chunked** transfer encoding
- **Keep-alive** connection support (HTTP/1.1)

### 13.4 TLS to Target

When `use_tls = true`:
- Uses `OnionCertVerifier` for .onion targets — accepts ANY certificate
- Rationale: Tor already provides encryption + .onion address is cryptographic auth
- Standard webpki roots for clearnet targets

---

## 14. Tor Bootstrap Channel (Join)

### 14.1 Overview

New nodes join the cluster by connecting to the master `.onion` address via Tor SOCKS. The existing node's reverse proxy intercepts the join request and exchanges WireGuard info.

### 14.2 Join Endpoint

**Path:** `POST /.rb/<join_secret>`

**JoinRequest payload:**
```json
{
  "cluster_token": "shared-secret",
  "wg_pubkey": "base64-pubkey",
  "wg_endpoint": "1.2.3.4:51820",
  "tunnel_ip": "10.200.200.2",
  "request_time": 1234567890
}
```

**JoinResponse payload:**
```json
{
  "success": true,
  "responder_node_id": "node-abc",
  "responder_wg_pubkey": "...",
  "responder_wg_endpoint": "...",
  "responder_tunnel_ip": "...",
  "known_peers": [...]
}
```

### 14.3 Join Validation (`balance/join_handler.rs`)

| Check | Method | Failure Response |
|-------|--------|-----------------|
| Path matches `/.rb/<join_secret>` | Constant-time comparison (`subtle::ConstantTimeEq`) | 404 (generic) |
| `cluster_token` matches | Constant-time comparison | 404 (generic, prevents oracle) |
| `request_time` within 5 minutes | Age check | 404 |
| `request_time` not >60s in future | Clock check | 404 |
| Content-Length 1–8192 | Size check | 400 |

All auth failures return generic 404 to prevent timing oracle.

**`MAX_REQUEST_AGE`** = 300 seconds (5 minutes)

### 14.4 Bootstrap Client (`balance/bootstrap.rs`)

**`BootstrapClient::join()`:**
1. Connect to Tor SOCKS5
2. SOCKS5 CONNECT to `master.onion:80`
3. Send HTTP POST to `/.rb/<join_secret>` with JSON body
4. Parse JSON response
5. Return `JoinResponsePayload`

**Retry:** `join_with_retry(max_attempts, delay)` — configurable retries with delay

**Initial bootstrap in scheduler:**
- 5 attempts × 15-second delay
- Happens BEFORE hidden service is configured (prevents self-connection)

---

## 15. Health Checking

### 15.1 Backend States (`balance/backend.rs`)

| State | Description | `is_usable()` |
|-------|-------------|----------------|
| `Unknown` | Initial state, no data yet | No |
| `Healthy` | Descriptor is fresh | Yes |
| `Stale` | Descriptor is aging | Yes |
| `Dead` | Descriptor too old or missing | No |
| `Excluded` | Manually excluded from rotation | No |

### 15.2 HealthChecker (`balance/health.rs`)

**Descriptor age evaluation:**

| Condition | Health |
|-----------|--------|
| Age < `descriptor_max_age_secs` × 2/3 | `Healthy` |
| Age ≥ 2/3 max but < max | `Degraded` |
| Age ≥ max | `Unhealthy` |

**Additional checks:**
- Descriptor is `Some` and is valid (`is_valid()`)
- Descriptor has introduction points
- HTTP probe placeholder (not yet implemented — returns `Ok(true)`)

### 15.3 Descriptor Freshness (`tor/descriptors.rs`)

```rust
fn is_valid(&self) -> bool {
    elapsed < lifetime * 60  // lifetime in minutes
}

fn is_fresher_than(&self, other) -> bool {
    self.revision_counter > other.revision_counter
}
```

---

## 16. Self-Repair

### 16.1 Repair Actions (`repair/actions.rs`)

| Action | Trigger | Implementation |
|--------|---------|----------------|
| `RestartTor` | Tor control port failure | `systemctl restart tor` or `service tor restart` |
| `RestartBackend` | Backend unhealthy | `systemctl restart rustbalance-backend-<name>` |
| `ExcludeBackend` | Persistent backend failure | State-level exclusion |
| `IncludeBackend` | Backend recovered | State-level re-inclusion |
| `ForceRepublish` | Descriptor issues | Scheduler-level immediate publish |
| `StepDown` | Self-detected issues | Coordinator-level role change |

### 16.2 Diagnosis Heuristics

```rust
fn diagnose(failure: &str) -> Option<RepairAction> {
    if failure.contains("tor") || failure.contains("control port") → RestartTor
    if failure.contains("descriptor") → ForceRepublish
}
```

### 16.3 Tor Liveness Check

```rust
fn is_tor_running() -> bool {
    systemctl is-active --quiet tor
}
```

---

## 17. Scheduler Loops & Timings

### 17.1 Concurrent Tasks

| Loop | Interval | Wait Before Start | Condition |
|------|----------|-------------------|-----------|
| **heartbeat_loop** | `heartbeat_interval_secs` (10s) | None | WG configured |
| **receive_loop** | 100ms timeout per recv | None | WG configured |
| **publish_loop** | `refresh_interval_secs` (600s) | 90s initial wait | Always |
| **intro_point_refresh_loop** | 30s | 60s initial wait | Always |
| **proxy (run_proxy)** | Event-driven (accept loop) | None | Always |
| **background_bootstrap_loop** | 30s | None | Joining node + WG |

### 17.2 Timing Summary

| Parameter | Default | Purpose |
|-----------|---------|---------|
| Heartbeat interval | **10s** | Liveness broadcast |
| Heartbeat timeout | **30s** | Peer unresponsive threshold |
| Dead threshold | **3 missed** | Mark peer dead (= 60s with 2× interval check) |
| Lease duration | **60s** | Publisher lease exclusivity |
| Takeover grace | **90s** | Wait before claiming publisher from suspect |
| Publish interval | **600s** (10 min) | Descriptor refresh |
| Publish startup delay | **90s** | Wait for HS + intro points |
| Intro point refresh | **30s** | Check for new intro points |
| Intro point startup delay | **60s** | Wait for HS to establish |
| Descriptor max age | **900s** (15 min) | Backend descriptor staleness |
| Descriptor lifetime | **180 min** (3 hours) | Per Tor spec |
| Time period length | **1440 min** (24 hours) | Key blinding rotation |
| Time period offset | **720 min** (12 hours) | Boundaries at 12:00 UTC |
| Bootstrap attempts | **5** | Join retries |
| Bootstrap delay | **15s** | Between join retries |
| Bootstrap circuit wait | **30s** | Wait for Tor circuits |
| Join request max age | **300s** (5 min) | Replay prevention |
| Clock skew tolerance | **5s** | Message timestamp validation |
| Backoff jitter | **15s** | Randomization for backoff |
| Probe timeout | **5s** | HTTP health probe timeout |
| SOCKS5 target connect | — | Via Tor circuits (variable) |
| Tor control timeout | **10s** | Per command response |
| Cert expiration | **+3 hours** | Descriptor certificates |
| WG keepalive | **25s** | NAT traversal |

### 17.3 Startup Timeline

```
t=0s    Load config, connect Tor, create coordinator
t=0s    Write master key to HiddenServiceDir

IF INIT NODE:
  t=0s    SETCONF HiddenServiceDir/Port
  t=5s    Verify hostname, mark HS running
  t=5s    Spawn all loops

IF JOINING NODE:
  t=0s    Wait 30s for Tor circuits
  t=30s   Bootstrap attempt 1 via master.onion
  t=45s   Bootstrap attempt 2 (if needed)
  t=60s   Bootstrap attempt 3 (if needed)
  t=75s   Bootstrap attempt 4 (if needed)
  t=90s   Bootstrap attempt 5 (if needed)
  t=~90s  SETCONF HiddenServiceDir/Port
  t=~95s  Verify hostname, mark HS running
  t=~95s  Spawn all loops

LOOPS:
  t=start+0s   receive_loop, heartbeat_loop, proxy start immediately
  t=start+60s  intro_point_refresh_loop begins checking
  t=start+90s  publish_loop begins publishing
```

---

## 18. State Model

### 18.1 RuntimeState (`state/model.rs`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `role` | NodeRole | `Standby` | Current election role |
| `last_publish` | Option\<SystemTime\> | `None` | When last published |
| `own_intro_points` | Vec\<IntroductionPoint\> | `[]` | This node's intro points |
| `peer_intro_points` | HashMap | `{}` | Intro points from peers |
| `lease` | Option\<Lease\> | `None` | Current publisher lease |
| `hs_running` | bool | `false` | Is hidden service active? |
| `target_healthy` | bool | `false` | Is target service healthy? |
| `tor_publish_disabled` | bool | `false` | Is Tor auto-publish off? |
| `node_onion_address` | Option\<String\> | `None` | This node's onion address (= master) |

### 18.2 State Sharing

All state is wrapped in `Arc<RwLock<RuntimeState>>` for safe async access across tasks.

---

## 19. Utility Functions

### 19.1 Encoding (`util/mod.rs`)

- `base64_encode(data)` → String (standard alphabet, no padding)
- `base64_decode(data)` → Option\<Vec\<u8\>\>

### 19.2 Randomization (`util/rand.rs`)

| Function | Description |
|----------|-------------|
| `jitter(base, max)` | base + random(0..=max) seconds |
| `signed_jitter(base, max)` | base ± random(-max..=max), min 0 |
| `backoff(attempt, base, max)` | base × 2^attempt, capped at max, with jitter |
| `random_bytes::<N>()` | N random bytes |

### 19.3 Time (`util/time.rs`)

| Function | Description |
|----------|-------------|
| `unix_timestamp()` | Current Unix seconds |
| `unix_timestamp_ms()` | Current Unix milliseconds |
| `from_unix_timestamp(ts)` | Convert to SystemTime |
| `is_time_valid(ts, tolerance)` | Within ±tolerance of now? |
| `format_duration(secs)` | "42s", "5m 30s", "2h 15m" |

---

## 20. Key Constants & Defaults

### Build & Runtime

| Constant | Value | Location |
|----------|-------|----------|
| `VERSION` | `"0.1.0"` | `lib.rs` |
| `COORD_PORT` | `51821` | `coord/wireguard.rs` |
| `WG_INTERFACE` | `"wg-rb"` | `coord/wireguard.rs`, `balance/join_handler.rs` |
| `WG_LISTEN_PORT` | `51820` | Config default |
| `LOCAL_PORT` | `8080` | Config default |

### Tor Protocol

| Constant | Value | Location |
|----------|-------|----------|
| `TIME_PERIOD_LENGTH_MINUTES` | `1440` (24h) | `crypto/blinding.rs` |
| `TIME_PERIOD_ROTATION_OFFSET_MINUTES` | `720` (12h) | `crypto/blinding.rs` |
| `DESCRIPTOR_LIFETIME` | `180` min (3h) | `tor/descriptors.rs` default |
| `MAX_INTRO_POINTS` | `20` | `scheduler/loops.rs`, config |
| `DESCRIPTOR_VERSION` | `3` | `tor/descriptors.rs` |

### Crypto

| Constant | Value | Purpose |
|----------|-------|---------|
| Blinding string | `"Derive temporary signing key\x00"` | Key blinding factor |
| Credential string | `"credential"` | Subcredential derivation |
| Subcredential string | `"subcredential"` | Subcredential derivation |
| Outer encryption | `"hsdir-superencrypted-data"` | Middle layer encryption |
| Inner encryption | `"hsdir-encrypted-data"` | Inner layer encryption |
| Descriptor sig prefix | `"Tor onion service descriptor sig v3"` | Descriptor signature |
| PRF derivation | `"Derive temporary signing key hash input"` | Blinded signing nonce |
| Cert type 0x08 | `BLINDED_ID_V_SIGNING` | Signing key cert |
| Cert type 0x09 | `HS_IP_V_SIGNING` | Auth key cert |
| Cert type 0x0B | `NTOR_CC_V_SIGNING` | Enc key cert |

### Cookie Paths

```
/run/tor/control.authcookie
/var/run/tor/control.authcookie
/var/lib/tor/control_auth_cookie
```

---

## 21. Security Measures

| Feature | Implementation | Location |
|---------|----------------|----------|
| Constant-time token comparison | `subtle::ConstantTimeEq` | `join_handler.rs` |
| Join request replay prevention | `request_time` within 5 min | `join_handler.rs` |
| Generic 404 on all auth failures | Prevents timing oracle | `join_handler.rs` |
| Message timestamp validation | ±5s clock skew tolerance | `messages.rs` |
| Own-message rejection | Skip messages from own `node_id` | `loops.rs` receive_loop |
| Key file permissions | 600 (files), 700 (dir) | `keys.rs` |
| Key file ownership | `chown debian-tor:debian-tor` | `keys.rs` |
| TLS cert skip for .onion only | `OnionCertVerifier` | `onion_service.rs` |
| MAC-then-decrypt | Verify MAC before decrypting | `descriptor.rs` |
| Ephemeral signing key | Fresh keypair per descriptor | `descriptor.rs` |
| Cluster token authentication | Token in PeerAnnounce messages | `loops.rs` |
| WG private key temp file cleanup | Written then deleted | `wg.rs` |

---

## 22. Data Flow Diagrams

### 22.1 Publish Cycle (Multi-Node)

```
intro_point_refresh_loop (every 30s)
  │
  ├─ Tor ControlPort: GETINFO hs/service/desc/id/<master>
  ├─ Decrypt descriptor → extract intro points
  ├─ Store in state.own_intro_points
  └─ Broadcast IntroPoints message to all peers (via WG UDP)
                │
                ▼
    Peers store in peer_tracker.intro_points[node_id]

heartbeat_loop (every 10s)
  │
  ├─ Broadcast Heartbeat (role, intro_point_count, known_peers)
  └─ Broadcast IntroPoints (redundant delivery)

receive_loop (100ms poll)
  │
  ├─ Process Heartbeat → update election, peer state, gossip
  ├─ Process IntroPoints → store peer intro points
  ├─ Process PeerAnnounce → add WG peer, validate cluster_token
  └─ Process LeaseClaim/Release → update election

publish_loop (every 600s, 90s startup delay)
  │
  ├─ Check active peers → multi-node detected
  ├─ Election: should_take_over() → become_publisher()
  ├─ SETCONF PublishHidServDescriptors=0 (once)
  ├─ Collect own_intro_points + peer_intro_points
  ├─ Merge + cap at 20
  ├─ DescriptorBuilder for current_time_period
  │   ├─ Blind identity key → blinded_key
  │   ├─ Derive subcredential
  │   ├─ Build inner layer (intro points)
  │   ├─ Encrypt inner → AES-256-CTR + MAC
  │   ├─ Build middle layer (auth fields + encrypted inner)
  │   ├─ Encrypt middle → AES-256-CTR + MAC
  │   ├─ Build outer (cert + encrypted middle + signature)
  │   └─ Sign with blinded private key
  ├─ DescriptorBuilder for next_time_period (same process)
  ├─ HSPOST descriptor_current to Tor
  └─ HSPOST descriptor_next to Tor
        │
        ▼
    Tor uploads to HSDirs → Clients can resolve master.onion
```

### 22.2 Node Join Flow

```
New Node (VM2)                           Init Node (VM1)
    │                                        │
    │  curl deploy.sh --join ...             │  Running with HS active
    │  RustBalance starts                    │  JoinHandler enabled at /.rb/<secret>
    │                                        │
    ├─ Wait 30s for Tor circuits             │
    │                                        │
    ├─ SOCKS5 CONNECT master.onion:80 ──────►│
    │                                        │
    ├─ POST /.rb/<secret> ──────────────────►│
    │  { cluster_token, wg_pubkey,           ├─ Validate join_secret (constant-time)
    │    wg_endpoint, tunnel_ip }            ├─ Validate cluster_token (constant-time)
    │                                        ├─ Validate request_time (<5 min)
    │                                        ├─ wg set peer <pubkey> endpoint <ep> ...
    │                                        ├─ Add to Coordinator + PeerTracker
    │                                        │
    │  ◄──────────────────────── 200 OK ─────┤
    │  { responder_*, known_peers }          │
    │                                        │
    ├─ wg set peer <responder_pubkey> ...    │
    ├─ Add to Coordinator                    │
    │                                        │
    ├─ SETCONF HiddenServiceDir (NOW)        │
    ├─ Wait 5s for intro points              │
    │                                        │
    ├─ heartbeat_loop starts ───────────────►│  receive_loop processes heartbeat
    │  ◄──────────────────────── heartbeat ──┤  heartbeat with gossip
    │                                        │
    ├─ intro_point_refresh_loop (60s wait)   │
    ├─ Fetches own descriptor                │
    ├─ Extracts intro points                 │
    ├─ Broadcasts IntroPoints ──────────────►│  Stores peer intro points
    │                                        │
    │                                        ├─ publish_loop: detects active peer
    │                                        ├─ Merges own + peer intro points
    │                                        └─ HSPOST merged descriptor
```

---

*Generated from complete source analysis of RustBalance. Every value, timing, check, and flow documented from the actual code.*
