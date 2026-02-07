# RustBalance — FlowChart

> Step-by-step engine breakdown, recurring check schedules, failure recovery matrix, and hardening roadmap.

---

## Table of Contents

1. [Single-Node Mode — Startup Sequence](#1-single-node-mode--startup-sequence)
2. [Single-Node → Multi-Node Transition](#2-single-node--multi-node-transition)
3. [New Node Joining a Cluster](#3-new-node-joining-a-cluster)
4. [Recurring Checks & Schedules](#4-recurring-checks--schedules)
5. [What RustBalance Can Currently Recover From](#5-what-rustbalance-can-currently-recover-from)
6. [What RustBalance Cannot Currently Recover From](#6-what-rustbalance-cannot-currently-recover-from)
7. [Hardening Roadmap](#7-hardening-roadmap-easy--difficult)

---

## 1. Single-Node Mode — Startup Sequence

This is what happens when you deploy the first node with `--init`. No peers exist yet.

### Phase 1: Process Initialization

| Step | What happens | Code location |
|------|-------------|---------------|
| 1 | Binary starts, CLI parses `rustbalance run` command | `main.rs` |
| 2 | Loads `config.toml` from disk (or `--config` path) | `config/file.rs` |
| 3 | Creates an empty `RuntimeState` (role=Standby, no intro points, hs_running=false) | `state/model.rs` |
| 4 | Connects to Tor control port at `127.0.0.1:9051`, authenticates via cookie file (tries 3 paths) or password | `tor/control.rs` |
| 5 | Creates Coordinator with WireGuard transport — sets up `wg-rb` interface, assigns tunnel IP, binds UDP socket on `tunnel_ip:51821` | `coord/mod.rs`, `coord/wireguard.rs` |
| 6 | Initializes election engine with this node's ID, priority, heartbeat timeout (30s), takeover grace (90s) | `coord/election.rs` |

### Phase 2: Hidden Service Setup

| Step | What happens |
|------|-------------|
| 7 | Detects no pre-configured WireGuard peers → this is an init node |
| 8 | Loads master Ed25519 identity key from `master.identity_key_path` |
| 9 | Writes `hs_ed25519_secret_key`, `hs_ed25519_public_key`, and `hostname` into `node.hidden_service_dir` |
| 10 | Sets file permissions: dir=0700, files=0600, owner=debian-tor |
| 11 | Sends `SETCONF HiddenServiceDir="..." HiddenServicePort="80 127.0.0.1:8080"` to Tor via control port |
| 12 | Sleeps 5 seconds waiting for Tor to create intro point circuits |
| 13 | Reads `hostname` file from HiddenServiceDir, verifies it matches the master `.onion` address |
| 14 | Stores onion address in state, marks `hs_running = true` |

### Phase 3: Service Startup

| Step | What happens |
|------|-------------|
| 15 | No WireGuard peers detected → auto-becomes Publisher immediately (no election needed) |
| 16 | Creates PeerTracker (heartbeat_interval=10s, dead_threshold=3) |
| 17 | Enables JoinHandler on the reverse proxy if `join_secret` is configured |
| 18 | Spawns 4 concurrent async tasks (heartbeat + receive only if WG configured, otherwise skipped): |

**Tasks spawned:**

| Task | Starts at | Runs every | What it does |
|------|-----------|------------|-------------|
| **Reverse proxy** | Immediately | Event-driven (accept loop) | Listens on `127.0.0.1:8080`, accepts TCP connections from Tor, proxies to target via SOCKS5 |
| **Publish loop** | t+90s | 600s (10 min) | Publishes descriptor for master address via HSPOST |
| **Intro point refresh** | t+60s | 30s | Fetches own descriptor from Tor, parses/decrypts it, extracts intro points |
| **Heartbeat loop** | Immediately | 10s | Broadcasts heartbeat + intro points to WG peers (no-op if no peers) |
| **Receive loop** | Immediately | 100ms poll | Listens for WG UDP messages (no-op if no peers) |

### Phase 4: Steady State (Single-Node)

Once everything is running, the engine is doing this on repeat:

```
Every 30 seconds:
  → Connect to Tor control port
  → GETINFO hs/service/desc/id/<master_address>
  → Decrypt the descriptor with master key
  → Extract 3 introduction points Tor created for us
  → Store in state.own_intro_points
  → Broadcast IntroPoints message to WG (no-op, no peers)

Every 10 minutes (first at t+90s):
  → Check active peers → 0 → single-node mode
  → Already publisher, proceed
  → Tor auto-publish is ON (default)
  → Collect own_intro_points (3 IPs)
  → Build descriptor: blind key for current time period, encrypt layers, sign
  → HSPOST to Tor (both current + next time period)
  → Revision counter = timestamp*3 (ensures our HSPOST beats Tor's auto-publish)

Every 10 seconds (heartbeat):
  → Build heartbeat message (role=Publisher, intro_point_count=3, known_peers=[self])
  → Broadcast via WG UDP → no peers to send to, silently succeeds

Every 100ms (receive):
  → Poll WG UDP socket → timeout → loop back
  → No messages arrive (no peers)

Reverse proxy (continuous):
  → Accept connection from Tor → peek first bytes
  → If /.rb/<secret> → handle join request
  → Otherwise → SOCKS5 connect to target.onion:port → bidirectional proxy with header rewriting
```

---

## 2. Single-Node → Multi-Node Transition

This describes what happens on the **existing init node (Node 1)** when a second node joins.

### Trigger: Join Request Arrives

| Step | What happens |
|------|-------------|
| 1 | Reverse proxy accepts TCP connection from Tor |
| 2 | Peeks first bytes → sees `POST /.rb/<join_secret>` → routes to JoinHandler |
| 3 | JoinHandler validates join_secret using constant-time comparison (`subtle::ConstantTimeEq`) |
| 4 | Parses JSON body: `cluster_token`, `wg_pubkey`, `wg_endpoint`, `tunnel_ip`, `request_time` |
| 5 | Validates cluster_token (constant-time comparison) |
| 6 | Validates request_time: not older than 300s (5 min), not more than 60s in the future |
| 7 | All auth failures return generic HTTP 404 (prevents timing oracle attacks) |
| 8 | Runs `wg set wg-rb peer <pubkey> endpoint <endpoint> allowed-ips <tunnel_ip>/32 persistent-keepalive 25` |
| 9 | Adds peer to Coordinator and PeerTracker (lifecycle=Joining) |
| 10 | Responds with 200 OK + JSON: own node info + all known_peers |

### Mode Transition (happens at next publish cycle tick)

| Step | What happens |
|------|-------------|
| 11 | Receive loop starts getting heartbeats from Node 2 on WG UDP (tunnel_ip:51821) |
| 12 | Validates timestamp (±5s clock skew tolerance) |
| 13 | Processes heartbeat → updates election state, peer tracker |
| 14 | Gossip: receives Node 2's known_peers list, checks for unknowns |
| 15 | Receive loop gets IntroPoints messages from Node 2 → stores in PeerTracker |
| 16 | **Next publish_loop tick:** checks active peers → alive_count > 0 → **MULTI-NODE MODE DETECTED** |
| 17 | Sends `SETCONF PublishHidServDescriptors=0` → Tor stops auto-publishing descriptors |
| 18 | Collects own intro points (3) + Node 2's intro points (3) = 6 total |
| 19 | Merges (cap at 20) → builds merged descriptor → HSPOST for both time periods |
| 20 | Clients now randomly select from 6 intro points → traffic distributed across both nodes |

### What the peer lifecycle looks like on Node 1:

```
Join request arrives  → PeerLifecycle::Joining
First heartbeat       → PeerLifecycle::Initializing (intro_point_count == 0)
Heartbeat with IPs    → PeerLifecycle::Healthy (intro_point_count > 0)
                         ↑ now eligible for descriptor inclusion
```

---

## 3. New Node Joining a Cluster

This describes the full startup of a **joining node (Node 2)** from first boot.

### Phase 1: Process Initialization (same as single-node)

| Step | What happens |
|------|-------------|
| 1–6 | Same as single-node: load config, create state, connect Tor, create Coordinator with WG, init election |

### Phase 2: Bootstrap via Tor (BEFORE hidden service)

| Step | What happens |
|------|-------------|
| 7 | Detects pre-configured WireGuard peers → this is a joining node |
| 8 | Writes master key to HiddenServiceDir (but does NOT tell Tor about it yet) |
| 9 | Logs "Joining node: Delaying HS config until after bootstrap" |
| 10 | Sleeps 30 seconds waiting for Tor to establish circuits |
| 11 | **Bootstrap attempt 1:** Connects to Tor SOCKS at `127.0.0.1:9050` |
| 12 | SOCKS5 CONNECT to `master.onion:80` (routes through Tor to Node 1) |
| 13 | Sends `POST /.rb/<join_secret>` with JSON body containing our WG info + cluster token |
| 14 | Receives JSON response: Node 1's WG info + known_peers list |
| 15 | Adds Node 1 as WireGuard peer: `wg set wg-rb peer <pubkey> endpoint <ip:51820> allowed-ips <tunnel_ip>/32` |
| 16 | Also adds any other known_peers from the response |

**If bootstrap attempt fails:** Retries up to 5 times with 15-second delays between attempts.

### Phase 3: Hidden Service Setup (AFTER bootstrap)

| Step | What happens |
|------|-------------|
| 17 | NOW sends SETCONF to Tor with the HiddenServiceDir + HiddenServicePort |
| 18 | Sleeps 5 seconds for Tor to create intro points |
| 19 | Reads hostname file, verifies it matches master address |
| 20 | Marks `hs_running = true` |

**Why this order matters:** If we configured the hidden service BEFORE bootstrap, our `SOCKS5 CONNECT master.onion:80` would route to ourselves (since we ARE the master address now). By bootstrapping first, Tor routes us to Node 1 (the only other node publishing the descriptor).

### Phase 4: Ongoing Operations

| Step | What happens |
|------|-------------|
| 21 | Spawns all 6 tasks: heartbeat, receive, publish, intro refresh, proxy, background bootstrap |
| 22 | Heartbeat loop starts broadcasting immediately → Node 1 receives our heartbeats |
| 23 | After 60s: intro_point_refresh_loop fetches our descriptor, extracts our 3 intro points |
| 24 | Broadcasts IntroPoints to Node 1 on every tick + every heartbeat |
| 25 | Receive loop processes Node 1's heartbeats → election: Node 1 is Publisher, we stay Standby |
| 26 | We store Node 1's intro points in our PeerTracker |
| 27 | Publish loop: not publisher → skip publish → wait for next tick |

### Node 2 Steady State

```
Every 30 seconds:
  → Fetch own descriptor from Tor → parse → extract 3 intro points
  → Broadcast IntroPoints to all peers
  → Store in own state

Every 10 seconds:
  → Send heartbeat (role=Standby, intro_point_count=3, known_peers=[self, node1])
  → Also broadcast IntroPoints data (redundant delivery for consistency)

Every 100ms:
  → Receive messages from Node 1
  → Process heartbeats (update election state)
  → Process IntroPoints (store Node 1's IPs)
  → Gossip: check for unknown peers

Every 10 minutes:
  → Check: are we publisher? → No → skip
  → (Only Node 1 publishes the merged descriptor)

Every 30 seconds (background bootstrap):
  → Check alive peer count
  → If > 0: log "X active peer(s)", done
  → If 0: log "waiting for WireGuard heartbeats" (can't re-bootstrap via Tor since HS is now live)
```

---

## 4. Recurring Checks & Schedules

### 4.1 Active Checks (things we actually do right now)

| Check | Frequency | What it does | Failure behavior |
|-------|-----------|-------------|------------------|
| **Intro point fetch** | Every 30s (after 60s startup delay) | `GETINFO hs/service/desc/id/<addr>` → parse → decrypt → extract IPs | Logs warning, retries next tick. If IPs drop to 0, clears state and logs warning |
| **Heartbeat broadcast** | Every 10s | UDP message to all WG peers with role, intro count, gossip | Logs "Failed to send heartbeat", retries next tick |
| **Heartbeat receive** | 100ms poll | Polls WG UDP socket for messages | Timeout → loop. Error → sleep 1s, retry |
| **Peer liveness** | Every heartbeat processed | Checks `last_heartbeat` age against `heartbeat_interval * 2` | Increments `missed_heartbeats`, transitions lifecycle: Healthy→Unhealthy→Dead |
| **Publish descriptor** | Every 600s (after 90s startup delay) | HSPOST merged descriptor to Tor | Logs warning, retries next tick |
| **Auto-detect mode** | Every publish tick (600s) | Checks `alive_count()` to determine single vs multi-node | Switches between modes automatically |
| **Election/takeover** | Every publish tick (600s) | Checks if publisher is alive, decides whether to take over | Grace period of 90s before takeover |
| **Timestamp validation** | Every received message | Rejects messages where `|now - msg.timestamp| > 5s` | Message silently dropped |
| **Own-message rejection** | Every received message | Drops messages with our own `node_id` | Prevents self-as-peer bug |
| **Background bootstrap** | Every 30s (joining nodes only) | Checks if we have active peers | If 0 peers: logs and waits for WG heartbeats |
| **Tor control port** | Each publish + intro refresh cycle | New TCP connection to 9051, authenticate, run command | Logs warning, retries next cycle |

### 4.2 Checks That DO NOT Exist Yet (placeholders / gaps)

| Check | Status | What it should do |
|-------|--------|------------------|
| **HTTP health probe to target** | **Placeholder** — `probe_http()` returns `Ok(Healthy)` always | Should: SOCKS5 → target.onion → GET `/health` → check for 200 OK |
| **Tor bootstrap status check** | **Not called in scheduler** — `is_bootstrapped()` exists but unused in loops | Should: periodically verify Tor is fully bootstrapped |
| **Tor process liveness** | **Not called in scheduler** — `is_tor_running()` exists but unused in loops | Should: check `systemctl is-active tor` periodically |
| **Descriptor age tracking** | **Not used in scheduler** — `HealthChecker` + `Backend` exist but scheduler doesn't use them | Should: track how old our published descriptor is |
| **Repair action execution** | **Never triggered** — `diagnose()` and `execute_repair()` exist but nothing calls them | Should: auto-diagnose failures and execute repair actions |
| **WireGuard interface health** | **Not checked** | Should: verify `wg-rb` interface is up, `wg show` succeeds |
| **Certificate expiration check** | **Not checked** — certs built with +3h expiration | Should: warn when approaching expiration |
| **Disk space / permissions** | **Not checked** | Should: verify HS dir permissions remain correct |

### 4.3 Timing Map

```
TIME ──────────────────────────────────────────────────────────►

t=0s     Process start, config load, Tor connect, WG setup
         │
t=0s     INIT: SETCONF HiddenServiceDir (immediate)
         JOIN: Sleep 30s for Tor circuits, then bootstrap 1-5 attempts
         │
t=5s     INIT: Read hostname, verify, mark HS running
t=~90s   JOIN: SETCONF after bootstrap, read hostname, verify
         │
         ├── Proxy: accept loop starts NOW
         ├── Heartbeat: broadcasts every 10s starting NOW
         ├── Receive: polls every 100ms starting NOW
         │
t+60s    ├── Intro refresh: first check (then every 30s)
         │
t+90s    └── Publish: first publish (then every 600s)
         │
         ▼ Steady state loops forever ▼

HEARTBEAT    ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░   (every 10s)
RECEIVE      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓   (continuous 100ms poll)
INTRO FETCH  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·  ·   (every 30s)
PUBLISH      ─────────────────────────  │  ─────────  (every 600s)
PROXY        ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■   (continuous accept)
BG BOOTSTRAP ·     ·     ·     ·     ·     ·     ·   (every 30s, join only)
```

---

## 5. What RustBalance Can Currently Recover From

### ✅ Full Recovery (automatic, no intervention)

| Failure | How it recovers | Time to recover |
|---------|----------------|-----------------|
| **Temporary network blip between nodes** | Heartbeats resume when connectivity restores; peer stays alive during `heartbeat_timeout` (30s) window | 0–30s |
| **Peer heartbeat jitter/delay** | 5-second clock skew tolerance on message timestamps; heartbeat timeout gives 30s window | Transparent |
| **Publisher node dies** | Surviving node detects missing heartbeats, waits 90s grace period, takes over publishing | ~120s (30s detection + 90s grace) |
| **Publisher node recovers after dying** | Lower-priority node backs off when it sees higher-priority LeaseClaim; election resolves deterministically | Next heartbeat cycle |
| **Peer joins while running** | JoinHandler adds WG peer at runtime, gossip propagates to all nodes, next publish merges their IPs | Next publish cycle (≤600s) |
| **Intro points rotate** | Intro refresh loop (30s) detects new IPs, broadcasts to peers, next publish uses fresh set | 30–630s |
| **Intro point count drops temporarily** | Loop detects decrease, logs warning, updates state; next Tor cycle may regenerate them | 30–60s |
| **Single → multi-node transition** | publish_loop auto-detects `alive_count > 0`, disables Tor auto-publish, starts merging | Next publish tick |
| **Multi → single-node fallback** | publish_loop detects `alive_count == 0`, re-enables Tor auto-publish, publishes own IPs only | Next publish tick |
| **Duplicate/own messages received** | Filtered by `node_id == config.node.id` check | Immediate |
| **Messages with bad timestamps** | Rejected by `is_valid_time()` check (±5s tolerance) | Immediate |
| **Failed HSPOST** | Logs warning, retries on next publish tick (600s) | ≤600s |
| **Failed Tor control connection (transient)** | Each operation creates a fresh TCP connection; failure logged, retried next cycle | 30s (intro refresh) or 600s (publish) |
| **Gossip mesh healing** | If nodes are connected in a chain (A→B→C), gossip in heartbeats propagates peer info; B tells A about C | 10–20s (1–2 heartbeat cycles) |

### ⚠️ Partial Recovery (works but with caveats)

| Failure | What happens | Limitation |
|---------|-------------|------------|
| **Bootstrap fails on join** | Retries 5 times with 15s delay (75s total). If all fail, proceeds in single-node mode | No re-attempt via Tor after HS is configured (would self-connect). Only WG heartbeats can establish mesh |
| **WG peer unreachable** | Heartbeat timeout (30s) → missed_heartbeats increments → lifecycle transitions: Healthy→Unhealthy→Dead (after 3 missed = ~60s) | Dead peer's intro points removed from descriptor, but descriptor update only happens at next publish tick (≤600s). Clients may hit dead intro points during gap |
| **Tor restarts underneath us** | Intro point refresh loop (30s) will notice descriptor is gone, set IPs to 0, log warning. Tor will re-establish HS from the key files we wrote | Tor needs ~30–60s to re-create intro circuits. During gap, our IPs are stale in published descriptor |

---

## 6. What RustBalance Cannot Currently Recover From

### ❌ No Recovery (requires manual intervention)

| Failure | Why it fails | Impact |
|---------|-------------|--------|
| **Tor process dies** | `is_tor_running()` exists but is never called. No loop monitors Tor's process state | All connectivity lost. Proxy cannot accept connections. Intro points go stale. No auto-restart |
| **Tor control port becomes unreachable permanently** | Each operation creates fresh TCP connection; all will fail. Logged as warnings but no escalation | Cannot fetch intro points, cannot HSPOST descriptors. Node is functionally dead |
| **Target service goes down** | HTTP health probe is a placeholder (`returns Ok(Healthy)` always). No actual check | Proxy accepts connections but they fail silently or hang at SOCKS5 connect stage. Clients see errors |
| **WireGuard interface goes down** | No check for `wg-rb` interface liveness | All coordination lost. Node becomes isolated. Still proxies traffic but descriptor diverges |
| **HS directory permissions changed** | No periodic permission check | Tor may fail to read keys, lose ability to accept connections |
| **Master key file corrupted/deleted** | Only loaded at startup, never re-verified | If Tor restarts and key files are damaged, HS cannot be re-established |
| **Disk full** | No disk space monitoring | Tor may crash, logs stop, descriptor writes fail |
| **System reboot** | No systemd unit file in the deploy. No auto-start mechanism | Service stays down until manually restarted |
| **Clock drift beyond 5 seconds** | Messages rejected, coordination breaks down | Node becomes isolated from cluster. No NTP validation or warning |
| **Config file corruption** | Only loaded at startup. No validation on reload | Process must be restarted manually |
| **OOM kill** | No memory monitoring or limits | Process dies silently, no recovery |
| **Tor descriptor not yet available** | intro_point_refresh_loop gets `None`, logs info, waits. But the 90s publish delay is hardcoded — if Tor takes longer, first publish has 0 IPs | Descriptor published with 0 intro points → site unreachable until next publish (600s) |
| **All nodes die simultaneously** | No external monitoring | Site goes completely offline. Manual deploy needed |
| **SOCKS5 connection to target hangs** | No timeout on the target-side connection in the proxy | Connection slot consumed forever. Memory leak over time |
| **Concurrent join requests** | JoinHandler doesn't deduplicate or rate-limit | Could add duplicate WG peers or exhaust resources |

---

## 7. Hardening Roadmap (Easy → Difficult)

### Tier 1 — Quick Wins (hours of work, high impact)

#### 1.1 Systemd Unit File + Auto-Restart
**Problem:** If the process or VM reboots, RustBalance doesn't start.
**Solution:** Create `rustbalance.service` with `Restart=always`, `RestartSec=5`, `WantedBy=multi-user.target`.
```
[Service]
Type=simple
Restart=always
RestartSec=5
ExecStart=/usr/local/bin/rustbalance run
```
**Also:** `After=tor.service` ensures Tor is up first.
**Recovery:** Survives process crash, OOM kill, system reboot.

#### 1.2 Tor Process Watchdog
**Problem:** Tor can die and nothing notices.
**Solution:** Add a `tor_health_loop` (every 15s) that calls `is_tor_running()` (already exists). If Tor is down, call `restart_tor()` (already exists). If Tor won't start after 3 attempts, log critical error.
**Lines to change:** Add ~30 lines to `scheduler/loops.rs`. The repair functions already exist in `repair/restart.rs`.

#### 1.3 Connection Timeout to Target
**Problem:** SOCKS5 connections to the target can hang forever.
**Solution:** Wrap the SOCKS5 connect + proxy with `tokio::time::timeout()`. 30 seconds for connection, 120 seconds idle timeout.
**Lines to change:** ~5 lines in `onion_service.rs` around the SOCKS5 connect call.

#### 1.4 Publish Retry on Failure
**Problem:** If HSPOST fails, we wait 600s for the next cycle.
**Solution:** On HSPOST failure, retry 3 times with 10s backoff before giving up. Already have `backoff()` in `util/rand.rs`.
**Lines to change:** ~15 lines wrapping the HSPOST call in `publish_loop`.

#### 1.5 Smarter First-Publish Timing
**Problem:** Hardcoded 90s wait may not be enough; or may be too much.
**Solution:** Instead of sleeping 90s, poll `state.own_intro_points.len() > 0` every 5s with a max wait of 120s.
**Lines to change:** Replace the `sleep(90)` with a polling loop (~15 lines).

---

### Tier 2 — Moderate Effort (days of work, significant impact)

#### 2.1 Target Health Check (HTTP Probe)
**Problem:** `probe_http()` is a placeholder. If the target is down, clients get errors.
**Solution:** Implement the actual probe: SOCKS5 → target.onion → GET `/health` → expect 200. Run every `probe_interval_secs` (60s). Track `target_healthy` in state. If unhealthy for 3 consecutive checks, log critical warning.
**Future enhancement:** If target is down, return a custom error page instead of proxy failure.

#### 2.2 WireGuard Interface Health Check
**Problem:** If `wg-rb` goes down, coordination is silently lost.
**Solution:** Every 30s, run `wg show wg-rb` and parse output. If interface is down, attempt to re-create it using the existing `WgInterface` setup code.
**Lines to change:** New loop in scheduler + ~40 lines of interface recreation logic.

#### 2.3 Descriptor Age Warning & Emergency Republish
**Problem:** If our published descriptor gets old (stale on HSDirs), clients can't connect.
**Solution:** Track `last_successful_publish` timestamp. If `now - last_publish > descriptor_max_age_secs` (900s), force an immediate publish attempt regardless of the 600s interval.
**Lines to change:** ~20 lines in publish_loop.

#### 2.4 Rate-Limited Join Handler
**Problem:** Unlimited join requests could exhaust WireGuard peer slots or cause DoS.
**Solution:** Track join timestamps. Max 5 joins per 60 seconds. Reject with 429 after that.
**Lines to change:** ~20 lines in `join_handler.rs`.

#### 2.5 Graceful Shutdown
**Problem:** No signal handling. SIGTERM kills the process mid-operation.
**Solution:** Handle SIGTERM/SIGINT: stop accepting connections, wait for in-flight proxied requests (5s), broadcast LeaseRelease to peers, release WireGuard interface, exit cleanly.
**Lines to change:** `tokio::signal` handler wrapping the `tokio::select!` block.

#### 2.6 Prometheus Metrics Endpoint
**Problem:** No observability into the running system.
**Solution:** Expose metrics on a local-only port (e.g., `127.0.0.1:9100`): intro_point_count, peer_count, last_publish_age, sessions_total, publish_errors, heartbeat_sent/received.
**Lines to change:** New module + endpoint, ~150 lines.

---

### Tier 3 — Substantial Effort (week+ of work, system-level impact)

#### 3.1 Encrypted Config & Key Storage
**Problem:** `config.toml` has secrets in plaintext (cluster_token, WG private key, join_secret). Master key stored as a raw file.
**Solution:**
- Encrypt sensitive config fields at rest using a passphrase-derived key (Argon2id + AES-256-GCM)
- Config decrypted at startup with password from environment variable or stdin prompt
- Master key file encrypted the same way
- Never write decrypted secrets to disk (tmpfs or memory-only)

#### 3.2 Active Intro Point Verification
**Problem:** We trust that the intro points in our descriptor are valid, but they may have expired or the relay may be gone.
**Solution:** Before publishing, test-connect to each intro point (or at least verify via Tor consensus that the relay is listed). Drop dead intro points before merging.
**Lines to change:** New function + GETINFO command for relay status.

#### 3.3 Full Repair Engine Integration
**Problem:** `repair/actions.rs` and `repair/restart.rs` exist but are NEVER called from the scheduler.
**Solution:** Create a `repair_loop` that:
1. Monitors all failure signals (Tor down, WG down, target unhealthy, publish failures)
2. Calls `diagnose()` to determine action
3. Calls `execute_repair()` with backoff
4. Tracks repair attempts to avoid infinite restart loops
5. After N failures, escalate (step down, alert, etc.)

#### 3.4 Hardened File System Posture
**Problem:** Keys, configs, and binary are on regular filesystem.
**Solution:**
- Install to `/opt/rustbalance/` with root ownership, 755
- Config in `/etc/rustbalance/` with root:rustbalance, 640
- Keys in `/var/lib/rustbalance/keys/` with rustbalance:rustbalance, 600
- HiddenServiceDir in `/var/lib/tor/rustbalance_hs/` with debian-tor, 700
- Binary with `CAP_NET_ADMIN` capability only (drop all others)
- Run as dedicated `rustbalance` user (not root)
- Read-only filesystem where possible (`ProtectSystem=strict` in systemd)

#### 3.5 Automatic NTP / Clock Sync Validation
**Problem:** Clock skew >5s breaks coordination. No warning when clocks drift.
**Solution:** On startup and every 300s, check system clock against Tor's consensus timestamp (available via GETINFO). If drift > 2s, log warning. If drift > 4s, log critical. Optionally trigger ntpdate.

#### 3.6 Circuit-Aware Publishing
**Problem:** HSPOST sends the descriptor, but we don't verify it was accepted by enough HSDirs.
**Solution:** Parse the HSPOST response to count successful uploads. If fewer than N HSDirs accepted, force immediate retry. Track hsdir acceptance rate.

---

### Tier 4 — Advanced Hardening (significant engineering, architecture-level)

#### 4.1 Redundant Tor Instances
**Problem:** Single Tor process is a single point of failure.
**Solution:** Run 2 Tor instances per node (different control ports, different SOCKS ports). If primary fails, failover to secondary. Primary intro point refresh checks both.

#### 4.2 Memory-Safe Secret Handling
**Problem:** Keys exist as regular `Vec<u8>` in memory. Could be swapped to disk, visible in core dumps.
**Solution:**
- Use `secrecy::SecretVec<u8>` for all key material (zeroized on drop)
- `mlock()` key pages to prevent swapping
- Disable core dumps via `prctl(PR_SET_DUMPABLE, 0)`
- Clear key material from `RuntimeState` when not actively needed

#### 4.3 Canary Endpoint (Self-Test)
**Problem:** The service may appear up but be serving errors.
**Solution:** Periodically (every 60s) make a test request through the full path: local Tor SOCKS → master.onion → reverse proxy → target. If this fails, we know the end-to-end path is broken and can trigger repair/alerts.

#### 4.4 Multi-Cluster Support
**Problem:** All nodes must share the same cluster token and master key.
**Solution:** Support cluster key rotation: broadcast a `KeyRotation` message with a new cluster token signed by the current one. Nodes validate the chain and switch atomically.

#### 4.5 Binary Integrity Verification
**Problem:** If the binary is tampered with, the node runs malicious code.
**Solution:** Self-verify binary hash at startup against a signed manifest. The deploy script pins the expected hash.

#### 4.6 Anti-Entropy Descriptor Consistency
**Problem:** Different HSDirs might have different descriptor versions.
**Solution:** After publishing, query multiple HSDirs to verify they have our latest revision counter. If any are behind, force HSPOST to that specific HSDir.

#### 4.7 Zero-Downtime Node Rotation
**Problem:** Replacing a node requires removing it, which temporarily reduces capacity.
**Solution:** Implement a `drain` mode: node stops accepting new connections but continues serving existing ones. Once idle, it can be safely replaced. New node's IPs are added to descriptor BEFORE old node's are removed.

---

### Priority Matrix

| # | Feature | Effort | Impact | Priority |
|---|---------|--------|--------|----------|
| 1.1 | Systemd unit + auto-restart | 🟢 Trivial | 🔴 Critical | **DO FIRST** |
| 1.2 | Tor process watchdog | 🟢 Easy | 🔴 Critical | **DO FIRST** |
| 1.3 | Connection timeout to target | 🟢 Easy | 🟡 High | **DO FIRST** |
| 1.4 | Publish retry on failure | 🟢 Easy | 🟡 High | **DO FIRST** |
| 1.5 | Smarter first-publish timing | 🟢 Easy | 🟡 Medium | Do soon |
| 2.1 | Target health check | 🟡 Moderate | 🔴 Critical | **Do next** |
| 2.2 | WireGuard health check | 🟡 Moderate | 🟡 High | Do next |
| 2.3 | Descriptor age emergency publish | 🟡 Moderate | 🟡 High | Do next |
| 2.4 | Rate-limited join handler | 🟡 Moderate | 🟡 Medium | Do next |
| 2.5 | Graceful shutdown | 🟡 Moderate | 🟡 Medium | Do next |
| 2.6 | Prometheus metrics | 🟡 Moderate | 🟡 Medium | Do next |
| 3.1 | Encrypted config/keys | 🟠 Substantial | 🟡 High | Plan it |
| 3.2 | Intro point verification | 🟠 Substantial | 🟡 Medium | Plan it |
| 3.3 | Full repair engine | 🟠 Substantial | 🔴 Critical | Plan it |
| 3.4 | Hardened filesystem | 🟠 Substantial | 🟡 High | Plan it |
| 3.5 | Clock sync validation | 🟠 Substantial | 🟡 Medium | Plan it |
| 3.6 | Circuit-aware publishing | 🟠 Substantial | 🟡 Medium | Plan it |
| 4.1 | Redundant Tor | 🔴 Major | 🟡 High | Someday |
| 4.2 | Memory-safe secrets | 🔴 Major | 🟡 Medium | Someday |
| 4.3 | Canary endpoint | 🔴 Major | 🟡 High | Someday |
| 4.4 | Multi-cluster / key rotation | 🔴 Major | 🟢 Low | Someday |
| 4.5 | Binary integrity | 🔴 Major | 🟢 Low | Someday |
| 4.6 | Anti-entropy HSDirs | 🔴 Major | 🟡 Medium | Someday |
| 4.7 | Zero-downtime rotation | 🔴 Major | 🟡 Medium | Someday |

---

*Generated from complete source analysis. Every statement references actual code behavior, not documentation aspirations.*
