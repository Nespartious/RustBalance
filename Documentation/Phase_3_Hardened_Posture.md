# Phase 3 — Hardened Posture

> Sprint goal: RustBalance locks down secrets, repairs itself, tightens the filesystem, exposes operational metrics, and validates the integrity of intro points before publishing.

---

## Sprint Summary

| # | Task | Files Changed | Est. Lines | Risk |
|---|------|--------------|------------|------|
| 3.1 | Encrypted config & key derivation | `src/config/file.rs`, `src/crypto/keys.rs`, `Cargo.toml` | ~200 | High |
| 3.2 | Wire repair engine into scheduler | `src/repair/actions.rs`, `src/repair/mod.rs`, `src/scheduler/loops.rs` | ~150 | Medium |
| 3.3 | Harden filesystem posture | `testing/deploy.sh` | ~50 | Low |
| 3.4 | Harden systemd sandbox | `testing/deploy.sh` | ~30 | Low |
| 3.5 | Prometheus metrics export | `src/metrics/mod.rs` (new), `src/scheduler/loops.rs`, `Cargo.toml` | ~250 | Medium |
| 3.6 | Intro point validation before merge | `src/scheduler/loops.rs`, `src/balance/merge.rs` | ~80 | Medium |
| 3.7 | Circuit-aware HSPOST with verification | `src/tor/control.rs`, `src/tor/hsdir.rs`, `src/scheduler/loops.rs` | ~120 | High |

---

## 3.1 — Encrypted Config & Proper Key Derivation

### Problem

Every secret is stored as plaintext:

| Secret | Type | File |
|--------|------|------|
| `control_password` | `Option<String>` | `src/config/mod.rs` — `TorConfig` |
| `cluster_token` | `String` | `src/config/mod.rs` — `CoordinationConfig` |
| `join_secret` | `String` | `src/config/mod.rs` — `CoordinationConfig` |
| `wg_private_key` | `String` | `src/config/mod.rs` — `WireguardConfig` |

The master identity key is loaded from disk via raw `std::fs::read()` in `src/crypto/keys.rs` with no decryption.

The **only** encryption in the codebase is join token encryption in `src/crypto/keys.rs` using AES-256-GCM, but the key derivation is **single-pass SHA-256**:

```rust
fn derive_key(password: &str) -> [u8; 32] {
    // Simple key derivation - could use Argon2 for production
    let mut hasher = Sha256::new();
    hasher.update(b"rustbalance-token-v1:");
    hasher.update(password.as_bytes());
    // ... returns hash directly
}
```

The code itself contains a comment acknowledging this should use Argon2.

### Changes Required

**Step A: Add Argon2 dependency**

```toml
# Cargo.toml
argon2 = "0.5"  # Argon2id key derivation
```

`aes-gcm = "0.10"` is already present.

**Step B: Replace SHA-256 KDF with Argon2id in `src/crypto/keys.rs`**

Replace the `derive_key()` function:

```rust
use argon2::{Argon2, Algorithm, Version, Params};

fn derive_key(password: &str, salt: &[u8; 16]) -> Result<[u8; 32]> {
    let params = Params::new(
        65536,    // 64 MiB memory cost
        3,        // 3 iterations
        1,        // 1 parallel lane
        Some(32), // 32-byte output
    )?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)?;
    Ok(key)
}
```

**Step C: Encrypted config file support in `src/config/file.rs`**

Currently `file.rs` does:
```rust
let contents = std::fs::read_to_string(path)?;
let config: Config = toml::from_str(&contents)?;
```

Add an alternate path for encrypted configs:

```
1. If file extension is `.toml` → load plaintext (current behavior)
2. If file extension is `.toml.enc` → decrypt then parse:
   a. Read binary file
   b. First 16 bytes = salt
   c. Next 12 bytes = nonce
   d. Remaining bytes = AES-256-GCM ciphertext
   e. Prompt for password via environment variable RUSTBALANCE_CONFIG_KEY
   f. Derive key via Argon2id(password, salt)
   g. Decrypt ciphertext → plaintext TOML
   h. Parse TOML as normal
```

**Step D: Add CLI tool for encrypting config**

New binary or subcommand: `rustbalance encrypt-config --input config.toml --output config.toml.enc`

```
1. Read plaintext TOML
2. Prompt for password (or read from stdin/env)
3. Generate random 16-byte salt
4. Derive key via Argon2id
5. Generate random 12-byte nonce
6. Encrypt with AES-256-GCM
7. Write: salt || nonce || ciphertext
```

### Migration Path

1. Deploy continues to generate plaintext TOML (backward compatible)
2. Admin can optionally encrypt after initial deploy
3. Systemd unit sets `Environment=RUSTBALANCE_CONFIG_KEY=...` or reads from a key file with `EnvironmentFile=`

### Test

```bash
# Create encrypted config:
rustbalance encrypt-config --input /etc/rustbalance/config.toml --output /etc/rustbalance/config.toml.enc
# Set env var and restart:
export RUSTBALANCE_CONFIG_KEY="my-strong-password"
rustbalance --config /etc/rustbalance/config.toml.enc
# Verify: RustBalance starts normally, logs show "Decrypted config loaded"
```

---

## 3.2 — Wire Repair Engine into Scheduler

### Problem

The entire `src/repair/` module is **dead code at runtime**:

**`src/repair/actions.rs`** defines 6 `RepairAction` variants:

| Action | Implementation |
|--------|---------------|
| `RestartTor` | ✅ Real — calls `restart::restart_tor()` |
| `RestartWireguard` | ✅ Real — calls `restart::restart_wireguard()` |
| `ForceRepublish` | ⚠️ Stub — `Ok(())` with comment "Handled at state level" |
| `ClearPeerState` | ⚠️ Stub — `Ok(())` with comment "Handled at state level" |
| `ResetElection` | ⚠️ Stub — `Ok(())` with comment "Handled at scheduler level" |
| `ReconnectPeer` | ⚠️ Stub — `Ok(())` with comment "Handled at coordinator level" |

**`src/repair/mod.rs`** has a `diagnose()` function:
```rust
pub fn diagnose(failure: &str) -> Option<RepairAction> {
    if failure.contains("tor") || failure.contains("control port") {
        return Some(RepairAction::RestartTor);
    }
    if failure.contains("descriptor") {
        return Some(RepairAction::ForceRepublish);
    }
    None
}
```

Simple string matching, only 2 of 6 patterns.

**`src/repair/restart.rs`** has service name bugs:
- `restart_tor()` runs `systemctl restart tor` — deploy uses `tor@default`
- `restart_wireguard()` runs `systemctl restart wg-quick@wg-rb` — **no such unit exists**; WireGuard is set up manually via `ip link` / `wg set` in `src/coord/wireguard.rs`, not via `wg-quick`
- `is_tor_running()` checks `systemctl is-active --quiet tor` — same mismatch

**The scheduler never imports or calls anything from `repair`.**

### Changes Required

**Step A: Fix `src/repair/restart.rs` service names**

```rust
// restart_tor(): try tor@default first, fall back to tor
fn restart_tor() -> Result<()> {
    let status = Command::new("systemctl")
        .args(["restart", "tor@default"])
        .status();
    match status {
        Ok(s) if s.success() => return Ok(()),
        _ => {
            // Fallback
            Command::new("systemctl")
                .args(["restart", "tor"])
                .status()?;
        }
    }
    Ok(())
}

// is_tor_running(): check both service names
fn is_tor_running() -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", "tor@default"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
    || Command::new("systemctl")
        .args(["is-active", "--quiet", "tor"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
```

For WireGuard: Remove `restart_wireguard()` entirely. WireGuard is managed in-process by `WgTransport::setup_interface()`, not by systemd. Replace with:

```rust
fn restart_wireguard(transport: &mut WgTransport) -> Result<()> {
    transport.cleanup();           // ip link delete wg-rb
    transport.setup_interface()?;  // recreate from scratch
    Ok(())
}
```

This requires making `WgTransport` accessible from the repair path — likely by passing an `Arc<RwLock<WgTransport>>` or a callback.

**Step B: Implement repair stubs**

```rust
// ForceRepublish: Set last_publish to None to trigger immediate republish
fn force_republish(state: &mut RuntimeState) {
    state.last_publish = None;
    info!("Repair: Forced republish by clearing last_publish timestamp");
}

// ClearPeerState: Reset all peer tracking
fn clear_peer_state(state: &mut RuntimeState) {
    state.peers.clear();
    info!("Repair: Cleared all peer state");
}

// ResetElection: Release lease and re-run election
fn reset_election(coordinator: &mut Coordinator) {
    coordinator.election_mut().release_lease();
    info!("Repair: Reset election state, lease released");
}
```

**Step C: Expand `diagnose()` pattern matching**

```rust
pub fn diagnose(failure: &str) -> Option<RepairAction> {
    let f = failure.to_lowercase();
    
    if f.contains("tor") || f.contains("control port") || f.contains("socks") {
        return Some(RepairAction::RestartTor);
    }
    if f.contains("wireguard") || f.contains("wg-rb") || f.contains("interface down") {
        return Some(RepairAction::RestartWireguard);
    }
    if f.contains("descriptor") || f.contains("publish") || f.contains("hspost") {
        return Some(RepairAction::ForceRepublish);
    }
    if f.contains("peer") && f.contains("invalid") {
        return Some(RepairAction::ClearPeerState);
    }
    if f.contains("election") || f.contains("lease") || f.contains("publisher") {
        return Some(RepairAction::ResetElection);
    }
    None
}
```

**Step D: Integrate into scheduler failure points**

In `src/scheduler/loops.rs`, at each `warn!()` or `error!()` that currently just continues:

```rust
// BEFORE (current pattern):
Err(e) => {
    warn!("HSPOST failed: {}", e);
    // ... continues to next iteration
}

// AFTER:
Err(e) => {
    warn!("HSPOST failed: {}", e);
    if let Some(action) = repair::diagnose(&e.to_string()) {
        info!("Repair engine suggests: {:?}", action);
        if let Err(repair_err) = action.execute() {
            error!("Repair action failed: {}", repair_err);
        }
    }
}
```

Apply this pattern to:
- HSPOST failures (~lines 740, 845)
- Tor control port connection failures (wherever `TorController::connect()` errors)
- WireGuard send failures (in heartbeat/coordination loops)

### Test

```bash
# Stop Tor manually:
sudo systemctl stop tor@default
# Within 30s (from Phase 1 Tor watchdog):
# WARN "Tor is not running"
# INFO "Repair engine suggests: RestartTor"
# INFO "Restarting tor@default"
# (Tor restarts)
```

---

## 3.3 — Harden Filesystem Posture

### Problem

`testing/deploy.sh` creates several files containing secrets with **no explicit permissions**:

| File | Contains | Current Perms |
|------|----------|---------------|
| `/etc/rustbalance/config.toml` | WG private key, cluster token, join secret, Tor control password | `644` (world-readable, `tee` default) |
| `/etc/rustbalance/cluster_token.txt` | Cluster token | `644` (world-readable) |
| `/etc/rustbalance/join_secret.txt` | Join secret | `644` (world-readable) |
| `/etc/rustbalance/join_info.txt` | Master key base64, cluster token, join secret | `644` (world-readable) |
| `/etc/rustbalance/master_onion.txt` | Master .onion address | `644` (less sensitive) |
| `/etc/rustbalance/join_command.sh` | Join CLI with all secrets embedded | `755` (world-readable+executable) |

Files that **do** have correct permissions:
| File | Current Perms | Set By |
|------|--------------|--------|
| `/var/lib/tor/rustbalance_hs/` | `700`, owner `debian-tor` | deploy.sh |
| `/var/lib/tor/rustbalance_node_hs/` | `700`, owner `debian-tor` | deploy.sh |
| HS key files inside those dirs | `600`, owner `debian-tor` | Rust code (`src/crypto/keys.rs`) |
| `/etc/wireguard/wg-rb.conf` | `600`, owner `root` | deploy.sh |

### Changes Required

**File: `testing/deploy.sh`** — Add `chmod` calls after every secret file creation:

```bash
# After writing config.toml:
sudo chmod 600 /etc/rustbalance/config.toml

# After writing cluster_token.txt:
sudo chmod 600 /etc/rustbalance/cluster_token.txt

# After writing join_secret.txt:
sudo chmod 600 /etc/rustbalance/join_secret.txt

# After writing join_info.txt:
sudo chmod 600 /etc/rustbalance/join_info.txt

# After writing join_command.sh:
sudo chmod 700 /etc/rustbalance/join_command.sh

# Directory itself:
sudo chmod 700 /etc/rustbalance
```

### Rule of Thumb

Every file under `/etc/rustbalance/` that contains a secret → `chmod 600` (owner read/write only). The directory itself → `chmod 700` (owner only). No world-readable secret files.

### Test

```bash
# After deploy:
ls -la /etc/rustbalance/
# Expected:
# drwx------ root root /etc/rustbalance/
# -rw------- root root config.toml
# -rw------- root root cluster_token.txt
# -rw------- root root join_secret.txt
# -rw------- root root join_info.txt
# -rwx------ root root join_command.sh

# Verify no world-readable secrets:
find /etc/rustbalance -perm /o+r -type f
# Expected: empty output
```

---

## 3.4 — Harden Systemd Sandbox

### Problem

The current systemd unit (`testing/deploy.sh` lines 397-421) has a basic sandbox:

```ini
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/tor/rustbalance_hs /var/lib/tor/rustbalance_node_hs /etc/rustbalance
PrivateTmp=yes
```

Missing standard hardening directives. Process runs as `User=root` — no dedicated service user.

### Changes Required

**Add to the `[Service]` section:**

```ini
# Kernel protections
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes

# Namespace restrictions
RestrictNamespaces=yes
RestrictSUIDSGID=yes

# Memory protections
MemoryDenyWriteExecute=yes
LockPersonality=yes

# System call filtering
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

# Capability bounding (needs NET_ADMIN for WireGuard)
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN
```

**Note on `User=root`:** RustBalance needs root for:
1. Creating WireGuard interfaces (`ip link add type wireguard`)
2. Running `wg set` to configure WireGuard
3. Reading `/var/lib/tor/` directories owned by `debian-tor`

A dedicated user with `CAP_NET_ADMIN` capability could replace root, but this requires careful testing with WireGuard. Defer user creation to Phase 4; for now, keep `User=root` but add the capability bounding set to limit what root can do.

### Test

```bash
# After deploy, verify hardening:
systemd-analyze security rustbalance.service
# Expected: Score should drop from ~9.6 (UNSAFE) to ~4-5 (MEDIUM)
# Key: No red items for kernel/namespace/memory protections
```

---

## 3.5 — Prometheus Metrics Export

### Problem

Zero metrics infrastructure exists. No prometheus, metrics, or opentelemetry dependencies. No counters, gauges, or histograms anywhere. The words "metrics" and "prometheus" appear only in documentation as TODO items.

The only "counting" in the codebase is:
- `revision_counter` in the publisher (functional state for Tor protocol)
- `missed_heartbeats` in peer state (functional state for coordination)

### Changes Required

**Step A: Add dependencies to `Cargo.toml`**

```toml
prometheus = "0.13"
```

Prometheus server can use the existing `hyper` dependency (already in Cargo.toml with `server` feature).

**Step B: Create `src/metrics/mod.rs`**

```rust
use prometheus::{Registry, IntCounter, IntGauge, Histogram, HistogramOpts, opts};
use std::sync::LazyLock;

pub static REGISTRY: LazyLock<Registry> = LazyLock::new(Registry::new);

// Publish metrics
pub static PUBLISH_SUCCESS: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("rustbalance_publish_success_total", "Successful descriptor publishes").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static PUBLISH_FAILURE: LazyLock<IntCounter> = LazyLock::new(|| {
    let c = IntCounter::new("rustbalance_publish_failure_total", "Failed descriptor publishes").unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

// Coordination metrics
pub static HEARTBEAT_SENT: LazyLock<IntCounter> = ...;
pub static HEARTBEAT_RECEIVED: LazyLock<IntCounter> = ...;
pub static ACTIVE_PEERS: LazyLock<IntGauge> = ...;
pub static IS_PUBLISHER: LazyLock<IntGauge> = ...;

// Proxy metrics
pub static PROXY_CONNECTIONS_ACTIVE: LazyLock<IntGauge> = ...;
pub static PROXY_CONNECTIONS_TOTAL: LazyLock<IntCounter> = ...;
pub static PROXY_BYTES_TX: LazyLock<IntCounter> = ...;
pub static PROXY_BYTES_RX: LazyLock<IntCounter> = ...;

// Health metrics
pub static TARGET_HEALTHY: LazyLock<IntGauge> = ...;
pub static TOR_HEALTHY: LazyLock<IntGauge> = ...;
pub static WG_HEALTHY: LazyLock<IntGauge> = ...;

// Descriptor metrics
pub static DESCRIPTOR_AGE_SECS: LazyLock<IntGauge> = ...;
pub static INTRO_POINTS_OWN: LazyLock<IntGauge> = ...;
pub static INTRO_POINTS_PEER: LazyLock<IntGauge> = ...;
pub static INTRO_POINTS_MERGED: LazyLock<IntGauge> = ...;
```

**Step C: Add metrics HTTP server**

Bind to `127.0.0.1:9100` (localhost only — not exposed via Tor):

```rust
async fn metrics_server() -> Result<()> {
    let addr = SocketAddr::from(([127, 0, 0, 1], 9100));
    // Hyper service that returns prometheus::TextEncoder output on GET /metrics
    // Return 404 on all other paths
}
```

**Step D: Instrument the scheduler**

Insert metric increments at key points in `src/scheduler/loops.rs`:

```
After successful HSPOST:     metrics::PUBLISH_SUCCESS.inc();
After failed HSPOST:         metrics::PUBLISH_FAILURE.inc();
After sending heartbeat:     metrics::HEARTBEAT_SENT.inc();
After receiving heartbeat:   metrics::HEARTBEAT_RECEIVED.inc();
After peer count changes:    metrics::ACTIVE_PEERS.set(peer_count as i64);
After election decision:     metrics::IS_PUBLISHER.set(if is_pub { 1 } else { 0 });
After successful proxy conn: metrics::PROXY_CONNECTIONS_TOTAL.inc();
When proxy conn opens:       metrics::PROXY_CONNECTIONS_ACTIVE.inc();
When proxy conn closes:      metrics::PROXY_CONNECTIONS_ACTIVE.dec();
After health checks:         metrics::TARGET_HEALTHY.set(if healthy { 1 } else { 0 });
After publish:               metrics::DESCRIPTOR_AGE_SECS.set(0);
```

**Step E: Add to scheduler spawn**

```rust
tokio::spawn(async { metrics_server().await });
```

### Configuration

```toml
# config.toml
[metrics]
enabled = true           # default: false
listen_addr = "127.0.0.1"
port = 9100
```

### Test

```bash
# Enable metrics in config, restart RustBalance
# Scrape:
curl http://127.0.0.1:9100/metrics
# Expected output includes:
# rustbalance_publish_success_total 5
# rustbalance_active_peers 1
# rustbalance_is_publisher 1
# rustbalance_proxy_connections_active 3
# rustbalance_target_healthy 1
```

---

## 3.6 — Intro Point Validation Before Merge

### Problem

When merging intro points before publishing, the publish loop in `src/scheduler/loops.rs` does:

```rust
// Peer intro points are deserialized from base64, then:
let mut merged: Vec<crate::tor::IntroductionPoint> = own_intro_points;
merged.extend(peer_intro_points);
if merged.len() > max_intro_points {
    merged.truncate(max_intro_points);
}
```

Issues:
1. **No deduplication** — same relay could appear multiple times (same `legacy_key_id` or link specifier)
2. **No crypto validation** — `IntroductionPoint::from_bytes()` does structural parsing (reads fields, checks lengths) but never validates that `onion_key` or `enc_key` are valid curve25519 points
3. **No staleness check** — intro points from a peer that stopped sending updates could be stale
4. **No fair distribution** — `merge.rs` has a `MergedDescriptor` struct with fair per-backend distribution, but it is **never used**. The publish loop does its own naive concat+truncate
5. **Hardcoded max** — `max_intro_points` is set to `20` at the usage site, not read from config despite `MaxIntroPointsConfig` existing

### Changes Required

**Step A: Add validation to intro point deserialization**

In the publish loop, after `IntroductionPoint::from_bytes()`:

```rust
fn is_valid_intro_point(ip: &IntroductionPoint) -> bool {
    // 1. Must have at least one link specifier
    if ip.link_specifiers.is_empty() {
        return false;
    }
    
    // 2. Must have non-zero onion_key (32 bytes, not all zeros)
    if ip.onion_key.iter().all(|&b| b == 0) {
        return false;
    }
    
    // 3. Must have non-zero enc_key
    if ip.enc_key.iter().all(|&b| b == 0) {
        return false;
    }
    
    // 4. Must have auth_key_cert with non-zero length
    if ip.auth_key_cert.is_empty() {
        return false;
    }
    
    true
}
```

**Step B: Add deduplication**

```rust
fn dedup_intro_points(points: &mut Vec<IntroductionPoint>) {
    let mut seen = HashSet::new();
    points.retain(|ip| {
        // Use first link specifier as dedup key (relay identity)
        let key = ip.link_specifiers.first()
            .map(|ls| ls.data.clone())
            .unwrap_or_default();
        seen.insert(key)
    });
}
```

**Step C: Use config max instead of hardcoded 20**

```rust
// Before:
if merged.len() > 20 {
    merged.truncate(20);
}

// After:
let max = config.balance.max_intro_points.unwrap_or(20);
if merged.len() > max {
    merged.truncate(max);
}
```

**Step D: Fair distribution across peers**

Rather than concat+truncate (which always puts our own intro points first and may cut peers short):

```rust
fn fair_merge(
    own: Vec<IntroductionPoint>,
    peer_sets: Vec<(String, Vec<IntroductionPoint>)>,  // (peer_id, intro_points)
    max: usize,
) -> Vec<IntroductionPoint> {
    let total_sources = 1 + peer_sets.len();
    let per_source = max / total_sources;
    let mut remainder = max % total_sources;
    
    let mut merged = Vec::with_capacity(max);
    
    // Take fair share from self
    let own_take = per_source + if remainder > 0 { remainder -= 1; 1 } else { 0 };
    merged.extend(own.into_iter().take(own_take));
    
    // Take fair share from each peer
    for (_id, points) in peer_sets {
        let take = per_source + if remainder > 0 { remainder -= 1; 1 } else { 0 };
        merged.extend(points.into_iter().take(take));
    }
    
    merged
}
```

### Test

```bash
# With 2 nodes (self + 1 peer), max=20:
# Self provides 12 intro points, peer provides 8
# Fair merge: 10 from self, 10 from peer (or 10/8 if peer has fewer)
# Log: "Merged 18 intro points: 10 own + 8 from peer_abc"

# Dedup test: inject duplicate relay in peer data
# Log: "Removed 2 duplicate intro points"
```

---

## 3.7 — Circuit-Aware HSPOST with Verification

### Problem

HSPOST publishing is fire-and-forget. The current implementation in `src/tor/control.rs`:

```rust
pub async fn upload_hs_descriptor(
    &mut self,
    descriptor: &str,
    hs_address: &str,
    servers: &[String],
) -> Result<()> {
    let server_list = if servers.is_empty() {
        String::new()
    } else {
        format!(" SERVER={}", servers.join(","))
    };
    let cmd = format!("+HSPOST{} HSADDRESS={}\r\n{}\r\n.\r\n",
        server_list, addr, descriptor_trimmed);
    self.send_command(&cmd).await?;
    Ok(())
}
```

Issues:
1. **Response discarded** — `send_command` returns a `String` but it's never checked. No way to know if HSPOST was accepted, rejected, or how many HSDirs received it
2. **`SERVER=` always empty** — every call site passes `&[]`, so Tor picks HSDirs automatically with no visibility
3. **`UploadResult` struct defined but unused** — `src/tor/hsdir.rs` has `UploadResult { success_count, failure_count, failures }` but it's never constructed
4. **`hsdir_indices()` exists but never called** — `src/tor/hsdir.rs` computes HSDir ring indices from blinded key + time period, but the publish path doesn't use it
5. **No post-publish verification** — after uploading, we never check that HSDirs actually stored the descriptor

### Changes Required

**Step A: Parse HSPOST response**

```rust
pub async fn upload_hs_descriptor(
    &mut self,
    descriptor: &str,
    hs_address: &str,
    servers: &[String],
) -> Result<UploadResult> {
    // ... existing command building ...
    
    let response = self.send_command(&cmd).await?;
    
    // Tor responds with "250 OK" on success
    // or "552 ..." on failure
    let mut result = UploadResult {
        success_count: 0,
        failure_count: 0,
        failures: Vec::new(),
    };
    
    for line in response.lines() {
        if line.starts_with("250") {
            result.success_count += 1;
        } else if line.starts_with("5") {
            result.failure_count += 1;
            result.failures.push((hs_address.to_string(), line.to_string()));
        }
    }
    
    Ok(result)
}
```

**Step B: Use `UploadResult` in publish loop**

In `src/scheduler/loops.rs`, replace fire-and-forget with result tracking:

```rust
let result = tor.upload_hs_descriptor(&descriptor, &onion_addr, &[]).await?;
if result.failure_count > 0 {
    warn!(
        "HSPOST partial: {}/{} HSDirs succeeded, failures: {:?}",
        result.success_count,
        result.success_count + result.failure_count,
        result.failures
    );
}
info!(
    "Published descriptor to {} HSDirs (revision {})",
    result.success_count, revision_counter
);
```

**Step C: Post-publish verification (deferred — Tor limitation)**

Verifying that HSDirs actually stored the descriptor requires fetching our own descriptor via `HSFETCH`. This is complex:

```rust
// Future: After HSPOST, wait 10s then:
// tor.get_info(&format!("hs/service/desc/id/{}", onion_addr))
// Compare revision_counter in fetched descriptor vs what we published
```

This is a Phase 4 item due to complexity. For Phase 3, focus on parsing HSPOST responses and logging results.

**Step D: Wire `get_circuit_status()` for diagnostics**

`get_circuit_status()` exists in `src/tor/control.rs` but is never called. Add it to the Tor health check (Phase 1 tor_health_loop or Phase 2 clock drift check):

```rust
// In tor health check:
let circuits = tor.get_circuit_status().await?;
let circuit_count = circuits.lines().count();
if circuit_count == 0 {
    warn!("No active Tor circuits — publishing may fail");
}
info!("Active Tor circuits: {}", circuit_count);
```

### Test

```bash
# After publish, logs should show:
# INFO "Published descriptor to 6 HSDirs (revision 1234567890)"
# 
# If HSDir rejects (rare):
# WARN "HSPOST partial: 4/6 HSDirs succeeded, failures: [...]"
```

---

## Definition of Done

All 7 items complete when:

- [ ] `rustbalance encrypt-config` encrypts config.toml with Argon2id + AES-256-GCM
- [ ] Encrypted config loads transparently when `RUSTBALANCE_CONFIG_KEY` is set
- [ ] Repair engine diagnoses Tor/WG/publish failures and executes appropriate actions
- [ ] `restart_tor()` uses `tor@default` service name (matches deploy.sh)
- [ ] All files under `/etc/rustbalance/` are `chmod 600` or `700`
- [ ] `systemd-analyze security rustbalance.service` scores ≤ 5.0
- [ ] `curl http://127.0.0.1:9100/metrics` returns Prometheus-format counters/gauges
- [ ] Duplicate intro points are filtered before merge
- [ ] Intro points validated (non-zero keys, has link specifiers) before merge
- [ ] Fair distribution: each peer gets proportional share of max_intro_points
- [ ] HSPOST response parsed and logged with success/failure counts
- [ ] `cargo build --release` succeeds with all changes
