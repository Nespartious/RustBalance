# Phase 2 — Monitoring & Resilience

> Sprint goal: RustBalance knows when things are wrong — target down, WireGuard dead, descriptors stale, clock drifting — and reacts before users notice. Also: graceful shutdown, join rate-limiting, and descriptor age emergency republish.

---

## Sprint Summary

| # | Task | Files Changed | Est. Lines | Risk |
|---|------|--------------|------------|------|
| 2.1 | Target health check (HTTP probe) | `src/balance/health.rs`, `src/scheduler/loops.rs`, `src/config/mod.rs` | ~120 | Medium |
| 2.2 | WireGuard interface health check | `src/scheduler/loops.rs`, `src/coord/wireguard.rs` | ~80 | Medium |
| 2.3 | Descriptor age emergency republish | `src/scheduler/loops.rs`, `src/state/model.rs` | ~40 | Low |
| 2.4 | Rate-limited join handler | `src/balance/join_handler.rs` | ~30 | Low |
| 2.5 | Graceful shutdown | `src/scheduler/loops.rs`, `src/coord/wireguard.rs` | ~60 | Medium |
| 2.6 | Clock drift detection | `src/scheduler/loops.rs`, `src/tor/control.rs` | ~50 | Low |

---

## 2.1 — Target Health Check (HTTP Probe)

### Problem

`probe_http()` in [src/balance/health.rs](src/balance/health.rs#L76-L91) is a stub that always returns `Ok(Healthy)`:

```rust
pub async fn probe_http(&self, backend: &Backend) -> Result<HealthStatus> {
    if !self.config.http_probe_enabled {
        return Ok(HealthStatus::Healthy);
    }
    // TODO: Implement actual HTTP probe via Tor SOCKS
    debug!("HTTP probe for {} (not yet implemented)", backend.onion_address);
    Ok(HealthStatus::Healthy)
}
```

The `target_healthy` field in `RuntimeState` ([src/state/model.rs](src/state/model.rs)) is initialized to `false` and **never set to `true`** anywhere. The `HealthChecker` struct is never instantiated from any scheduler loop. The `Backend` struct is a legacy concept from the original Onionbalance architecture and is not used in the current reverse-proxy design.

### Current HealthConfig (src/config/mod.rs)

```rust
pub struct HealthConfig {
    pub descriptor_max_age_secs: u64,     // default: 900
    pub http_probe_enabled: bool,          // default: false
    pub http_probe_path: String,           // default: "/health"
    pub http_probe_timeout_secs: u64,      // default: 5
}
```

Missing: `http_probe_interval_secs`, `consecutive_failures_threshold`.

### Approach: New Target Health Loop (not refactoring dead code)

Rather than wiring up the legacy `HealthChecker` + `Backend` pattern (which was designed for fetching other services' descriptors), create a purpose-built `target_health_loop` in the scheduler. This matches the current architecture where we reverse-proxy to a single target.

### Changes Required

**File: `src/config/mod.rs`** — Add fields to `HealthConfig`:

```rust
pub struct HealthConfig {
    pub descriptor_max_age_secs: u64,         // default: 900
    pub http_probe_enabled: bool,              // default: false
    pub http_probe_path: String,               // default: "/health"
    pub http_probe_timeout_secs: u64,          // default: 5
    pub http_probe_interval_secs: u64,         // NEW, default: 60
    pub probe_failure_threshold: u32,           // NEW, default: 3
    pub probe_expected_status: u16,             // NEW, default: 200
}
```

**File: `src/scheduler/loops.rs`** — Add `target_health_loop`:

```
New function: target_health_loop(state, config) -> Result<()>

Behavior:
  1. If http_probe_enabled is false: return immediately (noop)
  2. Wait 120 seconds (let proxy + HS fully establish)
  3. Every http_probe_interval_secs (default 60s):
     a. Connect to Tor SOCKS at 127.0.0.1:{socks_port}
     b. SOCKS5 CONNECT to {target.onion_address}:{target.port}
     c. Send: GET {health.http_probe_path} HTTP/1.1\r\nHost: {target}\r\n\r\n
     d. Read response, check for {probe_expected_status}
     e. Wrap entire operation in tokio::time::timeout(probe_timeout_secs)
  4. On success: 
     - Reset failure counter
     - If was unhealthy: log INFO "Target recovered"
     - Set state.target_healthy = true
  5. On failure:
     - Increment consecutive_failures counter
     - Log WARN "Target health probe failed ({n}/{threshold}): {error}"
     - If consecutive_failures >= probe_failure_threshold:
       - Set state.target_healthy = false
       - Log ERROR "Target is DOWN - {n} consecutive probe failures"
```

**Why use raw SOCKS5 instead of reqwest?** The existing `onion_service.rs` already implements SOCKS5 connect. We can extract that into a shared utility or replicate the ~30 lines. `reqwest` with SOCKS works too, but adds latency from its connection pooling. Either approach is fine.

**File: `src/state/model.rs`** — `target_healthy` already exists (bool, default false). No changes needed, just start writing to it.

### Spawn in `run()`:

```rust
let state_clone = Arc::clone(&state);
let config_clone = config.clone();
let health_handle = if config.health.http_probe_enabled {
    Some(tokio::spawn(async move {
        target_health_loop(state_clone, config_clone).await
    }))
} else {
    None
};
```

### Future Enhancement

When `target_healthy == false`, the reverse proxy could return a custom error page (e.g., "Service temporarily unavailable") instead of attempting the SOCKS5 connect. This prevents clients from hanging on dead targets. Defer this to Phase 3 (repair engine integration).

### Test

```bash
# Enable probe in config.toml:
# [health]
# http_probe_enabled = true
# http_probe_path = "/"

# Watch logs for:
# INFO "Target health probe succeeded (200)"
# Then stop target service, wait 3 minutes:
# WARN "Target health probe failed (1/3): connection refused"
# WARN "Target health probe failed (2/3): ..."
# ERROR "Target is DOWN - 3 consecutive probe failures"
```

---

## 2.2 — WireGuard Interface Health Check

### Problem

`WgInterface` in [src/coord/wg.rs](src/coord/wg.rs) has a `status()` method that runs `wg show wg-rb dump` and parses the output:

```rust
pub fn status(&self) -> Result<WgStatus> {
    let output = Command::new("wg")
        .args(["show", &self.name, "dump"])
        .output()
        .context("Failed to run 'wg show'")?;
    // parses into WgStatus { public_key, listen_port, peers: Vec<WgPeerStatus> }
}
```

But `WgInterface` is **never used at runtime**. The scheduler uses `WgTransport` exclusively, and `WgTransport` has no health check method.

Additionally, `WgTransport` stores the interface name in `self.interface` (string `"wg-rb"`) and has a `cleanup()` method that runs `ip link delete`. But there is no method to check if the interface is alive.

### Changes Required

**File: `src/coord/wireguard.rs`** — Add `is_interface_up()` method to `WgTransport`:

```rust
/// Check if the WireGuard interface is up and functional
pub fn is_interface_up(&self) -> bool {
    // Check interface exists and is UP
    let result = Command::new("ip")
        .args(["link", "show", &self.interface])
        .output();
    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("UP") || stdout.contains("state UP")
        },
        Err(_) => false,
    }
}
```

**File: `src/coord/wireguard.rs`** — Add `recreate_interface()` method that re-runs the setup steps from `setup_interface()` (lines ~42-85 in wireguard.rs). This is the same logic from `new()`: create interface, set key, add peers, assign IP, bring up. The existing peers list is in `self.peers`.

**File: `src/scheduler/loops.rs`** — Add `wg_health_loop`:

```
New function: wg_health_loop(coordinator, config) -> Result<()>

Behavior:
  1. Run every 30 seconds
  2. Check coordinator.transport().is_interface_up()
  3. If interface is up: trace log, continue
  4. If interface is down:
     a. Log WARN "WireGuard interface wg-rb is DOWN, attempting recovery"
     b. Call coordinator.transport_mut().recreate_interface()
     c. If success: log INFO "WireGuard interface restored"
     d. If failure (3 consecutive): log ERROR "WireGuard interface cannot be restored"
  
  Note: This requires either:
    - Making coordinator.transport() accessible (it's currently private)
    - Adding a coordinator.is_wg_up() / coordinator.recover_wg() wrapper method
    
  Simpler alternative: Just run `ip link show wg-rb` directly in the loop (no coordinator access needed):
    let output = Command::new("ip").args(["link", "show", "wg-rb"]).output();
```

### Simpler Implementation (Recommended for this phase)

Rather than exposing `WgTransport` internals, just check the interface directly:

```rust
async fn wg_health_loop(config: Config) -> Result<()> {
    let mut ticker = interval(Duration::from_secs(30));
    let interface = "wg-rb";
    let mut consecutive_failures = 0u32;

    loop {
        ticker.tick().await;
        
        let is_up = tokio::task::spawn_blocking(move || {
            Command::new("ip")
                .args(["link", "show", interface])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).contains("UP"))
                .unwrap_or(false)
        }).await.unwrap_or(false);

        if is_up {
            if consecutive_failures > 0 {
                info!("WireGuard interface recovered");
            }
            consecutive_failures = 0;
        } else {
            consecutive_failures += 1;
            warn!("WireGuard interface is DOWN ({} consecutive)", consecutive_failures);
            // Don't attempt automated recovery yet — just alert.
            // Phase 3 repair engine will handle recovery.
        }
    }
}
```

### Condition: Only spawn if WireGuard is configured

```rust
let wg_health_handle = if has_wg_config {
    Some(tokio::spawn(async move { wg_health_loop(config_clone).await }))
} else {
    None
};
```

### Test

```bash
# On VM: bring interface down manually
sudo ip link set wg-rb down

# Check logs within 30s:
# WARN "WireGuard interface is DOWN (1 consecutive)"

# Bring back up:
sudo ip link set wg-rb up
# INFO "WireGuard interface recovered"
```

---

## 2.3 — Descriptor Age Emergency Republish

### Problem

The `Publisher` struct in [src/balance/publish.rs](src/balance/publish.rs) tracks `last_publish: Option<SystemTime>` which is set after a successful HSPOST. The `RuntimeState` also has a `last_publish: Option<SystemTime>` field. But **neither is ever read** by the publish loop to detect staleness.

If a publish fails and the retry (Phase 1.4) also fails, the next publish attempt is 600 seconds later. During that window, the descriptor on HSDirs ages and may become stale (Tor treats descriptors older than ~3 hours as expired, but we lose our revision counter advantage much sooner).

### Changes Required

**File: `src/scheduler/loops.rs`** — `publish_loop()`:

Track `last_successful_publish` as a local variable:

```rust
let mut last_successful_publish: Option<Instant> = None;
let emergency_threshold = Duration::from_secs(config.health.descriptor_max_age_secs); // 900s
```

At the top of the main loop (before `ticker.tick().await` at the bottom):

```rust
// Check for emergency republish
if let Some(last) = last_successful_publish {
    let age = last.elapsed();
    if age > emergency_threshold {
        warn!(
            "Descriptor is {}s old (threshold: {}s) — forcing emergency republish",
            age.as_secs(), emergency_threshold.as_secs()
        );
        // Don't wait for ticker, fall through to publish logic immediately
    }
} else {
    // Never published successfully — always try
}
```

After successful publish:

```rust
last_successful_publish = Some(Instant::now());
```

The loop structure changes from:

```
loop {
    // ... publish logic ...
    ticker.tick().await;  // always wait full interval
}
```

To:

```
loop {
    // ... publish logic ...
    
    // Dynamic wait: shorter if descriptor is aging
    let wait_duration = if let Some(last) = last_successful_publish {
        let age = last.elapsed();
        if age > emergency_threshold / 2 {
            Duration::from_secs(60)  // Check every 60s when descriptor is aging
        } else {
            Duration::from_secs(config.publish.refresh_interval_secs)  // Normal interval
        }
    } else {
        Duration::from_secs(30)  // Never published — check frequently
    };
    
    tokio::time::sleep(wait_duration).await;
}
```

### Also update RuntimeState

After successful publish, sync to shared state:

```rust
{
    let mut state = state.write().await;
    state.last_publish = Some(SystemTime::now());
}
```

### Test

```bash
# Block control port temporarily for >900s (simulate publish failure)
# Observe in logs:
# WARN "Descriptor is 901s old (threshold: 900s) — forcing emergency republish"
# (followed by retry attempts)
```

---

## 2.4 — Rate-Limited Join Handler

### Problem

The `JoinHandler` in [src/balance/join_handler.rs](src/balance/join_handler.rs) has 8 fields:

```rust
pub struct JoinHandler {
    join_secret: String,
    cluster_token: String,
    node_id: String,
    wg_pubkey: String,
    wg_endpoint: String,
    tunnel_ip: String,
    peers: Arc<RwLock<PeerTracker>>,
    coordinator: Arc<RwLock<Coordinator>>,
}
```

There is **zero rate limiting**: no IP tracking, no timestamp tracking, no pubkey dedup. A valid token+secret allows unlimited joins. An attacker who obtains the join credentials could flood with join requests, adding thousands of WireGuard peers.

### Changes Required

**File: `src/balance/join_handler.rs`** — Add rate-limiting fields to `JoinHandler`:

```rust
pub struct JoinHandler {
    // ... existing 8 fields ...
    
    // Rate limiting
    recent_joins: Arc<RwLock<Vec<(Instant, String)>>>,  // (timestamp, wg_pubkey)
    max_joins_per_window: u32,                           // default: 5
    window_duration: Duration,                            // default: 300 seconds (5 min)
}
```

**In the request handler method** (currently `handle_join_request` around line 100-200):

Add checks before processing the join:

```rust
// 1. Dedup: Check if this WG pubkey is already known
{
    let coord = self.coordinator.read().await;
    if coord.has_wg_peer(&generated_node_id) {
        info!("Rejecting duplicate join from known peer: {}", generated_node_id);
        // Return 200 OK with the current peer info (idempotent — same response as first join)
        // This handles the case where a node retries after network failure
    }
}

// 2. Rate limit: Count recent joins within window
{
    let mut recent = self.recent_joins.write().await;
    let now = Instant::now();
    
    // Prune expired entries
    recent.retain(|(ts, _)| now.duration_since(*ts) < self.window_duration);
    
    if recent.len() >= self.max_joins_per_window as usize {
        warn!("Rate limit exceeded: {} joins in last {}s", 
              recent.len(), self.window_duration.as_secs());
        // Return 404 (same as auth failure — don't reveal rate limiting)
        return;
    }
    
    // Record this join
    recent.push((now, payload.wg_pubkey.clone()));
}
```

**Idempotent behavior:** If the same pubkey joins again (retry), return success with current info. This is critical because the `BootstrapClient` in [src/balance/bootstrap.rs](src/balance/bootstrap.rs) has retry logic (5 attempts, 15s delay). Dedup ensures retries don't count against the rate limit.

### Constants

```rust
const MAX_JOINS_PER_WINDOW: u32 = 5;
const JOIN_WINDOW_SECS: u64 = 300;  // 5 minutes
```

### Test

```bash
# Send 6 rapid join requests — 6th should be rejected (silently, 404)
# Send same pubkey twice — second should be idempotent (200 OK, same response)
```

---

## 2.5 — Graceful Shutdown

### Problem

There is **zero signal handling** in the entire codebase. No `tokio::signal`, no SIGTERM handler, no SIGINT handler. When the process is killed:

1. All proxy connections are severed immediately (clients see connection reset)
2. No `LeaseRelease` message is broadcast (peers wait 30s heartbeat timeout + 90s grace before takeover = 120s)
3. `WgTransport::Drop` fires and calls `ip link delete wg-rb` — this is the ONLY cleanup
4. No final heartbeat with "I'm shutting down" signal

### Changes Required

**File: `src/scheduler/loops.rs`** — Add shutdown signal to `tokio::select!`:

```rust
// At the top of run(), create a shutdown channel:
let (shutdown_tx, mut shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

// In the tokio::select! block (line ~269), add a branch:
_ = tokio::signal::ctrl_c() => {
    info!("Received shutdown signal");
}
```

**Then add shutdown sequence after the select:**

```rust
// After tokio::select! completes (line ~305):

info!("Initiating graceful shutdown...");

// 1. Broadcast LeaseRelease if we're publisher
{
    let coord = coordinator.read().await;
    if coord.election().is_publisher() {
        let msg = CoordMessage::lease_release(config.node.id.clone());
        let _ = coord.broadcast(&msg).await;
        info!("Broadcast LeaseRelease to peers");
    }
}

// 2. Wait briefly for in-flight proxy connections (best-effort)
info!("Waiting 3 seconds for in-flight connections...");
tokio::time::sleep(Duration::from_secs(3)).await;

// 3. WgTransport cleanup happens automatically via Drop
info!("Shutdown complete");
```

**Note on Unix signals:** `tokio::signal::ctrl_c()` handles SIGINT (Ctrl+C). For SIGTERM (systemd stop), use:

```rust
#[cfg(unix)]
let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

// In tokio::select!:
#[cfg(unix)]
_ = sigterm.recv() => {
    info!("Received SIGTERM");
}
```

### Impact on Cluster Recovery

**Before:** Publisher dies → peers wait 30s heartbeat timeout + 90s grace = **~120 seconds** before a new publisher takes over.

**After:** Publisher shuts down gracefully → broadcasts `LeaseRelease` → peers see release within next heartbeat cycle → new publisher elected within **~10 seconds**.

### Test

```bash
# Start RustBalance, then:
sudo systemctl stop rustbalance
# Logs should show:
# INFO "Received SIGTERM"
# INFO "Broadcast LeaseRelease to peers"
# INFO "Waiting 3 seconds for in-flight connections..."
# INFO "Shutdown complete"

# On peer node, check logs:
# Should see LeaseRelease processed, new publisher elected quickly
```

---

## 2.6 — Clock Drift Detection

### Problem

Messages are validated with `is_valid_time(clock_skew_tolerance_secs)` where tolerance defaults to 5 seconds. If system clocks drift beyond 5 seconds between nodes, all coordination messages are silently rejected and the node becomes isolated. There is no warning when clocks are drifting.

The Tor control port provides `GETINFO consensus/valid-after` which returns the consensus timestamp — a reliable external time reference.

### Current GETINFO Implementation (src/tor/control.rs)

The `TorController` has a generic `get_info(keyword)` method and specific wrappers for `status/bootstrap-phase`, `circuit-status`, `hs/service/desc/id/`, and `hs/client/desc/id/`. There is **no** `consensus/valid-after` wrapper.

### Changes Required

**File: `src/tor/control.rs`** — Add method:

```rust
/// Get the consensus valid-after timestamp (reliable external time reference)
pub async fn get_consensus_time(&mut self) -> Result<Option<chrono::NaiveDateTime>> {
    let response = self.get_info("consensus/valid-after").await?;
    // Response format: "2026-02-07 12:00:00"
    if let Some(time_str) = response.strip_prefix("consensus/valid-after=") {
        let dt = chrono::NaiveDateTime::parse_from_str(
            time_str.trim(), "%Y-%m-%d %H:%M:%S"
        )?;
        Ok(Some(dt))
    } else {
        Ok(None)
    }
}
```

**File: `src/scheduler/loops.rs`** — Add `clock_drift_check` inside `tor_health_loop` (from Phase 1.2) or as a separate periodic check:

```
Every 300 seconds (5 minutes):
  1. Connect to Tor control port
  2. Get consensus time via GETINFO consensus/valid-after
  3. Compare to system clock (UTC)
  4. Calculate drift = |system_time - consensus_time|
  5. Consensus can be up to 3 hours old (Tor refreshes hourly), so this gives an approximate check
  6. If drift > 2s: log WARN "System clock drift detected: {drift}s from Tor consensus"
  7. If drift > 4s: log ERROR "CRITICAL clock drift: {drift}s — coordination messages may be rejected"
```

**Note:** The consensus timestamp updates roughly hourly, so this isn't sub-second accurate. It catches major drift (NTP failure, VM clock skew) rather than fine-grained issues. The 5-second tolerance on messages is the real enforcement — this check provides early warning.

### Test

```bash
# On VM: Shift clock forward 3 seconds
sudo date -s "+3 seconds"
# Wait up to 5 minutes for check:
# WARN "System clock drift detected: ~3s from Tor consensus"

# Shift 6 seconds:
sudo date -s "+6 seconds"
# ERROR "CRITICAL clock drift: ~6s — coordination messages may be rejected"
# (Also: other node's heartbeats start getting rejected)
```

---

## Definition of Done

All 6 items complete when:

- [ ] `http_probe_enabled = true` → target probed every 60s via Tor SOCKS, state.target_healthy tracked
- [ ] Target goes down → 3 consecutive failures → `ERROR "Target is DOWN"` in logs
- [ ] `wg-rb` interface down → detected within 30s, logged as WARN
- [ ] Descriptor age > 900s → emergency republish triggered, shorter check interval
- [ ] `state.last_publish` synced after every successful HSPOST
- [ ] 6th join request in 5 minutes → rejected silently (404)
- [ ] Duplicate WG pubkey join → idempotent success response
- [ ] SIGTERM → LeaseRelease broadcast → clean shutdown within 5s
- [ ] Clock drift > 2s → WARN in logs from Tor consensus check
- [ ] All changes compile with `cargo build --release`
- [ ] Fresh deploy with all new loops visible in `journalctl -u rustbalance`
