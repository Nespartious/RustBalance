# Phase 1 — Survival Basics

> Sprint goal: RustBalance survives crashes, reboots, hung connections, failed publishes, and Tor dying underneath it. These are the foundational guardrails that make everything else possible.

---

## Sprint Summary

| # | Task | Files Changed | Est. Lines | Risk |
|---|------|--------------|------------|------|
| 1.1 | Harden systemd unit | `testing/deploy.sh` | ~15 | Low |
| 1.2 | Tor process watchdog loop | `src/scheduler/loops.rs`, `src/repair/restart.rs` | ~60 | Low |
| 1.3 | Connection timeout to target | `src/balance/onion_service.rs` | ~20 | Low |
| 1.4 | Publish retry on failure | `src/scheduler/loops.rs` | ~40 | Low |
| 1.5 | Smart first-publish timing | `src/scheduler/loops.rs` | ~20 | Low |

---

## 1.1 — Harden Systemd Unit

### Problem

The current systemd unit in [testing/deploy.sh](testing/deploy.sh#L397-L421) has two issues:

1. **`Restart=on-failure`** — only restarts on non-zero exit. If the process is killed by SIGTERM, SIGKILL, or OOM killer, systemd treats it as a clean stop and does NOT restart.
2. **`After=network.target tor@default.service`** — references `tor@default.service` but `repair/restart.rs` calls `systemctl restart tor` (no `@default`). The Tor service name is inconsistent.

### Current Code (deploy.sh lines 397–421)

```ini
[Unit]
Description=RustBalance - Tor Hidden Service Load Balancer
After=network.target tor@default.service
Wants=tor@default.service

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/rustbalance run
Restart=on-failure
RestartSec=5
...
```

### Changes Required

**File: `testing/deploy.sh`** — function `create_systemd_service()` (line ~397)

| Line | Current | Change To | Why |
|------|---------|-----------|-----|
| `Restart=on-failure` | `Restart=always` | Survives SIGTERM, SIGKILL, OOM kill. systemd restarts regardless of exit reason |
| `RestartSec=5` | `RestartSec=3` | 3 seconds is enough — Tor is already running, just need our process back |
| — | (missing) | Add `StartLimitIntervalSec=300` | Prevents infinite restart loop: max restarts within 5-minute window |
| — | (missing) | Add `StartLimitBurst=10` | Allows 10 restarts in 5 minutes before giving up |

**Also:** Add these optional hardening directives to the `[Service]` section:

```ini
# Prevent runaway memory usage
MemoryMax=512M
# Ensure we get killed cleanly before restart
TimeoutStopSec=10
```

### Service Name Consistency

Deploy uses `tor@default.service` but the code uses `tor`. Need to decide:

**Option A:** Standardize on `tor@default` — update `repair/restart.rs` to try `tor@default` first, then fall back to `tor`.

**Option B:** Standardize on `tor` — update `deploy.sh` to use `tor.service`.

**Recommendation:** Option A. The deploy script already handles both (`restart tor@default 2>/dev/null || restart tor` on deploy.sh line 327). Match that pattern in `repair/restart.rs`.

### Test

```bash
# After deploy: verify Restart=always
systemctl show rustbalance | grep Restart=
# Should output: Restart=always

# Test OOM survival
sudo systemctl start rustbalance
sudo kill -9 $(pidof rustbalance)
sleep 5
systemctl is-active rustbalance  # should be "active"
```

---

## 1.2 — Tor Process Watchdog Loop

### Problem

Two functions exist that are never called:
- `is_tor_running()` in [src/repair/restart.rs](src/repair/restart.rs#L63-L70) — checks `systemctl is-active --quiet tor`
- `restart_tor()` in [src/repair/restart.rs](src/repair/restart.rs#L8-L36) — runs `systemctl restart tor` with service fallback

Neither is called from `scheduler/loops.rs`. If Tor dies, RustBalance continues running but is completely non-functional: no proxy, no HSPOST, no intro points.

### Bug: Service Name Mismatch

`is_tor_running()` checks service `tor`:
```rust
// repair/restart.rs line 64
Command::new("systemctl").args(["is-active", "--quiet", "tor"])
```

But deploy.sh installs Tor as `tor@default`. On these VMs, `systemctl is-active tor` may return inactive while `tor@default` is running.

### Changes Required

**File: `src/repair/restart.rs`**

Update both functions to try `tor@default` first, then `tor`:

```rust
pub fn is_tor_running() -> bool {
    // Try tor@default first (Ubuntu/Debian with multiple instances)
    let result = Command::new("systemctl")
        .args(["is-active", "--quiet", "tor@default"])
        .status();
    if matches!(result, Ok(status) if status.success()) {
        return true;
    }
    // Fallback to 'tor' service
    let result = Command::new("systemctl")
        .args(["is-active", "--quiet", "tor"])
        .status();
    matches!(result, Ok(status) if status.success())
}
```

Same pattern for `restart_tor()` — try `tor@default` first, then `tor`, then `service tor restart`.

**File: `src/scheduler/loops.rs`**

Add new function `tor_health_loop` and spawn it alongside the other tasks.

### New Function: `tor_health_loop`

```
Location: src/scheduler/loops.rs (add after background_bootstrap_loop)

Behavior:
  - Runs every 15 seconds
  - Calls repair::restart::is_tor_running()
  - If Tor is down:
    - Log WARN: "Tor process is not running, attempting restart"
    - Call repair::restart::restart_tor()
    - If restart succeeds: log INFO, sleep 10s (let Tor bootstrap), continue
    - If restart fails: increment failure counter
    - If 3 consecutive failures: log ERROR "Tor cannot be restarted, manual intervention required"
    - Cap at 3 attempts per 5-minute window to prevent restart storm
  - If Tor is running: reset failure counter, trace-level log

Parameters:
  tor_health_loop(config: Config) -> Result<()>
```

### Spawn in `run()` function

Add the new task to the `tokio::select!` block (after the existing handles, around line 260):

```rust
let config_clone = config.clone();
let tor_health_handle = tokio::spawn(async move {
    tor_health_loop(config_clone).await
});
```

And add a branch to the `tokio::select!`:
```rust
r = tor_health_handle => {
    error!("Tor health loop exited: {:?}", r);
}
```

### Test

```bash
# On VM: Stop Tor manually
sudo systemctl stop tor@default

# Check RustBalance logs (within 15 seconds):
# WARN: "Tor process is not running, attempting restart"
# INFO: "Tor restarted via systemctl"

# Verify Tor is back
systemctl is-active tor@default
```

---

## 1.3 — Connection Timeout to Target

### Problem

In [src/balance/onion_service.rs](src/balance/onion_service.rs), the SOCKS5 connect and bidirectional proxy have **zero timeouts**:

- **SOCKS5 TCP connect** (line ~369): `TcpStream::connect(format!("127.0.0.1:{}", socks_port))` — no timeout
- **SOCKS5 CONNECT command** (lines ~370-430): writes request, reads response — no timeout
- **Bidirectional proxy** (lines ~490, ~544): `tokio::select!` over two `tokio::io::copy` — no idle timeout

If Tor SOCKS hangs or the target is unreachable, the connection task blocks **forever**. Over time, this leaks memory and file descriptors.

### Current Imports (onion_service.rs lines 1-12)

```rust
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
```

**Missing:** `tokio::time::{timeout, Duration}` — not imported at all.

### Changes Required

**File: `src/balance/onion_service.rs`**

**Add import:**
```rust
use tokio::time::{timeout, Duration};
```

**Timeout 1: SOCKS5 connect + handshake** — wrap the entire SOCKS5 sequence

In `handle_connection()` (starts ~line 340), wrap the SOCKS5 TCP connect + handshake + CONNECT command in a single timeout:

```rust
// Current (no timeout):
let mut socks = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await?;
// ... SOCKS5 handshake ...
// ... SOCKS5 CONNECT ...

// Change to:
let mut socks = timeout(
    Duration::from_secs(30),
    async {
        let mut s = TcpStream::connect(format!("127.0.0.1:{}", socks_port)).await?;
        // ... SOCKS5 handshake ...
        // ... SOCKS5 CONNECT ...
        Ok::<TcpStream, anyhow::Error>(s)
    }
).await
.context("SOCKS5 connect timed out after 30 seconds")??;
```

**Timeout 2: Bidirectional proxy idle timeout**

The proxy currently uses `tokio::select!` over two `tokio::io::copy` futures. Wrap the entire select in a timeout that covers total session duration:

```rust
// After SOCKS5 connect succeeds, wrap the proxy:
let proxy_result = timeout(
    Duration::from_secs(300), // 5-minute max session duration
    async {
        tokio::select! {
            r = tokio::io::copy(&mut client_read, &mut target_write) => r,
            r = tokio::io::copy(&mut target_read, &mut client_write) => r,
        }
    }
).await;

match proxy_result {
    Ok(Ok(bytes)) => debug!("Proxy session completed ({} bytes)", bytes),
    Ok(Err(e)) => debug!("Proxy session error: {}", e),
    Err(_) => debug!("Proxy session timed out after 300s"),
}
```

### Configuration

Consider adding to `TargetConfig` in `config/mod.rs`:

```rust
pub connect_timeout_secs: u64,  // default: 30
pub session_timeout_secs: u64,  // default: 300
```

But this can be hardcoded constants initially and made configurable later.

### Test

```bash
# Test timeout: stop target service, make a request
# Request should fail within 30s instead of hanging forever
curl --socks5-hostname 127.0.0.1:9050 http://master.onion/ -m 60
# Should error within ~30s, not 60s
```

---

## 1.4 — Publish Retry on Failure

### Problem

In `scheduler/loops.rs`, when HSPOST fails (both single-node path at ~line 740 and multi-node path at ~line 845), the code logs a warning and falls through to `ticker.tick().await` — waiting the full `refresh_interval_secs` (600 seconds) before trying again.

The `publish()` method in [src/balance/publish.rs](src/balance/publish.rs) uses `?` for early return, so if the current-period HSPOST succeeds but the next-period fails, only half the publish completes and `last_publish` is never set.

The `backoff()` function in [src/util/rand.rs](src/util/rand.rs) exists but is never called from the publish path.

### Changes Required

**File: `src/scheduler/loops.rs`** — both publish paths (single-node ~line 730 and multi-node ~line 835)

Replace the single-shot publish-or-warn pattern with a retry loop:

```
For both single-node and multi-node publish paths:

1. Attempt publish()
2. If success: log, continue to ticker.tick()
3. If failure:
   a. Log WARN with error details
   b. For attempt in 1..=3:
      - Sleep backoff(attempt, 5, 30) seconds   // 5s, 10s, 20s with jitter
      - Reconnect TorController
      - Retry publish()
      - If success: log, break
      - If failure: log WARN
   c. If all 3 retries fail: log ERROR "Failed to publish after 3 retries"
```

**Also fix partial publish:** In `src/balance/publish.rs`, the `publish()` method should not use `?` on individual HSPOST calls. Instead, track per-period success:

```rust
// Current (line ~40 of publish.rs):
tor.upload_hs_descriptor(&output.descriptor, &onion_addr, &[]).await?;

// Change to:
let mut any_success = false;
for (i, &tp) in time_periods.iter().enumerate() {
    // ... build descriptor ...
    match tor.upload_hs_descriptor(&output.descriptor, &onion_addr, &[]).await {
        Ok(_) => {
            info!("Published {} period descriptor", period_label);
            any_success = true;
        },
        Err(e) => {
            warn!("Failed to publish {} period descriptor: {}", period_label, e);
        },
    }
}
if any_success {
    self.last_publish = Some(SystemTime::now());
}
if !any_success {
    anyhow::bail!("Failed to publish any descriptor");
}
```

### Test

```bash
# Temporarily block control port access, then unblock:
sudo iptables -A OUTPUT -p tcp --dport 9051 -j DROP
# Wait for publish cycle, observe retry logs
# Then:
sudo iptables -D OUTPUT -p tcp --dport 9051 -j DROP
# Retry should succeed
```

---

## 1.5 — Smart First-Publish Timing

### Problem

In `scheduler/loops.rs` at line ~617:

```rust
info!("Publish loop waiting 90 seconds for hidden service and intro points...");
tokio::time::sleep(Duration::from_secs(90)).await;
```

This is a hardcoded 90-second unconditional sleep. If Tor creates intro points faster (which it often does — within 30-40 seconds), we waste up to 50 seconds. If Tor takes longer than 90 seconds (cold start, busy network), we publish with 0 intro points and the site is unreachable until the next cycle (600 seconds later).

The `state` parameter (type `Arc<RwLock<RuntimeState>>`) is available in `publish_loop` and already used later to read `own_intro_points`.

### Changes Required

**File: `src/scheduler/loops.rs`** — `publish_loop()`, replace lines ~616-618

Replace the hardcoded sleep with a poll-until-ready loop:

```rust
// Replace:
info!("Publish loop waiting 90 seconds for hidden service and intro points...");
tokio::time::sleep(Duration::from_secs(90)).await;

// With:
info!("Publish loop waiting for intro points (max 120 seconds)...");
let poll_start = tokio::time::Instant::now();
let max_wait = Duration::from_secs(120);
let poll_interval = Duration::from_secs(5);

loop {
    let has_intro_points = {
        let state = state.read().await;
        !state.own_intro_points.is_empty()
    };

    if has_intro_points {
        let elapsed = poll_start.elapsed().as_secs();
        info!("Intro points available after {}s — starting publish loop", elapsed);
        break;
    }

    if poll_start.elapsed() >= max_wait {
        warn!("No intro points after 120s — starting publish loop anyway (will retry)");
        break;
    }

    tokio::time::sleep(poll_interval).await;
}
```

### Behavior Change

| Scenario | Before | After |
|----------|--------|-------|
| Tor creates IPs in 35s | Wait full 90s, publish at 90s | Detect at 35s, publish at 40s (next 5s poll) |
| Tor creates IPs in 90s | Publish at 90s with IPs | Detect at 90s, publish at 95s |
| Tor needs 100s | Publish at 90s with **0 IPs** (broken!) | Wait full 120s, then publish with retry |
| Tor needs 130s | Publish at 90s with **0 IPs** (broken!) | Publish at 120s without IPs, **but retry logic (1.4) catches it** |

### Test

```bash
# Deploy fresh node, watch logs for timing:
# Should see "Intro points available after Xs" where X < 90
# Not "Publish loop waiting 90 seconds..."
```

---

## Definition of Done

All 5 items complete when:

- [ ] `systemctl show rustbalance | grep Restart=` returns `Restart=always`
- [ ] Tor process kill → auto-restart within 15 seconds (seen in logs)
- [ ] Tor service name consistency: `restart.rs` tries `tor@default` first
- [ ] Proxy connections time out in 30s on connect, 300s on idle
- [ ] Failed HSPOST retries 3 times with backoff before giving up
- [ ] Partial publish (one period fails) doesn't lose the successful period
- [ ] First publish happens as soon as intro points are ready, not after fixed 90s
- [ ] All changes compile with `cargo build --release`
- [ ] Fresh deploy on clean VM succeeds with all new behaviors observable in logs
