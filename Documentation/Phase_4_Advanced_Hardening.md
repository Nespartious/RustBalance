# Phase 4 — Advanced Hardening

> Sprint goal: Defense in depth — redundant Tor instances, memory-safe secret handling, self-test canary, supply chain integrity, and post-publish HSDir verification. These are the final hardening items that bring RustBalance to production-grade security posture.

---

## Sprint Summary

| # | Task | Files Changed | Est. Lines | Risk |
|---|------|--------------|------------|------|
| 4.1 | Redundant Tor instances | `src/tor/control.rs`, `src/config/mod.rs`, `src/scheduler/loops.rs`, `testing/deploy.sh` | ~300 | High |
| 4.2 | Memory-safe secrets (zeroize + mlock) | `src/crypto/keys.rs`, `src/config/mod.rs`, `src/coord/wireguard.rs`, `Cargo.toml` | ~150 | Medium |
| 4.3 | Canary endpoint (self-test) | `src/balance/onion_service.rs`, `src/scheduler/loops.rs` | ~100 | Medium |
| 4.4 | Cluster token rotation | `src/coord/messages.rs`, `src/config/mod.rs`, `src/scheduler/loops.rs` | ~120 | High |
| 4.5 | Binary integrity & supply chain | `Cargo.toml`, `.github/`, `testing/deploy.sh` | ~100 | Low |
| 4.6 | Anti-entropy HSDir verification | `src/tor/control.rs`, `src/tor/hsdir.rs`, `src/scheduler/loops.rs` | ~150 | High |

---

## 4.1 — Redundant Tor Instances

### Problem

The entire codebase assumes a **single Tor process** with one SocksPort (9050) and one ControlPort (9051):

- `TorController` in `src/tor/control.rs` connects to a single `127.0.0.1:9051`
- `testing/deploy.sh` configures exactly one Tor instance via `tor@default` template service
- `src/balance/onion_service.rs` connects to `127.0.0.1:9050` for SOCKS5 proxy
- All publish operations go through a single control port connection

If the Tor process crashes or becomes unresponsive, **all functionality stops**: no proxy, no publishing, no intro points. The Phase 1 Tor watchdog can restart it, but there's a gap.

### Architecture: Primary + Standby

Rather than active-active (complex, two HiddenServiceDirs), use **primary + standby**:

```
tor@default (primary) → SocksPort 9050, ControlPort 9051
tor@standby (standby) → SocksPort 9060, ControlPort 9061
```

Both share the same HiddenServiceDir (read-only for standby). On primary failure:
1. Watchdog detects primary is down
2. Switches all connections to standby ports
3. Attempts to restart primary
4. On primary recovery, switches back

### Changes Required

**Step A: Config additions in `src/config/mod.rs`**

```rust
pub struct TorConfig {
    pub control_port: u16,                    // existing, default 9051
    pub socks_port: u16,                      // existing, default 9050
    pub standby_control_port: Option<u16>,    // NEW, default None
    pub standby_socks_port: Option<u16>,      // NEW, default None
    // ...
}
```

**Step B: Failover-aware TorController in `src/tor/control.rs`**

```rust
pub struct TorController {
    stream: TcpStream,
    authenticated: bool,
    port: u16,                    // Which port we're connected to
    primary_port: u16,            // 9051
    standby_port: Option<u16>,    // 9061
}

impl TorController {
    pub async fn connect_with_failover(
        primary: u16,
        standby: Option<u16>,
        password: Option<&str>,
    ) -> Result<Self> {
        // Try primary first
        match Self::connect(primary, password).await {
            Ok(ctrl) => Ok(ctrl),
            Err(e) if standby.is_some() => {
                warn!("Primary Tor control port failed: {}, trying standby", e);
                Self::connect(standby.unwrap(), password).await
            }
            Err(e) => Err(e),
        }
    }
}
```

**Step C: Failover-aware proxy in `src/balance/onion_service.rs`**

The SOCKS5 connect currently targets `127.0.0.1:9050`. Add fallback:

```rust
async fn socks5_connect(
    target: &str,
    primary_port: u16,
    standby_port: Option<u16>,
) -> Result<TcpStream> {
    match connect_socks5(primary_port, target).await {
        Ok(stream) => Ok(stream),
        Err(e) if standby_port.is_some() => {
            warn!("SOCKS5 primary failed, trying standby: {}", e);
            connect_socks5(standby_port.unwrap(), target).await
        }
        Err(e) => Err(e),
    }
}
```

**Step D: Deploy script changes in `testing/deploy.sh`**

```bash
# Create standby Tor instance:
sudo cp /etc/tor/torrc /etc/tor/instances/standby/torrc
# Modify standby torrc:
#   SocksPort 9060
#   ControlPort 9061
#   DataDirectory /var/lib/tor-instances/standby
#   HiddenServiceDir /var/lib/tor/rustbalance_node_hs  (same as primary, read-only)

sudo systemctl enable tor@standby
sudo systemctl start tor@standby
```

**Note:** Sharing a HiddenServiceDir between two Tor instances is not standard. The standby instance may need its own HiddenServiceDir with a copy of the master key, or the standby may only function as a SOCKS proxy (no hidden service) and only the primary publishes. Design decision needed during implementation.

### Alternative: SOCKS-Only Standby (Simpler)

```
tor@default → Full HS with HiddenServiceDir + SocksPort 9050 + ControlPort 9051
tor@standby → SOCKS-only (no HiddenServiceDir) + SocksPort 9060
```

The standby only provides SOCKS proxy capability. If primary dies:
- Proxy traffic routes through standby SOCKS (clients stay connected)
- Publishing pauses until primary restarts (Phase 1 watchdog handles restart)
- Gap: no intro points created during primary downtime (descriptors age naturally)

This is much simpler and avoids the shared-HiddenServiceDir complexity.

### Test

```bash
# Stop primary Tor:
sudo systemctl stop tor@default

# Observe:
# WARN "Primary Tor control port failed, trying standby"
# Proxy connections should continue via standby SOCKS port
# Publishing pauses (no control port for HSPOST)

# Restart primary:
sudo systemctl start tor@default
# INFO "Primary Tor control port reconnected"
```

---

## 4.2 — Memory-Safe Secrets (Zeroize + Mlock)

### Problem

All sensitive key material is stored in **unprotected memory**:

| Location | Type | Issue |
|----------|------|-------|
| `MasterIdentity.private_scalar` | `[u8; 32]` | Not zeroed on drop, can be swapped to disk |
| `MasterIdentity.prf_secret` | `[u8; 32]` | Same |
| `CoordinationConfig.cluster_token` | `String` | Plain heap allocation, not zeroed |
| `CoordinationConfig.join_secret` | `String` | Same |
| `WireguardConfig.private_key` | `String` | Same |
| `TorConfig.control_password` | `Option<String>` | Same |

Additionally, `MasterIdentity` derives `Clone`, meaning key material can be freely copied with no tracking.

The WireGuard private key is also temporarily written to `/tmp/wg-{name}-key` in `src/coord/wireguard.rs` during interface setup — a crash-unsafe window where the key is on disk in a world-readable temp directory.

### Changes Required

**Step A: Add dependencies to `Cargo.toml`**

```toml
secrecy = { version = "0.10", features = ["alloc"] }
zeroize = { version = "1.8", features = ["derive"] }
```

**Step B: Wrap key material in `src/crypto/keys.rs`**

```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct MasterIdentity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,     // Public, but Zeroize for consistency
    private_scalar: [u8; 32],
    prf_secret: [u8; 32],
}

// Remove Clone derive — key material should not be freely copyable
```

On drop, `ZeroizeOnDrop` ensures all `[u8; 32]` fields are overwritten with zeros before deallocation.

**Step C: Wrap config secrets in `src/config/mod.rs`**

```rust
use secrecy::{SecretString, ExposeSecret};

pub struct CoordinationConfig {
    pub cluster_token: SecretString,    // was String
    pub join_secret: SecretString,      // was String
    // ...
}

pub struct WireguardConfig {
    pub private_key: SecretString,      // was String
    // ...
}

pub struct TorConfig {
    pub control_password: Option<SecretString>,  // was Option<String>
    // ...
}
```

All access points must change from `config.coord.cluster_token` to `config.coord.cluster_token.expose_secret()`. This is intentionally friction — it makes every secret access explicit and auditable.

**Step D: Mlock for master key**

```rust
use libc::{mlock, munlock};

impl MasterIdentity {
    pub fn new(seed: [u8; 32], prf_secret: [u8; 32]) -> Self {
        let mut identity = Self { /* ... */ };
        
        // Pin in physical memory — prevent swapping to disk
        unsafe {
            mlock(
                &identity.private_scalar as *const _ as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
            mlock(
                &identity.prf_secret as *const _ as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }
        
        identity
    }
}

impl Drop for MasterIdentity {
    fn drop(&mut self) {
        // Zeroize happens via ZeroizeOnDrop derive
        // Then unlock the memory pages
        unsafe {
            munlock(
                &self.private_scalar as *const _ as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
            munlock(
                &self.prf_secret as *const _ as *const libc::c_void,
                std::mem::size_of::<[u8; 32]>(),
            );
        }
    }
}
```

**Note:** `mlock` requires `CAP_IPC_LOCK` or `RLIMIT_MEMLOCK`. The systemd unit (Phase 3.4) should add:

```ini
LimitMEMLOCK=65536
```

**Step E: Fix WireGuard temp key file in `src/coord/wireguard.rs`**

Replace temp file with pipe:

```rust
// BEFORE (insecure):
let key_file = format!("/tmp/wg-{}-key", self.name);
std::fs::write(&key_file, &self.private_key)?;
// wg set ... private-key /tmp/wg-xxx-key
std::fs::remove_file(&key_file)?;

// AFTER (secure):
use std::process::Stdio;
let mut child = Command::new("wg")
    .args(["set", &self.name, "private-key", "/dev/stdin"])
    .stdin(Stdio::piped())
    .spawn()?;
child.stdin.take().unwrap().write_all(self.private_key.expose_secret().as_bytes())?;
child.wait()?;
```

This avoids writing the key to disk entirely.

### Ripple Effects

Changing `String` → `SecretString` for config fields will cause compile errors everywhere those fields are accessed. Key locations:

- `src/balance/join_handler.rs` — reads `cluster_token`, `join_secret`
- `src/balance/onion_service.rs` — reads `cluster_token`, `join_secret`
- `src/coord/wireguard.rs` — reads `private_key`
- `src/tor/control.rs` — reads `control_password`
- `src/balance/bootstrap.rs` — reads `cluster_token`, `join_secret`

Each must change to `.expose_secret()` access pattern. This is intentional — it creates a compile-time audit trail.

### Test

```bash
# After restart, verify mlock:
cat /proc/$(pidof rustbalance)/status | grep VmLck
# Expected: VmLck: 4 kB (or similar non-zero value)

# Verify no temp key files:
ls /tmp/wg-*
# Expected: No such file or directory

# Kill -9 RustBalance, then:
# Memory dump of the process should NOT contain private key bytes
# (zeroize ensures cleanup even on normal drop)
```

---

## 4.3 — Canary Endpoint (Self-Test)

### Problem

There is no way for RustBalance to verify **end-to-end** that the hidden service is reachable. The proxy works, descriptors are published, but we have no confirmation that a client can actually reach `master.onion` and get a response.

The HTTP server in `src/balance/onion_service.rs` is exclusively a reverse proxy — it forwards every request to the target. There is no `/health`, `/status`, or canary route.

### Architecture

Add an intercepted canary path in the reverse proxy. When a request arrives for a special path (e.g., `/__rustbalance/health`), return a health response directly instead of proxying.

A periodic self-test loop connects through Tor SOCKS to `master.onion/__rustbalance/health` to verify end-to-end reachability.

### Changes Required

**Step A: Canary route in `src/balance/onion_service.rs`**

In the request handler (the hyper service function), before proxying to target:

```rust
// Check for canary path
if req.uri().path() == "/__rustbalance/health" {
    let body = serde_json::json!({
        "status": "ok",
        "node_id": config.node.id,
        "is_publisher": state.read().await.is_publisher,
        "uptime_secs": start_time.elapsed().as_secs(),
        "target_healthy": state.read().await.target_healthy,
        "last_publish_age_secs": state.read().await.last_publish
            .map(|t| t.elapsed().unwrap_or_default().as_secs()),
        "active_peers": state.read().await.peers.len(),
    });
    return Ok(Response::new(body.to_string().into()));
}

// Existing proxy logic continues...
```

**Security note:** This endpoint is reachable by anyone who visits `master.onion/__rustbalance/health`. Consider:
- Making the path configurable (obscurity, not security)
- Adding a bearer token check (`Authorization: Bearer <canary_token>`)
- Returning minimal info by default (just `{"status":"ok"}`) with detailed info only when authenticated

**Step B: Self-test loop in `src/scheduler/loops.rs`**

```
New function: canary_loop(config, state) -> Result<()>

Behavior:
  1. Wait 300 seconds after startup (let everything stabilize)
  2. Every 120 seconds:
     a. Connect to Tor SOCKS at 127.0.0.1:{socks_port}
     b. SOCKS5 CONNECT to {master.onion}:80
     c. Send: GET /__rustbalance/health HTTP/1.1\r\nHost: {master.onion}\r\n\r\n
     d. Expect: HTTP 200 with {"status":"ok"} in body
     e. Wrap in 30-second timeout
  3. On success: trace log, reset failure counter
  4. On failure (3 consecutive):
     a. ERROR "Canary self-test FAILED — master.onion is unreachable"
     b. Trigger: ForceRepublish repair action (Phase 3.2)
```

**Why test through Tor SOCKS?** This verifies the entire chain:
- Tor SOCKS → Tor network → descriptor lookup → intro point selection → rendezvous → our hidden service → our proxy → canary response

If the canary fails, **something** in that chain is broken.

### Configuration

```toml
[canary]
enabled = false                          # default: false (opt-in)
path = "/__rustbalance/health"
interval_secs = 120
failure_threshold = 3
token = "optional-bearer-token"         # if set, canary requires auth
```

### Test

```bash
# Enable canary, restart
# From any machine with Tor:
curl --socks5-hostname 127.0.0.1:9050 http://master.onion/__rustbalance/health
# Expected: {"status":"ok","node_id":"...","is_publisher":true,...}

# In RustBalance logs:
# DEBUG "Canary self-test passed (200, status=ok)"
```

---

## 4.4 — Cluster Token Rotation

### Problem

The `cluster_token` is set once in `config.toml` and **never changes**. If compromised, an attacker can join the cluster indefinitely. There is no rotation mechanism and no `KeyRotation` message type in `src/coord/messages.rs`.

Tor's master key cannot be rotated (master key = .onion address), but the cluster token is our own authentication layer and can be rotated.

### Architecture

1. Publisher broadcasts `TokenRotation` message with new token, signed with current token
2. Nodes verify the signature matches the current token they hold
3. Nodes transition to the new token with a grace period (accept both old and new for 60s)
4. After grace period, old token is rejected

### Changes Required

**Step A: New message type in `src/coord/messages.rs`**

```rust
pub enum CoordMessage {
    Heartbeat { /* ... */ },
    LeaseRelease { /* ... */ },
    IntroPointShare { /* ... */ },
    PeerAnnounce { /* ... */ },
    TokenRotation {              // NEW
        node_id: String,
        new_token_hash: [u8; 32],  // SHA-256 hash of new token (don't send raw)
        signature: Vec<u8>,         // HMAC-SHA256(old_token, new_token_hash)
        transition_at: u64,         // Unix timestamp when new token becomes active
        grace_period_secs: u64,     // How long to accept both tokens (default: 60)
    },
}
```

**Step B: Token rotation handler**

On receiving `TokenRotation`:

```rust
1. Verify sender is current publisher (only publisher can rotate)
2. Verify signature: HMAC-SHA256(current_cluster_token, new_token_hash)
3. If valid:
   a. Store pending_token_hash
   b. At transition_at: new token becomes primary
   c. During grace period: accept both old and new tokens for auth
   d. After grace period: reject old token
4. Persist new token to config file (if file-backed)
```

**Step C: Rotation trigger**

Rotation can be triggered via:
- CLI command: `rustbalance rotate-token --new-token <token>`
- Signal: `SIGUSR1` triggers rotation with auto-generated token
- Scheduled: config option for auto-rotation every N days

For Phase 4, implement CLI trigger only.

### Security Considerations

- **Only the publisher can issue `TokenRotation`** — prevents non-publisher nodes from changing auth
- **New token is never sent in plaintext** — only its hash is broadcast. Nodes must receive the actual new token out-of-band (CLI or config update)
- **Grace period prevents lockout** — if some nodes update before others, both tokens work during transition
- **Alternative approach (simpler):** Instead of broadcasting, just update `config.toml` on all nodes simultaneously (via deploy script). This avoids the complex rotation protocol at the cost of requiring manual coordination.

### Recommended: Start Simple

For Phase 4, implement the **simple approach**:
1. Admin updates `cluster_token` in config.toml on all nodes
2. Admin restarts nodes in rolling fashion (one at a time)
3. During restart window, both old and new tokens are live (different nodes have different tokens)
4. Add a `previous_cluster_token` config field that's accepted during a grace window

This avoids the complexity of a rotation protocol while enabling token changes.

```rust
// In auth validation:
fn validate_token(received: &str, current: &str, previous: Option<&str>) -> bool {
    constant_time_eq(received, current)
        || previous.map(|p| constant_time_eq(received, p)).unwrap_or(false)
}
```

### Test

```bash
# Update cluster_token on VM1, restart VM1
# VM2 still has old token
# Verify: heartbeats still accepted (previous_cluster_token match)
# Update cluster_token on VM2, restart VM2
# Both nodes now on new token
# Remove previous_cluster_token from both configs
```

---

## 4.5 — Binary Integrity & Supply Chain

### Problem

The release profile is well-configured:
```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
panic = "abort"
strip = true
```

And security lints are enabled:
```rust
#![forbid(unsafe_code)]
```

However:
1. **`Cargo.lock` is gitignored** — builds are not reproducible. Different build times may resolve different dependency versions
2. **No dependency auditing** — no `cargo-audit` in CI
3. **No binary checksums** — deploy.sh builds from source but doesn't verify the result
4. **No SBOM** — no software bill of materials for the compiled binary

### Changes Required

**Step A: Commit `Cargo.lock`**

```bash
# Remove from .gitignore:
# (find the Cargo.lock line and remove it)

# Commit:
git add Cargo.lock
git commit -m "chore: commit Cargo.lock for reproducible builds"
```

Per [Cargo documentation](https://doc.rust-lang.org/cargo/guide/cargo-toml-vs-cargo-lock.html): "If you're building a binary, you should check in Cargo.lock." RustBalance is a binary application.

**Step B: Add `cargo-audit` to CI**

Create `.github/workflows/audit.yml`:

```yaml
name: Security Audit
on:
  schedule:
    - cron: '0 0 * * *'    # Daily
  push:
    paths:
      - 'Cargo.lock'
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rustsec/audit-check@v2
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

**Step C: Add `cargo-deny` config**

Create `deny.toml`:

```toml
[advisories]
vulnerability = "deny"
unmaintained = "warn"
yanked = "deny"

[licenses]
unlicensed = "deny"
allow = ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "Unicode-3.0"]

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "deny"
unknown-git = "deny"
```

**Step D: Binary checksum in deploy.sh**

After `cargo build --release` in deploy.sh:

```bash
# Generate and store checksum
sha256sum target/release/rustbalance > /etc/rustbalance/rustbalance.sha256
echo "Binary checksum: $(cat /etc/rustbalance/rustbalance.sha256)"

# On subsequent deploys, verify before replacing:
if [ -f /etc/rustbalance/rustbalance.sha256 ]; then
    echo "Previous binary checksum:"
    cat /etc/rustbalance/rustbalance.sha256
fi
```

**Step E: Static linking with musl (optional)**

For fully static binaries with no glibc dependency:

```bash
# Install musl target:
rustup target add x86_64-unknown-linux-musl

# Build:
cargo build --release --target x86_64-unknown-linux-musl
```

This produces a fully static binary that works on any Linux regardless of glibc version. However, it requires musl-compatible builds of all native dependencies. Test thoroughly.

### Test

```bash
# Verify Cargo.lock is committed:
git log --oneline Cargo.lock
# Should show commit

# Run audit locally:
cargo install cargo-audit
cargo audit
# Expected: 0 vulnerabilities found

# Verify checksum:
sha256sum /usr/local/bin/rustbalance
cat /etc/rustbalance/rustbalance.sha256
# Should match
```

---

## 4.6 — Anti-Entropy HSDir Verification

### Problem

Descriptor publishing is fire-and-forget:
1. `upload_hs_descriptor()` sends `+HSPOST` with empty `SERVER=` list
2. Tor picks HSDirs automatically
3. Response is discarded (Phase 3.7 fixes response parsing)
4. No verification that HSDirs actually stored the descriptor
5. `hsdir_indices()` in `src/tor/hsdir.rs` computes HSDir ring indices but is **never called**
6. `UploadResult` struct exists but is never constructed

If some HSDirs drop the descriptor (overloaded, restarting, malicious), clients who happen to query those HSDirs will get "service not found." We have no visibility into this.

### Architecture

After publishing, periodically verify that our descriptor is present on HSDirs:

```
1. Compute which HSDirs should have our descriptor (using hsdir_indices)
2. For each HSDir, attempt HSFETCH to retrieve our descriptor
3. Compare revision_counter of fetched descriptor vs expected
4. If any HSDir has stale/missing descriptor, re-upload specifically to that HSDir
```

### Changes Required

**Step A: Wire `hsdir_indices()` into the publish path**

`src/tor/hsdir.rs` has `hsdir_indices(blinded_key, time_period, store_params)` which computes SHA3-256 ring positions. This is currently dead code.

```rust
// After successful publish, compute which HSDirs should have the descriptor:
let indices = hsdir::hsdir_indices(&blinded_key, current_time_period, &store_params);
// Store indices for verification
```

**Note:** `hsdir_indices` returns ring positions, not relay fingerprints. To map positions to actual HSDirs, we'd need the consensus document, which is complex. **Alternative:** Use Tor's `HSFETCH` command which handles HSDir selection internally.

**Step B: HSFETCH verification in `src/tor/control.rs`**

```rust
pub async fn fetch_hs_descriptor(
    &mut self,
    onion_address: &str,
) -> Result<Option<String>> {
    // HSFETCH triggers Tor to fetch the descriptor from HSDirs
    let cmd = format!("HSFETCH {}\r\n", onion_address);
    let response = self.send_command(&cmd).await?;
    
    if response.contains("250") {
        // Descriptor fetch initiated — result comes async via HS_DESC event
        // Need to wait for the event or poll GETINFO hs/client/desc/id/<addr>
        tokio::time::sleep(Duration::from_secs(10)).await;
        
        let desc = self.get_info(&format!("hs/client/desc/id/{}", onion_address)).await?;
        if desc.contains("revision-counter") {
            Ok(Some(desc))
        } else {
            Ok(None)
        }
    } else {
        Ok(None)
    }
}
```

**Step C: Verification loop in `src/scheduler/loops.rs`**

```
New function: descriptor_verify_loop(config, state) -> Result<()>

Behavior:
  1. Run every 300 seconds (5 minutes), starting 60 seconds after a publish
  2. Connect to Tor control port
  3. HSFETCH our own master.onion address
  4. Wait 10s for descriptor to arrive
  5. Parse revision_counter from fetched descriptor
  6. Compare to last published revision_counter
  7. If mismatch or missing:
     a. WARN "Stale descriptor on HSDirs (got rev={fetched}, expected={published})"
     b. Trigger immediate republish
  8. If match:
     a. DEBUG "Descriptor verified on HSDirs (rev={published})"
```

### Limitations

- **HSFETCH fetches from ONE HSDir** — doesn't verify all 6. For full anti-entropy, we'd need to specify individual HSDirs via the `SERVER=` parameter, which requires knowing their fingerprints from the consensus
- **Race condition** — between publish and verify, another node may have published a newer descriptor with a higher revision counter. The verify should accept `fetched_rev >= expected_rev`
- **Self-fetch loop risk** — fetching our own descriptor creates a Tor circuit to ourselves. Ensure this doesn't interfere with regular operation

### Simpler Alternative (Recommended for Phase 4)

Rather than full anti-entropy, implement **publish-and-check**:

```rust
// After HSPOST, wait 15s, then:
let fetched = tor.get_info(&format!("hs/service/desc/id/{}", onion_addr)).await?;
// This queries Tor's own cache, not the HSDirs
// If Tor accepted the descriptor, it's in cache with correct revision
// If not in cache → something went wrong with the publish
```

This is much simpler and catches the most common failure mode (Tor rejecting the descriptor).

### Test

```bash
# After publish, logs should show:
# DEBUG "Descriptor verified on HSDirs (rev=1234567890)"

# Simulate stale descriptor (hard to test naturally):
# The verification should catch any rev counter mismatch
```

---

## Definition of Done

All 6 items complete when:

- [ ] Standby Tor instance configured and auto-failover works (SOCKS proxy continues on primary failure)
- [ ] `MasterIdentity` implements `ZeroizeOnDrop` — private keys zeroed on drop
- [ ] Config secrets wrapped in `SecretString` — compile-time audit of every access
- [ ] WireGuard private key piped via stdin (no temp file on disk)
- [ ] `/proc/{pid}/status` shows `VmLck > 0` (mlock active)
- [ ] `GET /__rustbalance/health` returns JSON status from any node
- [ ] Canary self-test loop verifies master.onion reachability through Tor
- [ ] `previous_cluster_token` config field enables rolling token updates
- [ ] `Cargo.lock` committed and `cargo-audit` runs in CI
- [ ] `deny.toml` configured and passing
- [ ] Binary SHA-256 checksum stored during deploy
- [ ] Post-publish descriptor verification catches stale/missing descriptors
- [ ] All changes compile with `cargo build --release`
