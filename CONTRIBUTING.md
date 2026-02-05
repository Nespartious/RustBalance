# Contributing to RustBalance

## Project Principles

### 1. Zero User Involvement After Setup
- First node: `rustbalance init` - generates everything, outputs join token
- Additional nodes: `rustbalance join <token>` - fully automatic
- System must self-heal without human intervention
- All failures should attempt automatic recovery before alerting

### 2. Security First (Tor Network Guidelines)
- **No cleartext secrets** - All keys encrypted at rest
- **No network metadata leaks** - Coordination only over WireGuard
- **Minimal attack surface** - No HTTP APIs, no open ports except WG
- **Fail closed** - On errors, stop publishing rather than publish garbage
- **Clock security** - Validate timestamps, reject stale messages

### 3. Tor Protocol Compliance
Reference specifications (must cite when implementing):
- [Tor Proposal 224](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/proposals/224-rend-spec-ng.txt) - Next-Gen Hidden Services
- [rend-spec-v3](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/rend-spec-v3.txt) - v3 Onion Service Spec
- [control-spec](https://gitlab.torproject.org/tpo/core/torspec/-/blob/main/control-spec.txt) - Tor Control Protocol

### 4. Dependency Rules
- **All crates must exist on crates.io** - No hallucinated dependencies
- **Pin major versions** - Use `"1.0"` not `"*"`
- **Verify before adding** - Check crate exists: `cargo search <crate>`
- **Security audit** - Run `cargo audit` before merging
- **Minimal dependencies** - Prefer std library when reasonable

---

## Code Quality Checks

### Before Every Commit
```bash
cargo fmt --all
cargo clippy --all-features -- -D warnings
cargo test
```

### Before Every PR
```bash
cargo deny check      # License + vulnerability + crate existence
cargo audit           # Security advisories
cargo doc --no-deps   # Ensure docs build
```

### CI Must Pass
- `cargo check` - Compiles
- `cargo test` - All tests pass
- `cargo clippy` - No warnings
- `cargo fmt --check` - Properly formatted
- `cargo deny check` - Dependencies valid
- `cargo audit` - No known vulnerabilities

---

## Architecture Rules

### Module Boundaries
```
config/     - TOML parsing only, no IO after load
crypto/     - Pure crypto, no IO, no async
tor/        - All Tor communication isolated here
coord/      - All WireGuard/peer communication here
balance/    - Core logic: health, merge, publish
repair/     - Recovery actions only
scheduler/  - All tokio::spawn calls live here
state/      - Shared state, minimal surface area
```

### Error Handling
- Use `anyhow::Result` for application errors
- Use `thiserror` for library error types
- Always provide context: `.context("what we were doing")?`
- Log errors at point of handling, not point of creation

### Async Rules
- All `tokio::spawn` in `scheduler/` only
- Use `Arc<RwLock<T>>` for shared state, not `Mutex`
- Prefer `tokio::select!` over complex join patterns
- Always handle cancellation gracefully

### Logging
- `error!` - Requires human attention eventually
- `warn!` - Unusual but handled automatically
- `info!` - Significant state changes (publisher elected, descriptor published)
- `debug!` - Diagnostic for troubleshooting
- `trace!` - Verbose, only in dev builds

---

## Preventing AI Hallucinations

When adding dependencies or using APIs:

### 1. Verify Crate Exists
```bash
cargo search ed25519-dalek
# Must show real results with version numbers
```

### 2. Check API is Current
```bash
cargo doc --open -p <crate>
# Read actual docs, not assumed APIs
```

### 3. Red Flags for Hallucinated Code
- Crate names that are "too perfect" (e.g., `tor-onion-easy`)
- APIs that seem too convenient
- Version numbers that don't exist
- Traits/methods not in official docs

### 4. Verified Crate List
These crates are confirmed real and appropriate:
| Crate | Version | Purpose | Verified |
|-------|---------|---------|----------|
| tokio | 1.x | Async runtime | ✅ |
| serde | 1.x | Serialization | ✅ |
| toml | 0.8.x | Config parsing | ✅ |
| ed25519-dalek | 2.x | Ed25519 signatures | ✅ |
| sha2 | 0.10.x | SHA-2 hashes | ✅ |
| sha3 | 0.10.x | SHA-3/Keccak | ✅ |
| rand | 0.8.x | Randomness | ✅ |
| tracing | 0.1.x | Logging | ✅ |
| tracing-subscriber | 0.3.x | Log output | ✅ |
| anyhow | 1.x | Error handling | ✅ |
| thiserror | 1.x | Error types | ✅ |
| socket2 | 0.5.x | Low-level sockets | ✅ |
| chrono | 0.4.x | Time handling | ✅ |
| base64 | 0.22.x | Base64 encoding | ✅ |
| curve25519-dalek | 4.x | X25519 ECDH | ✅ |
| x25519-dalek | 2.x | X25519 wrapper | ✅ |
| aes-gcm | 0.10.x | AES-GCM encryption | ✅ |

### 5. Crates to Avoid
| Crate | Reason |
|-------|--------|
| torut | Unmaintained, last update 2021 |
| Any `*-easy` crate | Usually thin wrappers, verify carefully |

---

## Tor Network Considerations

### Descriptor Publishing
- Publish to multiple HSDirs (spread parameter = 3 typical)
- Respect time periods (24h boundaries for key blinding)
- Revision counter must always increment
- Never publish with zero introduction points

### Introduction Points
- Maximum 20 per descriptor
- Fair distribution across backends
- Remove dead IPs immediately, don't wait for timeout
- Cross-certify properly (auth key → intro point key)

### Timing
- Descriptor lifetime: 180 minutes (3 hours)
- Refresh before expiry: publish at ~50% lifetime
- Clock skew tolerance: 5 seconds between nodes
- HSDir consensus: updates every hour

### Blinding (Critical)
- Keys change each time period (~24h)
- Must publish to BOTH current and next period HSDirs near boundaries
- Subcredential derivation must match Tor's exactly or clients can't connect

---

## Test Categories

### Unit Tests
- Crypto operations (blinding, signing, key derivation)
- Message serialization/deserialization
- Election logic state machine
- Lease expiration logic

### Integration Tests (require Tor)
- Control port communication
- Descriptor fetch/parse
- Descriptor upload

### End-to-End Tests (require 2+ nodes)
- Publisher election
- Failover timing
- Descriptor validity after publish

---

## Commit Message Format
```
<type>: <short description>

<body - what and why>

Refs: <spec section if relevant>
```

Types: `feat`, `fix`, `refactor`, `docs`, `test`, `ci`, `chore`

Example:
```
feat: implement Ed25519 key blinding for v3 descriptors

Implements time-period based key blinding per rend-spec-v3 §2.2.
Blinded keys rotate every 24 hours to prevent descriptor linkability.

Refs: rend-spec-v3 §2.2, Tor Proposal 224
```
