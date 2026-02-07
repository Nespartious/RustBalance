# RustBalance Crypto Architecture Validation

**Date:** February 5, 2026  
**Status:** Validated and Ready for Implementation  
**Issue:** Master address unreachable despite successful HSPOST  
**Root Cause:** INTRODUCE2 subcredential mismatch

---

## Executive Summary

This document validates the cryptographic architecture fix for RustBalance's multi-node Tor hidden service load balancing. The core issue was identified through Tor log analysis showing `Could not get valid INTRO2 keys` errors, and validated through extensive research of Tor specifications, OnionBalance source code, and official documentation.

---

## The Problem

### Symptoms
- Master address `2clzszzj2zxouhymnw33lgycxhcr67iv6ozbuyvugjblsohckzjux7yd.onion` is unreachable
- Node address `3q4t2jfbgmetjrxy66rwrc4fjcrdi6uh3ltleqqaksve4xvhnktsibyd.onion` works independently
- HSPOST to HSDirs succeeds (descriptors are published)
- Clients can find the descriptor but cannot complete the introduction

### Critical Tor Log Error
```
[warn] Could not get valid INTRO2 keys on circuit X for service [scrubbed]
```

This error occurs in Tor's hidden service introduction handling when the subcredential used to decrypt the INTRODUCE2 cell doesn't match.

---

## Technical Analysis

### The hs-ntor Handshake

From Tor's rend-spec-v3 specification, the hs-ntor handshake (used for INTRODUCE2 processing) requires:

```
intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
info = m_hsexpand | N_hs_subcred
hs_keys = KDF(intro_secret_hs_input | info, S_KEY_LEN+MAC_LEN)
```

The **subcredential** (`N_hs_subcred`) is derived from the service's identity:

```
N_hs_cred = SHA3_256("credential" | public-identity-key)
N_hs_subcred = SHA3_256("subcredential" | N_hs_cred | blinded-public-key)
```

### The Mismatch

When a client fetches the descriptor for the **master address** and attempts to introduce:

1. Client computes subcredential using **master's public key** (from the address)
2. Client encrypts INTRODUCE2 cell with master's subcredential
3. Backend Tor receives the cell at its intro point
4. Backend Tor tries to decrypt using **its own subcredential** (from node's identity)
5. **DECRYPTION FAILS** - subcredentials don't match

---

## OnionBalance Architecture (Reference)

From official OnionBalance documentation and source code analysis:

### Components

| Component | Role |
|-----------|------|
| Frontend/Publisher | Runs OnionBalance daemon, has master private key, publishes merged descriptor |
| Backend Instance | Runs separate Tor hidden service with unique keys |
| Master Descriptor | Contains intro points from all backends, signed by master key |

### How OnionBalance Solves the Subcredential Problem

Backend instances are configured with:

1. **`HiddenServiceOnionbalanceInstance 1`** in torrc
2. **`ob_config`** file in HiddenServiceDir containing:
   ```
   MasterOnionAddress <master.onion>
   ```

When configured, Tor logs:
```
[notice] ob_option_parse(): Onionbalance: MasterOnionAddress <master.onion> registered
```

This tells Tor to:
1. Read the master's public key from the address
2. Compute and store the master's subcredential
3. Accept INTRODUCE2 cells encrypted with **either** the backend's OR the master's subcredential

### OnionBalance Source Code Evidence

From `onionbalance/hs_v3/descriptor.py`:

```python
def _recertify_intro_point(intro_point, descriptor_signing_key):
    """
    We received an introduction point from an instance. Now we need to
    recertify its descriptor signing key with our own...
    """
```

The `_recertify_intro_point()` function only re-signs the AUTH_KEY certificate. It does NOT change the `enc_key` (introduction encryption public key). The backend keeps its private enc_key and can decrypt INTRODUCE2 cells.

---

## RustBalance Architecture

### Design Intent (from copilot-instructions.md)

> "Each RustBalance node IS a hidden service"
> "Uses file-based `HiddenServiceDir` with master identity key (enables PoW support)"

RustBalance is NOT designed as a traditional OnionBalance setup. Instead:

- **Each node runs AS the master identity** (same keys everywhere)
- **Nodes share intro points via coordination layer** (not by fetching descriptors)
- **Publisher node merges intro points and publishes via HSPOST**

### Why This Works

If all nodes use the **same master identity keys**:

1. Each node's Tor creates intro points as the master identity
2. All intro points use the same identity for subcredential derivation
3. When clients encrypt INTRODUCE2 with master's subcredential, any node can decrypt
4. No `HiddenServiceOnionbalanceInstance` needed - nodes ARE the master

### What Was Broken

The old RustBalance code:

1. Let Tor generate its own unique keys per node (creating `3q4t2jfb...` instead of `2clzszzj...`)
2. Published those intro points under the master address via HSPOST
3. Result: Client encrypts for master, node tries to decrypt with node's subcredential → FAIL

---

## The Fix

### Implementation

Write the master's identity keys to each node's `HiddenServiceDir` BEFORE Tor configures the hidden service:

```rust
pub fn write_tor_key_files(hs_dir: &Path, expanded_secret_key: &[u8; 64]) -> Result<()> {
    // Create hs_ed25519_secret_key (Tor format: 96 bytes)
    // - 32 bytes: "== ed25519v1-secret: type0 ==\0\0\0"
    // - 64 bytes: expanded secret key
    
    // Create hs_ed25519_public_key (Tor format: 64 bytes)
    // - 32 bytes: "== ed25519v1-public: type0 ==\0\0\0"
    // - 32 bytes: public key
    
    // Create hostname file with .onion address
}
```

### Integration Point

In `scheduler/loops.rs`, before calling `configure_tor_hs()`:

```rust
// Load master identity and write keys to HiddenServiceDir
let master_seed = load_master_seed(&config)?;
let master_identity = MasterIdentity::from_seed(&master_seed)?;
let expanded_key = master_identity.expanded_secret_key();
write_tor_key_files(&hs_dir_path, &expanded_key)?;

// Now configure Tor - it will use our master keys
configure_tor_hs(&control, &hs_dir, port).await?;
```

### Result

- Tor reads existing key files instead of generating new ones
- Hidden service identity matches the master
- Intro points are created for the master identity
- Subcredentials match when clients send INTRODUCE2 cells
- **Connection succeeds**

---

## Comparison Table

| Aspect | OnionBalance | RustBalance (Fixed) | RustBalance (Broken) |
|--------|--------------|---------------------|---------------------|
| Backend identity | Unique per backend | Same as master ✅ | Unique per node ❌ |
| Master key location | Publisher only | All nodes ✅ | None ❌ |
| ob_config needed? | Yes | No ✅ | No |
| HiddenServiceOnionbalanceInstance? | Yes | No ✅ | No |
| Subcredential source | Master (via ob_config) | Master (via keys) ✅ | Node's (wrong) ❌ |
| PoW support | Limited | Full ✅ | N/A |

---

## Validation Sources

### Tor Specifications
- **rend-spec-v3**: hs-ntor handshake, subcredential derivation
- **tor.1.txt (man page)**: `HiddenServiceOnionBalanceInstance` option documentation

### OnionBalance Source Code
- `onionbalance/hs_v3/service.py`: Master key loading, descriptor creation
- `onionbalance/hs_v3/descriptor.py`: `_recertify_intro_point()` function

### Official Documentation
- https://onionservices.torproject.org/apps/base/onionbalance/tutorial/
- https://onionservices.torproject.org/apps/base/onionbalance/design/

### Tor Log Evidence
- `Could not get valid INTRO2 keys` confirms subcredential mismatch
- Occurs at INTRODUCE2 processing, not at descriptor publication

---

## Implementation Status

- [x] Root cause identified (subcredential mismatch)
- [x] Architecture validated against Tor specs
- [x] OnionBalance approach documented for reference
- [x] RustBalance fix designed and coded
- [ ] Windows build fix (Unix file permissions)
- [ ] Deploy and test on VMs

---

## Appendix: Key Cryptographic Values

### Current Test Environment

| Key | Value |
|-----|-------|
| Master Address | `2clzszzj2zxouhymnw33lgycxhcr67iv6ozbuyvugjblsohckzjux7yd.onion` |
| Node Address | `3q4t2jfbgmetjrxy66rwrc4fjcrdi6uh3ltleqqaksve4xvhnktsibyd.onion` |
| Master Seed | `454cf9d7990b659e44900c12cd623bebd514eba5709cf0356cbfe224da47cbaf` |
| Master Blinded Key | `c42cba968b1d5526b22da6efa5942305e768b7d87ebfd59a9161f1d9f577c5b9` |

### File Formats

**hs_ed25519_secret_key** (96 bytes):
```
Bytes 0-31:  "== ed25519v1-secret: type0 ==\0\0\0"
Bytes 32-95: Expanded secret key (64 bytes)
```

**hs_ed25519_public_key** (64 bytes):
```
Bytes 0-31:  "== ed25519v1-public: type0 ==\0\0\0"
Bytes 32-63: Public key (32 bytes)
```

---

*This document serves as proof of work for the crypto architecture investigation and validation. It should be referenced when implementing, testing, or debugging the multi-node hidden service functionality.*
