# HSPOST Merged Descriptor Publishing - Implementation Guide

This document outlines what's needed to complete merged descriptor publishing.

## Current State ✅

We have the building blocks:

1. **TorController.upload_hs_descriptor()** - [src/tor/control.rs#L252](../src/tor/control.rs)
   - HSPOST command implementation
   - Handles CRLF line endings
   - Supports targeting specific HSDirs

2. **Publisher** - [src/balance/publish.rs](../src/balance/publish.rs)
   - Manages revision counter
   - Calls DescriptorBuilder
   - Uploads via TorController

3. **DescriptorBuilder** - [src/crypto/mod.rs](../src/crypto/mod.rs)
   - Builds v3 descriptor from intro points
   - Signs with master key
   - Handles encryption layers

4. **DescriptorMerger** - [src/balance/merge.rs](../src/balance/merge.rs)
   - Selects intro points from backends
   - Distributes evenly across backends
   - Caps at max_intro_points

5. **Intro Point Count Aggregation** - [src/scheduler/loops.rs](../src/scheduler/loops.rs)
   - Nodes report intro_point_count in heartbeats
   - Publisher sees total across all healthy peers
   - Currently logging: "merging 3 own + 6 peer intro points"

## What's Missing 🚧

### 1. Intro Point DATA Sharing (not just counts)

Currently, heartbeats only share `intro_point_count`. To actually build a merged
descriptor, we need the raw intro point data.

**Option A: Add intro points to heartbeats**
```rust
// In HeartbeatPayload
pub intro_points: Vec<IntroPointData>,  // Add actual intro point bytes
```

**Option B: Separate IntroPoints message** (already defined)
```rust
// MessageType::IntroPoints exists but isn't being used
pub struct IntroPointsPayload {
    pub intro_points: Vec<IntroPointData>,
    pub fetched_at: u64,
}
```

**Recommendation**: Use Option B - keep heartbeats small, send IntroPoints separately
when they change.

### 2. Extract Raw Intro Point Bytes from Tor

Current `intro_point_refresh_loop` only gets the COUNT (by checking descriptor size).
We need to actually parse the descriptor to extract intro point data.

**Required**:
1. Fetch our descriptor via `GETINFO hs/service/desc/id/<addr>`
2. Decrypt the inner layer (we have the keys)
3. Extract introduction-point sections
4. Store raw bytes in `state.own_intro_points`

**Existing code that helps**:
- `src/tor/descriptors.rs` - Descriptor parsing
- `src/crypto/keys.rs` - Subcredential derivation
- Decryption logic in crypto module

### 3. Wire Up Publisher to Use Merged Intro Points

In `publish_loop` at the TODO:

```rust
// Current TODO in src/scheduler/loops.rs ~line 619
if total_intro_count > 0 {
    info!("Multi-node mode: merging {} own + {} peer intro points", ...);
    // TODO: Implement merged descriptor publishing via HSPOST
}
```

**Implementation**:
```rust
// 1. Collect own intro points
let own_ips: Vec<IntroductionPoint> = {
    let state = state.read().await;
    state.own_intro_points.iter()
        .filter_map(|ip| IntroductionPoint::from_raw(&ip.raw_data).ok())
        .collect()
};

// 2. Collect peer intro points
let peer_ips: Vec<IntroductionPoint> = {
    let coord = coordinator.read().await;
    coord.peers().collect_peer_intro_points()
        .into_iter()
        .filter_map(|ip| IntroductionPoint::from_raw(&ip.data).ok())
        .collect()
};

// 3. Merge (use DescriptorMerger or simple concat with cap)
let mut all_ips = own_ips;
all_ips.extend(peer_ips);
if all_ips.len() > config.publish.max_intro_points {
    all_ips.truncate(config.publish.max_intro_points);
}

// 4. Build and publish
let mut tor = TorController::connect(&config.tor).await?;
publisher.publish(&mut tor, all_ips).await?;
```

### 4. Conversion Functions

Need `IntroductionPoint::from_raw()` and `OwnIntroPoint.raw_data` population:

```rust
// In src/tor/mod.rs or src/tor/descriptors.rs
impl IntroductionPoint {
    pub fn from_raw(data: &[u8]) -> Result<Self> {
        // Parse link specifiers, onion key, auth key, enc key
        // from raw intro point bytes extracted from decrypted descriptor
    }
    
    pub fn to_raw(&self) -> Vec<u8> {
        // Serialize back to bytes for inclusion in merged descriptor
    }
}
```

## Implementation Order

1. **Extract raw intro point bytes** from our own descriptor (modify `intro_point_refresh_loop`)
2. **Send IntroPoints messages** when intro points change
3. **Handle received IntroPoints** in receive_loop (already stubbed)
4. **Collect all intro points** in publish_loop
5. **Build and publish** merged descriptor via HSPOST

## Testing

1. Deploy 2+ nodes
2. Verify each node has 3 intro points
3. Trigger publish (publisher should merge 6+ intro points)
4. Fetch descriptor from HSDir to verify it contains intro points from all nodes
5. Test client connection - should reach different nodes based on intro point selection

## References

- [Tor Proposal 307](https://spec.torproject.org/proposals/307-onionbalance-v3.html)
- [Onionbalance v3 source](https://github.com/asn-d6/onionbalance)
- [GoBalance implementation](https://github.com/ArcticDev78/GoBalance)
