# RustBalance Self-Healing Architecture

## Design Philosophy

RustBalance is designed to not just survive failures but **thrive** through them. The system should be:
- **Self-aware**: Know its current state and what's expected
- **Self-healing**: Automatically recover from failures without manual intervention
- **Smart**: Make intelligent decisions about retries, waits, and fallbacks
- **Resilient**: Gracefully degrade rather than fail completely

## GoBalance Reference: Failure Recovery Scenarios

Based on GoBalance's proven architecture, RustBalance must handle these scenarios:

### 1. Front Node Death (Seizure or Power Loss)

**Condition**: A RustBalance node is physically seized, disconnected, or powered down.

**GoBalance Behavior**: Detects connection timeout or 404 when fetching descriptor. Treats node as "unavailable," excludes its Introduction Points, immediately generates new Master Descriptor with surviving nodes.

**RustBalance Implementation**:
- [ ] Heartbeat timeout detection (configurable threshold, default 3 missed heartbeats)
- [ ] Automatic intro point exclusion from merged descriptor
- [ ] Immediate descriptor republish when peer goes offline
- [ ] Grace period before declaring peer dead (prevent flapping)
- [ ] Logging and alerting for node death events

### 2. Introduction Point Exhaustion (DDoS Flooding)

**Condition**: Attackers flood a specific Introduction Point until the Tor relay closes the circuit.

**GoBalance Behavior**: Tor daemon automatically rotates to new Introduction Point. GoBalance picks up new IP during next polling cycle and propagates to Master Identity.

**RustBalance Implementation**:
- [ ] Monitor intro point health via Tor control port
- [ ] Detect circuit closures and intro point failures
- [ ] Share new intro points with peers immediately (not just on heartbeat cycle)
- [ ] Emergency descriptor update for intro point rotation
- [ ] Rate limiting to prevent excessive republishing

### 3. Network Partition / Directory Failure

**Condition**: Specific HSDirs become unreachable or desynchronized due to Tor network turbulence.

**GoBalance Behavior**: Calculates full list of responsible HSDirs, attempts upload to all. Redundancy ensures descriptor available on others. Client caching allows connection using older valid descriptors.

**RustBalance Implementation**:
- [ ] HSPOST to all responsible HSDirs (not just one)
- [ ] Track which HSDirs succeeded/failed
- [ ] Retry failed HSDirs with exponential backoff
- [ ] Log HSDir health for monitoring
- [ ] Maintain descriptor validity period awareness

### 4. Controller Process Crash/Restart

**Condition**: The RustBalance process crashes or server reboots.

**GoBalance Behavior**: Initializes statelessly on restart. Reads config and persisted private key from disk, polls all Fronts for status, publishes fresh descriptor. Requires synchronized clock (NTP).

**RustBalance Implementation**:
- [x] Stateless initialization from config file
- [x] Persisted master key in HiddenServiceDir
- [ ] Clock synchronization validation on startup
- [ ] Immediate peer discovery on restart
- [ ] Fast descriptor republish after restart
- [ ] Graceful handling of stale state

## RustBalance-Specific Recovery Scenarios

### 5. WireGuard Tunnel Failure

**Condition**: WireGuard tunnel between nodes goes down (network change, firewall, etc.)

**Recovery Strategy**:
- [ ] Detect tunnel failure via failed heartbeat delivery
- [ ] Fallback to Tor-based coordination temporarily
- [ ] Attempt WireGuard reconnection with backoff
- [ ] Re-establish tunnel when network recovers

### 6. Tor Bootstrap Channel Failure

**Condition**: Joining node cannot reach init node via Tor (network issues, init node overwhelmed).

**Recovery Strategy**:
- [x] Retry with configurable attempts (currently 5x with 15s delay)
- [ ] Exponential backoff for repeated failures
- [ ] Alternative bootstrap peers from known_peers list
- [ ] Circuit-level retry (new Tor circuit per attempt)

### 7. Publisher Election Conflict

**Condition**: Network partition causes multiple nodes to believe they're publisher.

**Recovery Strategy**:
- [x] Lease-based election with deterministic winner
- [ ] Detect conflicting descriptors on HSDirs
- [ ] Force re-election when conflict detected
- [ ] Prefer node with most intro points in conflict resolution

### 8. Descriptor Signing Failure

**Condition**: Cryptographic operation fails (clock skew, corrupted key, etc.)

**Recovery Strategy**:
- [ ] Validate clock before signing operations
- [ ] Key integrity check on startup
- [ ] Fallback to backup key if available
- [ ] Alert and graceful degradation

## Implementation Priority

### Phase 1: Core Stability (Current)
- Get multi-node coordination working
- Basic heartbeat and election
- Descriptor merging and publishing

### Phase 2: Self-Healing Basics
- Peer death detection and exclusion
- Automatic descriptor updates on peer changes
- Process restart recovery

### Phase 3: Advanced Resilience
- Intro point health monitoring
- HSDir upload verification
- WireGuard fallback to Tor
- Exponential backoff everywhere

### Phase 4: Hardening
- Clock validation and NTP checks
- Key integrity verification
- Conflict detection and resolution
- Comprehensive alerting

## Monitoring & Observability

For self-healing to work, we need visibility:

```
[INFO] Peer node-xyz missed 2 heartbeats, 1 more until dead
[WARN] Peer node-xyz declared DEAD, removing 3 intro points
[INFO] Publishing updated descriptor with 6 intro points (was 9)
[INFO] Peer node-xyz came back! Adding to mesh
[INFO] Re-fetching intro points from recovered peer
```

## Configuration Options (Future)

```toml
[resilience]
# How many missed heartbeats before declaring peer dead
dead_threshold = 3

# Grace period after peer death before removing from descriptor (seconds)
removal_grace_period = 30

# Enable Tor fallback when WireGuard fails
tor_fallback_enabled = true

# Maximum retries for HSDir uploads
hsdir_max_retries = 3

# Enable clock validation on startup
require_ntp_sync = true
```

## Testing Scenarios

To validate self-healing, we should test:

1. **Kill a node**: Stop rustbalance on one VM, verify other continues
2. **Network partition**: Block WireGuard port, verify detection
3. **Process restart**: Kill and restart, verify state recovery
4. **Slow network**: Add latency, verify timeouts work correctly
5. **Clock skew**: Offset system time, verify rejection/handling
