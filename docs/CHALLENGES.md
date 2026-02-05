# Challenges & Known Issues

A blunt assessment of difficulties in building RustBalance.

## Architectural Challenges

### 1. Not a Real Load Balancer
**Reality**: RustBalance manipulates directory information, not traffic.

| Traditional LB | RustBalance |
|---------------|-------------|
| Routes packets | Publishes descriptors |
| Sees all traffic | Sees no traffic |
| Can rate limit | Cannot rate limit |
| Can modify requests | Cannot modify requests |

**Implication**: Traffic distribution is statistical, not controlled.

### 2. Eventual Consistency Only
Multiple publishers → conflicting descriptors → latest timestamp wins.

**Problems**:
- Brief split-brain is inevitable during failover
- No atomic transitions
- Clients may see inconsistent state for ~60s

**Mitigation**: Grace periods, clock sync, deterministic priority.

### 3. Clock Sensitivity
NTP drift → descriptor rejected → silent failure.

**Symptoms**:
- "Everything looks fine but clients can't connect"
- Intermittent failures
- No error messages

**Critical**: Run `ntpd` or `chronyd` on ALL nodes.

## Health Monitoring Gaps

### 4. Passive Health = Hidden Failures
Standard approach: "Is descriptor present and fresh?"

**What this catches**:
- Tor process crashed
- Server rebooted
- Network partition

**What this misses**:
- Web server crashed (Tor still running)
- Application deadlocked
- Database unreachable
- Disk full

**Result**: "Zombie backends" that accept connections but fail requests.

### 5. Active Probing Complexity
To properly health check, we must:
1. Build Tor circuit to backend
2. Send HTTP request through circuit
3. Validate response
4. Timeout gracefully

**Problems**:
- Circuit building takes 5-30 seconds
- Circuits fail randomly (~10% failure rate)
- Probes add load to Tor network
- False positives from network issues

## Descriptor Merging

### 6. v3 Cross-Certification Complexity
Copying intro points isn't enough. Each IP contains:
- Link specifiers (how to reach relay)
- Onion key (for handshake)
- Auth key certificate (proves authorization)
- Enc key certificate (for encryption)

**Problem**: Certificates are signed by backend's key, not master key.

**Solution**: Re-sign everything with master key (Proposal 307).

**Difficulty**: 7/10 - crypto must be exact or HSDirs reject silently.

### 7. Intro Point Limits
Descriptor max size: ~50KB
Practical IP limit: ~20

**With many backends**:
- 10 backends × 3 IPs each = 30 IPs
- Must select subset
- Selection affects load distribution

**Strategies**:
- Even distribution per backend
- Prefer stable IPs
- Randomize per publish

### 8. Silent Failures
Bad descriptor → HSDir ignores → no error → clients fail.

**Debugging nightmare**:
- "Did the upload succeed?"
- "Is the signature valid?"
- "Are the certs correct?"
- "Is the timestamp right?"

**Only way to know**: Fetch your own descriptor and verify.

## Coordination Challenges

### 9. Shared-Nothing is Actually Useful
Original Onionbalance: no coordination, just publish independently.

**Why this works**:
- Simpler
- No coordination failures
- Eventually consistent

**Why we want coordination anyway**:
- Know when to take over
- Avoid unnecessary republishing
- Detect failures faster

### 10. Split-Brain Edge Cases
```
A: "I'm publisher"
B: "No, I'm publisher"
(both publish)
```

**Handled by**:
- Priority ordering
- Timestamp conflicts resolved by HSDir
- Grace periods

**Not handled by**:
- Perfect consistency (impossible)
- Instant failover (physics)

### 11. WireGuard Dependency
Coordination requires nodes to communicate.

**If WireGuard fails**:
- Nodes can't see heartbeats
- False failover triggers
- Split-brain

**Mitigation**: Monitor WireGuard health separately.

## Arti/Rust Ecosystem Issues

### 12. No Public Descriptor Builder API
`tor-hsservice` is designed for "run a service automatically."

We need: "Build a custom descriptor manually."

**Current state**: Possible but requires:
- Accessing `pub(crate)` internals
- Understanding undocumented structures
- Fighting the type system

### 13. Internal APIs Change
If we use internal APIs:
- Pinned to exact arti version
- Breakage on updates
- No stability guarantees

**Options**:
1. Fork and maintain (high cost)
2. Accept version pinning (medium cost)
3. Use C-Tor instead (what we're doing)

### 14. PoW Support Incomplete
Proof-of-Work (Proposal 327) for DoS resistance.

**Status in Arti**: Experimental, incomplete.

**Impact**: Can't merge backends that require PoW until this matures.

### 15. C-Tor Dependency
Current approach: Use C-Tor via ControlPort.

**Advantages**:
- Battle-tested
- Full feature support
- Known behavior

**Disadvantages**:
- Extra process to manage
- ControlPort is legacy
- Not "pure Rust"

## Operational Challenges

### 16. Key Security is Critical
Master key compromise = permanent address compromise.

**Unlike TLS**: Can't just rotate certificates.

**Mitigations**:
- Isolate key on management nodes
- No inbound connections
- Hardware security modules (future)

### 17. Debugging is Hard
```
User: "Site is down"
You: "Let me check..."
- Is Tor running? Yes
- Is descriptor published? Looks like it
- Can clients fetch it? Sometimes
- Are backends healthy? Descriptors present
- Is the application up? ...probably?
```

**Tools needed**:
- Onionprobe (external)
- Descriptor verification
- End-to-end testing

### 18. Outbound Traffic Fingerprinting
Management servers → HSDirs creates traffic patterns.

**Observable**:
- Regular upload cadence
- HSDir selection pattern
- Timing correlation

**Partial mitigation**: Run management over Tor (slower).

## Summary Table

| Challenge | Difficulty | Status |
|-----------|------------|--------|
| Not a real LB | Accept | By design |
| Eventual consistency | Accept | Use grace periods |
| Clock sensitivity | Must mitigate | NTP required |
| Passive health gaps | Can fix | HTTP probing planned |
| v3 cross-certification | Hard | Implementing |
| IP limits | Accept | Selection algorithm |
| Silent failures | Hard | Better logging |
| Split-brain | Accept | Priority + timestamps |
| WireGuard dependency | Accept | Monitor separately |
| No descriptor API | Hard | Using C-Tor |
| PoW incomplete | Wait | Block on Arti |
| C-Tor dependency | Accept | For now |
| Key security | Critical | Isolation |
| Debugging | Hard | Tooling needed |

## What This Means for MVP

**Must have**:
- Clock sync (NTP)
- Graceful failover
- Basic health checks
- Descriptor merging

**Nice to have**:
- Active HTTP probing
- Pure Arti (no C-Tor)
- PoW support

**Post-MVP**:
- HSM integration
- Advanced debugging tools
- Onionprobe integration
