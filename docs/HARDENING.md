# RustBalance Hardening Guide

This document tracks failure modes, scaling considerations, and resilience improvements for production deployments.

> **Status**: Living document - updated as we identify issues during development and testing.

---

## Failure Modes

### Node-Level Failures

| Failure Mode | Detection | Current Handling | Proposed Improvement |
|--------------|-----------|------------------|---------------------|
| **Node crash** | Missing heartbeats (30s timeout) | Grace period (90s), then takeover | ✅ Implemented |
| **Tor daemon crash** | Control port unreachable | Restart via repair module | 🚧 Needs testing |
| **WireGuard interface down** | No heartbeat responses | Node isolated, continues serving | Add interface health check |
| **Disk full** | Log/descriptor write failures | None | Add disk space monitoring |
| **Memory exhaustion** | OOM killer | Process dies, systemd restarts | Add memory limits to service |
| **CPU starvation** | Slow heartbeats/timeouts | False takeover | Consider heartbeat jitter tolerance |

### Network Failures

| Failure Mode | Detection | Current Handling | Proposed Improvement |
|--------------|-----------|------------------|---------------------|
| **WireGuard partition** | Asymmetric heartbeat loss | Split-brain risk | Quorum-based publishing (3+ nodes) |
| **Tor network congestion** | Slow descriptor publishing | Retries | Exponential backoff |
| **HSDir unreachable** | HSPOST failures | Upload retries | HSDir rotation, parallel uploads |
| **DDoS on intro points** | High connection rate | Tor drops connections | Auto-scale intro points |

### Coordination Failures

| Failure Mode | Detection | Current Handling | Proposed Improvement |
|--------------|-----------|------------------|---------------------|
| **Clock skew** | Message timestamp validation | Reject messages >5s skew | NTP monitoring, graceful handling |
| **Stale intro points** | Certificate expiration | Re-sign on publish | Track expiration, preemptive refresh |
| **Gossip loop** | Duplicate peer announcements | Dedupe by node_id | ✅ Implemented |
| **Election split** | Multiple publishers | Priority-based resolution | Lease conflict detection |

---

## Scaling Considerations

### Intro Point Scaling

**Current behavior:**
- Each node contributes 3 intro points (Tor default)
- 2-node cluster = 6 total intro points in merged descriptor
- Tor allows up to ~20 intro points per descriptor

**Saturation detection:**
```
If ALL nodes report 3 intro points AND connection success rate < threshold:
  → Cluster may benefit from more intro points
```

**Proposed auto-scaling:**
| Cluster Size | Base IPs/Node | Saturated Mode | Max IPs/Node |
|--------------|---------------|----------------|--------------|
| 1 node | 3 | N/A (Tor managed) | 3 |
| 2 nodes | 3 | +1 each → 8 total | 4 |
| 3+ nodes | 3 | Redistribute load | 3 |

**Implementation ideas:**
- [ ] Monitor intro point success rate via Tor events
- [ ] Track `INTRO_POINT_FAILURE` events from control port
- [ ] If failure rate > 10%, request additional intro point from Tor
- [ ] Configurable `min_intro_points` and `max_intro_points` per node

### Descriptor Size Limits

- V3 descriptors have size limits (~50KB practical)
- Each intro point adds ~500 bytes to inner layer
- **Max practical intro points**: ~80-100 per descriptor
- With 20 IPs/descriptor Tor limit, this isn't a concern

### Heartbeat Scaling

| Cluster Size | Heartbeat Traffic | Concern |
|--------------|-------------------|---------|
| 2 nodes | 12 msgs/min | None |
| 5 nodes | 60 msgs/min | None |
| 10 nodes | 180 msgs/min | Monitor bandwidth |
| 20+ nodes | 720+ msgs/min | Consider hierarchical gossip |

---

## Health Metrics to Track

### Per-Node Metrics
- [ ] Intro point count (own)
- [ ] Intro point age (time since last refresh)
- [ ] Heartbeat latency to each peer
- [ ] Tor control port response time
- [ ] Descriptor publish success rate
- [ ] Target service health check results

### Cluster-Wide Metrics
- [ ] Total intro points across cluster
- [ ] Publisher election count (high = instability)
- [ ] Peer churn rate
- [ ] Descriptor revision counter progression

---

## Defensive Configurations

### Tor Hardening
```torrc
# Limit connections to prevent resource exhaustion
HiddenServiceMaxStreams 100
HiddenServiceMaxStreamsCloseCircuit 1

# Enable PoW defense (requires Tor 0.4.8+)
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 100
HiddenServicePoWQueueBurst 200
```

### Systemd Hardening
```ini
[Service]
# Resource limits
MemoryMax=512M
CPUQuota=80%

# Restart policy
Restart=always
RestartSec=5
StartLimitBurst=5
StartLimitInterval=60

# Security
NoNewPrivileges=yes
ProtectSystem=strict
PrivateTmp=yes
```

### WireGuard Hardening
```ini
# Persistent keepalive for NAT traversal
PersistentKeepalive = 25

# Consider: rotate keys periodically
# Consider: fail-closed if no peers respond
```

---

## Future Improvements

### Short Term (Post-HSPOST)
- [ ] Add `/health` endpoint for external monitoring
- [ ] Prometheus metrics export
- [ ] Structured logging with correlation IDs
- [ ] Graceful shutdown with descriptor handoff

### Medium Term
- [ ] HSDir replication (upload to multiple HSDirs simultaneously)
- [ ] Circuit-level health checks (not just control port)
- [ ] Intro point affinity (prefer stable relays)
- [ ] Geographic distribution awareness

### Long Term
- [ ] Kubernetes operator for RustBalance
- [ ] Web dashboard for cluster status
- [ ] Automated incident response (PagerDuty integration)
- [ ] Chaos engineering test suite

---

## Known Issues / Watchlist

| Issue | Status | Notes |
|-------|--------|-------|
| Certificate re-signing expiration | 🔍 Investigating | Must preserve original expiration from intro points |
| Large cluster gossip overhead | 📋 Planned | Consider hierarchical gossip for 10+ nodes |
| Split-brain with 2 nodes | ⚠️ Inherent | Recommend 3+ nodes for production |
| Tor PoW compatibility | ✅ Supported | File-based HS mode enables PoW |

---

## Testing Checklist

### Failure Injection Tests
- [ ] Kill publisher node → verify takeover
- [ ] Network partition between nodes → verify continued operation
- [ ] Restart Tor daemon → verify service recovery
- [ ] Corrupt descriptor → verify re-publish
- [ ] Clock skew simulation → verify rejection

### Load Tests
- [ ] Sustained high connection rate
- [ ] Large descriptor (many intro points)
- [ ] Rapid publisher churn
- [ ] Concurrent node joins

---

*Last updated: 2026-02-05*
