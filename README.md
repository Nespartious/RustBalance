# RustBalance

**Tor hidden service load balancer — multi-node, self-healing, zero single point of failure.**

RustBalance distributes Tor `.onion` traffic across multiple VMs using a shared master address. Each node is a full hidden service that reverse-proxies to your real application. Nodes coordinate over WireGuard, elect a publisher, and merge their introduction points into one descriptor. If a node dies, traffic shifts to survivors automatically.

> Built in Rust. Inspired by [Onionbalance](https://onionservices.torproject.org/apps/base/onionbalance/). Designed to go further.

---

## How It Works

### 1 Node

```
    Client
      │
      ▼
┌────────────┐       ┌────────────┐
│ RustBalance│──────▶│  Target    │
│  Node A    │ proxy │  .onion    │
│ (master)   │       │ (your app) │
└────────────┘       └────────────┘

• Node IS the master .onion address
• Tor handles descriptor publishing natively
• Ready to scale — add nodes any time
```

### 2 Nodes

```
         Client
           │
     (random intro point)
       ┌───┴───┐
       ▼       ▼
┌──────────┐ ┌──────────┐
│  Node A  │ │  Node B  │
│ priority │ │ priority │
│   = 10   │ │   = 20   │
└────┬─────┘ └─────┬────┘
     │  WireGuard  │          ┌────────────┐
     │◄───────────►│──proxy──▶│   Target   │
     │  heartbeat  │          │   .onion   │
     └──────┬──────┘          └────────────┘
            │
    Node A publishes merged
    descriptor (6 intro pts)
    3 from A + 3 from B
```

### 5 Nodes

```
                       Client
                         │
                  (random intro point)
       ┌────────┬───────┼───────┬────────┐
       ▼        ▼       ▼       ▼        ▼
   ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐ ┌──────┐
   │  A   │ │  B   │ │  C   │ │  D   │ │  E   │
   │ p=10 │ │ p=20 │ │ p=30 │ │ p=40 │ │ p=50 │
   └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘ └──┬───┘
      │        │        │        │        │
      └────────┴────────┴────────┴────────┘
            WireGuard full-mesh (gossip)
                        │
             Node A publishes merged
             descriptor (15 intro pts)
                        │
                        ▼
                 ┌────────────┐
                 │   Target   │
                 │   .onion   │
                 └────────────┘

• All nodes reverse-proxy to same target
• Gossip protocol auto-discovers full mesh
• If Node A dies → Node B takes over publishing
• 15 intro points = 5× redundancy
```

---

## Quick Deploy

```bash
# Node 1 — generates master key + cluster token
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | \
  sudo bash -s -- --init --target your-real-service.onion --endpoint YOUR_IP:51820

# Node 2+ — use values from Node 1 output
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | \
  sudo bash -s -- --join --target your-real-service.onion --master-onion MASTER.onion \
  --master-key "BASE64_KEY" --peer-endpoint NODE1_IP:51820 --peer-pubkey "WG_PUBKEY" --cluster-token "TOKEN"
```

---

## Feature Status

### vs Onionbalance

Onionbalance is the standard Tor load balancer maintained by the Tor Project. RustBalance takes a different architectural approach — each node IS a hidden service (reverse-proxy model) rather than a separate publisher fetching descriptors from backend instances.

| Capability | Onionbalance | RustBalance | Status |
|:-----------|:------------:|:-----------:|:------:|
| Descriptor merging from multiple nodes | ✅ | ✅ | 🟢 |
| v3 onion service support | ✅ | ✅ | 🟢 |
| Introduction point aggregation | ✅ | ✅ | 🟢 |
| HSPOST descriptor publishing | ✅ | ✅ | 🟢 |
| Master key isolation | ✅ | ✅ | 🟢 |
| Multi-node coordination | ❌ | ✅ | 🟢 |
| WireGuard encrypted mesh | ❌ | ✅ | 🟢 |
| Gossip-based peer discovery | ❌ | ✅ | 🟢 |
| Self-healing mesh topology | ❌ | ✅ | 🟢 |
| Automatic publisher failover | ❌ | ✅ | 🟢 |
| Lease-based election (no consensus) | ❌ | ✅ | 🟢 |
| Integrated reverse proxy | ❌ | ✅ | 🟢 |
| One-command deploy script | ❌ | ✅ | 🟢 |
| Tor bootstrap join (no pre-shared WG) | ❌ | ✅ | 🟢 |
| Auto-detect single/multi-node mode | ❌ | ✅ | 🟢 |
| No single point of failure | ❌ | ✅ | 🟢 |
| Proof-of-Work support | ❌ | ✅ | 🟢 |
| Target health checking (HTTP probe) | ❌ | ❌ | 🔴 |
| Descriptor reupload on failure | ❌ | ❌ | 🔴 |
| Restricted discovery / client auth | ❌ | ❌ | 🔴 |

> 🟢 Implemented &nbsp; 🟡 In progress &nbsp; 🔴 Not yet implemented

### Improvements Over Onionbalance

These are features RustBalance adds that Onionbalance doesn't have:

- 🟢 **No single point of failure** — any node can become publisher
- 🟢 **Encrypted node coordination** — WireGuard mesh, not clearnet
- 🟢 **Gossip discovery** — nodes find each other automatically
- 🟢 **Self-healing mesh** — chain topology → full mesh, no manual wiring
- 🟢 **Automatic failover** — publisher election with grace period, no human intervention
- 🟢 **Integrated reverse proxy** — no separate backend onion services needed
- 🟢 **One-command deploy** — `curl | bash` to production in minutes
- 🟢 **Tor Bootstrap Channel** — joining nodes connect via master `.onion`, no pre-shared WireGuard info
- 🟢 **PoW support** — uses file-based `HiddenServiceDir` (Onionbalance uses `ADD_ONION` which can't do PoW)

### Roadmap — What's Left

| Feature | Phase | Difficulty |
|:--------|:-----:|:----------:|
| 🔴 Tor process watchdog | 1 | Easy |
| 🔴 Connection timeout to target | 1 | Easy |
| 🔴 Publish retry with backoff | 1 | Easy |
| 🔴 Smart first-publish timing | 1 | Easy |
| 🔴 Systemd hardening | 1 | Easy |
| 🔴 Target health check (HTTP probe via Tor) | 2 | Medium |
| 🔴 WireGuard interface health check | 2 | Medium |
| 🔴 Descriptor age emergency republish | 2 | Easy |
| 🔴 Graceful shutdown | 2 | Medium |
| 🔴 Clock drift detection | 2 | Easy |
| 🔴 Encrypted config & Argon2 key derivation | 3 | Hard |
| 🔴 Repair engine wired into scheduler | 3 | Medium |
| 🔴 Filesystem & systemd sandbox hardening | 3 | Easy |
| 🔴 Prometheus metrics export | 3 | Medium |
| 🔴 Intro point validation before merge | 3 | Medium |
| 🔴 Circuit-aware HSPOST with verification | 3 | Hard |
| 🔴 Redundant Tor instances (primary + standby) | 4 | Hard |
| 🔴 Memory-safe secrets (zeroize + mlock) | 4 | Medium |
| 🔴 Canary endpoint (self-test) | 4 | Medium |
| 🔴 Cluster token rotation | 4 | Hard |
| 🔴 Binary integrity & supply chain | 4 | Easy |
| 🔴 Anti-entropy HSDir verification | 4 | Hard |

---

## Architecture Decisions

| Decision | Why |
|:---------|:----|
| **Reverse-proxy model** | Each node IS a hidden service. No descriptor fetching, no backend key management. |
| **File-based HiddenServiceDir** | Enables Tor's native PoW support. `ADD_ONION` can't do this. |
| **WireGuard for coordination** | Fast, encrypted, kernel-level. No Tor latency for heartbeats. |
| **Lease-based election** | No voting, no quorum, no split-brain. Deterministic priority ordering. |
| **Gossip discovery** | Join any node → full mesh forms automatically. No topology planning. |

---

## Documentation

| Document | Description |
|:---------|:------------|
| [docs/CONFIG.md](docs/CONFIG.md) | Configuration reference |
| [docs/PROTOCOL.md](docs/PROTOCOL.md) | Message types and state machine |
| [docs/SECURITY.md](docs/SECURITY.md) | Security model and deployment guidelines |
| [docs/CHALLENGES.md](docs/CHALLENGES.md) | Technical challenges addressed |
| [Documentation/](Documentation/) | Phase 1–4 hardening development plans |

---

## License

MIT

## References

- [Tor Proposal 224: v3 Onion Services](https://spec.torproject.org/proposals/224-rend-spec-ng.html)
- [Tor Proposal 307: Onionbalance for v3](https://spec.torproject.org/proposals/307-onionbalance-v3.html)
- [Onionbalance Documentation](https://onionservices.torproject.org/apps/base/onionbalance/)
