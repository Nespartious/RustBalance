# RustBalance

**High-availability reverse proxy for Tor hidden services with automatic failover and mesh self-healing.**

> ⚠️ **Security Notice**: This project is for Tor/Onion network infrastructure. No JavaScript, XML, or browser-executable content.

---

## TL;DR

RustBalance lets you run **multiple VMs as a single .onion address** with automatic load distribution and failover:

1. Deploy RustBalance on 2+ VMs
2. All nodes share the same master .onion address  
3. Clients connect to any node randomly (Tor handles distribution)
4. If a node dies, traffic automatically goes to surviving nodes
5. Nodes discover each other via gossip - no manual mesh management

**Quick Deploy:**
```bash
# First node (generates master key + cluster token)
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \
  --init --target your-real-service.onion --endpoint YOUR_IP:51820

# Additional nodes (use values from first node output)
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \
  --join --target your-real-service.onion --master-onion MASTER.onion \
  --master-key "BASE64_KEY" --peer-endpoint FIRST_NODE_IP:51820 \
  --peer-pubkey "WG_PUBKEY" --cluster-token "TOKEN"
```

---

## How It Works

### Architecture

```
                    ┌─────────────────────┐
                    │       Client        │
                    │ visits master.onion │
                    └──────────┬──────────┘
                               │
                    Tor HS protocol (random intro point selection)
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│ RustBalance     │  │ RustBalance     │  │ RustBalance     │
│ Node A (VM1)    │  │ Node B (VM2)    │  │ Node C (VM3)    │
│                 │  │                 │  │                 │
│ - IS a Tor HS   │  │ - IS a Tor HS   │  │ - IS a Tor HS   │
│ - Own intro pts │  │ - Own intro pts │  │ - Own intro pts │
│ - Accepts conns │  │ - Accepts conns │  │ - Accepts conns │
│ - Reverse proxy │  │ - Reverse proxy │  │ - Reverse proxy │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         │   WireGuard mesh (auto-healing gossip)  │
         └────────────────────┼────────────────────┘
                              │
                    Reverse proxy over Tor SOCKS
                              │
                              ▼
                    ┌─────────────────────┐
                    │   Target Service    │
                    │  (real app .onion)  │
                    │                     │
                    │   Never publicly    │
                    │      exposed        │
                    └─────────────────────┘
```

### Key Concepts

| Concept | Description |
|---------|-------------|
| **Master Address** | The public `.onion` clients connect to - shared by all nodes |
| **Target Service** | Your real application's .onion - never publicly exposed |
| **Introduction Points** | Tor relays that accept connections on behalf of the service |
| **Descriptor** | Signed document listing intro points, published to HSDir ring |
| **Gossip Protocol** | How nodes discover each other and self-heal the mesh |

### What Makes It Different

| Feature | Traditional LB | Standard Onionbalance | RustBalance |
|---------|---------------|----------------------|-------------|
| Architecture | Centralized | Fetch descriptors | Reverse proxy |
| Single point of failure | Yes | Partially | No |
| Node coordination | N/A | None | WireGuard mesh |
| Failover | Manual | Slow (descriptor refresh) | Automatic |
| Mesh topology | N/A | N/A | Self-healing |

---

## Detailed Operation

### Single-Node vs Multi-Node (Auto-Detect)

RustBalance automatically determines its operating mode:

**Single-Node Mode** (no peers detected):
- Tor handles descriptor publishing natively
- Node runs as standard hidden service
- Ready to scale up at any time

**Multi-Node Mode** (peers detected via heartbeat):
- Election determines publisher node
- Publisher merges intro points from all nodes
- Merged descriptor published via HSPOST
- If publisher dies, next priority node takes over

### Gossip-Based Mesh Self-Healing

**Problem:** Node C joins via Node B. Node A and C don't know each other.

```
Node A ←──WG──→ Node B ←──WG──→ Node C
   ↑                              ↑
   └──────── NO CONNECTION ───────┘
```

**Solution:** Each heartbeat includes `known_peers` list:

1. Node B sends heartbeat to Node A with `known_peers: [Node C]`
2. Node A discovers Node C, adds WireGuard peer dynamically
3. Node A sends PeerAnnounce to Node C
4. Full mesh established automatically

```
A ─── B
 \   /
  \ /
   C

Full mesh (self-healed)
```

### Publisher Election

Lease-based election - no consensus required:

1. All nodes start as `Standby`
2. Nodes exchange heartbeats via WireGuard (every 10s)
3. If publisher heartbeat missing for `heartbeat_timeout` (30s):
   - Mark publisher as "suspect"
   - Start grace period timer (90s)
4. After grace expires:
   - Lowest priority number wins
   - Winner claims lease, becomes publisher
   - Others back off

**No voting. No quorum. No split-brain.**

### Takeover Timeline Example

```
T=0s     Node A (priority=10) is publisher, sends heartbeat
T=10s    Node B (priority=20) sees healthy heartbeat, stays standby
T=25s    Node A crashes
T=55s    Node B notices missing heartbeats, marks suspect
T=145s   Grace period (90s) expired
T=146s   Node B claims lease, becomes publisher
T=150s   Node B publishes new merged descriptor
```

---

## Configuration

### Minimal Example

```toml
[node]
id = "node-a"
priority = 10

[master]
onion_address = "yourmasteraddress.onion"
identity_key_path = "/etc/rustbalance/master_ed25519.key"

[target]
onion_address = "your-real-service.onion"
port = 80

[coordination]
cluster_token = "shared-secret-from-first-node"

[wireguard]
interface = "wg-rb"
listen_port = 51820
tunnel_ip = "10.200.200.1"
private_key = "BASE64_PRIVATE_KEY"
public_key = "BASE64_PUBLIC_KEY"
external_endpoint = "YOUR_PUBLIC_IP:51820"
```

See [docs/CONFIG.md](docs/CONFIG.md) for complete reference.

---

## Module Structure

```
src/
├── main.rs           # Entry point, arg parsing
├── lib.rs            # Library exports
├── logging.rs        # Structured logging
│
├── config/           # Configuration loading
│   ├── mod.rs        # Config structs
│   ├── file.rs       # TOML loading
│   └── validation.rs # Validation rules
│
├── crypto/           # Cryptographic operations
│   ├── mod.rs        # Module exports
│   ├── keys.rs       # Ed25519 key handling
│   └── blinding.rs   # v3 key blinding
│
├── tor/              # Tor daemon interaction
│   ├── mod.rs        # Module exports
│   ├── control.rs    # ControlPort client
│   ├── descriptors.rs # Descriptor parsing
│   └── hsdir.rs      # HSDir ring calculation
│
├── balance/          # Load balancing logic
│   ├── mod.rs        # Module exports
│   ├── backend.rs    # Backend tracking
│   ├── health.rs     # Health checking
│   ├── merge.rs      # Descriptor merging
│   └── publish.rs    # HSPOST publishing
│
├── coord/            # Node coordination
│   ├── mod.rs        # Coordinator struct
│   ├── messages.rs   # Protocol messages
│   ├── peers.rs      # Peer state tracking
│   ├── wireguard.rs  # WireGuard transport
│   ├── election.rs   # Publisher election
│   └── lease.rs      # Lease management
│
├── repair/           # Self-healing
│   ├── mod.rs        # Repair manager
│   ├── actions.rs    # Repair actions
│   └── restart.rs    # Tor restart logic
│
├── scheduler/        # Task orchestration
│   ├── mod.rs        # Scheduler exports
│   └── loops.rs      # Main event loops
│
├── state/            # Runtime state
│   ├── mod.rs        # State manager
│   └── model.rs      # State structures
│
└── util/             # Utilities
    ├── mod.rs        # Utility exports
    ├── time.rs       # Time helpers
    └── rand.rs       # Randomization
```

---

## Security Model

### Key Isolation
- Master identity key lives **only** on RustBalance nodes
- Target service key is separate and independent
- Compromised target doesn't expose master key

### Cluster Security
- **Cluster Token**: Shared secret authenticates new nodes joining mesh
- **WireGuard**: Encrypts and authenticates all inter-node traffic
- **Clock Validation**: Messages rejected if timestamp skew > 5s

### Attack Surface

| Threat | Impact | Mitigation |
|--------|--------|------------|
| Node compromise | Attacker can see traffic through that node | Other nodes continue operating |
| Target compromise | Service disruption | Master address unaffected, redeploy target |
| WireGuard key leak | Attacker could join mesh | Cluster token provides second factor |
| Network partition | Nodes can't coordinate | Each node continues serving independently |

---

## Development Status

**Current Phase**: Multi-node coordination ✅ → Merged descriptor publishing 🚧

### Completed ✅
- [x] Configuration system
- [x] Tor ControlPort client
- [x] WireGuard coordination transport
- [x] Heartbeat protocol with gossip
- [x] Peer discovery and mesh self-healing
- [x] Dynamic WireGuard peer addition
- [x] Cluster token authentication
- [x] Publisher election algorithm
- [x] Lease management
- [x] Auto-detect single/multi-node mode
- [x] **Tor Bootstrap Channel** - Join via master .onion (no pre-shared WireGuard info)
- [x] **Peer lifecycle tracking** - Joining → Initializing → Healthy
- [x] **Intro point aggregation** - Collect counts from all healthy peers

### In Progress 🚧
- [ ] Merged descriptor publishing (HSPOST) - Build merged descriptor from all nodes' intro points
- [ ] Active HTTP health probes
- [ ] Full integration tests

---

## Documentation

- [Configuration Reference](docs/CONFIG.md) - All config options explained
- [Protocol Specification](docs/PROTOCOL.md) - Message types and state machine
- [Security Guidelines](docs/SECURITY.md) - Deployment security best practices
- [Architecture Deep Dive](docs/ARCHITECTURE.md) - Detailed design decisions
- [Challenges & Solutions](docs/CHALLENGES.md) - Technical challenges addressed
- [Development Guide](docs/DEVELOPMENT.md) - Building and contributing
- [Roadmap](docs/ROADMAP.md) - Project phases and progress

---

## Deployment

### Prerequisites
- Ubuntu 22.04+ (or similar Linux)
- Tor daemon (installed by deploy script)
- WireGuard (installed by deploy script)
- Network connectivity between nodes on UDP/51820

### Using Deploy Script

The deploy script handles everything automatically:

```bash
# Download and run (first node)
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- \
  --init \
  --target your-real-service.onion \
  --endpoint YOUR_PUBLIC_IP:51820
```

The script will:
1. Install dependencies (Tor, WireGuard, Rust)
2. Clone and build RustBalance
3. Generate cryptographic keys
4. Configure Tor hidden service
5. Set up WireGuard interface
6. Create systemd service
7. Output join command for additional nodes

See [testing/deploy.sh](testing/deploy.sh) for full source.

---

## License

MIT

## References

- [Onionbalance Documentation](https://onionbalance-v3.readthedocs.io/)
- [Tor Proposal 307: Onionbalance for v3](https://spec.torproject.org/proposals/307-onionbalance-v3.html)
- [Tor Proposal 224: v3 Onion Services](https://spec.torproject.org/proposals/224-rend-spec-ng.html)
