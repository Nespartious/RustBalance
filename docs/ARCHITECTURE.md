# RustBalance Architecture

## User Experience Flow

### First Node Setup (Origin)
```
$ rustbalance init --vanity-prefix "mysite"

🔑 Generating master identity key...
🔑 Generating WireGuard keypair...
📝 Creating configuration...

✅ RustBalance initialized!

Master Onion Address: mysitexyz...............qd.onion
Node ID: node-alpha-7f3a
Priority: 1 (primary publisher)

Join token for additional nodes:
╔════════════════════════════════════════════════════════════════╗
║ rb1:eyJub2RlIjoibm9kZS1hbHBoYS03ZjNhIiwid2dfcHViIjoiTkVl...    ║
╚════════════════════════════════════════════════════════════════╝

Run on additional VPS: rustbalance join <token>

Starting RustBalance daemon...
```

### Additional Node Setup
```
$ rustbalance join rb1:eyJub2RlIjoibm9kZS1hbHBoYS03ZjNhIiwid2...

🔗 Connecting to origin node...
🔑 Generating local WireGuard keypair...
📦 Receiving cluster configuration...
🔄 Synchronizing peer list...

✅ Joined RustBalance cluster!

Node ID: node-beta-2c1d  
Priority: 2 (standby)
Cluster size: 2 nodes
Current publisher: node-alpha-7f3a

Starting RustBalance daemon...
```

### After Setup (Zero Touch)
```
System automatically:
├── Monitors backend health every ~5 minutes
├── Sends heartbeats every 10 seconds
├── Publishes descriptors every 10 minutes (if publisher)
├── Detects publisher failure after 30s silence
├── Waits 90s grace period before takeover
├── Re-publishes immediately on takeover
├── Repairs Tor connection on failure
├── Excludes dead backends from rotation
└── Re-includes recovered backends
```

---

## System Components

```
┌─────────────────────────────────────────────────────────────────────┐
│                         USER INTERACTION                            │
│   (only during init/join - zero touch after)                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────┐ │
│  │ rustbalance │    │ rustbalance │    │ rustbalance status      │ │
│  │ init        │    │ join <tok>  │    │ (optional monitoring)   │ │
│  └──────┬──────┘    └──────┬──────┘    └─────────────────────────┘ │
│         │                  │                                        │
│         ▼                  ▼                                        │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    CONFIG GENERATION                         │   │
│  │  • Master key (origin only)                                  │   │
│  │  • WireGuard keypair                                         │   │
│  │  • Node ID + priority                                        │   │
│  │  • Peer list                                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                              │                                      │
├──────────────────────────────┼──────────────────────────────────────┤
│                              ▼                                      │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                      SCHEDULER                               │   │
│  │                                                              │   │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐ │   │
│  │  │ Health   │  │Heartbeat │  │ Receive  │  │   Publish    │ │   │
│  │  │ Loop     │  │  Loop    │  │  Loop    │  │    Loop      │ │   │
│  │  │ (5min)   │  │ (10sec)  │  │ (async)  │  │  (10min)     │ │   │
│  │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘ │   │
│  │       │             │             │               │          │   │
│  └───────┼─────────────┼─────────────┼───────────────┼──────────┘   │
│          │             │             │               │              │
│          ▼             ▼             ▼               ▼              │
│  ┌───────────┐  ┌────────────┐  ┌─────────┐  ┌────────────────┐    │
│  │  HEALTH   │  │   COORD    │  │  COORD  │  │    BALANCE     │    │
│  │  CHECKER  │  │ TRANSPORT  │  │ELECTION │  │   PUBLISHER    │    │
│  └─────┬─────┘  └─────┬──────┘  └────┬────┘  └───────┬────────┘    │
│        │              │              │               │              │
│        │         ┌────┴────┐         │               │              │
│        │         │WireGuard│         │               │              │
│        │         │  wg0    │         │               │              │
│        │         └────┬────┘         │               │              │
│        │              │              │               │              │
│        ▼              ▼              │               ▼              │
│  ┌───────────────────────────────────┴─────────────────────────┐   │
│  │                    TOR CONTROLLER                            │   │
│  │  • HSFETCH (get backend descriptors)                        │   │
│  │  • HSPOST (upload master descriptor)                         │   │
│  │  • Event subscription                                        │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
│                             │                                       │
├─────────────────────────────┼───────────────────────────────────────┤
│                             ▼                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    LOCAL TOR DAEMON                          │   │
│  │  • ControlPort 9051                                          │   │
│  │  • SOCKSPort 9050 (for HTTP probes)                         │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### 1. Backend Health Check
```
Health Loop
    │
    ├─► For each backend in config:
    │       │
    │       ├─► HSFETCH backend.onion via Tor Control
    │       │
    │       ├─► Parse descriptor, extract intro points
    │       │
    │       ├─► Check descriptor age vs max_age
    │       │
    │       ├─► (Optional) HTTP probe via Tor SOCKS
    │       │
    │       └─► Update backend state: Healthy/Stale/Dead
    │
    └─► Store updated states in RuntimeState
```

### 2. Coordination Heartbeat
```
Heartbeat Loop
    │
    ├─► Build HeartbeatMessage {
    │       node_id: "node-alpha",
    │       timestamp: now(),
    │       role: Publisher|Standby,
    │       last_publish_ts: Option<u64>
    │   }
    │
    ├─► Serialize to JSON
    │
    └─► Send via WireGuard UDP to all peers
```

### 3. Publisher Election
```
Receive Loop
    │
    ├─► Receive message from WireGuard
    │
    ├─► Validate timestamp (clock skew check)
    │
    ├─► Update peer state table
    │
    └─► Election.process_message()
            │
            ├─► If Heartbeat: update last_seen, role
            │
            ├─► If LeaseClaim: check priority, maybe back off
            │
            └─► If LeaseRelease: clear current_publisher

Publish Loop (before publish)
    │
    ├─► Check Election.should_take_over():
    │       │
    │       ├─► Is current publisher healthy? (seen < 30s ago)
    │       │       Yes → return false
    │       │
    │       ├─► Publisher suspect > 90s (grace period)?
    │       │       No → return false
    │       │
    │       └─► Am I highest priority among healthy nodes?
    │               No → return false
    │               Yes → return true
    │
    └─► If should_take_over: become_publisher(), broadcast LeaseClaim
```

### 4. Descriptor Publishing
```
Publish Loop (as publisher)
    │
    ├─► Collect intro points from healthy backends
    │       │
    │       └─► Merger.merge(): fair distribution, cap at 20
    │
    ├─► Get current time period
    │
    ├─► Blind master identity key for time period
    │
    ├─► Derive subcredential
    │
    ├─► Build descriptor:
    │       │
    │       ├─► Encode intro points
    │       │
    │       ├─► Encrypt inner layer (subcredential)
    │       │
    │       ├─► Encrypt outer layer (blinded key)
    │       │
    │       └─► Sign with blinded key
    │
    ├─► Calculate HSDir ring positions
    │
    └─► HSPOST to Tor Control → uploads to HSDirs
```

---

## State Model

```rust
RuntimeState {
    // Identity
    node_id: String,              // "node-alpha-7f3a"
    
    // Role
    role: NodeRole,               // Publisher | Standby
    lease: Option<Lease>,         // If publisher, our lease
    
    // Cluster
    peers: HashMap<String, PeerState>,
    current_publisher: Option<String>,
    
    // Backends
    backends: Vec<Backend>,       // Health states
    
    // Timing
    last_publish: Option<SystemTime>,
    last_heartbeat_sent: Option<SystemTime>,
}

PeerState {
    id: String,
    priority: u32,
    role: NodeRole,
    last_seen: SystemTime,
    wg_endpoint: SocketAddr,
    wg_pubkey: [u8; 32],
}

Backend {
    name: String,
    onion_address: String,
    state: Healthy | Stale | Dead | Excluded,
    last_seen: Option<SystemTime>,
    descriptor: Option<HsDescriptor>,
    failure_count: u32,
}
```

---

## Failure Modes & Recovery

| Failure | Detection | Recovery |
|---------|-----------|----------|
| Publisher crash | No heartbeat for 30s | Grace period 90s, then highest-priority standby takes over |
| Tor daemon crash | Control port error | Restart Tor via systemd, reconnect |
| Backend dead | Descriptor fetch fails | Mark dead, exclude from merge |
| WireGuard down | No messages from any peer | Log warning, continue as isolated node |
| Split brain | Multiple LeaseClaims | Lowest priority wins, others back off |
| Clock drift | Message timestamp > 5s off | Reject message, log warning |
| All backends dead | No intro points to merge | Stop publishing, send alert |

---

## Join Token Format

```
rb1:<base64-encoded-json>
```

Decoded JSON:
```json
{
  "version": 1,
  "origin": {
    "node_id": "node-alpha-7f3a",
    "wg_pubkey": "<base64>",
    "wg_endpoint": "203.0.113.10:51820"
  },
  "master_key_encrypted": "<base64-aes-gcm>",
  "encryption_nonce": "<base64>",
  "cluster_secret": "<base64>"
}
```

The `cluster_secret` is used to:
1. Encrypt the master key in the token
2. Authenticate new peer announcements
3. Derive WireGuard PSK for additional security

---

## File Locations

```
/etc/rustbalance/
├── config.toml           # Main configuration
├── master.key            # Master Ed25519 identity (encrypted)
├── node.key              # This node's signing key
├── wg_private.key        # WireGuard private key
└── peers/                # Peer certificates
    ├── node-alpha.pub
    └── node-beta.pub

/var/lib/rustbalance/
├── state.json            # Persistent state (last publish, etc.)
└── descriptors/          # Cached backend descriptors
    ├── backend-1.desc
    └── backend-2.desc

/var/log/rustbalance/
└── rustbalance.log       # Logs (or journald)
```
