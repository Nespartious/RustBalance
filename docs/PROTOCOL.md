# Coordination Protocol

RustBalance nodes communicate via a simple message protocol over WireGuard (or Tor).

---

## TL;DR

- **6 message types**: Heartbeat, PeerAnnounce, IntroPoints, LeaseClaim, LeaseRelease, BackendUnhealthy
- **Heartbeats every 10s** include gossip (`known_peers`) for mesh self-healing
- **Gossip enables auto-discovery**: Nodes learn about other nodes through heartbeats
- **No consensus needed**: Lease-based election - lowest priority wins when publisher dies
- **WireGuard encrypts everything**: Messages are just JSON over UDP
- **Clock validation**: Messages rejected if timestamp differs by >5 seconds

---

## Design Principles

1. **Signaling only** - No remote commands, no state sync
2. **Authenticated** - WireGuard handles auth/encryption
3. **Time-validated** - Messages rejected outside clock window
4. **Gossip-based discovery** - Nodes discover each other via heartbeat gossip
5. **Auto-detect mode** - Single vs multi-node determined by peer presence

## Transport

### WireGuard (Recommended)
- UDP packets over WireGuard tunnel
- Peer-to-peer mesh (self-healing via gossip)
- Fast, reliable, authenticated

### Tor (Fallback)
- Onion-to-onion connections
- Slower, more fragile
- Use only when private network unavailable

## Message Envelope

All messages share this structure:

```json
{
  "node_id": "node-a",
  "timestamp": 1700000123,
  "type": "<message_type>",
  "payload": { }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `node_id` | string | Sender's node ID |
| `timestamp` | u64 | Unix timestamp (seconds) |
| `type` | string | Message type identifier |
| `payload` | object | Type-specific data |

## Message Types

### 1. Heartbeat

Sent periodically by all nodes. Includes peer gossip for mesh self-healing.

```json
{
  "node_id": "node-a",
  "timestamp": 1700000123,
  "type": "heartbeat",
  "payload": {
    "role": "publisher",
    "last_publish_ts": 1700000100,
    "known_peers": [
      {
        "node_id": "node-b",
        "wg_pubkey": "abc123...",
        "wg_endpoint": "192.168.1.2:51820",
        "tunnel_ip": "10.200.200.2"
      }
    ],
    "intro_point_count": 3
  }
}
```

| Payload Field | Type | Description |
|---------------|------|-------------|
| `role` | string | "publisher" or "standby" |
| `last_publish_ts` | u64? | Last publish timestamp (if publisher) |
| `known_peers` | array | List of known peers for gossip |
| `intro_point_count` | usize | Number of intro points this node has |

**Frequency**: Every `heartbeat_interval_secs` (default 10s)

**Gossip Protocol**: When a node receives a heartbeat with `known_peers`, it checks
for any peers it doesn't know about. Unknown peers are added to the tracker and
the receiving node initiates a WireGuard connection + PeerAnnounce to complete
the mesh.

### 2. Peer Announce

Sent when a node joins the cluster. Authenticated via cluster token.

```json
{
  "node_id": "node-c",
  "timestamp": 1700000150,
  "type": "peer_announce",
  "payload": {
    "cluster_token": "secret-token-here",
    "wg_pubkey": "xyz789...",
    "wg_endpoint": "192.168.1.3:51820",
    "tunnel_ip": "10.200.200.3"
  }
}
```

| Payload Field | Type | Description |
|---------------|------|-------------|
| `cluster_token` | string | Shared secret for authentication |
| `wg_pubkey` | string | Node's WireGuard public key |
| `wg_endpoint` | string | Node's public IP:port for WireGuard |
| `tunnel_ip` | string | Node's tunnel IP address |

**Triggers**:
- Node startup with `--join` mode
- Discovery via gossip (connecting to unknown peer)

### 3. Intro Points

Sent by nodes to share their introduction points for descriptor merging.

```json
{
  "node_id": "node-a",
  "timestamp": 1700000200,
  "type": "intro_points",
  "payload": {
    "intro_points": [
      { "data": "base64-encoded-intro-point-1" },
      { "data": "base64-encoded-intro-point-2" }
    ],
    "fetched_at": 1700000195
  }
}
```

| Payload Field | Type | Description |
|---------------|------|-------------|
| `intro_points` | array | Base64-encoded intro point data |
| `fetched_at` | u64 | Timestamp when intro points were fetched |

**Frequency**: Sent with or after heartbeat when intro points change

### 4. Lease Claim

Sent when a node is taking over as publisher.

```json
{
  "node_id": "node-b",
  "timestamp": 1700000200,
  "type": "lease_claim",
  "payload": {
    "priority": 20
  }
}
```

| Payload Field | Type | Description |
|---------------|------|-------------|
| `priority` | u32 | Node's election priority |

**Triggers**:
- Publisher heartbeat timeout
- Grace period expired
- This node has highest priority

### 5. Lease Release

Sent when a publisher is stepping down gracefully.

```json
{
  "node_id": "node-a",
  "timestamp": 1700000300,
  "type": "lease_release",
  "payload": {}
}
```

**Triggers**:
- Graceful shutdown
- Admin intervention
- Self-detected failure

### 6. Backend Unhealthy (Optional)

Hint to other nodes about backend failures.

```json
{
  "node_id": "node-a",
  "timestamp": 1700000400,
  "type": "backend_unhealthy",
  "payload": {
    "backend": "backend-2"
  }
}
```

| Payload Field | Type | Description |
|---------------|------|-------------|
| `backend` | string | Name of unhealthy backend |

**Note**: Each node still performs its own health checks. This is advisory only.

## Validation

### On Receipt

1. **Check sender** - Ignore unknown `node_id`
2. **Check timestamp** - Reject if outside `clock_skew_tolerance_secs`
3. **Parse payload** - Ignore malformed messages

### Clock Skew

```
valid = |now - message.timestamp| <= clock_skew_tolerance_secs
```

Default tolerance: 5 seconds

**Critical**: All nodes MUST run NTP or equivalent time sync.

## State Machine

```
                    ┌─────────────┐
                    │   STANDBY   │
                    └──────┬──────┘
                           │
         heartbeat_timeout │
                           ▼
                    ┌─────────────┐
                    │   SUSPECT   │
                    └──────┬──────┘
                           │
           takeover_grace  │
                           ▼
              ┌────────────────────────┐
              │ Am I highest priority? │
              └────────────┬───────────┘
                           │
                   yes     │     no
              ┌────────────┴────────────┐
              ▼                         ▼
       ┌─────────────┐          ┌─────────────┐
       │  PUBLISHER  │          │   STANDBY   │
       └─────────────┘          └─────────────┘
              │
              │ see higher priority claim
              ▼
       ┌─────────────┐
       │   STANDBY   │
       └─────────────┘
```

## Security Considerations

### What Messages Can Do
- Announce presence
- Announce role
- Trigger election logic

### What Messages Cannot Do
- Execute commands
- Modify configuration
- Access keys or data
- Override local health checks

### Threat Model
| Threat | Mitigation |
|--------|------------|
| Replay attack | Timestamp validation |
| Spoofed sender | WireGuard auth |
| Message injection | WireGuard encryption |
| DoS via messages | Rate limiting, ignore bursts |

## Example Flows

### Normal Operation

```
node-a (publisher)              node-b (standby)
     │                               │
     ├─── heartbeat(publisher) ─────▶│
     │                               │
     │◀── heartbeat(standby) ────────┤
     │                               │
    ... (every 10 seconds) ...
```

### Failover

```
node-a (publisher)              node-b (standby)
     │                               │
     ├─── heartbeat(publisher) ─────▶│
     │                               │
     X (crash)                       │
     │                               │
     │    (no heartbeat)             │
     │                               ├── mark suspect
     │                               │
     │    (30s timeout)              │
     │                               ├── suspect confirmed
     │                               │
     │    (90s grace)                │
     │                               ├── grace expired
     │                               │
     │                               ├── check priority: I win
     │                               │
     │◀── lease_claim(priority=20) ──┤
     │                               │
     │◀── heartbeat(publisher) ──────┤
     │                               │
                              node-b is publisher
```

### Priority Conflict

```
node-a (p=10)                   node-b (p=20)
     │                               │
     │ (both see dead publisher)     │
     │                               │
     ├── lease_claim(priority=10) ──▶│
     │                               ├── 10 < 20, back off
     │◀── (no claim) ────────────────┤
     │                               │
     │ (node-a becomes publisher)    │
```

## Auto-Detect Mode

RustBalance automatically detects whether it's running in single-node or multi-node
mode based on the presence of active peers.

### Single-Node Mode
- No active peers detected (alive_count == 0)
- Node automatically becomes publisher
- Tor handles descriptor publishing directly
- No coordination messages sent (except to listen for new peers)

### Multi-Node Mode
- One or more active peers detected (alive_count > 0)
- Election logic determines publisher
- Publisher merges intro points from all nodes
- Publisher sends merged descriptor via HSPOST

### Transition
Mode is checked on each publish loop tick:
- If peers appear: switch to multi-node mode, run election
- If all peers disappear: auto-become publisher, let Tor publish

## Mesh Self-Healing

The gossip protocol ensures the mesh self-heals regardless of join topology.

### Problem Scenario
```
Node 1 ←──WG──→ Node 2 ←──WG──→ Node 3
   ↑                              ↑
   └──────── NO CONNECTION ───────┘
```

If Node 3 joins via Node 2, Node 1 and Node 3 don't initially know each other.

### Solution: Heartbeat Gossip
1. Node 2 sends heartbeat to Node 1, includes `known_peers: [Node 3]`
2. Node 1 sees unknown peer Node 3
3. Node 1 adds WireGuard peer for Node 3
4. Node 1 sends PeerAnnounce to Node 3
5. Node 3 adds Node 1 as peer
6. Full mesh established

### Result
```
N1 ─── N2
 │ \   │
 │  \  │
 │   \ │
 └─── N3

Full mesh (self-healed)
```

## Tor Bootstrap Channel

New nodes can join the cluster using only the master .onion address - no pre-shared
WireGuard credentials required.

### Join Flow

```
                    Joining Node                           Existing Node (Node 1)
                         │                                        │
                         │                                        │
     1. Connect via Tor  │ ────── SOCKS5 to master.onion ───────▶ │
                         │                                        │
     2. POST join request│ ─── POST /.rb/<join_secret> ──────────▶│
                         │     { cluster_token, wg_pubkey,        │
                         │       wg_endpoint, tunnel_ip, ts }     │
                         │                                        ├── 3. Validate token
                         │                                        ├── 4. Add WG peer
                         │                                        │
                         │◀──────── JSON Response ─────────────────│
                         │     { responder_*, known_peers }       │
     5. Add WG peer      │                                        │
                         │                                        │
     6. Configure HS     ├── (now safe to configure local HS)     │
                         │                                        │
     7. Start heartbeats │ ════════ WireGuard tunnel ════════════▶│
                         │                                        │
```

### Join Request

```json
POST /.rb/<join_secret> HTTP/1.1
Content-Type: application/json

{
  "cluster_token": "secret-cluster-token",
  "wg_pubkey": "joiner-wireguard-pubkey",
  "wg_endpoint": "1.2.3.4:51820",
  "tunnel_ip": "10.200.200.11",
  "request_time": 1700000123
}
```

### Join Response

```json
{
  "success": true,
  "responder_node_id": "node-abc12345",
  "responder_wg_pubkey": "responder-wireguard-pubkey",
  "responder_wg_endpoint": "5.6.7.8:51820",
  "responder_tunnel_ip": "10.200.200.1",
  "known_peers": [
    {
      "node_id": "node-xyz98765",
      "wg_pubkey": "...",
      "wg_endpoint": "...",
      "tunnel_ip": "..."
    }
  ]
}
```

### Security

| Threat | Mitigation |
|--------|------------|
| Unauthorized join | `cluster_token` validation (constant-time) |
| Replay attack | `request_time` validated (max 5 min old) |
| Discovery attack | Hidden behind secret `join_secret` path |
| Brute force | Rate limiting, 404 on any validation failure |

### Why Bootstrap Before HS Config?

Joining nodes bootstrap via Tor **before** configuring their local hidden service.
This prevents the node from routing the master.onion request to itself (since all
nodes share the same master key, a local HS would respond to its own join request).
