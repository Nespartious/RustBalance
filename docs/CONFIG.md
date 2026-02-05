# Configuration Reference

RustBalance uses TOML configuration. All settings are explicit - no magic defaults in production.

---

## TL;DR

```toml
# Minimal working config
[node]
id = "node-a"
priority = 10

[master]
onion_address = "your-master-address.onion"
identity_key_path = "/etc/rustbalance/master_ed25519.key"

[target]
onion_address = "your-real-service.onion"

[coordination]
cluster_token = "shared-secret-from-first-node"

[wireguard]
listen_port = 51820
tunnel_ip = "10.200.200.1"
private_key = "YOUR_BASE64_PRIVATE_KEY"
```

**Key points:**
- `[target]` is the real service you're load balancing (never public)
- `[master]` is the address clients connect to (shared by all nodes)
- `cluster_token` authenticates nodes joining the mesh
- First node can have empty `peers = []` - others join via gossip

---

## Complete Example

```toml
#
# RustBalance Configuration
# /etc/rustbalance/config.toml
#

[node]
# Unique node identifier (required)
id = "node-a"

# Election priority - lower number = higher priority (required)
# When publisher fails, lowest priority healthy node takes over
priority = 10

# Clock skew tolerance in seconds (default: 5)
# Messages outside this window are rejected
clock_skew_tolerance_secs = 5


[master]
# Master onion address - the address users connect to (required)
# Must be a v3 address (56 characters before .onion)
onion_address = "exampleonionaddress1234567890abcdefghijklmnopqrstuv.onion"

# Path to Ed25519 master identity key (required)
# Supports 32-byte seed, 64-byte Tor expanded, or 96-byte with pubkey
identity_key_path = "/etc/rustbalance/master_ed25519.key"


[target]
# Target service to reverse proxy to (required)
# This is your real application - never publicly exposed
onion_address = "yourrealservice1234567890abcdefghijklmnopqrstuv.onion"

# Target port (default: 80)
port = 80


[tor]
# Tor control port host (default: 127.0.0.1)
control_host = "127.0.0.1"

# Tor control port (default: 9051)
control_port = 9051

# Control port password (optional - uses cookie auth if not set)
# control_password = "your-hashed-password"

# SOCKS port for circuit building (default: 9050)
socks_port = 9050


[publish]
# How often to republish descriptor in seconds (default: 600)
refresh_interval_secs = 600

# Grace period before takeover in seconds (default: 90)
# Must be >= heartbeat_timeout_secs
takeover_grace_secs = 90

# Maximum intro points in descriptor (default: 20)
# Limited by descriptor size (~50KB max)
max_intro_points = 20


[health]
# Maximum descriptor age before considered stale (default: 900)
descriptor_max_age_secs = 900

# Enable active HTTP health probes (default: false)
# Requires building Tor circuit to target service
http_probe_enabled = false

# HTTP probe endpoint path (default: /health)
http_probe_path = "/health"

# HTTP probe timeout in seconds (default: 5)
http_probe_timeout_secs = 5


[coordination]
# Coordination mode: "wireguard" or "tor" (default: wireguard)
mode = "wireguard"

# Heartbeat interval in seconds (default: 10)
heartbeat_interval_secs = 10

# Heartbeat timeout - mark publisher suspect (default: 30)
# Must be > heartbeat_interval_secs
heartbeat_timeout_secs = 30

# Lease duration in seconds (default: 60)
lease_duration_secs = 60

# Random backoff jitter in seconds (default: 15)
backoff_jitter_secs = 15

# Cluster join token for peer authentication (required for multi-node)
# Generated on first node, shared to joining nodes via deploy script
cluster_token = "your-shared-secret-token"


[wireguard]
# WireGuard interface name (default: wg-rb)
interface = "wg-rb"

# Listen port for WireGuard (external, e.g., 51820)
listen_port = 51820

# This node's tunnel IP (e.g., "10.200.200.1")
tunnel_ip = "10.200.200.1"

# Private key (base64) - REQUIRED
private_key = "BASE64_WIREGUARD_PRIVATE_KEY=="

# Public key (base64) - needed for PeerAnnounce gossip
public_key = "BASE64_WIREGUARD_PUBLIC_KEY=="

# External endpoint for other nodes to connect (your public IP:port)
external_endpoint = "YOUR_PUBLIC_IP:51820"

# Peer nodes (can be empty on first node - others join via gossip)
peers = []

# Example peer entry (for joining nodes, added by deploy script)
# [[wireguard.peers]]
# id = "node-first"
# endpoint = "192.168.1.1:51820"
# tunnel_ip = "10.200.200.1"
# public_key = "FIRST_NODE_WIREGUARD_PUBLIC_KEY=="
```

---

## Section Reference

### [node]

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `id` | string | yes | - | Unique node identifier |
| `priority` | u32 | yes | - | Election priority (lower wins) |
| `clock_skew_tolerance_secs` | u64 | no | 5 | Max time difference for messages |

### [master]

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `onion_address` | string | yes | Master .onion address (clients connect here) |
| `identity_key_path` | path | yes | Path to Ed25519 key file |

**Key file formats supported:**
- 32 bytes: Raw Ed25519 seed
- 64 bytes: Tor expanded secret key
- 96 bytes: Expanded key + public key

### [target]

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `onion_address` | string | yes | - | Target service .onion address (the real app) |
| `port` | u16 | no | 80 | Target service port |

**Note:** The target is never publicly exposed. RustBalance acts as a reverse proxy.

### [tor]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `control_host` | string | 127.0.0.1 | Tor control port host |
| `control_port` | u16 | 9051 | Tor control port |
| `control_password` | string | - | Password (uses cookie if unset) |
| `socks_port` | u16 | 9050 | SOCKS proxy port |

### [publish]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `refresh_interval_secs` | u64 | 600 | Republish interval (10 min) |
| `takeover_grace_secs` | u64 | 90 | Wait before takeover |
| `max_intro_points` | usize | 20 | Max IPs per descriptor |

### [health]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `descriptor_max_age_secs` | u64 | 900 | Stale threshold (15 min) |
| `http_probe_enabled` | bool | false | Enable active probing |
| `http_probe_path` | string | /health | Probe endpoint |
| `http_probe_timeout_secs` | u64 | 5 | Probe timeout |

### [coordination]

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `mode` | string | wireguard | "wireguard" or "tor" |
| `heartbeat_interval_secs` | u64 | 10 | Heartbeat frequency |
| `heartbeat_timeout_secs` | u64 | 30 | Miss threshold |
| `lease_duration_secs` | u64 | 60 | Lease TTL |
| `backoff_jitter_secs` | u64 | 15 | Random backoff range |
| `cluster_token` | string | - | Shared secret for peer auth |

### [wireguard]

Required when `coordination.mode = "wireguard"`.

| Key | Type | Required | Default | Description |
|-----|------|----------|---------|-------------|
| `interface` | string | no | wg-rb | WireGuard interface name |
| `listen_port` | u16 | yes | - | External UDP port |
| `tunnel_ip` | string | yes | - | This node's tunnel IP |
| `private_key` | string | yes | - | Base64 WireGuard private key |
| `public_key` | string | no | - | Base64 public key (for gossip) |
| `external_endpoint` | string | no | - | Public IP:port for peers |
| `peers` | array | no | [] | Initial peer list |

### [[wireguard.peers]]

| Key | Type | Description |
|-----|------|-------------|
| `id` | string | Peer node identifier |
| `endpoint` | string | Peer's public IP:port |
| `tunnel_ip` | string | Peer's tunnel IP |
| `public_key` | string | Peer's WireGuard public key |

**Note:** The peers array can be empty on the first node. Additional nodes join
via the gossip protocol and are automatically discovered.

---

## Validation Rules

1. `node.id` must be non-empty and ≤64 characters
2. `master.onion_address` must be valid v3 (56 chars + .onion)
3. `master.identity_key_path` must exist and be readable
4. `target.onion_address` must be valid v3 address
5. `heartbeat_timeout_secs` > `heartbeat_interval_secs`
6. `takeover_grace_secs` ≥ `heartbeat_timeout_secs`
7. `cluster_token` required for multi-node operation

---

## Environment Variables

Override log level:
```bash
RUST_LOG=rustbalance=debug ./rustbalance /etc/rustbalance/config.toml
```

Log levels: `error`, `warn`, `info`, `debug`, `trace`

---

## Deploy Script Integration

The deploy script automatically generates configuration:

**First node (`--init`):**
- Generates master identity key
- Generates WireGuard keypair
- Creates cluster token
- Sets `tunnel_ip = "10.200.200.1"`
- Outputs join command for other nodes

**Joining nodes (`--join`):**
- Copies master key from first node
- Generates own WireGuard keypair
- Uses provided cluster token
- Auto-assigns tunnel IP (10.200.200.X)
- Configures first node as initial peer

See [testing/deploy.sh](../testing/deploy.sh) for implementation.
