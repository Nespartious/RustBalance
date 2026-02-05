# Security Guidelines

Security requirements for RustBalance deployment.

---

## TL;DR

- **Master key = identity**: Protect it like your life depends on it (`chmod 600`)
- **Cluster token**: Shared secret authenticating nodes - never expose it
- **WireGuard**: Encrypts all inter-node traffic - use unique keys per node
- **No inbound needed**: Management nodes only make outbound connections
- **NTP required**: Clock skew >5s causes message rejection
- **Compromised node ≠ game over**: Other nodes continue, only that node's traffic exposed

---

## Threat Model

### Assets
1. **Master Identity Key** - Permanent onion address identity
2. **Backend Locations** - Physical/network location of backends  
3. **User Anonymity** - Client IP addresses
4. **Service Availability** - Ability to reach the service

### Adversaries
| Adversary | Capability | Goal |
|-----------|------------|------|
| Network observer | See traffic patterns | Deanonymize users/operators |
| Active attacker | Inject/drop packets | Disrupt service |
| Compromised backend | Full backend access | Pivot to master key |
| Compromised node | Full node access | Steal keys, disrupt |

## Key Protection

### Master Identity Key

**Location**: Only on management nodes

**NEVER**:
- Store on backends
- Transmit over network
- Include in backups without encryption
- Log or print

**Protection**:
```bash
# File permissions
chmod 600 /etc/rustbalance/master_ed25519.key
chown rustbalance:rustbalance /etc/rustbalance/master_ed25519.key

# Directory permissions  
chmod 700 /etc/rustbalance/
```

**Future**: HSM support for key storage

### Backend Keys

Backend keys are **disposable**. If compromised:
1. Generate new backend key
2. Update configuration
3. Restart backend Tor
4. Remove old backend from config

**No impact on master address**.

## Network Architecture

### Recommended Topology

```
┌─────────────────────────────────────────────────────┐
│                   MANAGEMENT ZONE                    │
│  ┌─────────────┐              ┌─────────────┐       │
│  │ RustBalance │◀──WireGuard──│ RustBalance │       │
│  │   Node A    │              │   Node B    │       │
│  └─────────────┘              └─────────────┘       │
│         │                            │              │
│         └──────────┬─────────────────┘              │
│                    │ Tor (outbound only)            │
└────────────────────┼────────────────────────────────┘
                     │
              ┌──────┴──────┐
              │  Tor Network │
              └──────┬──────┘
                     │
┌────────────────────┼────────────────────────────────┐
│                    │      BACKEND ZONE              │
│         ┌──────────┴──────────┐                     │
│         │                     │                     │
│  ┌──────┴──────┐       ┌──────┴──────┐             │
│  │  Backend 1   │       │  Backend 2   │             │
│  │  (disposable │       │  (disposable │             │
│  │   key)       │       │   key)       │             │
│  └─────────────┘       └─────────────┘             │
└─────────────────────────────────────────────────────┘
```

### Firewall Rules (Management Nodes)

```bash
# Default deny inbound
iptables -P INPUT DROP

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT

# Allow WireGuard from known peers only
iptables -A INPUT -p udp --dport 51820 -s 10.0.0.0/24 -j ACCEPT

# Allow SSH from management network (optional)
iptables -A INPUT -p tcp --dport 22 -s 192.168.1.0/24 -j ACCEPT

# Deny everything else
iptables -A INPUT -j DROP
```

**Key point**: Management nodes need NO inbound connections from the internet.

## Coordination Security

### Cluster Token

The cluster token is a shared secret that authenticates nodes joining the mesh.

**Protection:**
```bash
# Store securely
chmod 600 /etc/rustbalance/cluster_token.txt

# Never include in logs
# Never transmit over unencrypted channels
# Rotate if suspected compromise
```

**Generation** (on first node):
```bash
openssl rand -hex 32
```

**Compromise impact**: Attacker with token + network access could join mesh as a node.

### WireGuard Configuration

```ini
[Interface]
PrivateKey = <MANAGEMENT_NODE_PRIVATE_KEY>
Address = 10.0.0.1/24
ListenPort = 51820

[Peer]
PublicKey = <OTHER_NODE_PUBLIC_KEY>
AllowedIPs = 10.0.0.2/32
Endpoint = <OTHER_NODE_IP>:51820
PersistentKeepalive = 25
```

**Critical**:
- Use unique keys per node
- Restrict `AllowedIPs` to specific peers
- Keep WireGuard keys separate from RustBalance keys

### Message Security

Even with WireGuard, messages are validated:

1. **Node ID check** - Ignore unknown senders
2. **Timestamp check** - Reject stale/future messages
3. **No commands** - Messages only signal state

```rust
// Messages cannot:
msg.execute_command()     // ❌ No execution
msg.modify_config()       // ❌ No config changes  
msg.access_key()          // ❌ No key access
msg.override_health()     // ❌ No bypassing local checks
```

## Clock Security

### Why It Matters

Tor uses timestamps for:
- Descriptor versioning
- Replay prevention
- Freshness checks

**Attack**: Manipulate NTP → publish stale descriptors → denial of service

### Mitigations

```bash
# Use authenticated NTP
apt install chrony

# Configure multiple sources
# /etc/chrony/chrony.conf
server time1.google.com iburst
server time2.google.com iburst
server time.cloudflare.com iburst

# Monitor drift
chronyc tracking
```

**Check drift before deployment**:
```bash
# All nodes should be within 1 second
for node in node-a node-b node-c; do
  ssh $node "date +%s"
done
```

## Logging Security

### What to Log

```
✅ Heartbeat received from node-b
✅ Publisher election triggered
✅ Descriptor published (revision 42)
✅ Backend backend-1 marked unhealthy
```

### What NOT to Log

```
❌ Master key loaded: 0x7f3a...
❌ Backend address: backend1xyz.onion
❌ WireGuard private key
❌ User connection details
```

### Log Rotation

```bash
# /etc/logrotate.d/rustbalance
/var/log/rustbalance/*.log {
    daily
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 rustbalance adm
    sharedscripts
    postrotate
        systemctl reload rustbalance
    endscript
}
```

## Incident Response

### Key Compromise (Master)

**This is catastrophic**. The onion address is permanently compromised.

1. **Stop all nodes immediately**
2. Generate new master key
3. New onion address (unavoidable)
4. Notify users of address change
5. Forensic investigation

### Key Compromise (Backend)

1. Remove backend from configuration
2. Restart RustBalance nodes
3. Generate new backend key
4. Re-add backend with new address
5. Investigate how compromise occurred

### Node Compromise

1. Isolate compromised node
2. Revoke WireGuard peer
3. Check if master key accessed
4. Rebuild node from scratch
5. Update WireGuard configs on other nodes

## Checklist

### Pre-Deployment

- [ ] Master key permissions: `600`
- [ ] Config permissions: `600`
- [ ] Config directory permissions: `700`
- [ ] WireGuard configured and tested
- [ ] Firewall rules applied
- [ ] NTP synchronized and monitored
- [ ] Log rotation configured
- [ ] No sensitive data in logs

### Ongoing

- [ ] Monitor clock drift
- [ ] Review logs weekly
- [ ] Test failover monthly
- [ ] Rotate WireGuard keys quarterly
- [ ] Audit access logs

### Emergency

- [ ] Know where master key is stored
- [ ] Have new address announcement plan
- [ ] Document node rebuild procedure
- [ ] Test backup restoration
