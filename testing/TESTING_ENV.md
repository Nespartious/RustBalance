# RustBalance Live Testing Environment

## Overview

Two Ubuntu VMs connected via SSH for live integration testing.
- **VM1 (Master)**: Runs `rustbalance init`, becomes cluster initiator
- **VM2 (Mirror)**: Runs `rustbalance join <token>`, becomes standby node
- **Target**: Reverse proxy to a real .onion (e.g., Dread)

---

## VM Requirements

### Minimum Specs (per VM)
- Ubuntu 22.04 LTS or 24.04 LTS
- 2 CPU cores
- 2GB RAM
- 20GB disk
- Network: NAT or Bridged (VMs must be able to reach each other)

### Required Packages (will be installed by deploy script)
- `tor` - Tor daemon
- `wireguard-tools` - WireGuard VPN
- `build-essential` - Compiler toolchain
- `curl` - Download Rust installer
- Rust toolchain (installed via rustup)

---

## SSH Access Format

Provide the following for each VM:

```
VM1 (Master):
  IP: <vm1_ip>
  Port: 22
  User: <username>
  Auth: password OR key file path

VM2 (Mirror):
  IP: <vm2_ip>
  Port: 22
  User: <username>
  Auth: password OR key file path
```

### Recommended: SSH Key Authentication

1. Generate key on your Windows machine (if not exists):
   ```powershell
   ssh-keygen -t ed25519 -f $env:USERPROFILE\.ssh\rustbalance_test
   ```

2. Copy to each VM:
   ```powershell
   type $env:USERPROFILE\.ssh\rustbalance_test.pub | ssh user@vm_ip "mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys"
   ```

3. Provide me the key path: `~/.ssh/rustbalance_test`

---

## Network Setup

### Option A: Bridged Networking (Recommended)
- Both VMs get IPs on your local network
- VMs can reach each other directly
- Example: VM1=192.168.1.100, VM2=192.168.1.101

### Option B: NAT with Port Forwarding
- VMs have internal IPs (e.g., 10.0.2.x)
- Forward ports from host to VMs
- More complex, not recommended

### Required Connectivity
```
VM1 <---> VM2     (WireGuard UDP, port 51820)
VM1 ---> Internet (Tor network)
VM2 ---> Internet (Tor network)
```

---

## Guardrails & Safety Rules

### What I WILL Do:
1. ✅ Install required packages via apt
2. ✅ Install Rust toolchain
3. ✅ Clone/pull RustBalance from GitHub
4. ✅ Build and run RustBalance
5. ✅ Configure Tor and WireGuard
6. ✅ View logs and diagnose issues
7. ✅ Apply quick test fixes (temporary)
8. ✅ Full cleanup and redeploy after code changes

### What I WILL NOT Do:
1. ❌ Modify system files outside /home, /etc/tor, /etc/wireguard
2. ❌ Install kernel modules or modify boot config
3. ❌ Access or store any credentials outside the session
4. ❌ Leave test data after cleanup
5. ❌ Make network changes that could lock you out

### Cleanup Protocol
After each test cycle, I will:
1. Stop all RustBalance processes
2. Remove WireGuard interfaces
3. Stop Tor if we started it
4. Delete ~/rustbalance directory
5. Remove /etc/wireguard/wg0.conf
6. Remove generated keys and configs

---

## Testing Workflow

### Phase 1: Environment Verification
```
1. SSH into both VMs
2. Verify connectivity between VMs
3. Install dependencies
4. Verify Tor can bootstrap
```

### Phase 2: Fresh Deployment
```
1. Clone RustBalance from GitHub
2. Build release binary
3. On VM1: rustbalance init
4. Copy join token
5. On VM2: rustbalance join <token>
6. Verify WireGuard tunnel
7. Verify heartbeat exchange
```

### Phase 3: Functional Test
```
1. Add backend (e.g., dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion)
2. Verify descriptor fetch
3. Verify election (VM1 becomes publisher)
4. Verify descriptor publish
5. Test failover (stop VM1, verify VM2 takes over)
```

### Phase 4: Cleanup
```
1. Stop all services
2. Remove all configs
3. Delete cloned repo
4. VM is clean for next test
```

---

## Log Locations

```
RustBalance:    ~/rustbalance/logs/ (or stdout)
Tor:            /var/log/tor/log or journalctl -u tor
WireGuard:      journalctl -u wg-quick@wg0 or dmesg | grep wireguard
System:         journalctl -f
```

---

## Test Target

We'll use a known working .onion as our "backend":

**Dread** (forum):
```
dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion
```

This gives us a real descriptor to fetch and merge.

---

## Quick Reference Commands

### SSH Connection (from your Windows)
```powershell
# With key
ssh -i ~/.ssh/rustbalance_test user@vm_ip

# With password (will prompt)
ssh user@vm_ip
```

### Check VM Connectivity
```bash
# From VM1, ping VM2
ping -c 3 <vm2_ip>

# Check WireGuard
sudo wg show

# Check Tor
sudo systemctl status tor
```

### View RustBalance Logs
```bash
# If running in foreground
# Logs go to stdout

# If running as service
journalctl -u rustbalance -f
```

---

## Ready Checklist

Before we begin, confirm:

- [ ] VM1 created and running Ubuntu
- [ ] VM2 created and running Ubuntu  
- [ ] Both VMs have network connectivity
- [ ] SSH access configured (user/password or key)
- [ ] You can SSH into both VMs from Windows
- [ ] VMs can ping each other
- [ ] You've provided me the connection details

Once ready, provide:
```
VM1: ssh user@ip -p port [-i keyfile]
VM2: ssh user@ip -p port [-i keyfile]
```
