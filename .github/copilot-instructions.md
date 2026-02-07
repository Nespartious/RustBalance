# RustBalance - AI Assistant Instructions

## ⚠️ CRITICAL: Git Author Rule

**All commits to this repository MUST be authored by `nespartious`.**

Before any git commit, verify:
```
git config user.name   # Must be: nespartious
git config user.email  # Must be: nespartious@users.noreply.github.com
```

If the author is anything other than `nespartious`, **STOP and alert the user immediately**.

A pre-commit hook is installed to enforce this, but always verify before committing.

---

## ⚠️ CRITICAL: Branch & Workflow Rules

### Branch Strategy

| Branch | Purpose | Protected | Merge Via |
|--------|---------|-----------|-----------|
| `main` | **Production release** — last known working version. Never commit directly. | ✅ | Merge from `dev` only, after full test pass |
| `dev` | **Integration staging** — holds tested, confirmed-working code only. Never commit untested code. | ✅ | Merge from `feature/*` branches only, after VM deployment tests pass |
| `feature/*` | **All active work** — every change starts here. Branch from `dev`, test on VMs, merge back to `dev`. | ❌ | Merge to `dev` after passing all gates |

### Workflow Rules

1. **NEVER commit directly to `main`** — All changes reach main through a merge from `dev`.
2. **NEVER commit directly to `dev`** — All code changes must go through a `feature/*` branch first. The only exceptions are documentation-only changes (README, copilot-instructions, etc.) that don't affect runtime behavior.
3. **`dev` holds only tested, confirmed-working code** — Before merging any feature branch into `dev`, the code must be:
   - Compiled successfully (`cargo check`, `cargo clippy`, `cargo fmt`)
   - Deployed to test VMs from the feature branch
   - Verified working via `testing/verify_deployment.ps1` on both VMs
   - Load balance tested via `testing/load_balance_test.ps1`
4. **Feature branch → dev gate** (all must pass before merge to `dev`):
   - [ ] `cargo check` passes
   - [ ] `cargo clippy -- -D warnings` passes (zero warnings)
   - [ ] `cargo test` passes
   - [ ] `cargo fmt --check` passes
   - [ ] Deploy to test VMs from feature branch: `REPO_BRANCH=feature/xxx curl ... | sudo bash`
   - [ ] Run `testing/verify_deployment.ps1` — both VMs healthy, peers connected, no errors
   - [ ] Run `testing/load_balance_test.ps1` — load balancing confirmed across nodes
5. **Dev → main gate** (all must pass before merge to `main`):
   - [ ] All feature branch → dev gates passed
   - [ ] Fresh VM reset and redeploy from `dev` branch
   - [ ] `testing/verify_deployment.ps1` passes on fresh deploy
   - [ ] `testing/load_balance_test.ps1` confirms load balancing
   - [ ] No regressions in any existing functionality
6. **Atomic commits** — One logical change per commit. Don't mix refactors with features. Use conventional commit prefixes: `fix:`, `feat:`, `refactor:`, `docs:`, `chore:`, `test:`.
7. **Test scripts are mandatory** — After every deployment, run `testing/verify_deployment.ps1` before considering it "working". The load balance test (`testing/load_balance_test.ps1`) must be run before any merge to `dev` or `main`.

### Deployment Branch

- **Testing deployments** use `dev` branch:
  ```bash
  curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/dev/testing/deploy.sh | sudo bash -s -- [args]
  ```
- **Production deployments** use `main` branch (the default URL).
- **Never deploy from a feature branch** unless explicitly testing that branch.

### PR Checklist (enforce on every PR)

**Feature → Dev:**
- [ ] `cargo check` passes
- [ ] `cargo clippy -- -D warnings` passes (zero warnings)
- [ ] `cargo test` passes
- [ ] `cargo fmt --check` passes
- [ ] Commit messages use conventional format
- [ ] Related Phase document task is referenced
- [ ] Deployed to test VMs from feature branch
- [ ] `testing/verify_deployment.ps1` passes on both VMs
- [ ] `testing/load_balance_test.ps1` confirms load balancing

**Dev → Main (release):**
- [ ] All of the above, plus:
- [ ] Fresh VM reset and redeploy from `dev` branch
- [ ] Both verification scripts pass on fresh deploy
- [ ] No regressions in existing functionality

### Test Scripts

All test scripts live in `testing/` and are run from the Windows development machine.

| Script | Purpose | When to Run |
|--------|---------|-------------|
| `testing/verify_deployment.ps1` | Checks both VMs: service status, uptime, WG peers, errors, peer health, publishing status | After every deployment |
| `testing/load_balance_test.ps1` | Sends requests through Tor to master .onion, verifies traffic hits multiple nodes | Before every merge to `dev` or `main` |

---

## Terminology

| Term | Meaning |
|------|---------|
| **Master Address** | The public `.onion` address clients connect to. This is the "load balanced" address. |
| **RustBalance Node** | A VM/VPS running RustBalance software. Multiple nodes coordinate for redundancy. |
| **Target Service** | The actual application clients ultimately reach (e.g., `sigil...qid.onion`). Traffic flows TO this. |
| **Intro Points** | Tor relays that accept connection requests on behalf of a hidden service. |
| **Descriptor** | Signed document published to Tor containing intro points and crypto material. |

## What RustBalance Is

RustBalance is a Rust implementation of Onionbalance/gobalance with added health checking, self-healing, and **reverse proxy** capabilities.

### Core Purpose

RustBalance provides **load balancing for Tor hidden services** by:
1. Running multiple RustBalance nodes, each acting as a hidden service endpoint
2. Each node creates its own intro points and accepts connections
3. Nodes reverse proxy incoming traffic to a single target service
4. Nodes coordinate to publish a merged descriptor containing all nodes' intro points

### User Experience

**Visitor's view**: Visit `master.onion` → target service content loads (no awareness of RustBalance)

**Admin's view**: Deploy RustBalance on multiple VMs, configure target service address, start and forget

### Architecture

```
                    ┌─────────────────────┐
                    │      Client         │
                    │  visits master.onion│
                    └──────────┬──────────┘
                               │
                    (Tor HS protocol - random intro point selection)
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
         │     WireGuard coordination mesh         │
         │   (heartbeats, intro point sharing)     │
         └────────────────────┼────────────────────┘
                              │
                    (Reverse proxy over Tor SOCKS)
                              │
                              ▼
                    ┌─────────────────────┐
                    │   Target Service    │
                    │  (target.onion)     │
                    │                     │
                    │  The real app -     │
                    │  never public       │
                    └─────────────────────┘
```

### Key Concepts

1. **Each RustBalance node IS a hidden service**
   - Uses file-based `HiddenServiceDir` with master identity key (enables PoW support)
   - Tor creates intro points for that node
   - Node accepts connections and reverse proxies to target

2. **The target .onion is just a proxy destination**
   - Never publicly shared
   - No descriptor fetching needed
   - Simply where RustBalance forwards connections

3. **Nodes coordinate via WireGuard (or Tor fallback)**
   - Share heartbeats and health status
   - Share intro points with each other
   - Lease-based publisher election
   - Publisher merges intro points from all healthy nodes

4. **Merged descriptor publishing**
   - Publisher collects intro points from all nodes
   - Creates single descriptor with combined intro points
   - Publishes to HSDirs via HSPOST
   - Clients randomly select intro points = load distribution across nodes

### Health Checking

- **Active HTTP probing**: Optional probing through Tor circuits to verify target is responding
- **Heartbeat monitoring**: Nodes monitor each other's liveness
- **Target health**: Check if target service is responding

### Self-Healing / Repairability

- **Automatic failover**: If publisher dies, next priority node takes over
- **Grace periods**: Prevent flapping during brief outages
- **Lease-based election**: Deterministic, no consensus needed
- **Clock validation**: Reject messages with bad timestamps
- **Mesh self-healing**: Gossip protocol ensures full mesh regardless of join topology

### Auto-Detect Mode

RustBalance automatically determines single vs multi-node mode:
- **No active peers**: Single-node mode, Tor handles publishing
- **Active peers detected**: Multi-node mode, merge intro points and HSPOST

This allows seamless transition - start with one node, add more later without reconfiguration.

### Gossip Protocol

Nodes discover each other through heartbeat gossip:
1. Each heartbeat includes `known_peers` list
2. Receiving nodes check for unknown peers
3. Unknown peers are added via WireGuard + PeerAnnounce
4. Mesh self-heals regardless of join topology (chain → full mesh)

### Configuration

Single target service address:
```toml
[target]
onion_address = "sigilahzwq5u34gdh2bl3ymokyc7kobika55kyhztsucdoub73hz7qid.onion"
port = 80
```

Cluster token for peer authentication:
```toml
[coordination]
cluster_token = "your-secret-cluster-token"
```

### What NOT to Do

- Do NOT fetch the target's descriptor - we don't need its intro points
- Do NOT use ADD_ONION - use file-based HiddenServiceDir for PoW support
- The target's intro points are irrelevant - we use OUR OWN intro points

### Implementation Notes

- Use file-based `HiddenServiceDir` with master key for PoW support
- Configure Tor via torrc or SETCONF for hidden service
- Each node's Tor creates its own intro points
- Nodes share intro point info via coordination layer (new message type needed)
- Publisher builds descriptor with intro points from all healthy nodes
- Reverse proxy uses Tor SOCKS to reach target service

## Testing Environment

### Test VMs

We have 2 headless Ubuntu Server VMs for testing:

| VM | IP | Hostname | Username | SSH Key |
|----|-----|----------|----------|---------|
| VM1 | 192.168.40.144 | hlsn1 | hlu1 | `~/.ssh/rustbalance_test` |
| VM2 | 192.168.40.145 | hlsn2 | hlu1 | `~/.ssh/rustbalance_test` |

**Password for sudo**: `pass`

### Testing Rules

1. **VMs may be reset to fresh state** - During development and testing, I may reset these VMs to an earlier snapshot. Treat each reset as a fresh deploy and start from the beginning.

2. **Why fresh deploys matter** - As we develop and test, we need to ensure everything works from a clean environment. This catches issues that might be hidden by leftover state.

3. **Manual execution only** - During testing:
   - You may use SSH CLI to **retrieve information** (status checks, log viewing, etc.)
   - You must **NOT use SSH to make changes** to the VMs
   - Instead, provide the commands and tell me which terminal to use
   - I will copy/paste and execute commands manually

4. **SSH for information retrieval**:
   ```powershell
   # OK - Reading logs, checking status
   ssh -i ~/.ssh/rustbalance_test hlu1@192.168.40.144 "systemctl status rustbalance"
   
   # NOT OK - Making changes (provide command for manual execution instead)
   ssh -i ... "sudo systemctl restart rustbalance"  # Don't do this
   ```

5. **Provide clear instructions** - When I need to run commands, format them clearly:
   - Specify which VM (VM1 or VM2)
   - Provide the exact command to run
   - Explain what it does

## Deployment Rules

### CRITICAL: Always Deploy from GitHub

**NEVER copy files directly to VMs.** All deployments MUST use the GitHub download method:

```bash
# Testing: Deploy from dev branch
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/dev/testing/deploy.sh | sudo bash -s -- [args]

# Production: Deploy from main branch
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/main/testing/deploy.sh | sudo bash -s -- [args]

# Or clone a specific branch
git clone -b dev https://github.com/Nespartious/RustBalance.git
```

**Why this matters:**
1. **Consistency**: All nodes run identical, version-controlled code
2. **Auditability**: Deployments are traceable to specific commits
3. **Branch support**: `dev` for testing, `main` for stable releases
4. **No drift**: Prevents local modifications from polluting deployments

**The deploy script itself clones from GitHub** - it never uses locally copied files.

### Deployment Commands

**First node (--init mode):**
```bash
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/dev/testing/deploy.sh | sudo bash -s -- \
  --init \
  --target <target.onion> \
  --endpoint <this_node_ip>:51820
```

**Additional nodes (--join mode):**
```bash
curl -sSL https://raw.githubusercontent.com/Nespartious/RustBalance/dev/testing/deploy.sh | sudo bash -s -- \
  --join \
  --target <target.onion> \
  --master-onion <master.onion> \
  --master-key "<base64_master_key>" \
  --peer-endpoint <first_node_ip>:51820 \
  --peer-pubkey "<first_node_wg_pubkey>" \
  --cluster-token "<cluster_token>"
```
