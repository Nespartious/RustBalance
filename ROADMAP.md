# RustBalance Roadmap

## Version 0.1.0 - MVP (Two-Node Cluster)

### Phase 1: WireGuard Auto-Setup & Join Protocol ✅
**Goal:** User runs `rustbalance init` on first VPS, `rustbalance join <token>` on second.

- [x] **1.1 CLI Structure**
  - [x] Add clap-based CLI with `init`, `join`, `status`, `backend`, `run` subcommands
  - [x] Parse command-line arguments in main.rs
  - [x] Handle config file path option
  
- [x] **1.2 Init Command**
  - [x] Generate Ed25519 master identity key
  - [x] Derive .onion address from master key
  - [x] Generate WireGuard keypair
  - [x] Create default config.toml
  - [x] Generate join token (base64 encoded JSON)
  - [x] Print token to stdout for user to copy
  
- [x] **1.3 Join Token Format**
  - [x] Define JoinToken struct (version, origin info, encrypted master key)
  - [x] Encrypt master key with cluster secret (AES-GCM)
  - [x] Serialize to base64 with "rb1:" prefix
  - [x] Parse and validate token on receiving node
  
- [x] **1.4 Join Command**
  - [x] Parse join token from argument
  - [x] Decrypt master key
  - [x] Generate local WireGuard keypair
  - [x] Create local config with peer info
  - [x] Exchange public keys with origin node
  
- [x] **1.5 WireGuard Interface Setup**
  - [x] Call `wg` CLI to generate keys (or use library)
  - [x] Configure wg0 interface via `ip link`
  - [x] Add peer configurations
  - [x] Peer tracking and status monitoring

### Phase 2: Descriptor Polling ✅
**Goal:** Nodes fetch backend descriptors and track health.

- [x] **2.1 HSFETCH Implementation**
  - [x] Implement proper HSFETCH command in TorController
  - [x] Handle async HS_DESC events
  - [x] Store raw descriptor on receive
  
- [x] **2.2 Descriptor Parsing**
  - [x] Parse outer descriptor layer (version, lifetime, revision)
  - [x] Extract signing key certificate
  - [x] Extract encrypted body
  - [x] Decode base64 body and signature
  
- [x] **2.3 Descriptor Decryption**
  - [x] Derive subcredential from master key + blinded key
  - [x] Decrypt outer layer with subcredential
  - [x] Decrypt inner layer
  - [x] Extract introduction points
  
- [x] **2.4 Health Loop Integration**
  - [x] Add descriptor fetch to health loop
  - [x] Update backend states based on fetch success
  - [x] Track descriptor ages

### Phase 3: Descriptor Publishing ✅
**Goal:** Publisher node can create and upload valid v3 descriptors.

- [x] **3.1 Key Blinding**
  - [x] Implement blinding parameter derivation
  - [x] SHA3-256 based blinding (placeholder for full EC)
  - [ ] Full EC point multiplication (future: real Tor compat)
  
- [x] **3.2 Cross-Certification**
  - [x] Create Ed25519 cert for signing key
  - [x] Sign with master key
  - [x] Build cert structure
  
- [x] **3.3 Intro Point Encoding**
  - [x] Encode link specifiers (Ed25519 identity)
  - [x] Encode onion key
  - [x] Encode auth key with cert placeholder
  - [x] Encode encryption key with cert placeholder
  
- [x] **3.4 Descriptor Encryption**
  - [x] Build inner encrypted layer (intro points)
  - [x] Build middle encrypted layer
  - [x] AES-256-GCM with subcredential-derived keys
  
- [x] **3.5 HSPOST Implementation**
  - [x] Build complete descriptor blob via DescriptorBuilder
  - [x] Sign with master key
  - [x] Upload via Tor control port
  - [x] Publisher uses DescriptorBuilder

### Phase 4: Election & Failover ✅
**Goal:** Nodes elect a publisher and handle failover.

- [x] **4.1 Complete Election Logic**
  - [x] Heartbeat loop sends correctly
  - [x] Receive loop processes messages
  - [x] Takeover logic with priority-based election
  
- [x] **4.2 Lease Management**
  - [x] Lease struct with holder/expiration
  - [x] Broadcast lease claims
  - [x] Handle lease conflicts via priority
  
- [x] **4.3 Failover Testing**
  - [x] Test publisher death → standby takeover
  - [x] Test priority-based election
  - [x] Test grace period timing (8 election tests)

### Phase 5: Tor Bootstrap Channel ✅
**Goal:** New nodes can join the mesh using only the master .onion address - no pre-shared WireGuard info.

- [x] **5.1 Join Request Protocol**
  - [x] Define JoinRequest/JoinResponse message types
  - [x] Cluster token validation (constant-time comparison)
  - [x] Request timestamp validation (anti-replay)
  
- [x] **5.2 Bootstrap Client**
  - [x] Connect to master .onion via Tor SOCKS
  - [x] POST join request to /.rb/<join_secret>
  - [x] Parse response with WireGuard credentials
  - [x] Retry logic with backoff
  
- [x] **5.3 Join Handler**
  - [x] HTTP endpoint for join requests inside proxy loop
  - [x] Validate cluster_token and join_secret
  - [x] Add new peer to WireGuard transport
  - [x] Return responder's WireGuard info + known peers
  
- [x] **5.4 Multi-Node Coordination**
  - [x] Heartbeat exchange with intro point counts
  - [x] Peer lifecycle tracking (Joining → Initializing → Healthy)
  - [x] Auto-detect single-node vs multi-node mode
  - [x] Intro point refresh loop (query Tor for own intro points)
  - [x] Aggregate peer intro point counts for merging

---

## Version 0.2.0 - Production Ready

### Phase 6: Merged Descriptor Publishing 🚧
**Goal:** Publisher creates merged descriptor from all nodes' intro points and uploads via HSPOST.

- [ ] **6.1 Intro Point Data Sharing**
  - [ ] Add IntroPointData message type with raw intro point bytes
  - [ ] Nodes broadcast their intro points (not just count)
  - [ ] Store peer intro points in PeerState
  
- [ ] **6.2 Descriptor Building**
  - [ ] Collect intro points from state.own_intro_points
  - [ ] Collect intro points from all healthy peers
  - [ ] Build merged descriptor with DescriptorBuilder
  - [ ] Sign with master key
  
- [ ] **6.3 HSPOST Upload**
  - [ ] Use TorController.upload_hs_descriptor()
  - [ ] Target all responsible HSDirs (not just one)
  - [ ] Handle upload failures gracefully
  - [ ] Log success/failure for debugging

### Phase 7: HTTP Health Probes
- [ ] Implement SOCKS proxy client
- [ ] Route HTTP requests through Tor
- [ ] Parse health endpoint responses
- [ ] Integrate with health loop

### Phase 8: Self-Repair
- [ ] Implement Tor restart via systemd
- [ ] Backend exclusion/re-inclusion
- [ ] Automatic republish on failure
- [ ] Alerting hooks (optional)

### Phase 9: Vanity Address Support
- [ ] Integrate vanity prefix search on init
- [ ] GPU-accelerated search (optional)
- [ ] Progress reporting during search

---

## Version 0.3.0 - Hardening

### Phase 10: Security Audit
- [ ] Review all crypto operations
- [ ] Check for timing side channels
- [ ] Verify no key material in logs
- [ ] Add memory zeroing for secrets

### Phase 11: Performance
- [ ] Profile descriptor building
- [ ] Optimize crypto operations
- [ ] Benchmark election timing
- [ ] Reduce memory allocations

### Phase 12: Observability
- [ ] Prometheus metrics endpoint
- [ ] Structured JSON logging option
- [ ] Health endpoint for monitoring
- [ ] Dashboard templates

---

## Backlog (Future)

- [ ] Tor-based coordination (no WireGuard)
- [ ] Multi-master key support
- [ ] Backend priority/weights
- [ ] Geographic awareness
- [ ] IPv6 support for WireGuard
- [ ] Automatic TLS for health probes
- [ ] Backup/restore cluster state
- [ ] Docker/container packaging
- [ ] Ansible/Terraform deployment
