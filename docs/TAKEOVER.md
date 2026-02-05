# Takeover Timeline

This document details exact timing during publisher failover.

## Configuration Assumptions

```toml
[coordination]
heartbeat_interval_secs = 10
heartbeat_timeout_secs = 30
[publish]
takeover_grace_secs = 90
```

## Timeline: Normal Failover

```
TIME    EVENT                                    NODE-A (p=10)    NODE-B (p=20)
─────   ─────────────────────────────────────   ──────────────   ──────────────
T=0s    Node A publishes descriptor             PUBLISHER        STANDBY
        Node A sends heartbeat                  └─ heartbeat ──▶
        
T=10s   Node A sends heartbeat                  └─ heartbeat ──▶
        Node B sees healthy publisher                            └─ received
        
T=20s   Node A sends heartbeat                  └─ heartbeat ──▶
        
T=25s   *** NODE A CRASHES ***                  DEAD             STANDBY
        
T=30s   Node B expects heartbeat                                 └─ waiting...
        Heartbeat not received (1 miss)                          └─ count: 1
        
T=40s   Heartbeat not received (2 misses)                        └─ count: 2
        
T=50s   Heartbeat not received (3 misses)                        └─ count: 3
        
T=55s   heartbeat_timeout (30s) reached                          SUSPECT
        Node B marks publisher suspect                           └─ grace timer
        
T=55s   Grace period starts                                      └─ grace: 0s
        
T=85s   Grace at 30s                                             └─ grace: 30s
        
T=115s  Grace at 60s                                             └─ grace: 60s
        
T=145s  takeover_grace (90s) reached                             CANDIDATE
        Node B checks priority                                   
        Node B: "Am I highest priority?"                         └─ yes!
        
T=146s  Node B broadcasts lease_claim                            └─ claim ──▶
        Node B becomes publisher                                 PUBLISHER
        
T=150s  Node B fetches backend descriptors                       └─ polling
        
T=155s  Node B merges introduction points                        └─ merging
        
T=160s  Node B publishes master descriptor                       └─ published!
        Node B sends heartbeat(publisher)        (dead)          └─ heartbeat
        
T=170s  Clients can reach service via new descriptor
```

## Timeline: Priority Conflict

Two nodes both detect failure simultaneously.

```
TIME    EVENT                                    NODE-A (p=10)    NODE-B (p=20)
─────   ─────────────────────────────────────   ──────────────   ──────────────
T=0s    Publisher (Node-C) is healthy           STANDBY          STANDBY
        
T=25s   *** NODE C CRASHES ***
        
T=55s   Both nodes hit heartbeat_timeout        SUSPECT          SUSPECT
        
T=145s  Both nodes hit grace expiry             CANDIDATE        CANDIDATE
        Both check priority
        
T=145s  Node A: priority=10, checking peers
        Node A sees Node B (p=20) alive
        Node A: 10 < 20, I win                  └─ claiming
        
T=145s  Node B: priority=20, checking peers
        Node B sees Node A (p=10) alive
        Node B: 20 > 10, backing off                             └─ back off
        
T=146s  Node A broadcasts lease_claim           └─ claim ──▶     └─ received
        Node B confirms Node A is taking over                    STANDBY
        
T=147s  Node A becomes publisher                PUBLISHER
```

## Timeline: Network Partition

Nodes temporarily lose contact.

```
TIME    EVENT                                    NODE-A           NODE-B
─────   ─────────────────────────────────────   ──────────────   ──────────────
T=0s    Normal operation                        PUBLISHER        STANDBY
        
T=10s   *** NETWORK PARTITION ***
        WireGuard packets not reaching
        
T=40s   Node B: no heartbeat for 30s                             SUSPECT
        Node A: still publishing (unaware)      └─ publishing
        
T=130s  Node B: grace expired                                    CANDIDATE
        Node B claims lease                                      └─ claim
        Node B becomes publisher                                 PUBLISHER
        
T=135s  *** SPLIT BRAIN ***
        Both publishing descriptors             PUBLISHER        PUBLISHER
        HSDirs receive both                     └─ upload        └─ upload
        Latest timestamp wins
        
T=140s  *** NETWORK RESTORED ***
        Node B sees Node A heartbeat                             └─ received!
        Node A has higher priority (lower #)
        Node B: "A has priority, stepping down"                  STANDBY
        
T=145s  Single publisher restored               PUBLISHER        STANDBY
        Brief overlap handled by HSDir
```

## Key Timing Constants

| Constant | Default | Purpose |
|----------|---------|---------|
| `heartbeat_interval_secs` | 10 | How often heartbeats sent |
| `heartbeat_timeout_secs` | 30 | When to mark suspect |
| `takeover_grace_secs` | 90 | Wait before claiming |
| `clock_skew_tolerance_secs` | 5 | Message time validation |

## Timing Relationships

```
heartbeat_interval < heartbeat_timeout < takeover_grace
      10s          <       30s          <      90s
```

**Rules:**
1. `timeout` > 2× `interval` (catch 2+ missed heartbeats)
2. `grace` > `timeout` (don't claim too fast)
3. `grace` should allow descriptor propagation (~60s)

## Worst Case Scenarios

### Maximum Failover Time
```
Detection:   heartbeat_timeout     = 30s
Grace:       takeover_grace        = 90s
Polling:     backend fetch         = ~10s
Publishing:  descriptor upload     = ~5s
Propagation: HSDir distribution    = ~60s
────────────────────────────────────────
TOTAL:                              ~195s (~3.25 minutes)
```

### Minimum (Already Suspect)
```
Grace already running              = 0s
Claim + publish                    = ~15s
Propagation                        = ~60s
────────────────────────────────────────
TOTAL:                              ~75s
```

## Tuning Recommendations

### High Availability (Aggressive)
```toml
heartbeat_interval_secs = 5
heartbeat_timeout_secs = 15
takeover_grace_secs = 45
```
↳ Faster failover, more false positives

### Stable (Conservative)
```toml
heartbeat_interval_secs = 30
heartbeat_timeout_secs = 90
takeover_grace_secs = 180
```
↳ Slower failover, fewer false positives

### Default (Balanced)
```toml
heartbeat_interval_secs = 10
heartbeat_timeout_secs = 30
takeover_grace_secs = 90
```
