# RustBalance Design Notes

Future architectural ideas and research notes for post-v1.0 implementation.

---

## Stacked Mirror Architecture (20+ Backends)

**Problem**: A single v3 descriptor can only hold ~10 introduction points. With 20+ backends, we exceed this limit.

**Solution**: Two-layer hierarchy:
1. **Master** merges sub-master addresses
2. **Sub-masters** merge backend addresses

### Dynamic Grouping Algorithm

```
plan_intro_points(nodes, max_intro=10):
    if len(nodes) <= max_intro:
        return [nodes]  # Single layer sufficient
    
    # Calculate optimal grouping
    num_groups = ceil(len(nodes) / max_intro)
    group_size = ceil(len(nodes) / num_groups)
    
    groups = chunk(nodes, group_size)
    return groups
```

### Trade-offs
- ❌ Added latency (extra hop)
- ❌ More complexity
- ❌ Slower failover
- ✅ Unlimited backend scaling
- ✅ Better load distribution

---

## Tor Rotation Timing Reference

Understanding Tor's native rotation intervals is critical for Rustbalance configuration.

### 1. Hidden Service Intro Points

| Event | Frequency |
|-------|-----------|
| Scheduled descriptor publication | ~24 hours |
| Key rotation | ~28 days |
| On-demand (intro point failure) | Immediately |

- v3 HS descriptors include intro points chosen from HS's own onion service nodes
- Tor does **not** constantly rotate intro points, but periodically republishes
- Descriptor also rotates when HS keys change (~28 days)

### 2. Circuits & Exit Nodes (Client-side)

- Guard nodes: sticky for weeks/months (attack protection)
- Middle/exit nodes: rotate more frequently
- Default circuit lifetime: **10 minutes**
- This is separate from HS intro point rotation

### 3. Rustbalance Control

With Rustbalance/Onionbalance, you control rotation more aggressively:
- Configurable: typically 15–60 minutes for intro point rotation
- Can be more aggressive than vanilla Tor
- **Caveat**: Too aggressive → increased client failures

### Key Points

1. Intro point rotation happens on:
   - Descriptor republish (~24h vanilla)
   - On-demand if intro fails
2. Clients cache descriptors ~1 hour (even if your IPs rotate)
3. Rustbalance gives more control but must balance stability vs freshness

---

## Staggered Republishing Strategy

### Concept

- Keep **one main master onion address static** for clients
- Each sub-master randomly republishes intro points hourly (or every few hours)
- Each publication picks slightly different intro points from the pool
- Master descriptor always points to sub-master onion addresses

### 24-Hour Timeline

```
Time:   0h       2h       4h       6h       8h      10h      12h      14h      16h      18h      20h      22h      24h
        |--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|--------|

Top-Level Master Descriptor (public)
        ─────────────────────────────────────────────────────────────────────────────────────────────────────
        (static, always points to Sub-Masters 1–3)

Sub-Master 1 Intro Points
        [A1 A2 A3 A4] → rotate 1–2 IPs per publication
                  ↑                 ↑
        republish hourly, random offset ±15 min

Sub-Master 2 Intro Points
        [B1 B2 B3 B4] → rotate 1–2 IPs per publication
                  ↑                 ↑
        staggered republish hourly (different random offset)

Sub-Master 3 Intro Points
        [C1 C2 C3 C4] → rotate 1–2 IPs per publication
                  ↑                 ↑
        staggered republish hourly (different random offset)

Client View:
        0h: fetch master → Sub-Master 1 (A1/A2)
        1h: fetch master → Sub-Master 2 (B2/B3)
        2h: fetch master → Sub-Master 1 (A1/A3)
        3h: fetch master → Sub-Master 3 (C1/C4)
        ...
        24h: all intro points rotated at least once
```

### Benefits

| Aspect | Effect |
|--------|--------|
| Load distribution | ✅ Better, gradual balancing across nodes |
| Availability | ✅ Failed intro points replaced over time |
| Descriptor churn | ⚠️ Moderate increase; must monitor |
| Fingerprinting | ⚠️ Slightly higher if patterns predictable |
| Complexity | ⚠️ Higher, but manageable with automation |

### Best Practices

1. **Keep master address stable** - clients always fetch same top-level onion
2. **Randomize within window** - ±10–15 minutes, not exact hourly
3. **Limit rotation per publication** - only 1–2 intro points, not all
4. **Monitor failures** - detect and republish stale intro points

### Summary

Staggered hourly publishing is **net positive** for load balancing and resilience if you:
- Don't rotate all intro points at once
- Add randomness to timing
- Keep master address stable

Main cost: more descriptors + operational complexity (worth it for multi-layer stacked system).

---

## Future: Full Rotation Matrix

Consider implementing a 24-hour rotation matrix showing:
- All 3 sub-masters
- All 20 nodes
- Which intro points are active each hour
- Full coverage visualization

This would help operators understand and tune rotation parameters.
