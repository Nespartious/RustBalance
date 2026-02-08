# RustBalance — Upcoming Tasks

## Verification Script Updates

- [ ] **Add `PublishHidServDescriptors` check to `verify_deployment.ps1`**
  Query each node's Tor control port and verify `PublishHidServDescriptors=0` when peers are active (multi-node mode). If ANY node has `1`, report **FAIL**.

- [ ] **Add `PublishHidServDescriptors` check to `post_deployment_report.ps1`**
  Same check in the comprehensive report. Include in the Tor config agreement section.

- [ ] **Commit `post_deployment_report.ps1` to dev branch**
  Script is complete and working but not yet committed.

## Coordination Resilience

- [ ] **Timestamp rejection burst guardrail**
  When a node restarts or joins, it can receive a burst of queued/stale messages that all get rejected with "invalid timestamp". If the rejection rate is high enough in a short window, this could theoretically destabilize peer health tracking (rapid Healthy→Unhealthy flapping). Add a guardrail:
  - Rate-limit timestamp rejection logging (e.g., log first + summary count)
  - Don't let a burst of stale messages reset the peer's health grace period
  - Consider a "warming up" state after restart where stale messages are silently discarded
  - Ensure the heartbeat timeout counter only starts AFTER the first valid message is received from a peer

## Testing Enforcement

- [ ] **Mandatory `load_balance_test.ps1` after every redeployment**
  The checklist requires this but it wasn't enforced after today's redeployment. Consider adding a reminder to `deploy.sh` output.
