# RustBalance — Upcoming Tasks

## Verification Script Updates

- [ ] **Add `PublishHidServDescriptors` check to `verify_deployment.ps1`**
  Query each node's Tor control port and verify `PublishHidServDescriptors=0` when peers are active (multi-node mode). If ANY node has `1`, report **FAIL**.

- [ ] **Add `PublishHidServDescriptors` check to `post_deployment_report.ps1`**
  Same check in the comprehensive report. Include in the Tor config agreement section.

- [ ] **Commit `post_deployment_report.ps1` to dev branch**
  Script is complete and working but not yet committed.

## Testing Enforcement

- [ ] **Mandatory `load_balance_test.ps1` after every redeployment**
  The checklist requires this but it wasn't enforced after today's redeployment. Consider adding a reminder to `deploy.sh` output.
