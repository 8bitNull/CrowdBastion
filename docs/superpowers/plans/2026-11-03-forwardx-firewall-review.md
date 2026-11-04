# ForwardX implementation review and repair

User requested another review/fix cycle for the delivered chain and relay-acceptance changes. Reuse the isolated worktree; preserve original dirty baseline and prior audit artifacts. No SSH, deployment, commit or push.

- [x] RED/GREEN: official Bouncer missing/null slices mean empty, not implicit INPUT. Required INPUT/FORWARD remain explicit in startup/remote writers. Preserve family-only scope in credential setup and status.
- [x] RED/GREEN: remote reapply uses valid owned overlay as part of effective config, preserving custom fields/chains across base package changes.
- [x] RED/GREEN: startup writes keep managed remote ownership coherent; verify ownership before any change, update marker only for the exact controlled result, back up marker with startup transaction and restore configuration/marker together on failure. Do not adopt arbitrary drift.
- [x] RED/GREEN: reject nftables evidence with unsafe rules in selected hooked chain; bind counter identity to relevant chain structure and available named-counter identity.
- [x] Review cancellation scope: documented q/EOF/Ctrl+C must remain correct. Record TERM limitations separately unless concrete required semantics justify changing the API.
- [x] Focused regression suite; independent second review of repairs; full suite once code is final, plus syntax/static/doc checks.
- [x] Copy only this round's files back with new baseline guards; retain prior reports/artifacts unchanged and distinguish their historical live-source manifest entries. Write fresh report/logs/manifest.
