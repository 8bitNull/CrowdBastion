# Approved script re-review fixes

## Global constraints

Implement the user-approved three findings from the script re-review. Public CLI, selected existing policies and fresh-install defaults remain compatible. No VPS deployment, push or external messages. Preserve all pre-existing workspace changes. The binding requirements are the approved conversation plan, reproduced below; no separate spec file exists.

### Task 1: Verify live Nginx reloads and make policy changes interrupt-safe

Shared reload verification for `configure_appsec_policy` in `lib/appsec_audit.sh` and `upgrade_native_execution` in `lib/native_web_bouncer.sh`:

- Capture actual Nginx master PID and worker PID set before reload, including Docker-managed Nginx and host services.
- Send reload and wait at most 10 seconds, polling every 200 ms.
- Require an unchanged master and new workers alive for two consecutive samples. Verify managed hooks after this, before committing.
- Neither `nginx -t`, reload exit status nor `nginx -T` alone proves that the live master accepted configuration.
- On failure restore backups, verify recovery and report incomplete recovery honestly, preserving backups.
- Make policy mutation an independent transaction/subshell with EXIT/INT/TERM cleanup and a commit flag. Before commit, failures and interruption must restore both config and the ownership manifest `$WEB_INSTALLS`; outer Hub workflow traps do not protect this function.
- Cover real master/worker reload acceptance and rejection (vendor Lua initialization failure, e.g. missing external mTLS cert), policy rollback on interruption, upgrade rollback and incomplete recovery. Existing real runtime fixture uses master_process off and needs a master/worker fixture for these cases.
- Use TDD: add regression tests, observe the intended failure, implement and verify. Update affected fixtures with realistic runtime process metadata; do not bypass verification in all workflow tests. Preserve existing CLI/defaults and selected policies. Avoid unrelated install/remove expansion.

### Task 2: Guard the effective startup Bouncer binary

In `lib/crowdsec_firewall.py`, retain audit precedence for `/proc/<MainPID>/exe`, but the mutating `guard` must also inspect the disk executable from the effective systemd ExecStart property (including drop-ins). Reject before mutation if either runtime or startup target is confirmed nftables version 0.0.36 or 0.0.38. Unknown versions remain clearly unverified and do not cause automatic migration or blanket rejection. Do not execute/eval systemctl text as shell code. Preserve sanitized YAML errors.

Relevant callers are remote configure/update in `lib/remote_bouncer.sh` and local repair in `crowdbastion.sh`; confirm their guard occurs before mutation/restart. Add TDD regressions for runtime/startup mismatch in both directions, effective ExecStart parsing (including spaces/quoted values), malicious shell text, missing/unknown metadata, iptables/ipset bypass and preserved audit precedence. Prefer a separate new test file to avoid shared edits with Task 1.

### Task 3: Integrate, review and deliver

Run focused regression and full suite with the available pinned real Lua/Nginx runtime, static syntax/AST checks and diff whitespace checks. Request task-scoped and final independent read-only review. Fix confirmed findings and recheck affected behavior. Record actual verification and practical limits in a concise audit document. Copy only this task's delta to the original workspace after comparing fresh baseline hashes; preserve concurrent edits and the entry-point symlink.

The approved delivery follow-up replaces fragile reload-failure string substitution in both workflow and policy tests with a final optional `reload_succeeds=True` fixture argument. Failed reloads return nonzero without advancing the simulated worker generation. Rerun affected tests and full discovery, finalize audit/results evidence, then deliver only task paths after checking their original baseline. Compare unrelated files to a fresh pre-delivery inventory, preserving the source branch, concurrent edits and symlink. Verify delivered hashes and run integration regression in the source workspace. No public CLI changes, VPS deployment, push or automatic backend migration.
