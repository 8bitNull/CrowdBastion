# VPS179 realm protection rollout

> Execution: inline under executing-plans; user authorized applying the prior inspection recommendations. This is a remote operations task; preserve the existing dirty product worktree and do not commit unrelated files.

**Goal:** improve observability and demonstrate current CrowdSec enforcement without disrupting ForwardX sessions or enabling speculative automatic bans.

**Architecture:** retain ForwardX realm 2.9.4 and iptables Bouncer. Add narrowly labelled realm journal acquisition and a parser that records observation metadata without source_ip or scenarios. Cap journal storage. Validate TCP INPUT at actual realm ports and UDP INPUT through controlled listeners using temporary isolated sources, with exact cleanup.

**Spec:** docs/audit/2026-11-03-vps179-realm.md and user instruction to optimize according to its recommendations.

## Constraints and review focus

- Preserve realm configuration, units, binary, PIDs, connection limits and current transport; topology unknown, assume potentially shared source.
- No PROXY change, no per-IP threshold, no global allowlisting, no raw API exposure, no new Telegram/email messages.
- Observe logs only: no added scenario, no source IP enrichment, no ban generated from EOF/timeouts.
- Snapshot existing configurations privately before changes; reject unexpected file/owner changes and restore only owned changes if validation fails.
- Keep temporary addresses out of management/real peers and remove only owned decision IDs or reason-specific test decisions; never flush firewall/state.
- Isolated verification is not public WAN/backend application validation; record exact coverage.

## Tasks

- [x] 1. Record fresh baseline and backup. Stage parser with real CrowdSec offline parsing. Show absence before staging, successful realm event classification after staging, unrelated SSH unchanged, and no extracted source_ip/remediation.
- [x] 2. Add parser/acquisition only after engine configuration validation. Apply journal retention cap (persistent 128M/runtime 32M; no forced vacuum). Restart only CrowdSec core and journald as needed; preserve ForwardX/Bouncer PIDs. Verify effective configuration and source registration. Roll back on failure.
- [x] 3. Verify actual Bouncer decisions using temporary network namespace sources, both actual realm TCP listeners and an isolated UDP echo listener behind the same INPUT rule. Confirm normal/banned/control/recovery, counters and cleanup; UDP application end-to-end remains pending. Record final health, continuity, changes, backups and rollback instructions.

## Execution notes

- Baseline and offline parser tests passed. Initial live acceptance incorrectly required nonempty acquisition counters before any new realm event; configuration was automatically rolled back. Core logs prove the follower had started. Corrected readiness checks verify the actual journalctl child process; live event parsing remains pending until a real event arrives.

- Tasks 1–3 complete: final config validates, protected files/PIDs preserved, two actual Bouncer ingress runs pass and clean up; final decision sync 16850/16850.
- Independent review: fixed failed-restart recovery and timeout-resilient resource cleanup. Two injected failures observed RED then GREEN. Corrected network script revalidated on VPS.
- Ruling: topology unknown, keep detection observational and do not add per-IP thresholds; cost is no new automatic realm attack detector.
- Ruling: UDP test covers common INPUT enforcement, not realm UDP application response; WAN/IPv6/backend authentication remain explicit limitations.
