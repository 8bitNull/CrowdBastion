# ForwardX firewall implementation plan

> Execute natively using executing-plans and test-driven-development; one independent final review. User confirmed the proposed work; no additional approval gate.

**Goal:** Correct additive chain generation and make the default iptables/ipset backend usable with guided relay acceptance.

**Architecture:** A shared pure canonical chain helper feeds all config writers. A strict iptables-save/ipset parser produces the existing snapshot interface, while an opt-in lifecycle workflow adds renewal, exact deletion and natural expiry without mutating the host.

**Spec:** `docs/superpowers/specs/2026-11-03-forwardx-firewall-design.md`.

**Constraints:** Preserve dirty baseline, package YAML/credentials, existing nft workflow and incomplete results, IPv4/IPv6 and INPUT/FORWARD source guards. No live VPS actions or commits.

**Review focus:** additive common/custom family preservation; stale/missing/wrong-family or excluded sets; rule counter identity/reset and bypass order; early lifecycle confirmation/cancellation cleanup; current tests versus actual WAN validation.

- [x] Baseline full unittest suite in snapshot; preserve log and distinguish pre-existing failures.
- [x] Task 1 RED: tests expose duplicate effective lists in startup, migration, local and remote paths, common custom-chain loss and invalid list values.
- [x] Task 1 GREEN: shared `canonical_iptables_chains(data, required_v4=(), required_v6=())` in `lib/crowdsec_config.py`; use in `crowdsec_firewall_runtime.py`, `crowdsec_firewall_migrate.py`, `crowdsec_remote_bouncer.py`, config bouncer action and relay status. Test idempotence, family separation and credential retention.
- [x] Task 2 RED: literal iptables-save/ipset fixtures and command-boundary tests for selected path, family, membership, counters, predicates, missing sets, reads/errors and all lifecycle states.
- [x] Task 2 GREEN: backend dispatch and strict read-only snapshot in `lib/crowdbastion_relay_verify.py`; explicit optional lifecycle with monotonic waits and safe manual decision instructions; preserve short default tests and existing nft path.
- [x] Docs: usage/CLI/firewall maintenance explain canonical lists, two acceptance scopes, source safety, renewal/expiry timing and limits.
- [x] Appropriate focused tests, full unittest suite, Python/Bash syntax, relevant ShellCheck and diff checks. No test-count claim before reading results.
- [x] Fresh independent code review of changed-file diff against dirty snapshot baseline; resolve important findings and rerun relevant checks.
- [x] Copy only changed deliverables to original workspace after verifying each original file still matches snapshot baseline; verify copied hashes and record delivery evidence.
