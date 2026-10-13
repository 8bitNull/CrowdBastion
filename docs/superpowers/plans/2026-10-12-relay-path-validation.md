# Relay path validation implementation plan

> Execution: use subagent-driven-development for the independent diagnostic task, with task review and final code review. Keep the current feature checkout and all pre-existing edits; do not commit or deploy.

**Goal:** Extend the existing relay mode with role/path diagnostics and an isolated real forwarding/ban/recovery acceptance runner.

**Architecture:** Runtime diagnostics remain read-only and distinguish operator-supplied node role from local listener/NAT evidence. A separate test runner creates a private network/mount namespace, uses synthetic clients and echo backends, and runs actual gost/realm and official Firewall Bouncer against a local decision API fixture. If native namespaces are unavailable, attempt verification inside an isolated VM; report unsupported checks as unverified, never substitute mocks for packet blocking.

**Tech stack:** Bash, Python 3/PyYAML, Linux network namespaces, iproute2/nftables, gost v3.3.0, realm v2.9.6, official Firewall Bouncer v0.0.36. QEMU TCG is a verification-only fallback, not a product dependency.

**Spec:** User-approved next step in this conversation: isolated real forwarding acceptance tests, plus node role and traffic path read-only diagnostics. No rate limits, custom behavioral detection or production firewall changes.

## Constraints and rulings

- Existing website and minimal installation behavior must be preserved.
- No production service restart, decision, firewall mutation, forwarding configuration read with credentials, or automatic whitelist.
- Ruling: implement in the current `refactor/menu-consolidation` checkout — the previous relay implementation and user edits are uncommitted here; creating a checkout from HEAD would omit the baseline being extended.
- Ruling: use a synthetic local decision-stream API with the real official bouncer — the existing official engine already validates acquisition/LAPI separately; this runner isolates packet enforcement from unrelated Hub/CAPI traffic. Its report must disclose the API fixture.
- Native `unshare --user --map-root-user --net true` is denied in this container. Missing isolation or dependencies must return 2; failed assertions return 1; successful requested checks return 0.
- Report normal reachability, blocked-client failure, healthy-client reachability during ban, rule counter increase, unban recovery and backend-observed source for each tested tool/protocol/address family.
- Cleanup only owned processes and private namespaces. No host firewall changes or global flushes, even on failure.

## Task 1: Read-only role/path diagnostic

**Files:** `lib/crowdsec_relay_paths.py`, `lib/relay.sh`, `install-crowdsec-1panel.sh`, `tests/test_relay_paths.py`.

- [x] Add failing tests for explicit role/mode/port selection, listener/NAT evidence, unavailable commands, secrets excluded, source-IP cautions, cancellation/EOF, CLI/menu routing and read-only no-lock behavior.
- [x] Run `PATH="$PWD/.venv/bin:$PATH" python3 -m unittest discover -s tests -p test_relay_paths.py` and inspect the expected failures.
- [x] Add `--relay-path` and diagnostic menu entry, reuse existing Bouncer evidence without converting it into a protection pass. Ask role (entry/transit/exit/unknown), path (userspace/NAT/bridge/unknown), and optional TCP/UDP port selectors; do not persist answers.
- [x] Parse local listening socket and NAT evidence conservatively; do not infer remote user IP from PROXY protocol or trust a shared upstream.
- [x] Repeat targeted tests and review the task against the constraints above.

## Task 2: Real forwarding/firewall acceptance runner

**Files:** `tests/verify_relay_network.py`, `tests/relay_network_lab.py`, `tests/test_relay_network.py`.

- [x] Add failing tests for isolation guard, selectors/dependency preflight, process cleanup, normal/blocked/healthy/unban classification and structured JSON reporting. Unit tests exercise guard and evidence handling, not pretend to prove kernel enforcement.
- [x] Implement a namespace driver and a separate loopback-only `--forward-only` mode. The driver passes the original network namespace inode; the worker rejects execution if it is unchanged.
- [x] Build two synthetic source clients and a relay namespace, assign distinct IPv4/IPv6 addresses, and run an echo backend. Gost/realm test traffic uses local process forwarding; kernel NAT tests use a separate backend namespace and scoped DNAT/SNAT.
- [x] Run official Bouncer with temporary configuration and only a loopback API fixture. Toggle bans for one client, wait for set synchronization, measure actual packet counter changes, check the other client remains reachable, remove ban and check recovery.
- [x] Run actual gost/realm forwarding checks in this environment. Attempt a no-external-network QEMU guest if native isolation is unavailable; save component versions and test matrix as evidence.
- [x] Review runner isolation and cleanup, then run final unit, syntax and real integration checks.

## Task 3: Documentation and final verification

**Files:** `readme.md`, `docs/relay-mode.md`, `docs/verification.md`, `docs/audit/2026-10-12-relay-network-results.json`.

- [x] Document commands, role/path semantics, fixture API, new-session scope, unsupported matrix cells and limitations.
- [x] Run complete unittest with existing PyYAML environment; run optional official plugin checks using available binaries.
- [x] Run Bash syntax, Python compilation, documented ShellCheck and `git diff --check`.
- [x] Resolve important review findings, record verification evidence and report completed changes and remaining deployment-specific checks.

## Execution notes

- Task 1: 13 diagnostic tests pass; independent review found inverted NAT matches were flattened, fixed with failing regressions first.
- Task 2: 10 runner tests pass; all 8 real loopback gost/realm cases pass. Reviewer findings for mount isolation, UDP reuse and nested SIGTERM cleanup fixed and re-reviewed. Native host run returns 2 for missing tools; native namespace capability denied separately.
- Guest preparation: QEMU TCG, no NIC/shared filesystem, Debian kernel 6.1.0-47. Explicit nft_objref and nft_nat preloads needed in minimal initramfs; each missing-module failure independently reproduced before fixing guest. Production host untouched.
- Verification: full suite 422 tests, 415 pass and 7 optional skips; separately enabled official plugin suite 7/7 pass. Bash syntax, Python compilation, ShellCheck and diff-check pass.

- Final isolated guest result: all 12 gost/realm/NAT × IPv4/IPv6 × TCP/UDP cases pass with actual official Bouncer DROP counters, healthy-client reachability and unban recovery. Raw evidence saved to docs/audit/2026-10-12-relay-network-results.json.
