# Audit optimizations implementation plan

> Execute using subagent-driven-development, with isolated file/function ownership, regression-first changes and a final independent review.

**Goal:** Apply the confirmed fixes and operational improvements from `docs/feature-audit-2026-10-11.md`.
**Architecture:** Retain the Bash entrypoints and Python configuration helpers. Resolve effective configuration consistently, fail closed on unknown destructive checks, and distinguish configured/running/request-verified states. No production service or external message is changed during development.
**Tech stack:** Bash, Python/PyYAML, unittest, official CrowdSec/OpenResty verifiers.
**Spec:** `docs/feature-audit-2026-10-11.md`, approved by the user's request to execute its recommendations.

## Constraints

- Preserve unrelated configurations/accounts/WAF hooks and existing undo records.
- Do not automatically trust Headers, whitelist proxy ranges, migrate private whitelist ranges to AppSec bypass, or silently change AppSec failure/body policies.
- Add regression evidence for confirmed bugs before implementing fixes.
- Work on feature branch; no deployment, merge or push is included.

## Tasks

1. Effective configuration and operations: empty YAML overrides, active core acquisition paths, active notification/profile paths and earlier local profiles, notification error propagation, WebUI auth/readiness/credentials, optional-component health.
   - Tests: add isolated cases to a dedicated operations regression module; run failing tests before implementation, then targeted suite.
   - Files: `lib/crowdsec_config.py`; core/Telegram/WebUI/health functions in main script.
2. Web/AppSec: guard effective `.local` overrides in every link path; implement HTTP + metric/rule evidence verification with explicit inconclusive status; display/configure body/failure strategies without changing defaults blindly.
   - Tests: `.local` host/Docker link rejection, HTTP200 unchanged counters failure, 403 unrelated WAF inconclusive, matched metrics verification, cancellation; existing web/host suites.
   - Files: AppSec functions in main; new focused helper as needed; web libraries.
3. Destructive safety and maintenance: tri-state firewall residue inspection, uninstall full preflight, loopback/local/admin self-ban guard, explicit administrative allowlist and read-only Self-Report diagnosis, Hub snapshot/lock/log/rollback shared by manual and cron updates.
   - Tests: unknown checker aborts before deletion, unsupported OS before stop, self-address refusal, allowlist explicit-only, Hub validation/reload failure restore and concurrent lock behavior.
   - Files: firewall/uninstall/cron/rules/menu functions in main; focused maintenance helpers.
4. Unified evidence collection: replace duplicated old real-IP log analysis with bounded shared diagnosis, resolve effective Prometheus endpoint; Cloudflare range-change evidence and current verification documentation.
   - Tests: NPM client extraction, stream exclusion, custom metrics URL, no config mutation.
   - Files: `tools/diagnose-detection.sh`, real-IP diagnosis/repair modules, docs.
5. Integrate and independently review changes. Run complete unittest suite, syntax/ShellCheck, real engine/firewall config, real web and real-IP verifiers. Update current verification baseline with evidence and limitations.

## Progress

- Design authorization: user approved report recommendations; no further design approval needed.
- Baseline: 178 tests passed during audit; existing audit documents retained.
- Branch: `fix/audit-optimizations-20261011`.
- Tasks 1–4: implemented. Includes optional read-only 1–60 second counter sampling and Console post-acceptance status instructions.
- Task 5: independent review corrections implemented; final full checks and real runtime policy checks recorded in `docs/verification.md`. Production matrix checks requiring a VPS or real external accounts are explicitly distinguished from local verification.
