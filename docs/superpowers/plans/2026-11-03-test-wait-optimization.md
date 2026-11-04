# Test Wait Optimization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement task-by-task.

**Goal:** Remove redundant real waiting from three mocked business regression scenarios without reducing deadline coverage.

**Architecture:** Explicit test-only virtual clock, scoped to three tests. Real nginx verification and transaction code remain.

**Tech Stack:** Existing unittest, Bash, awk; no new dependencies.

**Spec:** docs/superpowers/specs/2026-11-03-test-wait-optimization-design.md

## Global Constraints

- Production files, default fixtures, tier manifest, actual deadline tests and historical evidence remain unchanged. No commits or VPS actions.
- Preserve all old IDs; only three allowed test bodies receive clock injection. Keep assertions unchanged.
- Each fixture clock is isolated, shared across its shell substitutions, and advances only on fake sleep.

## Review Focus

- Virtual clocks must never leak into actual timeout/child cleanup tests.
- Successful reload must still require stable fresh PID and fresh master log evidence.
- Both original rollback rejection assertions must still catch erroneous cleanup/success.
- Clock persistence and invalid delay handling must not silently hang or move backwards.
- Full discovery and existing skip conditions remain intact.

### Task 1: Prove and remove repeated waits

**Files:** tests/reload_clock.py, tests/test_nginx_reload.py, tests/test_real_ip_reload_review.py, tests/test_script_review_fixes.py.
**Interfaces:** `virtual_reload_clock() -> str` returns Bash overrides for monotonic clock and sleep, state under `$TRACE.reload-clock`.

- [x] Capture baseline hashes and three target timings; inspect setup/process profiling.
- [x] Add failing helper behavior contracts, observe RED.
- [x] Implement helper and explicitly inject only in the three target methods.
- [x] Verify GREEN, compare target timings and run unmodified real deadline tests.
- [x] Verify targeted mutations fail original business assertions; restore fixture source.

### Task 2: Full validation, review and delivery

**Files:** tests/README.md, docs/audit/2026-11-03-test-wait-optimization.md and evidence.
**Interfaces:** Existing run_tests.py and full discovery unchanged.

- [x] Verify old IDs/test body hashes except allowed injections and unchanged real-time tests.
- [x] Run full once, independent code review, resolve any important findings.
- [x] Document timing interpretation, boundaries and test commands.
- [x] Baseline-guarded delivery; verify source bytes, unrelated file preservation and focused main smoke.
