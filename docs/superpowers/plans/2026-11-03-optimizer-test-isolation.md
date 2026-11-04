# Optimizer Test Isolation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans task-by-task.

**Goal:** Avoid repeatedly running full health diagnostics in transaction-only optimizer regressions while retaining integration coverage.

**Architecture:** Explicit run_optimizer fixture wrapper, fixed pending health result, real optimizer/transaction helpers and caller overrides. Four existing end-to-end cases retain original run_shell.

**Tech Stack:** Existing Python unittest/Bash/PyYAML only.

**Spec:** docs/superpowers/specs/2026-11-03-optimizer-test-isolation-design.md

## Global Constraints

- No production, default run_shell, real timeout, tier manifest, historical artifact or VPS changes. No commit/push.
- All 1667 IDs and assertion ASTs preserved; only 10 selected old test method bodies can change.
- Four listed optimizer integration cases and all health report test sources remain unchanged.

## Review Focus

- Diagnostic replacement is explicit and does not reach health or integration tests.
- Return 2 means pending evidence; dependency checks or transaction guards must not be bypassed.
- Caller overrides retain precedence, input/timeouts and subprocess result preserved.
- Source mutations still trigger original rollback/no-mutation assertions.
- Report local timing and full timing separately; never infer whole-suite speedup.

### Task 1: Introduce explicit transaction fixture

**Files:** tests/workflow_fixture.py, tests/test_workflows.py, tests/test_test_runner.py.
**Interfaces:** WorkflowFixtureMixin.run_optimizer(user_input='', overrides='', timeout=15) -> subprocess.CompletedProcess, calls unchanged run_shell.

- [x] Capture baseline source hashes, call profile and 10 target timing.
- [x] Add two failing fixture behavior contracts, verify RED.
- [x] Implement minimal wrapper and change 10 explicit call sites, preserve assertions.
- [x] Verify GREEN, focused before/after timings, real integration and health suite.
- [x] Verify disposable transaction mutations fail original assertions; prove discovery/source preservation.

### Task 2: Final validation and delivery

**Files:** tests/README.md, docs/audit/2026-11-03-optimizer-test-isolation.md and evidence.
**Interfaces:** Existing full runner/tier manifests unchanged; quick adds two fixture contract checks.

- [x] Independent review, resolve important findings.
- [x] Final full run, validate skips/statuses and measured runtime.
- [x] Document scope, evidence and remaining costs.
- [x] Deliver guarded file set and verify main smoke/source hashes.
