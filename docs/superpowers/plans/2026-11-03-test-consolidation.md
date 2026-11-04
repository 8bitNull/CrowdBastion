# Test Consolidation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Reduce everyday validation and fixture maintenance cost while preserving independent risk coverage.

**Architecture:** Test-free fixture mixin, explicit quick/integration/archive module lists, unittest wrapper with opt-in timing JSON. Full discovery remains authoritative.

**Tech Stack:** Python 3 stdlib unittest, existing PyYAML fixture dependency.

**Spec:** docs/superpowers/specs/2026-11-03-test-consolidation-design.md

## Global Constraints

- No production code, VPS, dependency, commit or deployment changes. Preserve unrelated workspace edits and historical audit files.
- Keep all original test IDs and method body hashes. No automatic timing-based exclusion or shared mutable fixtures.
- Default execution includes every discovered test; quick is a documented subset. Missing dependencies remain visible skips, with opt-in strict skip rejection.

## Review Focus

- Missing/misspelled manifest modules and explicit filters must not silently yield success.
- Test errors, failing subtests and module/class setup errors preserve nonzero exit and timing report integrity.
- Importing helpers must not duplicate or suppress real test discovery.
- Fixture copies remain isolated and use the correct source root in both worktrees.
- Listing tests must not execute setup; reports must not turn skips into passing evidence.

### Task 1: Extract the shared workflow fixture

**Files:** tests/workflow_fixture.py, tests/test_workflows.py, consumers of Workflows fixture methods.
**Interfaces:** WorkflowFixtureMixin contains only the existing non-test helper methods.

- [x] Capture baseline IDs/method hashes and run full baseline with timings.
- [x] Assert fixture module is importable, test-free and does not subclass TestCase (RED before extraction).
- [x] Move helper methods verbatim; preserve test classes/IDs and replace consumers, remove inherited-method suppression.
- [x] Compare discovery IDs/method hashes and run focused workflow consumers.

### Task 2: Add test tiers and timing entrypoint

**Files:** tests/run_tests.py, tests/test_tiers.json, tests/test_test_runner.py.
**Interfaces:** CLI --tier {full,quick,integration,archive}, --module NAME (repeatable), --list, --timings PATH, --top N, --require-no-skips. Timing JSON includes counts, total duration, per-test status/duration and skip reasons.

- [x] Add failing CLI self-tests with temporary small suites covering selection, reports, failures/subtests/skips and invalid input.
- [x] Implement minimal unittest runner; classify explicit quick and specialty lists.
- [x] Run self-tests and inspect original discovery preservation.

### Task 3: Validate and document

**Files:** tests/README.md, docs/audit/2026-11-03-test-consolidation.md and evidence directory.
**Interfaces:** New entrypoint consumes the unchanged fixture discovery from Task 1.

- [x] Run quick with timings and full suite with timings, inspect skip reasons and slow modules.
- [x] Document commands, boundaries, measured results and any further optimizations supported by data.
- [x] Independent final review; fix important findings with regression evidence.
- [x] Deliver only current batch files using baseline hash guards and verify delivered hashes.
