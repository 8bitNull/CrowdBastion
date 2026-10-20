# Repository consolidation plan

**Goal:** Consolidate the existing reviewed script fixes and Telegram changes, verify the complete result, and synchronize local and remote `main`.

**Architecture:** Start from `origin/main` (`e960b08`) in an isolated integration worktree. Import the preserved current workspace, compare the other worktrees against it, then merge the Telegram delivery branch while preserving the later firewall and Nginx fixes. Exclude accidental executable-bit changes from the final tree.

**Scope:** Existing implementations and tests only; no VPS deployment or Telegram messages. Original workspaces and the verified backup at `/projects/script/CrowdBastion-backups/20261020T015901Z` preserve all intermediate states.

- [x] Verify the source workspace baseline with the complete unittest suite and the prepared real Nginx/Lua runtime.
- [x] Import all 38 modified and 63 new source files, preserving the compatibility symlink and original tracked modes. Confirm that the other script worktrees contain no missing files or newer undelivered fixes.
- [x] Squash-integrate `codex/tg-reliability-submit-20261020` and reconcile bot navigation, health checks, documentation, and tests with the source snapshot. Preserve review fixes from `70f4dfe`, `6365f02`, and the subsequent worker-respawn follow-up; keep the original commits under local archive refs.
- [x] Run focused Telegram, firewall, policy, and Nginx regressions, then the complete unittest suite, shell syntax, Python AST checks, ShellCheck, whitespace checks, and documentation link checks. Record exact results and optional skips.
- [x] Request an independent read-only review of the final change; resolve substantive findings and repeat affected checks.
- [x] Commit the consolidated result and validation record. Fetch the remote again and fast-forward `main`, then push without force. Verify the remote SHA and clean local checkout. Retain backups of intermediate development work before removing superseded worktree registrations and branches.

The user confirmed integration, regression testing, and push after the initial cleanup. Execute inline; use a separate reviewer for the final review as required by `requesting-code-review`.
