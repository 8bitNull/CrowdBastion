# VPS82 review and repair plan

> Execute natively for the user's authorized review/fix request; independent read-only review is in progress. No product changes or repository commit.

Goal: fix the confirmed sysctl persistence error while preserving current relay behavior; reassess deployment risks using fresh evidence.

Scope: `/etc/sysctl.d/99-network-optimize.conf`, only the rejected `net.core.netdev_budget_usecs=6000` assignment. Candidate value is the current accepted runtime value 8000, not a new tuning target. Reversible private backup and hash guards precede edits. No OS upgrade, CrowdSec installation, module loading, firewall mutation, business service restart or reboot.

Approach: retain existing MSS persistence pending review of its actual table scope. A cron loading only mangle does not prove filter ban removal. Replacing that mechanism merely to suppress a future audit warning would add unneeded behavior; only migrate if a present defect is demonstrated.

- [x] Fresh preflight: configuration/hash and all configured readable numeric sysctls, services/PIDs, realm files, startup task, firewall, listening sockets, failure logs, resource sample.
- [x] Determine why 6000 is rejected without repeating the invalid write on the host; inspect current kernel configuration/source when available. The prior journal is the red evidence.
- [x] Backup root-private, exact assignment rewrite to 8000, guarded atomic replacement. Apply only `/net/core/netdev_budget_usecs` through the installed systemd-sysctl prefix option. Validate all observed kernel values before/after. On failure restore only the owned candidate file; no full sysctl reload.
- [x] Evaluate historical failed-unit acknowledgement separately from applying the fix. Do not claim a full service/coldboot pass from a targeted invocation.
- [x] Independent reviewer checks proposed scope and evidence. Resolve important findings before closing.
- [x] Final separate SSH session, TCP entry sampling, service/file continuity, failure status, kernel values, firewall and resource verification. Preserve all old sealed evidence.
- [x] Write new report and SHA manifest, retaining deployment limits and Debian 11 maintenance issue. No product suite pass claim.

Verification focus: concurrent configuration edits, symlink/file ownership, rollback guarded by candidate hash, unrelated sysctl drift, honest systemd status and mangle-only cron assessment.
