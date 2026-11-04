# ForwardX firewall correctness and relay acceptance

The user confirmed the proposed priorities after the VPS144 deployment and VPS82 assessment. This batch addresses the first two priorities: duplicate Bouncer chain configuration and iptables/ipset guided acceptance. Remaining capacity/sysctl/startup-classification/installer improvements are separate batches unless the user steers scope.

Canonical configuration must reflect the official Bouncer's additive common+family lists. Preserve the effective union and custom chain ordering, clear the common list in generated overrides, and emit deduplicated family lists. Reuse one implementation in startup repair, migration, local Bouncer configuration and remote configuration. Keep Docker chains in their currently intended families; configuration alone is not proof of live coverage. Preserve credentials and package base YAML.

Extend the existing operator-guided, read-only `--verify-relay` to iptables/ipset. Keep nftables compatibility. All host commands remain bounded read-only queries; show manual, uniquely scoped decision commands for the operator/remote center. Evidence must establish the selected INPUT/FORWARD path starts with an unconditional CrowdSec jump, exact source-set DROP/REJECT rules and matching family ipsets; reject predicates, bypasses, exclusions, unsupported set types and missing counters. Counter resets or rule changes cannot count as growth. Restrict reads to relevant referenced sets where possible.

Preserve the existing four-stage path as default and add an explicit full-lifecycle choice for iptables users: initial reachability/control, short ban, renewal beyond the first deadline, exact reason-scoped deletion/recovery, fresh short ban and natural expiry/recovery. Timing uses a monotonic clock; early confirmation cannot produce an expiry/renewal pass. Independent test/control sources and manager-source protections remain required. UDP requires actual application responses. No automatic decisions, firewall mutation, test namespace or remote messages are introduced by this interactive wizard.

Acceptance conclusions identify the selected family/protocol/entry and lifecycle scope, retain unknown/fault precedence, preserve cleanup instructions on cancellation, and keep static health traffic pending. History must not imply lifecycle coverage when only the default four-stage test ran.

Work in a snapshot of the dirty current tree, then copy only reviewed changed files back after original-baseline hash guards. No VPS deployment, commit or push in this task.
