# Selected ingress port policy

This optional feature restricts explicitly selected TCP/UDP destination ports on explicitly named ingress interfaces. It does not install a firewall backend, change Compose, restart Docker, or recreate containers. Existing node roles v1 remain unchanged. The supported path uses readable IPv4 and IPv6 iptables filter rules, an unconditional first jump to an existing `CROWDSEC*` chain in INPUT, and, when Docker is present, the same first jump in DOCKER-USER. FORWARD must lead unconditionally to DOCKER-USER as its first rule, or immediately after its first CrowdSec jump. Other layouts remain read-only until their ownership and ordering are resolved.

Create `/var/lib/crowdbastion/port-policy.json` as a root-owned regular file with mode `0600`, under root-owned directories that are not writable by others. Symlink paths are refused. An example private configuration:

```json
{
  "version": 1,
  "topology": {
    "kind": "shared-relay",
    "relay_sources": ["198.51.100.0/24", "2001:db8:1234::/48"]
  },
  "ingress": [
    {
      "interface": "eth0",
      "protocol": "tcp",
      "port": 443,
      "mode": "sources",
      "sources": ["198.51.100.0/24", "2001:db8:1234::/48"]
    },
    {
      "interface": "eth0",
      "protocol": "udp",
      "port": 8443,
      "mode": "local",
      "sources": []
    }
  ]
}
```

Each apply replaces the complete managed profile. Omitting a previously selected port releases its managed restriction; the read-only plan reports these entries in `released_selectors`. Use your actual interface, addresses, protocol and ports. Documentation address ranges above are examples. Every object has fixed fields; unknown fields and duplicate JSON keys are rejected. Version must be integer `1`; ports are integers `1..65535`; protocol is `tcp` or `udp`. Each interface/protocol/port combination must be unique. Interfaces are exact Linux names, never wildcards or `lo`. CIDRs must use canonical network notation; `/0`, loopback, unspecified, multicast and link-local source networks are refused. Lists are bounded, and the immutable transaction manifest must fit within 8 MiB; an oversized plan refuses before firewall mutation.

`mode` is `public`, `local`, or `sources`. `sources` must be nonempty only for `sources`; the other modes require `[]`. Public removes previous managed restrictions for the selected scope and never inserts ACCEPT. Local drops selected ingress traffic while loopback remains available. Sources return permitted addresses to the existing firewall path and drop all others, including an address family for which no sources were supplied. Source ports are unrestricted. The topology kind is `direct`, `shared-relay`, or `unknown`; only shared-relay has a nonempty `relay_sources` list. Relay sources are an explicit declaration for other diagnostics; this declaration does not automatically populate ingress allow rules or infer trust from an SSH connection.

The shell accepts one operation per invocation:

```bash
sudo bash crowdbastion.sh --port-policy-plan
sudo bash crowdbastion.sh --port-policy-apply
sudo bash crowdbastion.sh --port-policy-status
sudo bash crowdbastion.sh --port-policy-verify
sudo bash crowdbastion.sh --port-policy-commit
# Or recover the uncommitted change:
sudo bash crowdbastion.sh --port-policy-rollback
```

Plan and status are read-only and bypass the maintenance lock. Apply shows the plan and asks once before mutation. Check access from an independent external client before committing. Commit always performs a fresh independent rules/persistence verification; a separate verify command is available but is not a prerequisite for commit. A rules verification is not a traffic test. All actions return 0 on their stated successful state, 1 on refusal/failure/unknown, and 75 for a busy lock or an environment preflight that is not stable. Failed apply remains failure even when its automatic recovery succeeds. Canceling the shell confirmation returns 0 without applying.

Automation can use `python3 lib/crowdbastion_port_policy.py ACTION --config /absolute/private/profile.json`. `ACTION` is plan/apply/status/verify/commit/rollback/reapply. Apply is the explicit authorization and does not add an interactive prompt. `--root` selects a private state directory; verify/commit/rollback may supply `--id UUIDHEX`. Without an ID, exactly one pending transaction must exist across the shared change root. Production defaults are `/var/lib/crowdbastion/changes` and a 900-second rollback deadline. Root is required.

Both host INPUT (including docker-proxy) and Docker's forwarded path are covered. Docker matching uses conntrack ORIGINAL direction and original destination port, so DNAT to a different container port remains in scope and reply traffic is not misclassified as new ingress. Existing CrowdSec jumps and unrelated rule order are preserved. Only owned `CBP_` chains and scoped parent jumps change, with no flush, restore, default-policy change or early ACCEPT. New restrictions are built before their jumps are installed; surviving selectors are not removed merely to change their order.

On a node with no Docker chains, an inactive/absent Docker service and a readable process inventory with no dockerd/docker-proxy prove that INPUT-only coverage is appropriate. Unknown Docker state refuses application. Existing Docker chains or a running Docker daemon require both families' Docker forwarding paths. If Docker starts later, automatic reapplication upgrades the managed policy to include DOCKER-USER. Once Docker coverage has been recorded, it stays required; removing Docker later requires resolving that ownership explicitly rather than silently downgrading protection.

Listening sshd ports and the current SSH connection's destination port are protected. Restricting any known SSH TCP port refuses, and ambiguous administration evidence refuses restrictive policy. The tool does not guess an administrator source exemption, even if the current address appears in the configured sources.

The shared maintenance lock is `/run/lock/crowdsec-1key.lock`, followed by a transaction lock inside the private change root. Shell calls reuse a verified inherited fd 9; direct Python calls take the real lock. The Task 1 pressure guard runs inside the maintenance lock before backups/runtime publication and writes. Recovery never depends on an environment-stable verdict. Every transaction contains an immutable before/after manifest, a durable progress journal, and all Python helpers needed for recovery in its own private runtime directory. The runtime survives removal of the checkout and temporary directories.

An owned systemd timer uses an absolute persistent deadline, survives session disconnect/reboot, and retries incomplete rollback every 60 seconds. Each inverse is recorded before mutation; rollback compares exact expected state, continues independent items after errors, and retains retries until all items recover. Foreign drift is reported without overwriting it. Successful commit is durably recorded before the timer is disabled, so an already queued rollback cannot undo a commit. An expired transaction cannot be committed merely because its timer is waiting for a lock. Transactions interrupted before any journal was published are reported as `preparation_incomplete`; no resource could yet have been mutated, and they do not block later work.

Persistence uses owned `crowdbastion-port-policy.service` and `.timer`, plus `60-crowdbastion-port-policy.conf` post-start drop-ins for Docker and the firewall bouncer. The service is ordered after both, retries failures, and is independently invoked every 30 seconds; drop-ins request a nonblocking reapply without restarting Docker. An intact policy is verified with zero rule mutations. Missing owned chains/jumps can be recreated, while altered chains, foreign references or missing prerequisite CrowdSec paths refuse and leave a visible failed/retrying unit. The service never removes policy on stop. This is monitored recovery, not a guarantee against arbitrary administrator flushes or a promise that packets cannot pass during service startup. Inspect `--port-policy-status` and the systemd unit if verification fails. Do not delete transaction runtimes or journals while their policy or rollback timers reference them.

These local checks exercise rule construction and lifecycle contracts. Actual remote allow/deny acceptance and kernel packet behavior require an authorized isolated network lab or a separate deployment verification.

Python 3 must already be installed before any mutating shell command, including first installation: shared safe-lock validation uses its standard library and refuses before lock/business writes when it is absent. PyYAML is not needed for transaction recovery. The shell's explicit plan/status actions retain JSON; mutation actions and menu `4 → 4 → 8` show short outcomes. Direct Python actions retain complete JSON. A no-op is explicitly reported and creates no new transaction; an existing verified pending transaction keeps its original deadline.

`pending_change` with `pending_kind` identifies the transaction type to resolve first. Expired commit reports `verification_failed` with `refusal_code=transaction_expired`; it does not disarm recovery. Verification failure preserves staged state. Status JSON remains the detailed source for unknown ownership, drift and incomplete rollback; safe messages never print raw exception text or guess that a timeout proves authentication failure.
