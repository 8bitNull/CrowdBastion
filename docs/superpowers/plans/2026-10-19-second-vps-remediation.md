# Second VPS Remediation Implementation Plan

> **For agentic workers:** Execute inline, task by task. User approval already covers this operational remediation. No repository branch integration or unrelated source edits are required.

**Goal:** Bound expensive shop-filter work and verify the CrowdSec enforcement chain on the authorized second VPS.

**Architecture:** Add a path-specific shared request/concurrency budget at OpenResty, retain the existing per-IP controls, and verify enforcement using isolated traffic. Patch only the known AppSec status defect and remove only the duplicate update schedule. Each production change has an independent backup and guarded rollback.

**Tech Stack:** Python 3, SSH, OpenResty, CrowdSec, nftables, systemd.

**Spec:** `docs/superpowers/specs/2026-10-19-second-vps-remediation-design.md`

## Global Constraints

- Never expose credentials or business identities in public evidence.
- Preserve preexisting workspace edits and unrelated remote configuration.
- Never ban management sources or CDN nodes; test sources must be isolated.
- No live order, payment, service restart, new proxy trust, or dynamic-page cache.
- Check file bytes immediately before each atomic production mutation.
- Evidence precedes completion claims; document unverified historical anomalies.

## Task 1: Filter budget

Files: private `initial.py`, `shop_runtime.py`, `deploy_shop.py`; remote site A server config and existing HTTP guard include; public remediation evidence.

- [x] Capture fresh config, services, decisions and both nftables sets; save privately with hashes.
- [x] Run a loopback-only OpenResty instance with the actual existing map/server directives and a backend that holds filter requests open. Send 8 distinct test sources with browser UAs to `/shop?products-test=...`; assert no more than 2 reach the backend concurrently and excess requests return 429. Confirm the existing configuration fails this assertion.
- [x] Add a shared nonempty key only for filter requests, `limit_conn_zone ... zone=aomway_shop_filter_total_conn:1m`, `limit_req_zone ... zone=aomway_shop_filter_total_rate:1m rate=1r/s`, `limit_conn aomway_shop_filter_total_conn 2`, and `limit_req zone=aomway_shop_filter_total_rate burst=2 nodelay`. Use HTTP 429 for both limits.
- [x] Re-run the same runtime test; check GET/HEAD, both slash forms, internal redirects, POST, ordinary shop, product, cart, checkout and account controls. Verify cleanup and unchanged production processes.
- [x] Record baseline page GETs, prepare atomic write/rollback, run `docker exec openresty nginx -t`, gracefully reload and confirm new workers. Repeat safe live GETs.

## Task 2: Detection and firewall lifecycle

Files: private scenario and isolated firewall test scripts; remote custom filter scenario only if validated.

- [x] Use `cscli explain`/offline scenario replay with identical paths and two UAs to demonstrate the current UA-dependent coverage gap.
- [x] Remove only the UA requirement, replay the enumeration and benign low-frequency controls, run `crowdsec -t`, back up and reload the validated change.
- [x] Compare every current local IP ban with the union of local and CAPI sets. Investigate overlap and stream lifecycle with controlled isolated decisions and network traffic; always clean up the owned decisions and namespace.
- [x] Add a production firewall fix only if a root cause is reproduced; otherwise report the remaining uncertainty and test results without restarting the bouncer.
- [x] Reproduced root cause: nftables skips existing IPs and does not extend TTL. Validate the official iptables/ipset backend inside a separate network namespace, install only the missing ipset dependency, then migrate with a temporary ban snapshot and guarded rollback. Re-run the same live IPv4/IPv6 TCP/UDP renewal test and verify INPUT/FORWARD/DOCKER-USER ordering.

## Task 3: AppSec status and update scheduler

Files: private `appsec_runtime.py`, `deploy_appsec.py`, `deduplicate_scheduler.py`; remote managed `crowdsec.lua`, installation state and exact duplicate cron file.

- [x] Under the actual OpenResty, reproduce refusal/timeout/503 AppSec denial returning HTTP 200 with zero backend hits. Patch the single verified fallback to set `status_code = ngx.HTTP_FORBIDDEN`; repeat and require 403, with healthy/passthrough controls.
- [x] Verify all managed hashes, back up, write only the Lua fix and its one recorded resource hash, validate/reload OpenResty, and recheck managed integrity. Keep policy bytes unchanged.
- [x] Verify package timer enabled/active and last result successful. Remove only the exact duplicate daily update line after backup; verify unrelated scheduler contents and guarded rollback.

## Task 4: Acceptance and reporting

- [x] Confirm post-deploy hashes, active services, master/worker state, safe business GET results and controlled enforcement/recovery.
- [x] Check that temporary listeners, processes, test decisions and namespaces are removed.
- [x] Publish sanitized result JSON and Chinese report with changes, runtime evidence, backup/rollback paths and limitations. Do not claim a full checkout or a historical firewall-gap repair without evidence.

## AppSec failure-policy correction

User subsequently rejected AppSec failure passthrough. This amendment supersedes the instruction in Task 3 to preserve policy bytes.

- [x] Copy the actual installed Lua and current policy into an isolated OpenResty instance. Demonstrate that passthrough permits refusal, timeout and HTTP 503 to reach the counted backend.
- [x] Change only `APPSEC_FAILURE_ACTION` to `deny`, update its normalized managed resource hash, preserve a guarded backup, validate and gracefully reload OpenResty.
- [x] Repeat with the configured deny policy: all three faults return HTTP 403 with zero backend calls; the healthy case returns HTTP 200 with one backend call.
- [x] Verify policy readback, managed integrity, current file hashes, replaced workers, unchanged CrowdSec/Firewall Bouncer services, cleanup and production page GETs. Publish the [follow-up report](../../audit/2026-10-19-second-vps-appsec-failure-policy.md) and separate snapshot evidence.

## Acceptance boundaries after both changes

External CDN identity was verified. The public HTTP egress is also an established SSH management source, so no public ban cycle was performed; the live vhost ban cycle used a local controlled proxy, original WAF and counted backend. Forwarding hook order was checked; traffic probes covered INPUT. No production order/payment or rollback drill was executed. See the final audit report for evidence and rollback order.
