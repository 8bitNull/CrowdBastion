# Unknown upstream real-IP diagnosis plan

User authorized extending the existing trusted-proxy workflow after reviewing unknown-upstream handling.

- Add explicit Unknown (read-only diagnosis) and Confirmed direct access options; neither changes configuration, removes existing trust, fetches CDN ranges, nor reloads services.
- Add --diagnose-real-ip without requiring CrowdSec core, curl, or the HTTP real-IP module. Existing apply/restore prerequisites remain.
- Collect bounded recent access-log evidence via actual mounts, support standard Nginx and NPM Client fields, exclude stream logs, mark rewritten log IPs as evidence rather than TCP peers, and show existing trust plus ownership status.
- Give a unique normal-page external request marker, safe shell-quoted log correlation commands and next-step guidance. No requests are sent by diagnosis and no Header/CDN becomes trusted from observation.
- Test unknown/direct cancellation and no-write/no-fetch/no-reload behavior, missing module/core read-only access, NPM/custom/missing log evidence, and unsafe/unmounted paths. Update docs/help, run full tests/lint and independent review, then commit/push.
