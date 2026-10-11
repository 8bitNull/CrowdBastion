# Trusted proxy real-IP implementation plan

User-approved design: identify trusted CDN/proxy first, choose its documented Header, preserve peer IP when unavailable, and verify log/Lua IP using the same request. Never choose the first header present.

- Extend lib/crowdsec_realip.py with Cloudflare and explicit custom policies, CIDR/header validation, configuration discovery, and NPM server-layer merge preserving original bytes and permissions. Existing managed Cloudflare files remain compatible.
- Extend lib/real_ip.sh with provider selection, existing-header evidence, explicit custom proxy networks, scope preview, transactional apply/update/restore. Cloudflare ranges come only from fixed official HTTPS URLs. No proxy ranges inferred from traffic.
- Add failing tests for NPM inherited/default rules, merge/update/restoration, conflicting server overrides, custom trust and unsupported Forwarded; preserve cancellation and rollback tests.
- Verify actual OpenResty header selection, untrusted-source spoof prevention, invalid/missing Header peer fallback, XFF chain behavior, NPM server-layer inheritance and Lua/log agreement.
- Update help/docs. Run regression suite, bash syntax, ShellCheck, runtime tests; request independent review and resolve findings before commit/push.

Scope: existing Docker repair adapter only; host Nginx/Tunnel require explicit deployment configuration. NPM applies to proxy hosts loading server_proxy.conf and previews this scope; it does not edit generated proxy-host files or http_top.conf. Unknown headers/peers stay diagnostic until explicitly configured.
