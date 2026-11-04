# Protocol capability and diagnosis boundary


交互使用：从首页 `4 → 11` 选择程序、协议、实际传输和拓扑，无需设置环境变量；V2bX 专项菜单 `5` 也可进入选择器。选择仅用于本次只读指导，不保存用途或业务配置。完整导航见[使用说明](usage-guide.md#代理协议使用导航)。旧 `--protocol-status` 保持非交互，声明画像仍返回 `2`。
Research began after Tasks 1–3 general fixes were accepted, on 2026-11-03 UTC. Runtime definitions are shipped in `lib/crowdbastion_protocols.py`; no runtime reads this document, source receipts, or temporary downloads. [protocol-source-receipts.json](protocol-source-receipts.json) records each successful official fetch URL, time, byte count and SHA-256. A digest of a fetched documentation page is a **documentation snapshot**, not proof of an installed program version. Failed 404/403 requests are not support evidence.

`--diagnose-v2bx` / `--diagnose-v2bx-details` retain the existing bounded V2bX config and xray/sing/hysteria2 inventory. Their added capability profiles describe configuration declarations and the standard protocol envelope. They do not discover panel transport, runtime protocol options, ciphers, users or QUIC controllers. Existing `transport_status=panel_or_runtime_required` remains authoritative. In particular, VMess/VLESS are never assigned TCP from their name.

A generic read-only declaration profile is available without installing a backend:

```bash
NODE_PROGRAM=v2node NODE_PROTOCOL=anytls NODE_TRANSPORT=udp-over-tcp \
  NODE_TOPOLOGY=shared-relay bash crowdbastion.sh --protocol-status
NODE_PROGRAM=v2bx NODE_PROTOCOL=tuic NODE_TRANSPORT=quic \
  bash crowdbastion.sh --protocol-status
python3 lib/crowdbastion_protocols.py --program v2bx --protocol vless --transport grpc --json
```

Exit 2 means runtime remains unverified. These fields are operator declarations, independent of saved roles v1. A backend name (`v2node`, `v2bx`) is invalid as a protocol. Unknown or mixed transport values remain unknown and request sanitized panel/runtime evidence. `NODE_VERSION` is accepted only as unverified input and never echoed or used to authorize a parser. Unknown backend names and arbitrary input values are reduced to allowlisted labels. No directories are scanned and no logs, command lines, config paths or credentials are printed by the profile command.

| Protocol declaration | Bounded transport guidance | Evidence |
|---|---|---|
| VMess / VLESS | Missing/mixed/XHTTP or TLS-only security stays unknown. Explicit raw/TCP, WS/WebSocket, gRPC or HTTPUpgrade indicates TCP. TLS is security and can accompany non-TCP transports. XHTTP requires more evidence because its HTTP version matters. | `vmess`, `vless`, `xray-transport`, `xray-transport-pinned` receipts |
| Shadowsocks / Shadowsocks2022 | Explicit TCP, UDP, or TCP+UDP; absent transport stays unknown. Supported cipher families do not prove which cipher or plugin a host uses. | `shadowsocks`, `singbox-shadowsocks` receipts; sing-box documents TCP/UDP independently and 2022 methods |
| Trojan | Standard TLS/TCP envelope; declared supported Xray transport variants handled independently. UDP ASSOCIATE carries UDP payload over the stream. | `trojan`, `xray-transport` |
| Hysteria1 (`hysteria` alias) | Mode required. UDP/wechat-video indicate UDP/QUIC. faketcp is a distinct envelope that bypasses the system TCP stack. No mode is inferred from a panel label. | `hysteria1`, `singbox-hysteria` |
| Hysteria2 | Standard UDP/QUIC profile; explicit faketcp identifies current docs' optional mimic envelope. Profile does not discover whether mimic is enabled. | `hysteria2` |
| TUIC | Explicit QUIC implementation profile; absent transport stays unknown because SPEC says transport independent although mainly designed for QUIC. | `tuic-spec`, `singbox-tuic` |
| AnyTLS | TLS/TCP; UDP payload via sing-box UDP-over-TCP v2, not native QUIC. Conflicting declared QUIC stays unknown. | `anytls` |

`host_tcp_relevant` describes the declared outer connection only. Kernel TCP BBR does not configure a userspace QUIC controller. The host's separate TCP connection to a destination can still be affected by kernel TCP choices. Hysteria2's fetched docs describe BBR, Reno and Brutal with direction/bandwidth negotiation; the sing-box TUIC page describes cubic/new_reno/bbr. Neither establishes the controller of an installed V2bX core. Hysteria1 faketcp and Hysteria2 mimic are never treated as ordinary kernel TCP simply because packets look like TCP.

The Task 3 `--network-status` / `--network-plan` interface remains an independent selected host TCP baseline. Profiles do not modify that plan or claim throughput. Observe UDP socket errors, packet loss and buffer ceilings before measurement; there is no universal UDP memory setting. There are no proxy installs/upgrades, cipher/password/certificate changes, TFO changes, or tuning operations here.

## Backend evidence and exact source versions

Candidate V2Node repository: [wyx2685/v2node](https://github.com/wyx2685/v2node), actual default branch `main`, observed commit **129abe1a3db0d8f314e1c21a30a9d41fc42ecfc1**. Fetched commit-pinned README describes a V2board backend based on a modified Xray core; its build replaces `cmd.version` with ldflags. Pinned `cmd/version.go` uses `TempVersion` by default. The README's installer link still names `master`; that does not establish a supported release, service/config schema, or this user's installed project. No exact host repository/version/schema was supplied, so V2Node is **candidate_repository_host_provenance_unknown**. No V2Node config parser, service name discovery or version support is claimed. Next step: identify the actual repository, immutable release/commit and sanitized schema before adding one.

The official Xray page's own edit link resolves to [XTLS/Xray-docs-next](https://github.com/XTLS/Xray-docs-next), not the guessed older repo. Observed docs commit **e9f8a16331af0dd80a7bf8d2793205555d7909d2**; the transport Markdown was also fetched at that exact commit. Rendered VMess/VLESS pages have their own recorded snapshot digests.

TUIC [SPEC.md](https://github.com/tuic-protocol/tuic/blob/8e118f242f24a17a9f487dc344cc50d7e63e557e/SPEC.md) declares protocol **0x05**; observed repo commit **8e118f242f24a17a9f487dc344cc50d7e63e557e**. AnyTLS [protocol.md](https://github.com/anytls/anytls-go/blob/fd6167acd6d73b9fa3e607659951847fbc9e6c50/docs/protocol.md) includes protocol version 2 changes; observed commit **fd6167acd6d73b9fa3e607659951847fbc9e6c50**. These source bodies were fetched via their default branches with concurrent commit metadata; page/body digests in the receipts are the authoritative observations. Trojan protocol page is a fetched snapshot; concurrent project commit **3e7bb9aecdc694f9bcae8d646fae395f773d60f8** is not asserted to generate that deployed page. Hysteria v1/v2 and sing-box are fetched documentation snapshots; no arbitrary installed release support is inferred.

Official pages used: [VMess](https://xtls.github.io/config/inbounds/vmess.html), [VLESS](https://xtls.github.io/config/inbounds/vless.html), [Xray transport](https://xtls.github.io/config/transport.html), [Shadowsocks overview](https://shadowsocks.org/doc/what-is-shadowsocks.html), [Trojan](https://trojan-gfw.github.io/trojan/protocol), [Hysteria1](https://v1.hysteria.network/docs/advanced-usage/), [Hysteria2](https://v2.hysteria.network/docs/advanced/Full-Server-Config/), [sing-box Hysteria](https://sing-box.sagernet.org/configuration/inbound/hysteria/), [sing-box TUIC](https://sing-box.sagernet.org/configuration/inbound/tuic/), [sing-box Shadowsocks](https://sing-box.sagernet.org/configuration/inbound/shadowsocks/).

## Observation, website and packaging compatibility

No log regex or attack-detection support was added. Existing source-pinned/captured V2bX parser behavior remains in `docs/v2bx-structured-events.md` and its linked audit evidence. Authentication failure, protocol rejection, integrity failure, ordinary TLS/timeout/reset and healthy connection events remain distinct. A capability profile always requires backend version and sanitized sample evidence before log-detection claims. Existing experimental structured QUIC auth events do not imply support in stock binaries.

Shared relay topology is a declaration, never proof of individual client identity. Existing observer relay CIDR exclusion and observation-only behavior remain authoritative; no profile authorizes banning a relay. Source ownership checks are unchanged.

`--optimize` validates existing role preferences first. Explicit node/remote/relay roles with no managed website skip HTTP repair and explain why it is not applicable. Unset roles retain legacy prompt order; managed website state retains web checks. Independent website deployments still use dedicated website commands, and absent HTTP/AppSec is not an AnyTLS/TUIC fault.

New observer snapshots ship the capability helper because diagnostics import it. Older bundles may omit the new capability helper and/or the earlier health helper; their actual recorded files and hashes, including unit, are validated. An unrecorded helper or altered recorded file is still rejected. Existing bundles remain readable and disable-able; their code is not silently rewritten.
