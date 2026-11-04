RELEASE='/opt/crowdbastion/releases/vps45-repair-20261102-1f5c867f601e'
MAINTENANCE='/usr/local/lib/crowdsec-1key/release-vps45-repair-20261102-1f5c867f601e'
FINGERPRINT='1f5c867f601eb346e73f91a79d8417b0f2be055e24c480a600d3aff6a3ddc742'
RESOURCES={'rules/v2bx/README.md': '# V2bX 仅观察规则\n\n本目录用于已脱敏的固定字段投影，原始 V2bX 日志不能直接作为输入。`--enable-v2bx-alerts` 可显式安装独占规则与 acquisition，并在 profiles 最前加入专用决策隔离 guard；当前宿主机未部署，真实 VPS 仍待验收。\n\n| 文件 | 作用 |\n| --- | --- |\n| [解析器](parsers/s01-parse/10-v2bx-observation.yaml) | 只接受 `v2bx-observation` 标签、固定契约、合法 IP 和已列出的失败类型／内核／协议 |\n| [场景](scenarios/v2bx-failure-observation.yaml) | 单事件观察触发，`remediation: false`；没有攻击速率阈值 |\n\n合格失败覆盖 xray VMess/VLESS，sing VMess/VLESS/Trojan/AnyTLS，以及固定实验构建的 sing TUIC/Hysteria1/2 和 hysteria2 core Hysteria2。匹配格式及语义见 [V2bX 指南](../../docs/v2bx-guide.md)。\n\nxray Trojan 的拒绝可能进入 fallback，保持中性；Shadowsocks 的完整性错误不进入失败场景。健康连接、普通网络错误、未知格式及声明为 `relay_address` 的共享中转事件排除。`unverified` 不是可信用户标记，部署前仍须核对实际来源和中转范围。\n\n离线投影可以由 `--v2bx-log-check` 或 `--v2bx-observe` 取得；后者为完整一次性快照，不得重复或重叠接入。常驻接入从采集器 SQLite 增量发布，持久记录发布游标与意图；消费端重启／部分写入必须停止核对，不能宣称 CrowdSec 端恰好一次。详见[常驻告警接入](../../docs/v2bx-guide.md#常驻仅观察告警接入)。\n\n即使场景声明 `remediation: false`，忽略该字段的自定义 profiles 仍可能产生决策。真实 VPS 接入前必须隔离核查 profiles、采集去重、来源排除与停用方式，见 [部署验收](../../docs/v2bx-deployment-acceptance.md)。\n\n最近的 [实际事件回放](../../docs/audit/2026-10-13-v2bx-mixed-ingress.md)按来源／内核／协议去重后形成 20 组观察告警、0 决策；这不是逐行告警率，也不是生产封禁验收。\n', 'rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml': "name: crowdsec-1key/v2bx-observation\ndescription: Parse projected V2bX failures for observation only; source trust is unverified\nfilter: >-\n  evt.Line.Labels.type == 'v2bx-observation' &&\n  JsonExtract(evt.Line.Raw, 'schema_version') == '1' &&\n  JsonExtract(evt.Line.Raw, 'observation_only') == 'true' &&\n  JsonExtract(evt.Line.Raw, 'source_status') == 'unverified' &&\n  JsonExtract(evt.Line.Raw, 'event_type') in ['auth_failure', 'protocol_rejection'] &&\n  ((JsonExtract(evt.Line.Raw, 'core') == 'xray' && JsonExtract(evt.Line.Raw, 'protocol') in ['vless', 'vmess', 'trojan']) ||\n   (JsonExtract(evt.Line.Raw, 'core') == 'sing' && JsonExtract(evt.Line.Raw, 'protocol') in ['vless', 'vmess', 'trojan']) ||\n   (JsonExtract(evt.Line.Raw, 'core') == 'sing' && JsonExtract(evt.Line.Raw, 'protocol') == 'anytls' && JsonExtract(evt.Line.Raw, 'event_type') == 'auth_failure') ||\n   (JsonExtract(evt.Line.Raw, 'core') == 'sing' && JsonExtract(evt.Line.Raw, 'protocol') in ['tuic', 'hysteria', 'hysteria2'] && JsonExtract(evt.Line.Raw, 'event_type') == 'auth_failure') ||\n   (JsonExtract(evt.Line.Raw, 'core') == 'hysteria2' && JsonExtract(evt.Line.Raw, 'protocol') == 'hysteria2' && JsonExtract(evt.Line.Raw, 'event_type') == 'auth_failure')) &&\n  (IpInRange(JsonExtract(evt.Line.Raw, 'source_ip'), '0.0.0.0/0') ||\n   IpInRange(JsonExtract(evt.Line.Raw, 'source_ip'), '::/0'))\nonsuccess: next_stage\nstatics:\n  - target: evt.StrTime\n    expression: JsonExtract(evt.Line.Raw, 'timestamp')\n  - meta: source_ip\n    expression: JsonExtract(evt.Line.Raw, 'source_ip')\n  - meta: log_type\n    value: v2bx_failure_observation\n  - meta: v2bx_core\n    expression: JsonExtract(evt.Line.Raw, 'core')\n  - meta: v2bx_protocol\n    expression: JsonExtract(evt.Line.Raw, 'protocol')\n  - meta: v2bx_event_type\n    expression: JsonExtract(evt.Line.Raw, 'event_type')\n  - meta: v2bx_source_status\n    value: unverified\n", 'rules/v2bx/scenarios/v2bx-failure-observation.yaml': "type: trigger\nname: crowdsec-1key/v2bx-failure-observation\ndescription: Observe individual V2bX failure events; does not establish an attack or request a ban\nfilter: evt.Meta.log_type == 'v2bx_failure_observation' && evt.Meta.v2bx_source_status == 'unverified'\ngroupby: evt.Meta.source_ip + '/' + evt.Meta.v2bx_core + '/' + evt.Meta.v2bx_protocol\nblackhole: 1s\nlabels:\n  service: v2bx\n  type: observation\n  remediation: false\n"}
HASHES={'rules/v2bx/README.md': '33c38bd3ae1126e9f8a1c809b6c94ffb5c9455a4dec0033f397012ebb54e4c03', 'rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml': '47c5b539b2e363887e72f66aa05a31c58458badf0b70fdf5c0ddb3110392276d', 'rules/v2bx/scenarios/v2bx-failure-observation.yaml': '58480d84e97abd46270b35ca7ad99c217f4c4408bb30e9252f6793ac90282a93'}
from pathlib import Path
import datetime,hashlib,json,os,sys,time
os.umask(0o077);sys.path.insert(0,RELEASE+'/lib')
from crowdsec_bot_runtime import maintenance_guard
from crowdbastion_ux import code_fingerprint
roots=[Path(RELEASE),Path(MAINTENANCE),Path('/root/crowdsec-1key')]
stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');backup=Path('/var/backups/crowdbastion/vps45-resources-'+stamp)
created=[];before={}
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 for root in roots:
  assert code_fingerprint(root/'crowdbastion.sh')==FINGERPRINT
  for name,value in RESOURCES.items():
   p=root/name
   for ancestor in [p,*p.parents]:assert not ancestor.is_symlink()
   if p.exists():assert p.is_file() and p.read_bytes()==value.encode(),str(p)
   before[str(p)]=hashlib.sha256(p.read_bytes()).hexdigest() if p.exists() else None
 backup.mkdir(mode=0o700)
 try:
  for root in roots:
   for name,value in RESOURCES.items():
    p=root/name
    if not p.exists():
     p.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
     with p.open('xb') as f:f.write(value.encode())
     p.chmod(0o600);created.append(p)
    assert hashlib.sha256(p.read_bytes()).hexdigest()==HASHES[name]
 except BaseException:
  for p in reversed(created):
   if p.read_bytes()==RESOURCES[str(p.relative_to(next(r for r in roots if r in p.parents)))].encode():p.unlink()
  raise
 result={'completed_at':time.time(),'backup':str(backup),'resources':HASHES,'before':before,'files_created':[str(p) for p in created],'root_existing_resources_unchanged':all(before[str(Path('/root/crowdsec-1key')/p)]==HASHES[p] for p in RESOURCES),'fingerprint_unchanged':all(code_fingerprint(root/'crowdbastion.sh')==FINGERPRINT for root in roots),'optional_component_enabled':False,'services_restarted':False}
 (backup/'resources-completion.json').write_text(json.dumps(result,indent=2)+'\n');(backup/'resources-completion.json').chmod(0o600)
 manifest={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in backup.iterdir() if p.is_file()}
 (backup/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(backup/'manifest.json').chmod(0o600)
 result['supplemental_manifest_sha256']=hashlib.sha256((backup/'manifest.json').read_bytes()).hexdigest()
print(json.dumps(result,ensure_ascii=False))
