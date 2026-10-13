from pathlib import Path
import json,shutil,hashlib
repo=Path('/data/project/script/crowdsec-1key');b=Path(__file__).resolve().parent;a=repo/'docs/audit/v2bx-observation-stability-2026-10-13';a.mkdir(exist_ok=True)
for name in ('lab.py','source_check.py','archive.py','results.json','real-replay.json','synthetic-results.json','log-source-check.json','xray.ndjson','sing.ndjson','hysteria2.ndjson','relay-sing.ndjson'):
 if (b/name).exists():shutil.copy2(b/name,a/name)
for p in b.glob('*.go'):shutil.copy2(p,a/p.name)
shutil.copy2(repo/'docs/audit/v2bx-real-protocol-2026-10-13/sources.json',a/'program-sources.json')
checks=[]
for name in ('lib/crowdsec_v2bx_logs.py','lib/crowdsec_v2bx_observe.py','lib/v2bx.sh','install-crowdsec-1panel.sh','tests/test_v2bx_observe.py','tests/test_v2bx_logs.py','tests/verify_v2bx_observation.py','tests/verify_v2bx_real_observation.py','rules/v2bx/parsers/s01-parse/10-v2bx-observation.yaml','rules/v2bx/scenarios/v2bx-failure-observation.yaml'):
 checks.append(dict(path=name,sha256=hashlib.sha256((repo/name).read_bytes()).hexdigest()))
(a/'implementation-hashes.json').write_text(json.dumps(checks,indent=2)+'\n')
failures={'new_protocol_tests':'AnyTLS and SS fixtures initially failed unsupported_format, then passed exact parser additions','observer_tests':'Missing implementation; restart during rename gap; missing new source recovery; source/export alias conflict; source/database alias conflict; cross-database duplicate source. Each gained failing regression before fix.','synthetic_rule_test':'Permissive AnyTLS protocol_rejection produced unexpected observation; filter tightened to AnyTLS auth_failure only; actual and synthetic final validations passed','rotation_limit':'Observed EOF handoff can miss subsequent old-writer writes. Explicit continuity risk on every handoff; late-write regression ensures risk is reported, not losslessness.'}
(a/'failed-attempts.json').write_text(json.dumps(failures,indent=2)+'\n')
(a/'artifact-hashes.json').write_text(json.dumps({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in a.iterdir() if p.is_file() and p.name!='artifact-hashes.json'},indent=2)+'\n')
print(a)
