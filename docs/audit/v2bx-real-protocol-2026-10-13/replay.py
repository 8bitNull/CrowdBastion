from pathlib import Path
import json,sys,types
repo=Path('/data/project/script/crowdsec-1key');sys.path.insert(0,str(repo/'lib'))
from crowdsec_v2bx_logs import eligible
rows=json.loads(Path('/tmp/v2bx-real-lab/results.json').read_text())['cases']
for case in rows:
 for phase in case['phases']:
  if phase['phase']!='wrong_credentials' and any(eligible(e) for e in phase['log_projection']['events']):raise RuntimeError('Healthy/recovery produced eligible failure observation')
  if case['path']=='proxy-gost' and any(eligible(e) for e in phase['log_projection']['events']):raise RuntimeError('Relay source unexpectedly eligible')
events=[e for c in rows for p in c['phases'] for e in p['log_projection']['events']]
groups={}
for e in events:
 if eligible(e):groups.setdefault((e['source_ip'],e['core'],e['protocol']),e)
selected=[e for e in events if not eligible(e)]+list(groups.values())
source=(repo/'tests/verify_v2bx_observation.py').read_text().replace('events, expected = samples()', 'events, expected = samples()\n            expected_count = len(real_groups)').replace('len(expected)', 'expected_count').replace("'scope': 'isolated official CrowdSec 1.8.1, synthetic/source-backed events; no production traffic'", "'scope': 'isolated official CrowdSec 1.8.1; actual V2bX lab log projections; deduplicated eligible groups; no production traffic'")
source=source.replace("metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))\n            rows =", "Path('/tmp/v2bx-real-lab/replay-alerts-temp.json').write_text(json.dumps(alerts))\n            checked_groups=set()\n            for alert in alerts:\n                for event in alert.get('events', []):\n                    metadata=event.get('meta', [])\n                    meta=metadata if isinstance(metadata,dict) else {m['key']:m['value'] for m in metadata}\n                    checked_groups.add((str(alert.get('source',{}).get('value')),meta.get('v2bx_core'),meta.get('v2bx_protocol')))\n            if checked_groups != set(real_groups):\n                raise RuntimeError('Actual alert core/protocol group mapping failed')\n            metrics = json.loads(cli('metrics', 'show', 'acquisition', '-o', 'json'))\n            rows =")
module=types.ModuleType('real_replay');module.__file__=str(repo/'tests/verify_v2bx_observation.py');exec(compile(source,module.__file__,'exec'),module.__dict__)
module.real_groups=groups;module.samples=lambda:(selected,{e['source_ip'] for e in groups.values()})
result=module.verify('/tmp/crowdsec-qa-engine/crowdsec-v1.8.1')
result.pop('invalid_normalized_records_excluded',None)
result['actual_alert_groups_verified']=True
result.update(raw_projected_events=len(events),eligible_events_before_deduplication=sum(eligible(e) for e in events),expected_groups=[dict(source_ip=k[0],core=k[1],protocol=k[2]) for k in groups],scope_exclusions='No invented authentication failures; unsupported log formats excluded; relay addresses ineligible')
Path('/tmp/v2bx-real-lab/replay-results.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2))
