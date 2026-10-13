import json,hashlib,shutil,ast
from pathlib import Path
lab=Path('/tmp/v2bx-mixed-ingress-20261013')
result=json.loads((lab/'results.json').read_text())
rows=result['cases'];events=[e for r in rows for p in r['phases'] for e in p['events']]
(lab/'events.ndjson').write_text(''.join(json.dumps(e,sort_keys=True)+'\n' for e in events))
summary={'status':result['status'],'cases':len(rows),'tcp_and_source_safety_passed':sum(r['passed'] for r in rows),'healthy_udp_forwarded_cases':sum(r['udp_healthy_verified'] for r in rows),'udp_unverified_cases':[{k:r[k] for k in ('family','core','protocol')} for r in rows if not r['udp_healthy_verified']],'all_measured_attempts_overlap':all(r['concurrency_verified'] for r in rows),'healthy_tcp_tokens':sum(r['probes'][0]['verified'] for row in rows for p in row['phases'] for r in p['results'] if not r['role'].startswith('bad')),'healthy_udp_tokens':sum(r['probes'][1]['verified'] for row in rows for p in row['phases'] for r in p['results'] if not r['role'].startswith('bad')),'bad_token_responses':sum(probe['verified'] for row in rows for p in row['phases'] for r in p['results'] if r['role'].startswith('bad') for probe in r['probes']),'projected_events':len(events)}
(lab/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary,indent=2))
import sys
sys.path.insert(0,'/data/project/script/crowdsec-1key/lib')
from crowdsec_v2bx_logs import eligible
protocols=[('xray','vmess'),('xray','vless')]+[('sing',p) for p in ('vmess','vless','trojan','anytls','tuic','hysteria','hysteria2')]+[('hysteria2','hysteria2')]
expected={(ip,c,p) for ip in ('10.231.1.2','fd42:231:1::2') for c,p in protocols}
actual={(e['source_ip'],e['core'],e['protocol']) for e in events if eligible(e)}
checks={'26_cases':len(rows)==26,'healthy_baseline_peers_verified':all(({'10.231.2.2','10.231.3.1'} if row['family']==4 else {'fd42:231:2::2','fd42:231:3::1'})<=set(row['phases'][0]['observed_sources']) for row in rows),'all_tcp_and_concurrency':all(r['passed'] for r in rows),'all_healthy_udp_forwarded':all(r['udp_healthy_verified'] for r in rows),'all_socks_negotiated_and_probe_valid':all(probe['negotiated'] and probe['probe_valid'] for row in rows for phase in row['phases'] for role in phase['results'] for probe in role['probes']),'no_bad_token':summary['bad_token_responses']==0,'exact_20_failure_groups':actual==expected,'all_failure_relay_groups_excluded':{(e['source_ip'],e['core'],e['protocol']) for e in events if e['event_type'] in ('auth_failure','protocol_rejection') and e['source_status']=='relay_address'}=={(ip,c,p) for ip in ('10.231.3.1','fd42:231:3::1') for c,p in protocols}}
(lab/'acceptance-checks.json').write_text(json.dumps({'checks':checks,'actual_eligible_groups':[{'source_ip':ip,'core':c,'protocol':p} for ip,c,p in sorted(actual)]},indent=2)+'\n');print(checks)
if not all(checks.values()):raise SystemExit('One or more strict acceptance checks failed; inspect actual result, do not claim full coverage')
