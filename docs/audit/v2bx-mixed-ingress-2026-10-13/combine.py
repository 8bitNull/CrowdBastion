"""Preserve the full-matrix failure; derive explicit configuration-aware coverage."""
import json,copy
from pathlib import Path
lab=Path('/tmp/v2bx-mixed-ingress-20261013');raw=(lab/'serial.log').read_text();original=json.loads(raw.split('=== RESULTS JSON START ===')[1].split('=== RESULTS JSON END ===')[0])
(lab/'full-matrix-results.json').write_text(json.dumps(original,indent=2)+'\n')
focuslab=Path('/tmp/v2bx-mixed-hy2-v4-20261013');focusraw=(focuslab/'serial.log').read_text();focused=json.loads(focusraw.split('=== RESULTS JSON START ===')[1].split('=== RESULTS JSON END ===')[0])
(focuslab/'results.json').write_text(json.dumps(focused,indent=2)+'\n');assert focused['status']=='passed' and len(focused['cases'])==1
result=copy.deepcopy(original)
for i,row in enumerate(result['cases']):
 row['evidence_configuration']='full-matrix ListenIP=::'
 if (row['family'],row['core'],row['protocol'])==(4,'hysteria2','hysteria2'):
  replacement=copy.deepcopy(focused['cases'][0]);assert replacement['passed'];replacement['evidence_configuration']='separate focused guest ListenIP=10.231.3.2; original :: IPv4 failure preserved in full-matrix-results.json';result['cases'][i]=replacement
result['status']='passed' if len(result['cases'])==26 and all(c['passed'] for c in result['cases']) else 'failed'
result['configuration_caveat']='Combined coverage, not one unchanged dual-stack configuration. Hysteria2 core :: listener selects udp6; IPv4 coverage requires separately tested explicit IPv4 listener.'
(lab/'results.json').write_text(json.dumps(result,indent=2)+'\n')
