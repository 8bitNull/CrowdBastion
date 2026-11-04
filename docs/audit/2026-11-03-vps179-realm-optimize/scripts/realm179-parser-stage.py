from pathlib import Path
import json,subprocess,yaml,hashlib
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z');stage=base/'stage'
parser=r'''name: local/realm-forwardx-observation
description: ForwardX realm diagnostics only; never extracts source_ip or emits decisions
filter: "evt.Line.Labels.type == 'realm-forwardx'"
onsuccess: next_stage
grok:
  pattern: '^.*?\[%{YEAR:realm_year}-%{MONTHNUM:realm_month}-%{MONTHDAY:realm_day}\]\[%{TIME:realm_time}\]\[%{DATA:realm_module}\]\[%{LOGLEVEL:realm_level}\](?:\[%{WORD:realm_protocol}\])?%{GREEDYDATA:realm_message}$'
  apply_on: Line.Raw
statics:
  - meta: log_type
    value: realm_forwardx_observation
  - meta: service
    value: realm
  - meta: realm_level
    expression: evt.Parsed.realm_level
  - meta: realm_module
    expression: evt.Parsed.realm_module
  - meta: realm_protocol
    expression: evt.Parsed.realm_protocol
'''
acq={'source':'journalctl','journalctl_filter':['_SYSTEMD_UNIT=forwardx-realm-both-56017.service','_SYSTEMD_UNIT=forwardx-realm-both-58372.service'],'labels':{'type':'realm-forwardx'}}
(stage/'parsers/s01-parse/20-realm-forwardx-observation.yaml').write_text(parser)
(stage/'acquis.d/crowdbastion-realm-forwardx.yaml').write_text(yaml.safe_dump(acq,sort_keys=False))
fixture='[2026-11-03][01:00:00][realm_core::tcp][ERROR][tcp][::ffff:203.0.113.77]:45012 => 192.0.2.13:2053, error: Connection timed out (os error 110)'
fixtures={'error':fixture,'warn':'[2026-11-03][01:00:00][realm_core::tcp::socket][WARN][tcp]connect to 192.0.2.13:2053 as 192.0.2.13:2053: Connection timed out (os error 110), try next ip','malformed':'unexpected realm diagnostics without structured fields'}
r={'backup':str(base),'fixtures':{}}
for name,line in fixtures.items():
 p=subprocess.run(['cscli','-c',str(stage/'config.yaml'),'explain','--log',line,'--type','realm-forwardx','--verbose'],capture_output=True,text=True,timeout=50)
 (base/('parser-green-'+name+'.json')).write_text(p.stdout);(base/('parser-green-'+name+'.stderr')).write_text(p.stderr)
 r['fixtures'][name]={'exit':p.returncode,'observation_marker_present':'realm_forwardx_observation' in p.stdout,'bytes':len(p.stdout)}
 assert p.returncode==0,(name,p.stderr[-1500:])
 assert ('realm_forwardx_observation' in p.stdout)==(name!='malformed'),(name,p.stdout[-1000:])
 # Parser intentionally leaves source identity unset: generic enrichment/scenarios cannot ban the peer.
 assert 'evt.Meta.source_ip' not in p.stdout,(name,'unexpected source_ip')
p=subprocess.run(['cscli','-c',str(stage/'config.yaml'),'explain','--log','Nov  3 01:00:00 relay-test sshd[1234]: Failed password for invalid user test from 203.0.113.77 port 2222 ssh2','--type','syslog','-o','json'],capture_output=True,text=True,timeout=50)
(base/'parser-ssh-control.json').write_text(p.stdout)
r['ssh_control']={'exit':p.returncode,'sshd_parser_present':'crowdsecurity/sshd-logs' in p.stdout,'realm_marker_present':'realm_forwardx_observation' in p.stdout}
assert p.returncode==0 and 'crowdsecurity/sshd-logs' in p.stdout and 'realm_forwardx_observation' not in p.stdout
p=subprocess.run(['crowdsec','-c',str(stage/'config.yaml'),'-t'],capture_output=True,text=True,timeout=60)
(base/'staged-config-check.txt').write_text(p.stdout+p.stderr);r['config_validation']={'exit':p.returncode}
assert p.returncode==0,p.stdout[-2000:]+p.stderr[-2000:]
(base/'staged-result.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2))
