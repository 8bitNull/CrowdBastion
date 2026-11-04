PARSER='name: local/realm-forwardx-observation\ndescription: ForwardX realm diagnostics only; never extracts source_ip or emits decisions\nfilter: "evt.Line.Labels.type == \'realm-forwardx\'"\nonsuccess: next_stage\ngrok:\n  pattern: \'^.*?\\[%{YEAR:realm_year}-%{MONTHNUM:realm_month}-%{MONTHDAY:realm_day}\\]\\[%{TIME:realm_time}\\]\\[%{DATA:realm_module}\\]\\[%{LOGLEVEL:realm_level}\\](?:\\[%{WORD:realm_protocol}\\])?%{GREEDYDATA:realm_message}$\'\n  apply_on: Line.Raw\nstatics:\n  - meta: log_type\n    value: realm_forwardx_observation\n  - meta: service\n    value: realm\n  - meta: realm_level\n    expression: evt.Parsed.realm_level\n  - meta: realm_module\n    expression: evt.Parsed.realm_module\n  - meta: realm_protocol\n    expression: evt.Parsed.realm_protocol\n'
from pathlib import Path
import yaml,json,os,subprocess
base=Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
acq={'source':'journalctl','journalctl_filter':['_SYSTEMD_UNIT=forwardx-realm-both-'+str(p)+'.service' for p in (53534,53536,53537)],'labels':{'type':'realm-forwardx'}}
files={Path('/etc/crowdsec/parsers/s01-parse/20-realm-forwardx-observation.yaml'):PARSER,Path('/etc/crowdsec/acquis.d/crowdbastion-realm-forwardx.yaml'):yaml.safe_dump(acq,sort_keys=False),Path('/etc/systemd/journald.conf.d/60-crowdbastion-storage-cap.conf'):'[Journal]\nSystemMaxUse=128M\nSystemKeepFree=512M\nRuntimeMaxUse=32M\nRuntimeKeepFree=16M\n'}
created=[]
try:
 for p,data in files.items():
  assert not p.exists();p.parent.mkdir(parents=True,exist_ok=True);p.write_text(data);p.chmod(0o644);created.append(p)
 p=subprocess.run(['crowdsec','-t'],capture_output=True,text=True,timeout=60);(base/'observation-config-test.log').write_text(p.stdout+p.stderr);assert p.returncode==0,p.stderr[-1000:]
except BaseException:
 for p in created:p.unlink(missing_ok=True)
 raise
# Journal limit does not require realm to restart. Core loads observation during install.
subprocess.run(['systemctl','restart','systemd-journald'],check=True)
print(json.dumps({'new_files':[str(p) for p in created],'config_test':0,'auto_ban_scenarios_added':0}))
