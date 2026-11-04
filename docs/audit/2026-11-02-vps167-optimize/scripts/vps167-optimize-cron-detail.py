import json,re,shlex
from pathlib import Path
lines=Path('/etc/cron.d/crowdsec-autoupdate').read_text().splitlines();r=[]
allowed={'cscli','/usr/bin/cscli','hub','update','upgrade','-a','--all','&&','systemctl','/bin/systemctl','/usr/bin/systemctl','reload','crowdsec','>/dev/null','>','/dev/null','2>&1','root'}
for line in lines:
 m=re.search(r'(?<!\S)([0-9*/,-]+(?:\s+[0-9*/,-]+){4})\s+(.*)$',line)
 if m:
  r.append({'schedule':m[1],'disabled':line.lstrip().startswith('#'),'prefix':line[:m.start()] if not re.search(r'key|token|secret|password|=',line[:m.start()],re.I) else '<redacted>','command_tokens':[x if x in allowed else '<other argument>' for x in shlex.split(m[2])]})
 else:r.append({'disabled':line.lstrip().startswith('#'),'comment':line if line.lstrip().startswith('#') and not re.search(r'key|token|secret|password|=',line,re.I) else '<not exported>'})
print(json.dumps({'cron_lines':r},ensure_ascii=False,indent=2))
