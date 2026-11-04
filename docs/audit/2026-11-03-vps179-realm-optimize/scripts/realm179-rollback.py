"""Undo only the three owned files from the VPS179 realm observation rollout.

Run with the backup path as argv[1]. Refuses external modifications. Does not
restore firewall tables, decisions, application state or ForwardX configuration.
"""
from pathlib import Path
import fcntl,hashlib,json,os,subprocess,sys
base=Path(sys.argv[1]).resolve()
assert base.parent==Path('/var/backups/crowdbastion') and base.name.startswith('vps179-realm-opt-')
lock=open('/run/lock/crowdsec-1key.lock','a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
applied=json.loads((base/'apply-result.json').read_text())
expected=applied['new_files'];owned={}
for name,digest in expected.items():
 p=Path(name)
 assert not p.is_symlink() and p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==digest,('refuse modified file',name)
 owned[p]=p.read_bytes()
removed=[];errors=[]
def run(args):
 p=subprocess.run(args,capture_output=True,text=True,timeout=55)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stderr[-1000:])
try:
 for p in owned:p.unlink();removed.append(p)
 run(['crowdsec','-t'])
 for unit in ('systemd-journald','crowdsec'):run(['systemctl','restart',unit])
 print('Removed owned realm observation and journal-cap files; ForwardX and Bouncer unchanged.')
except BaseException:
 for p in removed:
  if p.exists():errors.append('cannot restore externally recreated file '+str(p));continue
  fd=os.open(p,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644)
  with os.fdopen(fd,'wb') as out:out.write(owned[p])
 for unit in ('systemd-journald','crowdsec'):
  try:run(['systemctl','restart',unit])
  except Exception as error:errors.append(str(error))
 if errors:print(json.dumps({'restore_errors':errors}),file=sys.stderr)
 raise
