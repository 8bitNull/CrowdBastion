HELPER='#!/usr/bin/env python3\n"""Restore only VPS144\'s reviewed static rules, never a dynamic snapshot.\n\nThe nine-rule manifest is deliberately pinned. Future policy changes require\nan explicit review and helper update; unexpected JSON is rejected untouched.\n"""\nfrom contextlib import contextmanager\nimport fcntl\nimport json\nimport os\nfrom pathlib import Path\nimport signal\nimport stat\nimport subprocess\nimport sys\n\nPOLICY = Path(\'/usr/local/lib/crowdbastion-static-policy\')\nLOCK = Path(\'/run/lock/crowdsec-1key.lock\')\nSIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)\nREVIEWED = [\n    {\'binary\': \'iptables\', \'table\': table, \'rule\': rule.split()}\n    for table, rule in [\n        (\'mangle\', \'-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\'),\n        (\'mangle\', \'-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448\'),\n        (\'mangle\', \'-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu\'),\n        (\'mangle\', \'-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448\'),\n        (\'filter\', \'-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\'),\n        (\'filter\', \'-A INPUT -i lo -j ACCEPT\'),\n        (\'filter\', \'-A INPUT -p tcp -m tcp --dport 53322 -j ACCEPT\'),\n        (\'filter\', \'-A FORWARD -i lo -j ACCEPT\'),\n        (\'filter\', \'-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT\'),\n    ]\n]\n\n\ndef command(argv):\n    return subprocess.run(argv, capture_output=True, text=True, timeout=10)\n\n\ndef checked(result, argv, allowed=(0,)):\n    if result.returncode not in allowed:\n        raise RuntimeError(\'command failed: \' + repr(argv) + \': \' + str(result.stderr)[-1000:])\n    return result.returncode\n\n\ndef apply(rules, runner=command):\n    """Apply an already loaded manifest; caller holds the maintenance lock."""\n    if rules != REVIEWED:\n        raise ValueError(\'static manifest differs from the reviewed nine-rule policy\')\n    # Copy the validated values before calling any external runner.\n    commands = [([\'/usr/sbin/iptables\', \'-w\', \'5\', \'-t\', item[\'table\']], item[\'rule\'][1:])\n                for item in rules]\n    intended = []\n    previous = {number: signal.getsignal(number) for number in SIGNALS}\n    cancelled = False\n    recovering = False\n\n    def interrupted(number, frame):\n        nonlocal cancelled\n        if cancelled or recovering:\n            return\n        cancelled = True\n        raise InterruptedError(\'static policy cancelled by signal \' + str(number))\n\n    try:\n        for number in SIGNALS:\n            signal.signal(number, interrupted)\n        missing = []\n        # A late inspection failure must not leave earlier rules appended.\n        for prefix, rule in commands:\n            argv = prefix + [\'-C\'] + rule\n            if checked(runner(argv), argv, (0, 1)) == 1:\n                missing.append((prefix, rule))\n        for prefix, rule in missing:\n            # Record ownership intent first: even a timeout/cancellation can\n            # arrive after the kernel accepted the append.\n            intended.append((prefix, rule))\n            argv = prefix + [\'-A\'] + rule\n            checked(runner(argv), argv)\n        for prefix, rule in commands:\n            argv = prefix + [\'-C\'] + rule\n            checked(runner(argv), argv)\n    except BaseException as error:\n        recovering = True\n        # Further TERM/HUP/INT must not interrupt the cleanup of this attempt.\n        for number in SIGNALS:\n            signal.signal(number, signal.SIG_IGN)\n        failures = []\n        for prefix, rule in reversed(intended):\n            try:\n                argv = prefix + [\'-C\'] + rule\n                if checked(runner(argv), argv, (0, 1)) == 0:\n                    argv = prefix + [\'-D\'] + rule\n                    checked(runner(argv), argv)\n            except BaseException as cleanup_error:\n                failures.append(str(cleanup_error))\n        if failures:\n            raise RuntimeError(str(error) + \'; rollback incomplete: \' + \'; \'.join(failures)) from error\n        raise\n    finally:\n        for number, handler in previous.items():\n            signal.signal(number, handler)\n\n\ndef safe_info(info, directory=False, private=False):\n    kind = stat.S_ISDIR if directory else stat.S_ISREG\n    forbidden = 0o077 if private else 0o022\n    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & forbidden\n            or (not directory and info.st_nlink != 1)):\n        raise RuntimeError(\'unsafe root-owned static policy file or lock\')\n\n\ndef load_rules():\n    # Reject replaced/link-based policy paths before reading privileged input.\n    for parent in reversed((POLICY, *POLICY.parents)):\n        safe_info(parent.lstat(), directory=True)\n    directory = os.open(POLICY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)\n    try:\n        safe_info(os.fstat(directory), directory=True, private=True)\n        fd = os.open(\'rules.json\', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)\n        try:\n            safe_info(os.fstat(fd), private=True)\n            with os.fdopen(fd, \'r\') as stream:\n                fd = None\n                return json.load(stream)\n        finally:\n            if fd is not None:\n                os.close(fd)\n    finally:\n        os.close(directory)\n\n\n@contextmanager\ndef maintenance_lock():\n    # /run/lock is root-owned sticky 1777 on this host. Root-owned entries\n    # cannot be replaced by other users there; reject unsafe files and links.\n    parent = LOCK.parent.lstat()\n    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0\n            or (parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX)):\n        raise RuntimeError(\'unsafe maintenance lock directory\')\n    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)\n    try:\n        safe_info(os.fstat(fd))\n        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)\n        current = LOCK.lstat()\n        safe_info(current)\n        opened = os.fstat(fd)\n        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):\n            raise RuntimeError(\'maintenance lock replaced\')\n        yield\n    finally:\n        os.close(fd)\n\n\ndef main():\n    if len(sys.argv) != 1 or os.geteuid() != 0:\n        raise RuntimeError(\'root required; this helper accepts no arguments\')\n    os.umask(0o077)\n    with maintenance_lock():\n        apply(load_rules())\n\n\nif __name__ == \'__main__\':\n    try:\n        main()\n    except Exception as error:\n        print(\'Static policy failed: \' + str(error), file=sys.stderr)\n        raise SystemExit(1)\n'
UNIT_TEXT='[Unit]\nDescription=CrowdBastion static non-dynamic firewall rules\nAfter=local-fs.target\nBefore=crowdsec-firewall-bouncer.service\nStartLimitIntervalSec=0\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 -B /usr/local/lib/crowdbastion-static-policy/apply.py\nRemainAfterExit=yes\nUMask=0077\nRestart=on-failure\nRestartSec=10s\nTimeoutStartSec=600s\nTimeoutStopSec=300s\n[Install]\nWantedBy=multi-user.target\n'
EXPECTED={'/usr/local/lib/crowdbastion-static-policy/apply.py': 'c8d831620f63396109e3358186603c8e84045ba7b81af9ca82e7b3ccf0f00dd0', '/etc/systemd/system/crowdbastion-static-policy.service': 'c1b7ba54a9feb1ae5494aa5d953ce86c8d213c088d6c82d86a047d6abd99e33d'}
from pathlib import Path
import json,os,hashlib,subprocess,datetime,fcntl,runpy,shutil
base=Path('/var/backups/crowdbastion')/('vps144-static-review-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ'));base.mkdir(mode=0o700)
helper=Path('/usr/local/lib/crowdbastion-static-policy/apply.py');unit=Path('/etc/systemd/system/crowdbastion-static-policy.service')
files={helper:(HELPER.encode(),0o600),unit:(UNIT_TEXT.encode(),0o644)}
def cmd(args,t=60):
 p=subprocess.run(args,capture_output=True,text=True,timeout=t)
 if p.returncode:raise RuntimeError(str(args)+': '+p.stdout[-1000:]+p.stderr[-1000:])
 return p.stdout

def snapshot():return {name:cmd([name+'-save']) for name in ['iptables','ip6tables']}
def canonical(text):
 rows=[]
 for line in text.splitlines():
  if line.startswith('#') or line.startswith('-A CROWDSEC_CHAIN '):continue
  if line.startswith(':'):line=' '.join(line.split()[:2])
  if line:rows.append(line)
 return rows
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'backup':str(base),'new_files':{},'before_files':{},'service_restarts':['crowdbastion-static-policy'],'business_restarts':[]}
prior=snapshot();r['services_before']=cmd(['systemctl','show','forwardx-agent','forwardx-realm-both-53534','forwardx-realm-both-53536','forwardx-realm-both-53537','crowdsec','crowdsec-firewall-bouncer','systemd-journald','-p','Id','-p','MainPID','-p','ActiveState','-p','NRestarts'])
(base/'services-before.txt').write_text(r['services_before'])
for name,text in prior.items():(base/(name+'-before.txt')).write_text(text)
with open('/run/lock/crowdsec-1key.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 for p in files:
  if p.is_symlink() or hashlib.sha256(p.read_bytes()).hexdigest()!=EXPECTED[str(p)]:raise RuntimeError('source changed '+str(p))
  copy=base/(p.name+'.before');shutil.copy2(p,copy);r['before_files'][str(p)]=str(copy)
 candidate=base/'candidate';candidate.mkdir(mode=0o700)
 (candidate/'static_policy.py').write_text(HELPER);(candidate/unit.name).write_text(UNIT_TEXT)
 compile(HELPER,str(helper),'exec');functions=runpy.run_path(str(candidate/'static_policy.py'),run_name='review_only');assert functions['load_rules']()==functions['REVIEWED']
 cmd(['systemd-analyze','verify',str(candidate/unit.name)])
 for p,(data,mode) in files.items():
  tmp=p.with_name('.'+p.name+'.review-tmp');fd=os.open(tmp,os.O_CREAT|os.O_EXCL|os.O_WRONLY,mode)
  with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
  os.chmod(tmp,mode);os.replace(tmp,p);r['new_files'][str(p)]=hashlib.sha256(data).hexdigest()
 cmd(['systemctl','daemon-reload'])
# The service must acquire the same lock itself, so do not hold it here.
try:
 cmd(['systemctl','restart','crowdbastion-static-policy'],120)
 cmd(['systemctl','is-active','--quiet','crowdbastion-static-policy'])
 cmd(['systemctl','restart','crowdbastion-static-policy'],120)
 functions=runpy.run_path(str(helper),run_name='review_only');calls=[]
 def observed(argv):calls.append(argv);return subprocess.run(argv,capture_output=True,text=True,timeout=10)
 with functions['maintenance_lock']():functions['apply'](functions['load_rules'](),runner=observed)
 r['live_lookup_calls']=len(calls);r['live_mutation_calls']=[a for a in calls if '-A' in a or '-D' in a];assert not r['live_mutation_calls']
 after=snapshot();r['rule_graph_unchanged']=all(canonical(prior[name])==canonical(after[name]) for name in prior);assert r['rule_graph_unchanged']
 r['unit_status']=cmd(['systemctl','show','crowdbastion-static-policy','-p','ActiveState','-p','SubState','-p','ExecMainStatus','-p','Restart','-p','RestartUSec','-p','TimeoutStartUSec','-p','TimeoutStopUSec','-p','UnitFileState'])
 r['status']='deployed_and_verified'
except BaseException as error:
 r['status']='restored_previous';r['error']=str(error)
 subprocess.run(['systemctl','stop','crowdbastion-static-policy'],capture_output=True,timeout=300)
 with open('/run/lock/crowdsec-1key.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  for p in files:
   if hashlib.sha256(p.read_bytes()).hexdigest()==r['new_files'][str(p)]:shutil.copy2(r['before_files'][str(p)],p)
  cmd(['systemctl','daemon-reload'])
 cmd(['systemctl','start','crowdbastion-static-policy']);(base/'deploy-result.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2));raise
(base/'deploy-result.json').write_text(json.dumps(r,indent=2));print(json.dumps(r,indent=2))
