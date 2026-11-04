import subprocess,json,re,os,hashlib,datetime
from pathlib import Path
base=Path('/var/backups/crowdbastion/anytls-20261103')
assert not base.exists(),'transaction already exists'
base.mkdir(parents=True,mode=0o700)
def digest(b):return hashlib.sha256(b).hexdigest()
def readkey(k):
 p=subprocess.run(['sysctl','-n',k],capture_output=True,text=True,check=True,timeout=5)
 return ' '.join(p.stdout.split())
paths=[Path('/etc/sysctl.conf'),Path('/etc/sysctl.d/99-bbr-ultimate.conf'),Path('/etc/sysctl.d/99-network-optimize.conf')]
assert Path('/etc/sysctl.d/99-sysctl.conf').resolve()==paths[0]
new=Path('/etc/sysctl.d/99-zz-crowdbastion-anytls.conf');assert not new.exists()
original={str(p):p.read_bytes() for p in paths}
keys=set()
for data in original.values():
 for line in data.decode().splitlines():
  m=re.match(r'^\s*(net\.[\w.]+)\s*=',line)
  if m:keys.add(m[1])
old={k:readkey(k) for k in sorted(keys)}
page=os.sysconf('SC_PAGE_SIZE');total=int(re.search(r'MemTotal:\s+(\d+)',Path('/proc/meminfo').read_text())[1])*1024//page
changes={'net.ipv4.tcp_syn_retries':'6','net.ipv4.tcp_synack_retries':'5','net.ipv4.tcp_orphan_retries':'0','net.ipv4.tcp_mem':f'{total//16} {total//8} {total//4}'}
assert set(changes)<=keys
settings={**old,**changes}
files=[]
for index,(name,data) in enumerate(original.items()):
 p=Path(name);backup=base/f'original-{index}'
 backup.write_bytes(data);backup.chmod(0o600)
 lines=data.decode().splitlines(keepends=True)
 out='# Network settings moved to /etc/sysctl.d/99-zz-crowdbastion-anytls.conf\n'+''.join('# consolidated: '+l if re.match(r'^\s*net\.[\w.]+\s*=',l) else l for l in lines)
 cand=base/f'candidate-{index}';cand.write_text(out);cand.chmod(0o600)
 files.append({'path':name,'before':digest(data),'backup':str(backup),'candidate':str(cand),'after':digest(out.encode()),'mode':p.stat().st_mode&0o777})
text='# CrowdBastion AnyTLS exit baseline, 2026-11-03\n# Consolidated from existing effective runtime; BBR/fq and buffer limits retained.\n# TCP memory thresholds use 1/16, 1/8, 1/4 of physical RAM in kernel pages.\n# Restore standard SYN retry tolerance; orphan_retries=0 uses kernel heuristics.\n'+'\n'.join(k+' = '+v for k,v in sorted(settings.items()))+'\n'
cand=base/'candidate-network';cand.write_text(text);cand.chmod(0o600)
files.append({'path':str(new),'before':None,'backup':None,'candidate':str(cand),'after':digest(text.encode()),'mode':0o644})
manifest={'files':files,'runtime_before':old,'settings':settings,'changes':changes,'page_size':page,'memory_pages':total,'status':'staged'}
(base/'manifest.json').write_text(json.dumps(manifest,indent=2));(base/'manifest.json').chmod(0o600)
# Check candidate definitions: exactly one active assignment per managed key.
seen={}
for f in files:
 for line in Path(f['candidate']).read_text().splitlines():
  m=re.match(r'^\s*(net\.[\w.]+)\s*=\s*(.*?)\s*$',line)
  if m:
   assert m[1] not in seen,'duplicate active network setting'
   seen[m[1]]=' '.join(m[2].split())
assert seen==settings
assert settings['net.ipv4.tcp_congestion_control']=='bbr'
assert settings['net.core.default_qdisc']=='fq'
assert settings['net.core.rmem_max']=='16777216'
# Back up existing firewall snapshots for audit only. Never restore these on production.
for binary in ['iptables-save','ip6tables-save']:
 p=subprocess.run([binary],capture_output=True,check=True,timeout=10)
 (base/binary).write_bytes(p.stdout);(base/binary).chmod(0o600)
print(json.dumps({'status':'staged','backup':str(base),'managed_keys':len(settings),'changed_runtime':{k:{'before':old[k],'after':v} for k,v in changes.items()},'candidate_unique':True,'page_size':page}))
