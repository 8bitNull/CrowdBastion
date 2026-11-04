import hashlib,json,os,shlex,stat,subprocess,time
from pathlib import Path


def meta(name):
    p=Path(name)
    if not p.exists() and not p.is_symlink():return {'exists':False}
    s=p.lstat();r={'exists':True,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'symlink':p.is_symlink()}
    if p.is_symlink():r['target']=os.readlink(p)
    elif p.is_file():r.update(size=s.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    return r


def run(argv,timeout=15):
    p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
    return p.returncode,p.stdout


r={'checked_at':time.time(),'protected_files':{name:meta(name) for name in PROTECTED_PATHS},'filter_rules':{},'all_table_rule_digests':{}}
for binary in ['iptables','ip6tables']:
    code,text=run([binary,'-w','5','-S']);r['filter_rules'][binary]={'exit':code,'sha256':hashlib.sha256(text.encode()).hexdigest(),'lines':len(text.splitlines())}
    code,text=run([binary+'-save']);lines=[line for line in text.splitlines() if not line.startswith('#')];r['all_table_rule_digests'][binary]={'exit':code,'canonical_sha256':hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),'lines':len(lines),'tables':[line[1:] for line in lines if line.startswith('*')],'scope':'iptables-save without counters; generation comments excluded; ipset contents excluded'}
reference=Path('/var/backups/crowdbastion/vps4-cycle-20261030/vps4-source-manifest.json')
r['original_deployment_manifest']=meta(reference);r['historical_source_matches']={}
for name,digest in json.loads(reference.read_text()).items():
    relative=Path(name)
    if relative.is_absolute() or '..' in relative.parts:raise ValueError('unsafe historical source path')
    r['historical_source_matches'][name]={root:(Path(root)/relative).is_file() and hashlib.sha256((Path(root)/relative).read_bytes()).hexdigest()==digest for root in ['/root/crowdsec-1key','/opt/crowdbastion/releases/review-20261030-vps4']}
r['v2bx_inventory']={}
code,text=run(['python3','-B','/root/crowdsec-1key/lib/crowdsec_v2bx.py','--json'])
try:r['v2bx_inventory']={'exit':code,'data':json.loads(text)}
except ValueError:r['v2bx_inventory']={'exit':code,'json_parse_error':True}
r['finished_at']=time.time()
print(json.dumps(r,ensure_ascii=False,indent=2))
