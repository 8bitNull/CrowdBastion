import collections,datetime,hashlib,json,os,re,stat,subprocess,time
from pathlib import Path
import yaml


def run(argv, timeout=15):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
        return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except (OSError,subprocess.TimeoutExpired) as e:
        return {'error':type(e).__name__}


def meta(name):
    p=Path(name)
    if not p.exists() and not p.is_symlink(): return {'exists':False}
    s=p.lstat();r={'exists':True,'uid':s.st_uid,'gid':s.st_gid,'mode':oct(stat.S_IMODE(s.st_mode)),'symlink':p.is_symlink()}
    if p.is_symlink():r['target']=os.readlink(p)
    elif p.is_file():r.update(size=s.st_size,sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    return r


r={'checked_at':time.time(),'protected_files':{}}
for name in ['/etc/crowdsec/config.yaml','/etc/crowdsec/config.yaml.local','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml','/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml.local','/etc/crowdsec/local_api_credentials.yaml','/etc/crowdsec/online_api_credentials.yaml','/var/spool/cron/crontabs/root','/etc/cron.d/crowdsec-autoupdate','/etc/default/netfilter-persistent','/etc/iptables/rules.v4','/etc/iptables/rules.v6','/etc/sysctl.d/99-network-optimize.conf','/etc/systemd/system/crowdsec-firewall-bouncer.service.d/20-crowdbastion-docker-order.conf','/home/docker/gost/docker-compose.yml','/home/web/nginx.conf','/etc/V2bX/config.json','/home/docker/openlist/config.json']:
    r['protected_files'][name]=meta(name)
for base,pattern in [('/home/web/conf.d','*.conf'),('/home/web/stream.d','*.conf'),('/etc/crowdsec/acquis.d','*'),('/etc/crowdsec/profiles.d','*')]:
    for p in sorted(Path(base).glob(pattern)):
        if p.is_file():r['protected_files'][str(p)]=meta(p)
p=Path('/etc/crowdsec/acquis.yaml');r['protected_files'][str(p)]=meta(p)
r['restore_services']={}
for unit in ['netfilter-persistent.service','iptables.service','ip6tables.service','nftables.service']:
    result=run(['systemctl','show',unit,'--no-pager','--property=Id,Names,FragmentPath,LoadState,ActiveState,SubState,UnitFileState,ExecStart,ExecStop,Before,After'])
    r['restore_services'][unit]={line.split('=',1)[0]:line.split('=',1)[1] for line in result.get('stdout','').splitlines() if '=' in line}
r['netfilter_defaults']={}
p=Path('/etc/default/netfilter-persistent')
if p.is_file():
    for line in p.read_text().splitlines():
        m=re.fullmatch(r'\s*(FLUSH_ON_STOP|SAVE_ON_STOP|IPTABLES_SKIP_SAVE|IP6TABLES_SKIP_SAVE|IPTABLES_RESTORE_NOFLUSH|IP6TABLES_RESTORE_NOFLUSH)\s*=\s*[\"\']?([\w-]+)[\"\']?\s*(?:#.*)?',line)
        if m:r['netfilter_defaults'][m[1]]=m[2]
r['restore_plugins']={}
for p in sorted(Path('/usr/share/netfilter-persistent/plugins.d').glob('*')):
    if not p.is_file():continue
    text=p.read_text();r['restore_plugins'][str(p)]={'metadata':meta(p),'restore_invocations':[line.strip() for line in text.splitlines() if re.search(r'\b(?:iptables|ip6tables)-restore\b',line)],'mentions_noflush':'--noflush' in text or '-n ' in text,'mentions_flush_on_stop':'FLUSH_ON_STOP' in text}
r['saved_rules']={}
for name in ['/etc/iptables/rules.v4','/etc/iptables/rules.v6']:
    p=Path(name)
    if not p.is_file():continue
    text=p.read_text();r['saved_rules'][name]={'metadata':meta(name),'lines':len(text.splitlines()),'tables':re.findall(r'^\*(\w+)',text,re.M),'crowdsec_lines':sum('crowdsec' in x.lower() for x in text.splitlines()),'docker_lines':sum('docker' in x.lower() for x in text.splitlines()),'mentions_missing_interface_candidates':sorted(set(re.findall(r'\bbr-[0-9a-f]+\b',text)))}
r['filter_rules']={};r['all_table_rule_digests']={}
for binary in ['iptables','ip6tables']:
    p=run([binary,'-w','5','-S']);text=p.get('stdout','');r['filter_rules'][binary]={'exit':p.get('exit'),'sha256':hashlib.sha256(text.encode()).hexdigest(),'lines':len(text.splitlines())}
    p=run([binary+'-save']);lines=[line for line in p.get('stdout','').splitlines() if not line.startswith('#')];r['all_table_rule_digests'][binary]={'exit':p.get('exit'),'canonical_sha256':hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),'lines':len(lines),'tables':[line[1:] for line in lines if line.startswith('*')],'scope':'iptables-save without counters; generation comments excluded; ipset contents excluded'}
r['scheduled_jobs']=[]
for p in [Path('/etc/crontab'),Path('/etc/rc.local'),*Path('/etc/cron.d').glob('*'),*Path('/var/spool/cron').rglob('*')]:
    if not p.is_file():continue
    for num,line in enumerate(p.read_text(errors='replace').splitlines(),1):
        if not re.search(r'crowdsec|crowdbastion|(?:ip6tables|iptables)-restore|\bnft\s+(?:-f|--file)',line,re.I):continue
        disabled=line.lstrip().startswith('#');text=line.lstrip('# ').strip();tokens=text.split()
        r['scheduled_jobs'].append({'path':str(p),'line':num,'disabled':disabled,'sha256':hashlib.sha256(line.encode()).hexdigest(),'schedule':tokens[:1] if tokens and tokens[0].startswith('@') else tokens[:5] if len(tokens)>=5 and all(re.fullmatch(r'[0-9*/,-]+',x) for x in tokens[:5]) else [],'options':re.findall(r'--[a-z][a-z-]+',text),'command_names':re.findall(r'\b(?:cscli|systemctl|iptables-restore|ip6tables-restore)\b',text)})
r['unit_hub_references']=[]
for base in ['/etc/systemd/system','/usr/lib/systemd/system','/lib/systemd/system']:
    for p in Path(base).glob('*'):
        if not p.is_file() or p.suffix not in ['.service','.timer']:continue
        text=p.read_text(errors='replace')
        if re.search(r'cscli\s+hub\s+(?:update|upgrade)|--update-hub',text):r['unit_hub_references'].append(str(p))
r['timer_listing']=run(['systemctl','list-timers','--all','--no-pager'])
r['acquisition_configuration']=[]
for p in [Path('/etc/crowdsec/acquis.yaml'),*Path('/etc/crowdsec/acquis.d').glob('*.yaml'),*Path('/etc/crowdsec/acquis.d').glob('*.yml')]:
    if not p.is_file():continue
    for document in yaml.safe_load_all(p.read_text()):
        entries=document if isinstance(document,list) else [document]
        for entry in entries:
            if isinstance(entry,dict):r['acquisition_configuration'].append({'path':str(p),'source':entry.get('source'),'filenames':entry.get('filenames'),'label_type':entry.get('labels',{}).get('type')})
r['parser_inventory']=run(['cscli','parsers','list','-o','json'])
if r['parser_inventory'].get('exit')==0:
    try:
        data=json.loads(r['parser_inventory']['stdout']);r['parser_inventory']={'exit':0,'data':data}
    except ValueError:r['parser_inventory']={'exit':0,'json_parse_error':True}
r['config_checks']={}
for label,argv in [('crowdsec',['crowdsec','-t','-c','/etc/crowdsec/config.yaml']),('nginx',['docker','exec','nginx','nginx','-t'])]:
    result=run(argv,30);r['config_checks'][label]={k:result[k] for k in ['exit','error'] if k in result}
r['nginx_summary']={};p=run(['docker','exec','nginx','nginx','-T']);text=p.get('stdout','')
r['nginx_summary']={'exit':p.get('exit'),'server_names':sorted(set(x for row in re.findall(r'^\s*server_name\s+([^;]+);',text,re.M) for x in row.split() if re.fullmatch(r'[a-zA-Z0-9_.-]+',x))),'real_ip_headers':sorted(set(re.findall(r'^\s*real_ip_header\s+([^;]+);',text,re.M))),'trusts_all_ipv4':bool(re.search(r'set_real_ip_from\s+0\.0\.0\.0/0\s*;',text)),'trusts_all_ipv6':bool(re.search(r'set_real_ip_from\s+::/0\s*;',text)),'access_by_lua_present':'access_by_lua' in text,'request_limit_directive_count':len(re.findall(r'\blimit_(?:req|conn)\b',text))}
r['http_checks']={}
for label,extra in [('origin',['--insecure','--resolve','site-05.example.com:443:127.0.0.1']),('public',[])]:
    r['http_checks'][label]=run(['curl','--silent','--show-error','--max-time','8','--noproxy','*',*extra,'--output','/dev/null','--write-out','%{http_code}','https://site-05.example.com/'],10)
r['failed_units']=run(['systemctl','list-units','--failed','--no-legend','--plain','--no-pager'])
r['timezone']=run(['timedatectl','show','--property=Timezone','--value'])
r['sysctl_budget_usecs']=run(['sysctl','-n','net.core.netdev_budget_usecs'])
r['conflicting_proxy_compose']={'exists':False}
p=Path('/home/docker/gost/docker-compose.yml')
if p.is_file():
    d=yaml.safe_load(p.read_text());entry=d.get('services',{}).get('gost-http',{});r['conflicting_proxy_compose']={'exists':True,'service_exists':bool(entry),'restart':entry.get('restart'),'profiles':entry.get('profiles')}
r['migration_backup']={name:meta(Path('/var/backups/crowdbastion/vps4-cycle-20261030')/name) for name in ['committed','rolled-back','before.tar.gz','vps4-source-manifest.json','migrate.py']}
r['finished_at']=time.time()
print(json.dumps(r,ensure_ascii=False,indent=2))
