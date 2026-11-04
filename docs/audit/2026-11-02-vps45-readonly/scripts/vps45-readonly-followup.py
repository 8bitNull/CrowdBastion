EVIDENCE_SOURCE = '"""Read-only Bouncer decision snapshots and referenced ipset coverage."""\nfrom bisect import bisect_right\nimport ipaddress\nimport json\nfrom pathlib import Path\nimport re\nimport shlex\nimport subprocess\nimport time\nimport urllib.request\n\nimport yaml\nfrom crowdsec_config import merged_config\n\n\nclass EvidenceError(ValueError):\n    """Only fixed diagnostics may cross the credential-reading boundary."""\n\n\nclass NoRedirect(urllib.request.HTTPRedirectHandler):\n    def redirect_request(self, *args, **kwargs):\n        raise EvidenceError(\'决策检查拒绝重定向。\')\n\n\ndef seconds(value):\n    if not isinstance(value, str):\n        raise EvidenceError(\'决策时长格式无效。\')\n    if value.startswith(\'-\'):\n        return 0\n    parts = re.findall(r\'(\\d+(?:\\.\\d+)?)(ns|us|µs|ms|h|m|s)\', value)\n    if not parts or \'\'.join(n+u for n, u in parts) != value:\n        raise EvidenceError(\'决策时长格式无效。\')\n    scale = {\'h\': 3600, \'m\': 60, \'s\': 1, \'ms\': .001, \'us\': .000001, \'µs\': .000001, \'ns\': 1e-9}\n    return sum(float(n)*scale[u] for n, u in parts)\n\n\ndef networks(rows, minleft=15):\n    result = set()\n    for row in rows:\n        if not isinstance(row, dict):\n            raise EvidenceError(\'决策记录格式无效。\')\n        if row.get(\'type\') == \'ban\' and str(row.get(\'scope\', \'\')).lower() in (\'ip\', \'range\') and seconds(row.get(\'duration\', \'0s\')) > minleft:\n            result.add(ipaddress.ip_network(row[\'value\'], strict=False))\n    return result\n\n\ndef live(config):\n    try:\n        data = merged_config(config)\n        for field in (\'origins\', \'scopes\', \'scenarios_containing\', \'scenarios_not_containing\'):\n            if data.get(field):\n                raise EvidenceError(\'存在自定义决策过滤，自动入核比对尚未支持。\')\n        if data.get(\'supported_decisions_types\', [\'ban\']) != [\'ban\']:\n            raise EvidenceError(\'自定义决策类型尚未支持自动比对。\')\n        url, key = data[\'api_url\'], data[\'api_key\']\n        from crowdsec_remote_bouncer import validate\n        url = validate(url, key)\n        if data.get(\'insecure_skip_verify\') or any(data.get(k) for k in (\'cert_path\', \'key_path\', \'ca_cert_path\')):\n            raise EvidenceError(\'自定义 TLS 认证尚未支持自动决策检查。\')\n        request = urllib.request.Request(url+\'v1/decisions\', headers={\'X-Api-Key\': key})\n        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())\n        with opener.open(request, timeout=10) as response:\n            payload = response.read(32*1024*1024+1)\n        if len(payload) > 32*1024*1024:\n            raise EvidenceError(\'决策响应超过检查容量。\')\n        rows = json.loads(payload)\n        if rows is None:\n            rows = []\n        if not isinstance(rows, list):\n            raise EvidenceError(\'决策响应格式无效。\')\n        networks(rows, 0)\n        return rows\n    except EvidenceError:\n        raise\n    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):\n        raise EvidenceError(\'无法读取有效决策（配置、认证、TLS 或连接错误）；未输出凭据。\') from None\n\n\ndef membership(expected, references, payload):\n    created, actual = {}, {4: set(), 6: set()}\n    for line in payload.splitlines():\n        words = shlex.split(line)\n        if len(words) >= 3 and words[0] == \'create\':\n            if \'family\' not in words:\n                continue\n            family = words[words.index(\'family\')+1]\n            created[words[1]] = 4 if family == \'inet\' else 6 if family == \'inet6\' else None\n    for version, names in references.items():\n        for name in names:\n            if created.get(name) != version:\n                raise EvidenceError(\'实际引用的集合不存在或地址族不匹配。\')\n    for line in payload.splitlines():\n        words = shlex.split(line)\n        if len(words) >= 3 and words[0] == \'add\':\n            for version, names in references.items():\n                if words[1] in names:\n                    if \'nomatch\' in words[3:]:\n                        raise EvidenceError(\'引用集合存在排除项，无法证明完整封禁。\')\n                    net = ipaddress.ip_network(words[2], strict=False)\n                    if net.version != version:\n                        raise EvidenceError(\'集合成员地址族不匹配。\')\n                    actual[version].add(net)\n    missing = 0\n    for version in (4, 6):\n        collapsed = list(ipaddress.collapse_addresses(actual[version]))\n        starts = [int(net.network_address) for net in collapsed]\n        for net in (n for n in expected if n.version == version):\n            index = bisect_right(starts, int(net.network_address))-1\n            if index < 0 or not net.subnet_of(collapsed[index]):\n                missing += 1\n    return {\'expected\': len(expected), \'kernel\': sum(map(len, actual.values())), \'missing\': missing}\n\n\ndef inspect(config, docker=None):\n    from crowdsec_firewall_runtime import iptables_references, docker_present, run, PathCoverageError\n    try:\n        data = merged_config(config)\n        if data.get(\'mode\') != \'iptables\':\n            return {\'state\': \'unknown\', \'reason\': \'当前后端尚未支持此入核检查。\'}\n        refs = iptables_references(config, docker_present() if docker is None else docker)\n        rows = live(config)\n        expected = networks(rows)\n        # Read expected decisions before the kernel, allowing normal sync to\n        # catch up. Near-expiry decisions are excluded from this snapshot.\n        report = membership(expected, refs, run([\'ipset\', \'save\']).stdout)\n        report[\'state\'] = \'pending\' if report[\'missing\'] else \'ok\'\n        return report\n    except PathCoverageError:\n        return {\'state\': \'fault\', \'reason\': \'防火墙执行入口或引用规则不完整。\'}\n    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError, subprocess.SubprocessError):\n        return {\'state\': \'unknown\', \'reason\': \'无法完整核对适用决策及实际引用的内核集合；请查看配置和连接状态。\'}\n\n\ndef wait(config, seconds=30, docker=None):\n    deadline = time.monotonic()+seconds\n    while True:\n        report = inspect(config, docker)\n        if report[\'state\'] == \'ok\':\n            return report\n        if report[\'state\'] == \'unknown\' or time.monotonic() >= deadline:\n            if report[\'state\'] == \'pending\':\n                report = {**report, \'state\': \'fault\'}\n            return report\n        time.sleep(2)\n\n\ndef render(report):\n    from crowdbastion_health import emit\n    state = report[\'state\']\n    emit(\'decisions\', \'required\')\n    emit(\'decisions\', state)\n    label = {\'ok\': \'[已检查]\', \'fault\': \'[异常]\', \'pending\': \'[等待同步]\', \'unknown\': \'[尚未验证]\'}[state]\n    if \'missing\' in report:\n        print(f"{label} 决策入核：适用网络 {report[\'expected\']}，实际集合网络 {report[\'kernel\']}，遗漏 {report[\'missing\']}。")\n    else:\n        print(label+\' 决策入核：\'+report[\'reason\'])\n    return 0 if state == \'ok\' else 1 if state == \'fault\' else 2\n\n\nif __name__ == \'__main__\':\n    import argparse\n    parser = argparse.ArgumentParser(description=__doc__)\n    parser.add_argument(\'config\', type=Path)\n    parser.add_argument(\'--wait\', type=int, default=0, choices=range(0, 61))\n    args = parser.parse_args()\n    raise SystemExit(render(wait(args.config, args.wait) if args.wait else inspect(args.config)))'
import contextlib,hashlib,importlib.util,io,json,os,re,shlex,subprocess,sys,time
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_config,crowdsec_web

def run(argv,timeout=15):
    try:
        p=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,env=dict(os.environ,LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'))
        return {'exit':p.returncode,'stdout':p.stdout,'stderr':p.stderr}
    except (OSError,subprocess.TimeoutExpired) as e:return {'error':type(e).__name__}
def meta(path):
    p=Path(path)
    if not p.is_file():return {'exists':False}
    st=p.stat();return {'exists':True,'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'size':st.st_size,'uid':st.st_uid,'mode':oct(st.st_mode&0o7777)}
def registry():
    result=run(['cscli','bouncers','list','-o','json'])
    return [{'name':v.get('name'),'last_pull':v.get('last_pull'),'type':v.get('type'),'version':v.get('version')} for v in json.loads(result['stdout'])]
report={'checked_at':time.time(),'registry_before':registry()}
report['restore_crons']=[]
for p in [Path('/etc/crontab'),Path('/etc/rc.local'),*Path('/etc/cron.d').glob('*'),*Path('/var/spool/cron').rglob('*')]:
    if not p.is_file():continue
    for number,line in enumerate(p.read_text(errors='replace').splitlines(),1):
        if not line.lstrip().startswith('#') and re.search(r'\b(?:ip6tables|iptables)-restore\b|\bnft\s+(?:-f|--file)\b',line):
            report['restore_crons'].append({'path':str(p),'line':number,'line_sha256':hashlib.sha256(line.encode()).hexdigest(),'schedule':line.split()[:1] if line.lstrip().startswith('@') else line.split()[:5],'delay_seconds':re.findall(r'\bsleep\s+(\d+)',line),'commands':re.findall(r'\b(?:ip6tables|iptables)-restore\b',line),'absolute_paths':re.findall(r'(?<!\w)/(?:[A-Za-z0-9_.-]+/)*[A-Za-z0-9_.-]+',line)})
report['saved_rule_files']={}
for row in report['restore_crons']:
    for path in row['absolute_paths']:
        if Path(path).is_file() and path not in report['saved_rule_files']:
            text=Path(path).read_text(errors='replace')
            report['saved_rule_files'][path]={'metadata':meta(path),'lines':len(text.splitlines()),'crowdsec_lines':sum('crowdsec' in s.lower() for s in text.splitlines()),'docker_lines':sum('docker' in s.lower() for s in text.splitlines()),'tables':re.findall(r'^\*(\w+)$',text,re.M),'policies':re.findall(r'^:(INPUT|FORWARD|OUTPUT) (ACCEPT|DROP)',text,re.M)}
base=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml');config=crowdsec_config.merged_config(base)
report['filter_rules']={};references={};paths={}
for binary,family in [('iptables',4),('ip6tables',6)]:
    result=run([binary,'-w','5','-S']);lines=[shlex.split(s) for s in result['stdout'].splitlines()]
    report['filter_rules'][str(family)]=result
    chain=config.get('iptables_chain','CROWDSEC_CHAIN')
    first={entry:next((t for t in lines if t[:2]==['-A',entry]),None) for entry in ['INPUT','FORWARD','DOCKER-USER']}
    direct={entry:t==['-A',entry,'-j',chain] for entry,t in first.items()}
    indirect=first['FORWARD']==['-A','FORWARD','-j','DOCKER-USER'] and direct['DOCKER-USER']
    drop_rules=[]
    for tokens in lines:
        if tokens[:2]!=['-A',chain]:continue
        norm=[];i=0
        while i<len(tokens):
            if tokens[i:i+3]==['-m','comment','--comment']:i+=4
            else:norm.append(tokens[i]);i+=1
        drop_rules.append(norm)
    names=config.get('blacklists_ipv4' if family==4 else 'blacklists_ipv6','crowdsec-blacklists' if family==4 else 'crowdsec6-blacklists')
    names=[names] if isinstance(names,str) else names
    drops_valid=bool(drop_rules) and all(len(t)==9 and t[2:5]==['-m','set','--match-set'] and t[6:]==['src','-j','DROP'] and any(re.fullmatch(re.escape(n)+r'(?:-\d+)?',t[5]) for n in names) for t in drop_rules)
    references[family]={t[5] for t in drop_rules} if drops_valid else set()
    paths[str(family)]={'first_rules':first,'direct_first':direct,'forward_unconditional_via_docker_user':indirect,'all_crowdsec_rules_unconditional_source_drop':drops_valid,'sets':sorted(references[family]),'all_required_paths_reach_crowdsec_before_other_rules':direct['INPUT'] and direct['DOCKER-USER'] and (direct['FORWARD'] or indirect) and drops_valid}
report['static_path_analysis']=paths
# Load the reviewed read-only decision helper into memory, without installing it.
import types
m=types.ModuleType('vps45_readonly_membership');m.__file__='<stdin-readonly-membership>'
exec(compile(EVIDENCE_SOURCE,m.__file__,'exec'),m.__dict__)
if all(v['all_required_paths_reach_crowdsec_before_other_rules'] for v in paths.values()):
    rows=m.live(base);expected=m.networks(rows)
    report['decision_membership_independent']=m.membership(expected,references,run(['ipset','save'])['stdout'])
else:report['decision_membership_independent']={'state':'unconfirmed_paths'}
report['bouncer_binary_version']=run(['/usr/bin/crowdsec-firewall-bouncer','-version'])
report['core_configuration_check']={k:v for k,v in run(['crowdsec','-t','-c','/etc/crowdsec/config.yaml'],timeout=25).items() if k in ['exit','error']}
report['nginx_configuration_check']=run(['docker','exec','openresty','nginx','-t'])
report['acquisition_configs']={}
import yaml
for p in [Path('/etc/crowdsec/acquis.yaml'),*sorted(Path('/etc/crowdsec/acquis.d').glob('*.yaml'))]:
    if p.is_file():
        report['acquisition_configs'][str(p)]=[{'source':v.get('source'),'filenames':v.get('filenames'),'labels':{k:v.get('labels',{}).get(k) for k in ['type','service'] if k in v.get('labels',{})}} for v in yaml.safe_load_all(p.read_text()) if isinstance(v,dict)]
report['unparsed_log_classes']={}
for path in ['/var/log/kern.log','/var/log/syslog','/opt/1panel/apps/openresty/openresty/log/error.log']:
    p=Path(path)
    if not p.is_file():continue
    with p.open('rb') as f:
        f.seek(max(0,p.stat().st_size-65536));lines=f.read().decode(errors='replace').splitlines()[-100:]
    report['unparsed_log_classes'][path]={'sample_lines':len(lines),'levels':{k:sum(bool(re.search(r'\['+k+r'\]',s)) for s in lines) for k in ['emerg','alert','crit','error','warn','notice','info']},'classes':{k:sum(bool(re.search(pattern,s,re.I)) for s in lines) for k,pattern in [('ufw',r'\[UFW '),('kernel_routine',r'kernel:'),('systemd',r'systemd\['),('crowdsec_bouncer',r'crowdsec|bouncer'),('template',r'template.*(?:not found|missing|No such file)|No such file.*template'),('recaptcha',r'recaptcha'),('reload_evidence',r'CB_EXEC_V1'),('upstream',r'upstream.*(?:timed out|refused|no live)'),('traceback',r'Traceback')]} }
report['container_health']={}
for row in json.loads(run(['docker','inspect',*run(['docker','ps','-q'])['stdout'].split()])['stdout']):
    state=row['State'];health=state.get('Health',{})
    report['container_health'][row['Name'].lstrip('/') ]={'status':state.get('Status'),'health':health.get('Status'),'failing_streak':health.get('FailingStreak'),'started_at':state.get('StartedAt'),'restart_count':row.get('RestartCount')}
report['core_log_file_errors_24h']={}
for p in [Path('/var/log/crowdsec.log'),Path('/var/log/crowdsec-firewall-bouncer.log')]:
    if p.is_file():
        with p.open('rb') as f:
            f.seek(max(0,p.stat().st_size-256*1024));text=f.read().decode(errors='replace')
        lines=text.splitlines();report['core_log_file_errors_24h'][str(p)]={'scope':'last_256KiB_not_guaranteed_24h','sample_lines':len(lines),'error_or_fatal_lines':sum(bool(re.search(r'level=(?:error|fatal)|\[(?:ERROR|FATAL)\]',s)) for s in lines)}
report['final_services']={}
for unit in ['crowdsec','crowdsec-firewall-bouncer','docker']:
    r=run(['systemctl','show',unit,'--no-pager','--property=MainPID,NRestarts,ActiveState,ExecMainStartTimestamp,UnitFileState'])
    report['final_services'][unit]=dict(s.split('=',1) for s in r['stdout'].splitlines() if '=' in s)
# Listing registry records does not refresh the clients' last_pull timestamps.
start=time.monotonic()
while True:
    after=registry();before={r['name']:r.get('last_pull') for r in report['registry_before']}
    firewall=[r for r in after if r.get('type')=='crowdsec-firewall-bouncer']
    if firewall and any(r.get('last_pull')!=before.get(r['name']) for r in firewall):break
    if time.monotonic()-start>=15:break
    time.sleep(2)
report['registry_after']=after;report['registry_observation_seconds']=round(time.monotonic()-start,3)
report['finished_at']=time.time()
print(json.dumps(report,ensure_ascii=False,indent=2))
