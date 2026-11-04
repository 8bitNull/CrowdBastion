from pathlib import Path
import ast,datetime,hashlib,json,os,re,stat,subprocess
root=Path('/projects/script/CrowdBastion');folder=root/'docs/audit/2026-11-02-vps45-repair';worktree=Path('/projects/script/CrowdBastion-vps45-repair');docs=[root/'docs/audit/2026-11-02-vps45-repair.md',root/'docs/audit/README.md',root/'docs/superpowers/plans/2026-11-02-vps45-repair.md']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(name):return json.loads((folder/name).read_text())
expected=load('source-after.json');assert expected==load('source-before.json')
for name,digest in expected.items():assert sha(root/name)==digest,name
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()=='ce8e8677a18bfe7df6ef5262c0139935afadb57f'
assert load('full-suite-result.json')['exit']==0 and load('full-suite-result.json')['source_unchanged']
log=(folder/'full-suite.txt').read_text();assert 'Ran 1433 tests' in log and 'OK (skipped=89)' in log
r=load('verification.json');p=load('preflight.json');d=load('detail.json')
before={u:dict(line.split('=',1) for line in text.splitlines() if '=' in line) for u,text in p['units'].items()}
assert all(r['services'][u]['MainPID']==before[u]['MainPID'] for u in before)
assert sorted(r['containers'],key=lambda x:x['id'])==sorted(d['containers'],key=lambda x:x['id'])
assert len(r['containers'])==10 and len([x for x in r['containers'] if x['health']=='healthy'])==7
assert r['protected_files_unchanged'] and r['protected_files']==699
assert r['core_config_test']['exit']==0 and r['lapi_status']['exit']==0 and r['firewall_check']['exit']==0
assert '16687' in r['firewall_check']['stdout'] and '遗漏 0' in r['firewall_check']['stdout']
h=json.loads(r['health']['stdout']);assert h['checks']['traffic']=='pending' and all(v=='ok' for k,v in h['checks'].items() if k!='traffic');assert r['health']['exit']==2 and h['summary']['status']==2
assert all(x['exit']==0 and x['stdout']=='200' for x in r['origin_http_checks'].values())
for web in r['web_hooks'].values():
 assert web['nginx_exit']==0 and web['target_loaded'] and web['resource_hashes_and_mounts']=='ok'
 assert all(all(x.values()) for x in web['phases'].values())
assert load('autonomous-sync.json')['firewall_pull_advanced']
assert load('static-restart.json')['rules_unchanged'] and load('static-restart.json')['existing_units_unchanged']
isolated=load('isolated-static.json');assert isolated['unit_verify']['exit']==0 and isolated['isolated_network_namespace']['exit']==0
assert load('remote-seal.json')['all_stable_hashes_verified'] and load('remote-seal.json')['original_source_permissions_and_content_preserved']
resources=load('resources-completion.json');assert resources['root_existing_resources_unchanged'] and resources['fingerprint_unchanged'] and len(resources['files_created'])==6
assert not resources['optional_component_enabled'] and not resources['services_restarted']
for name,digest in resources['resources'].items():assert sha(root/name)==digest
scan=load('credential-scan.json');assert scan['matched_artifacts']=={} and scan['distinct_credentials_checked']>=5 and not scan['values_disclosed']
for name,digest in scan['scanned_artifacts'].items():assert sha(root/name)==digest,('changed after exact credential scan',name)
assert len([s for s in r['root_crontab']['stdout'].splitlines() if s.startswith('# CrowdBastion disabled: @reboot ')])==2
assert r['backend']['mode']=='iptables' and r['backend']['update_frequency']=='10s'
assert all(r['optional_components_absent'].values())
assert len(set(r['source_fingerprints'].values()))==1 and next(iter(r['source_fingerprints'].values()))==load('stage.json')['fingerprint']
ast_paths=[*sorted((root/'lib').glob('*.py')),*sorted((root/'tests').glob('*.py')),*sorted((folder/'scripts').glob('*.py'))]
for p in ast_paths:ast.parse(p.read_text(),filename=str(p))
bash_paths=[root/'crowdbastion.sh',root/'install-crowdsec-1panel.sh',*sorted((root/'lib').glob('*.sh'))]
for p in bash_paths:subprocess.run(['bash','-n',str(p)],check=True)
subprocess.run(['git','diff','--check'],cwd=root,check=True)
links=[];pending={folder/'manifest.json',folder/'local-verification.json'}
for doc in docs:
 for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
  target=target.strip().strip('<>')
  if re.match(r'\w+://',target) or target.startswith('#'):continue
  target=target.split('#',1)[0];p=(doc.parent/target).resolve();assert p.exists() or p in pending,(str(doc),target);links.append(p)
for p in [folder,*folder.rglob('*')]:p.chmod(0o700 if p.is_dir() else 0o600)
for p in docs:p.chmod(0o644)
for p in [folder,*folder.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
json_count=0
for p in folder.glob('*.json'):
 if p in pending or p.name=='remote-seal-first.json':continue
 json.loads(p.read_text());json_count+=1
for name in ['lib/crowdsec_firewall_runtime.py','tests/test_firewall_runtime.py','tests/test_vps45_static_policy.py','docs/audit/2026-11-02-vps45-repair.md','docs/superpowers/plans/2026-11-02-vps45-repair.md']:
 assert sha(root/name)==sha(worktree/name)
result={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'source_hashes_verified':len(expected),'ast_files':len(ast_paths),'bash_checks':len(bash_paths),'unique_bash_files':len({p.resolve() for p in bash_paths}),'initial_json_files':json_count,'local_links':len(links),'remote_verification_assertions':'passed','git_diff_check':'passed','local_permissions':'passed','worktree_matches_main_workspace':True,'full_suite':{'total':1433,'passed':1344,'skipped':89,'failed':0},'product_changes':['lib/crowdsec_firewall_runtime.py'],'production_changes':['independent static INPUT policy','two restore crons commented','manager daily and maintenance copies updated'],'daemon_restarts':[],'cold_boot_tested':False,'public_business_blocking_tested':False,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()}
(folder/'local-verification.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n');(folder/'local-verification.json').chmod(0o600)
files={str(p.relative_to(folder)):sha(p) for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json'}
manifest={'sealed_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'files':files,'supporting_documents':{str(p.relative_to(root)):sha(p) for p in docs},'source':expected,'head':result['head']}
(folder/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n');(folder/'manifest.json').chmod(0o600)
for name,digest in manifest['files'].items():assert sha(folder/name)==digest
for name,digest in manifest['supporting_documents'].items():assert sha(root/name)==digest
for p in links:assert p.exists()
print(json.dumps({**result,'evidence_files':len(files),'manifest_sha256':sha(folder/'manifest.json')},ensure_ascii=False,indent=2))
