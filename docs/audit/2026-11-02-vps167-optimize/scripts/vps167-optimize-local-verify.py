from pathlib import Path
import ast,datetime,hashlib,json,re,shutil,stat,subprocess
root=Path('/projects/script/CrowdBastion-vps167-optimize');main=Path('/projects/script/CrowdBastion');folder=root/'docs/audit/2026-11-02-vps167-optimize'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name):return json.loads((folder/name).read_text())
expected_historical={'docs/audit/2026-11-02-vps45-repair/manifest.json':'168843511dbc8684649a6acd9255f1fc2410dcb6712555a4c3e978ffadc9e248','docs/audit/2026-11-02-vps45-readonly/manifest.json':'d859c967ff2c6dcaba6b84974fed86d931bc9bf8cd557c7d3c77019cd4b63c05','docs/audit/2026-11-02-vps167-readonly/manifest.json':'e9ff72d0af676fc6e6b930b9b5d14665ba0c313f0be782fb539a6e7da0f8ad9e'}
for name,digest in expected_historical.items():
 for base in [root,main]:assert sha(base/name)==digest,name
full=load('full-suite-result.json');sources=load('source-after.json');assert full['exit']==0 and full['source_unchanged'] and full['source_files']==173 and len(sources)==173
assert load('source-before.json')==sources
text=(folder/'full-suite.txt').read_text();assert re.search(r'^Ran 1440 tests in ',text,re.M) and re.search(r'^OK \(skipped=89\)',text,re.M)
for name,digest in sources.items():
 for base in [root,main]:assert sha(base/name)==digest,(str(base),name)
package=load('package.json');stage=load('stage.json');deployment=load('deployment.json');v=load('verification.json');sync=load('autonomous-sync.json');lock=load('lock-refusal.json');seal=load('remote-seal.json')
for name,digest in package['file_hashes'].items():assert sha(root/name)==digest,name
assert package['fingerprint']==stage['fingerprint']==deployment['fingerprint']
assert stage['package_files']==66 and len(stage['rules_resources'])==3 and stage['prepared']
assert deployment['protected_items_unchanged']==750 and deployment['containers_unchanged']==9 and deployment['iptables_rules_unchanged'] and not deployment['hub_update_executed']
assert v['protected_items_unchanged'] and v['original_source_preserved'] and v['original_service_identities_unchanged'] and v['containers_unchanged'] and len(v['containers'])==9
assert sum(x['health']=='healthy' for x in v['containers'].values())==4
for u,pid in [('crowdsec','1798'),('crowdsec-firewall-bouncer','2095'),('docker','708')]:
 s=v['services'][u];assert s['MainPID']==pid and s['ActiveState']=='active' and s['UnitFileState']=='enabled' and s['NRestarts']=='0'
assert all(v['rules_unchanged'].values()) and all(v['complete_package_matches'].values()) and all(v['optional_components_absent'].values())
assert v['root_crontab_unchanged'] and v['entry_sha256_matches'] and v['hub_cron_sha256_matches']
assert v['decision_membership']=={'expected':15225,'kernel':15225,'missing':0} and v['firewall_check']['exit']==0
h=v['health_document'];assert h['version']==1 and h['checks']['traffic']=='pending' and all(x=='ok' for k,x in h['checks'].items() if k!='traffic') and v['health']['exit']==2
counter=v['acquisition']['sources'][':']
assert v['acquisition']['state']=='ok' and set(counter)=={'whitelisted'} and type(counter['whitelisted']) in (int,float) and counter['whitelisted']>0
assert v['core_config_test']['exit']==v['lapi_status']['exit']==0 and not v['failed_units']['stdout'].strip()
for web in v['web_hooks'].values():assert web['nginx_exit']==0 and web['target_loaded'] and web['resource_hashes_and_mounts']=='ok' and all(all(row.values()) for row in web['phases'].values())
assert all(x['exit']==0 and x['stdout']=='200' for x in v['origin_http_checks'].values())
assert all(lock[name]['exit']==75 and 'SHOULD_NOT_RUN' not in lock[name]['stdout']+lock[name]['stderr'] for name in ['daily_cli','source_operation'])
assert sync['firewall_pull_advanced'] and sync['method'].startswith('Only cscli bouncers list;')
assert seal['stable_items_sealed']==312 and seal['stable_files_or_links']==282 and seal['stable_records_rechecked'] and seal['original_source_preserved'] and seal['private_backup_material_verified'] and not seal['active_state_restored']
assert v['rollback_check']['check_only'] and load('rollback-check-before.json')['rollback_check']['exit']==0
assert (folder/'stage-first.json').read_bytes()==b'' and "name 'true' is not defined" in (folder/'stage-first.stderr.txt').read_text()
scan=load('credential-scan.json');assert scan['distinct_credentials_checked']==5 and not scan['matched_artifacts'] and not scan['values_disclosed']
for name,digest in scan['scanned_artifacts'].items():assert sha(root/name)==digest,('changed since credential scan',name)
scripts=sorted((folder/'scripts').glob('*.py'))
for p in scripts:ast.parse(p.read_text(),filename=str(p))
python_sources=[root/name for name in sources if name.endswith('.py')]
for p in python_sources:ast.parse(p.read_text(),filename=str(p))
shell_sources=[root/name for name in sources if name.endswith('.sh')]
for p in shell_sources:subprocess.run(['bash','-n',str(p)],check=True,capture_output=True)
jsons=[p for p in folder.glob('*.json') if p.name not in ['stage-first.json','local-verification.json','manifest.json']]
for p in jsons:json.loads(p.read_text())
documents=[root/'docs/audit/2026-11-02-vps167-optimize.md',root/'docs/audit/README.md',root/'docs/superpowers/plans/2026-11-02-vps167-optimize.md',root/'docs/superpowers/specs/2026-11-02-vps167-optimize-design.md']
assert '- [ ]' not in documents[2].read_text(),'plan unfinished'
links=[];pending={folder/'local-verification.json',folder/'manifest.json'}
for doc in documents:
 for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
  if target.startswith(('http://','https://','#')):continue
  p=(doc.parent/target.split('#',1)[0]).resolve();assert p.exists() or p in pending,(doc,target);links.append(p)
for base in [root,main]:subprocess.run(['git','diff','--check'],cwd=base,check=True)
assert sha(folder/'prior-audit-index.md')==json.loads((root/'docs/audit/2026-11-02-vps167-readonly/manifest.json').read_text())['supporting_documents']['docs/audit/README.md']
for p in [folder,*folder.rglob('*')]:p.chmod(0o700 if p.is_dir() else 0o600)
for p in documents:p.chmod(0o644)
for p in [folder,*folder.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
for p in documents:
 destination=main/p.relative_to(root)
 assert sha(destination)==load('workspace-sync.json')['initial_document_hashes'][str(p.relative_to(root))],'main document changed after initial synchronization'
 destination.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,destination)
main_folder=main/folder.relative_to(root)
assert not main_folder.exists(),'new evidence destination unexpectedly exists'
shutil.copytree(folder,main_folder)
r={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'full_suite_tests':1440,'passed':1351,'skipped':89,'failed':0,'tested_sources_unchanged':173,'source_hashes_match_main':True,'python_source_ast_checked':len(python_sources),'shell_sources_bash_n_checked':len(shell_sources),'audit_scripts_ast_checked':len(scripts),'initial_json_files_checked':len(jsons),'local_links_checked':len(links),'protected_objects_unchanged':750,'containers_unchanged':9,'original_service_identities_unchanged':True,'firewall_rules_unchanged':True,'traffic':'pending','hub_schedule':'30 3 * * * Asia/Shanghai','actual_scheduled_update_observed':False,'known_remote_credentials_checked':scan['distinct_credentials_checked'],'exact_scan_artifacts':scan['artifacts_checked'],'credential_matches':0,'historical_manifests_unchanged':True,'prior_index_matches_previous_seal':True,'evidence_permissions':'directories0700 files0600','source_and_supporting_documents_synchronized_to_main':True,'independent_reviewer':False,'cold_boot_tested':False,'public_business_blocking_tested':False,'production_rollback_executed':False,'committed':False,'pushed':False}
(folder/'local-verification.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n');(folder/'local-verification.json').chmod(0o600)
manifest={'sealed_at':r['verified_at'],'files':{str(p.relative_to(folder)):sha(p) for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json'},'supporting_documents':{str(p.relative_to(root)):sha(p) for p in documents},'local_source':sources,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()}
(folder/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');(folder/'manifest.json').chmod(0o600)
for name in ['local-verification.json','manifest.json']:shutil.copy2(folder/name,main_folder/name)
for name,digest in manifest['files'].items():
 for base in [folder,main_folder]:assert sha(base/name)==digest
for name,digest in manifest['supporting_documents'].items():
 for base in [root,main]:assert sha(base/name)==digest
assert sha(main_folder/'manifest.json')==sha(folder/'manifest.json')
for p in links:assert p.exists()
for p in [main_folder,*main_folder.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
print(json.dumps(dict(r,evidence_files_sealed=len(manifest['files']),manifest_sha256=sha(folder/'manifest.json'),evidence_copy_in_main_matches=True),ensure_ascii=False,indent=2))
