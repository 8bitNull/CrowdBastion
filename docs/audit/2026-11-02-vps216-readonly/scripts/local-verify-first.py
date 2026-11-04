from pathlib import Path
import ast,datetime,hashlib,json,re,stat,subprocess
ROOT=Path('/projects/script/CrowdBastion');FOLDER=ROOT/'docs/audit/2026-11-02-vps216-readonly';REPORT=ROOT/'docs/audit/2026-11-02-vps216-readonly.md';INDEX=ROOT/'docs/audit/README.md'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(name):return json.loads((FOLDER/name).read_text())
a=load('inventory-before.json');b=load('inventory-after.json');h=load('health.json');d=load('detail.json');final=load('final.json');c=load('code-comparison.json');logs=load('log-analysis.json');sync=load('autonomous-sync.json');baseline=load('baseline.json');scan=load('credential-scan.json')
assert load('login.json')['uid']==0
assert all(c['source_roots_unchanged'].values()) and all(c['service_identities_unchanged'].values()) and c['containers_unchanged']
assert all(c['protected_paths_unchanged'].values()) and (c['protected_paths'],c['protected_existing_paths'])==(24,21)
assert c['filter_rules_unchanged'] and len(c['root_release_common_hashes_match'])==54 and all(c['root_release_common_hashes_match'].values())
assert len(final['historical_source_matches'])==56 and c['historical_56_file_manifest_all_match']
assert (len(c['local_source_hashes']),len(c['matches']),len(c['different']),len(c['missing_on_remote']))==(62,32,21,9)
for unit,pid in [('crowdsec.service','1245'),('crowdsec-firewall-bouncer.service','1306'),('docker.service','700'),('V2bX.service','661')]:
    assert a['services'][unit]['MainPID']==pid and a['services'][unit]['ActiveState']=='active' and a['services'][unit]['NRestarts']=='0' and a['services'][unit]['UnitFileState']=='enabled'
assert a['services']['systemd-sysctl.service']['ActiveState']=='active'
assert len(a['containers'])==4 and len([item for item in a['containers'] if item['state']['Running']])==3
assert all(item['health'] is None for item in a['containers'])
assert a['services']['crowdsec-v2bx-observer.service']['LoadState']=='not-found'
assert a['services']['crowdsec-1key-bot.service']['LoadState']=='not-found' and a['services']['crowdbastion-notify.service']['LoadState']=='not-found'
assert h['decision_membership']=={'expected':15296,'kernel':15296,'missing':0,'state':'ok'}
assert h['latest_readonly_firewall_audit']['exit']==1 and 'netfilter-persistent.service' in h['latest_readonly_firewall_audit']['output']
assert h['lapi_status']['exit']==0 and h['acquisition']['state']=='fault' and not h['web_registry_present']
assert h['acquisition']['sources']['file:/var/log/syslog']=={'reads':18294,'unparsed':18294}
assert h['existing_manager_status']['exit']==2 and h['existing_node_diagnosis']['exit']==2
assert d['restore_services']['netfilter-persistent.service']['UnitFileState']=='enabled'
assert all(d['restore_services'][name]['Id']=='netfilter-persistent.service' for name in ['netfilter-persistent.service','iptables.service','ip6tables.service'])
assert d['saved_rules']['/etc/iptables/rules.v4']['crowdsec_lines']==0 and d['saved_rules']['/etc/iptables/rules.v6']['metadata']['size']==0
assert len(d['scheduled_jobs'])==1 and d['scheduled_jobs'][0]['disabled'] and not d['unit_hub_references']
assert all(item['exit']==0 for item in d['config_checks'].values()) and d['failed_units']['stdout']==''
assert all(item['exit']==0 and item['stdout']=='200' for item in d['http_checks'].values())
assert d['sysctl_budget_usecs']['stdout'].strip()=='8000' and d['timezone']['stdout'].strip()=='America/Los_Angeles'
assert d['conflicting_proxy_compose']['restart']=='no' and 'disabled-port-conflict' in d['conflicting_proxy_compose']['profiles']
assert sync['firewall_pull_advanced'] and sync['method'].startswith('Only cscli bouncers list;')
assert logs['error_breakdown']['/var/log/crowdsec.log']['errors_last_24h']==3
assert logs['error_breakdown']['/var/log/crowdsec.log']['recent_classes']=={'other':1,'console_not_enrolled':2}
assert logs['error_breakdown']['/var/log/crowdsec-firewall-bouncer.log']['recent_classes']=={'timeout':1}
assert logs['v2bx_journal']['records']==2000 and logs['v2bx_journal']['error_like_records']==0
assert final['v2bx_inventory']['exit']==2 and final['v2bx_inventory']['data']['end_to_end_status']=='unverified'
assert (FOLDER/'health-initial.stdout.txt').stat().st_size==0 and 'not responding' in (FOLDER/'health-initial.stderr.txt').read_text()
assert (FOLDER/'rules-normalization-failure.stdout.txt').stat().st_size==0
scan_completed=scan.get('status')!='not_completed'
if scan_completed:
    assert scan['distinct_credentials_checked']>0 and not scan['matched_artifacts'] and not scan['values_disclosed']
    assert all(not item.get('exists') or item.get('parsed') for item in scan['source_summary'].values())
    for name,digest in scan['scanned_artifacts'].items():assert sha(ROOT/name)==digest,('changed since credential scan',name)
else:
    assert scan['reason'] and scan['source_values_compared'] is False
for name,digest in c['local_source_hashes'].items():assert sha(ROOT/name)==digest
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()==baseline['head']==c['local_head']
for name,digest in baseline['historical_manifests'].items():assert sha(ROOT/name)==digest
assert sha(FOLDER/'prior-audit-index.md')==baseline['prior_index_sha256']
scripts=list((FOLDER/'scripts').glob('*.py'))
for p in scripts:ast.parse(p.read_text(),filename=str(p))
modules=load('in-memory-modules.json')
for name,info in modules.items():assert sha(ROOT/'lib'/str(name+'.py'))==info['sha256'];ast.parse((ROOT/'lib'/str(name+'.py')).read_text())
embedded=ast.parse(Path('/tmp/vps216-readonly-health.py').read_text())
assert ast.dump(ast.Module(body=embedded.body[1:],type_ignores=[]))==ast.dump(ast.parse((FOLDER/'scripts/health-template.py').read_text()))
for name,text in ast.literal_eval(embedded.body[0].value).items():assert hashlib.sha256(text.encode()).hexdigest()==modules[name]['sha256']
jsons=list(FOLDER.glob('*.json'))
for p in jsons:json.loads(p.read_text())
links=[];pending={FOLDER/'verification.json',FOLDER/'manifest.json'}
for doc in [REPORT,INDEX]:
    for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
        if target.startswith(('http://','https://','#')):continue
        p=(doc.parent/target.split('#',1)[0]).resolve();assert p.exists() or p in pending,(doc,target);links.append(p)
subprocess.run(['git','diff','--check'],cwd=ROOT,check=True)
for p in [FOLDER,*FOLDER.rglob('*')]:p.chmod(0o700 if p.is_dir() else 0o600)
for p in [REPORT,INDEX]:p.chmod(0o644)
for p in [FOLDER,*FOLDER.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
r={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scripts_ast_checked':len(scripts),'in_memory_modules_ast_hash_and_payload_checked':len(modules),'json_files_checked_before_seal':len(jsons),'local_links_checked':len(links),'local_source_hashes_checked':len(c['local_source_hashes']),'source_roots_unchanged':6,'service_records_unchanged':9,'containers_unchanged':4,'protected_paths_unchanged':24,'protected_existing_paths':21,'original_deployed_files_or_aliases_matched_per_copy':56,'filter_rules_unchanged':True,'initial_all_table_digest_includes_policy_counters':True,'extra_all_table_normalization_completed':False,'credential_scan_completed':scan_completed,'known_values_checked':scan.get('distinct_credentials_checked'),'credential_scan_artifacts':scan.get('artifacts_checked'),'credential_matches':len(scan.get('matched_artifacts',[])) if scan_completed else None,'historical_manifests_unchanged':len(baseline['historical_manifests']),'prior_index_snapshot_matches':True,'evidence_permissions':'directories 0700; files 0600','git_diff_check':'passed','product_code_modified':False,'production_configuration_changes':False,'service_actions_performed':False,'normal_queries_may_change_logs_counters_and_api_metadata':True,'full_suite_rerun':False,'independent_reviewer':False,'cold_boot_tested':False,'public_business_blocking_tested':False,'ssh_intermittent_timeout_cause_established':False}
p=FOLDER/'verification.json';assert not p.exists();p.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
manifest={'sealed_at':r['verified_at'],'files':{str(p.relative_to(FOLDER)):sha(p) for p in sorted(FOLDER.rglob('*')) if p.is_file() and p.name!='manifest.json'},'supporting_documents':{str(p.relative_to(ROOT)):sha(p) for p in [REPORT,INDEX]},'local_source':c['local_source_hashes'],'head':c['local_head']}
p=FOLDER/'manifest.json';assert not p.exists();p.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
for name,digest in manifest['files'].items():assert sha(FOLDER/name)==digest
for name,digest in manifest['supporting_documents'].items():assert sha(ROOT/name)==digest
assert all(p.exists() for p in links)
print(json.dumps(dict(r,evidence_files_sealed=len(manifest['files']),manifest_sha256=sha(p)),ensure_ascii=False,indent=2))
