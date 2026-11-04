from pathlib import Path
import ast,datetime,hashlib,json,re,stat,subprocess
root=Path('/projects/script/CrowdBastion');folder=root/'docs/audit/2026-11-02-vps167-readonly';report=root/'docs/audit/2026-11-02-vps167-readonly.md';index=root/'docs/audit/README.md'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def load(n):return json.loads((folder/n).read_text())
a=load('inventory.json');b=load('inventory-after.json');h=load('health.json');d=load('detail.json');c=load('code-comparison.json');logs=load('log-analysis.json');sync=load('autonomous-sync.json');scan=load('credential-scan.json')
assert load('login.json')['uid']==0 and load('login.json')['manager_exists']
assert all(c['source_unchanged_during_inspection'].values()) and all(c['service_identity_unchanged'].values()) and c['containers_unchanged']
assert all(c['protected_config_hashes_unchanged'].values()) and len(c['protected_config_hashes_unchanged'])==9
assert len(c['root_release_common_hashes_match'])==53 and all(c['root_release_common_hashes_match'].values())
assert (len(c['local_source_hashes']),len(c['matches']),len(c['different']),len(c['missing_on_remote']))==(62,32,21,9)
assert not a['manager_flags']['--status-json'] and not a['source_roots']['/usr/local/lib/crowdsec-1key/current']['metadata']['exists']
assert len(a['containers'])==9 and all(x['state']['Running'] for x in a['containers'])
assert len([x for x in a['containers'] if x.get('health')=='healthy'])==4
assert all(x.get('health') in [None,'healthy'] for x in a['containers'])
for u,pid in [('crowdsec.service','1798'),('crowdsec-firewall-bouncer.service','2095'),('docker.service','708')]:
 assert a['services'][u]['MainPID']==pid and a['services'][u]['ActiveState']=='active' and a['services'][u]['NRestarts']=='0' and a['services'][u]['UnitFileState']=='enabled'
assert h['decision_membership']=={'expected':15225,'kernel':15225,'missing':0,'state':'ok'}
assert h['latest_readonly_firewall_audit']['exit']==0 and h['effective_firewall']['mode']=='iptables' and h['effective_firewall']['update_frequency']=='10s'
assert h['lapi_status']['exit']==0 and h['existing_manager_status']['exit']==2
assert d['core_config_check']['exit']==0 and d['nginx_config_check']['exit']==0 and d['failed_units']['stdout']==''
assert not d['restore_crons']
restore_rows=[x for x in d['cron_entries'] if x['commands'] and any(v in ['iptables-restore','ip6tables-restore'] for v in x['commands'])];assert len(restore_rows)==2 and all(x['disabled'] for x in restore_rows)
hub_rows=[x for x in d['cron_entries'] if x['path']=='/etc/cron.d/crowdsec-autoupdate' and 'cscli' in x['commands']];assert hub_rows and all(x['disabled'] for x in hub_rows)
assert all(x['exit']==0 and x['stdout']=='200' for x in d['origin_http_checks'].values())
for web in d['web_hooks'].values():
 assert web['nginx_T_exit']==0 and web['resource_hashes_and_mounts']=='ok' and web['target_in_effective_configuration']
 assert all(all(p.values()) for p in web['phases'].values())
 assert ['error_log','/var/log/nginx/error.log','notice'] in web['error_log_directives']
assert sync['firewall_pull_advanced'] and sync['method'].startswith('Only cscli bouncers list;')
core=logs['error_breakdown']['/var/log/crowdsec.log'];bouncer=logs['error_breakdown']['/var/log/crowdsec-firewall-bouncer.log']
assert core['message_counts']=={'Failed to process request body':75} and core['recent_classes']=={'appsec_xml_body':72,'appsec_other_body':2}
assert bouncer['recent_classes']=={'chain_cleanup':20} and bouncer['latest_error_utc']=='2026-11-01T09:58:58+00:00'
engine=logs['appsec_metrics']['data']['appsec-engine']['127.0.0.1:7422/'];assert engine['processed']==72201 and engine['blocked']==59
assert logs['failure_policy']['openresty']['APPSEC_FAILURE_ACTION']=='deny'
assert h['acquisition']['state']=='pending' and h['acquisition']['sources'][':']=={'whitelisted':9}
assert all(not x.get('reads') or x.get('parsed') for x in h['acquisition']['sources'].values())
assert not scan['matched_artifacts'] and not scan['values_disclosed'] and scan['distinct_credentials_checked']>0
for name,digest in scan['scanned_artifacts'].items():assert sha(root/name)==digest,('changed since credential scan',name)
for name,digest in c['local_source_hashes'].items():assert sha(root/name)==digest,name
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==c['local_head']
old=root/'docs/audit/2026-11-02-vps45-repair/manifest.json';assert sha(old)=='168843511dbc8684649a6acd9255f1fc2410dcb6712555a4c3e978ffadc9e248'
assert sha(folder/'prior-audit-index.md')==json.loads(old.read_text())['supporting_documents']['docs/audit/README.md']
assert sha(root/'docs/audit/2026-11-02-vps45-readonly/manifest.json')=='d859c967ff2c6dcaba6b84974fed86d931bc9bf8cd557c7d3c77019cd4b63c05'
scripts=sorted((folder/'scripts').glob('*.py'))
for p in scripts:ast.parse(p.read_text(),filename=str(p))
embedded=ast.literal_eval(ast.parse((folder/'scripts/vps167-readonly-health.py').read_text()).body[0].value)
for name,source in embedded.items():
 ast.parse(source,filename=name+'.py');assert hashlib.sha256(source.encode()).hexdigest()==c['local_source_hashes']['lib/'+name+'.py']
jsons=list(folder.glob('*.json'))
for p in jsons:json.loads(p.read_text())
links=[];pending={folder/'verification.json',folder/'manifest.json'}
for doc in [report,index]:
 for target in re.findall(r'\]\(([^)]+)\)',doc.read_text()):
  if target.startswith(('http://','https://','#')):continue
  p=(doc.parent/target.split('#',1)[0]).resolve();assert p.exists() or p in pending,(doc,target);links.append(p)
subprocess.run(['git','diff','--check'],cwd=root,check=True)
for p in [folder,*folder.rglob('*')]:p.chmod(0o700 if p.is_dir() else 0o600)
for p in [report,index]:p.chmod(0o644)
for p in [folder,*folder.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
r={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scripts_ast_checked':len(scripts),'in_memory_modules_checked':len(embedded),'json_files_checked_before_seal':len(jsons),'local_links_checked':len(links),'local_source_hashes_checked':len(c['local_source_hashes']),'remote_service_identities_unchanged':True,'remote_sources_unchanged':True,'containers_unchanged':True,'protected_config_comparisons':9,'known_credentials_checked':scan['distinct_credentials_checked'],'exact_scan_artifacts':scan['artifacts_checked'],'credential_matches':0,'historical_manifests_unchanged':True,'index_prior_version_matches_previous_seal':True,'evidence_permissions':'directories 0700; files 0600','git_diff_check':'passed','product_code_modified':False,'production_configuration_changes':False,'normal_queries_can_write_logs_and_counters':True,'full_suite_rerun':False,'independent_reviewer':False,'cold_boot_tested':False,'public_business_blocking_tested':False}
(folder/'verification.json').write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n');(folder/'verification.json').chmod(0o600)
manifest={'sealed_at':r['verified_at'],'files':{str(p.relative_to(folder)):sha(p) for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json'},'supporting_documents':{str(p.relative_to(root)):sha(p) for p in [report,index]},'local_source':c['local_source_hashes'],'head':c['local_head']}
(folder/'manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');(folder/'manifest.json').chmod(0o600)
for name,digest in manifest['files'].items():assert sha(folder/name)==digest
for name,digest in manifest['supporting_documents'].items():assert sha(root/name)==digest
for p in links:assert p.exists()
print(json.dumps(dict(r,evidence_files_sealed=len(manifest['files']),manifest_sha256=sha(folder/'manifest.json')),ensure_ascii=False,indent=2))
