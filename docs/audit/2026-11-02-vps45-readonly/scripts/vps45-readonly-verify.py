from pathlib import Path
import ast,datetime,hashlib,json,re,stat,subprocess
root=Path('/projects/script/CrowdBastion');folder=root/'docs/audit/2026-11-02-vps45-readonly';report=root/'docs/audit/2026-11-02-vps45-readonly.md';index=root/'docs/audit/README.md'
def load(name):return json.loads((folder/name).read_text())
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
comparison=load('code-comparison.json');follow=load('followup.json');hooks=load('hooks-and-source-recheck.json');final=load('final.json')
assert all(comparison['source_unchanged_during_inspection'].values())
assert all(comparison['service_pids_unchanged'].values())
assert all(comparison['protected_config_hashes_unchanged'].values())
assert len(comparison['matches'])==31 and len(comparison['different'])==22 and len(comparison['missing_on_remote'])==9
assert follow['decision_membership_independent']=={'expected':16701,'kernel':16701,'missing':0}
assert len(follow['restore_crons'])==2
assert all(v['all_required_paths_reach_crowdsec_before_other_rules'] for v in follow['static_path_analysis'].values())
assert load('autonomous-sync.json')['firewall_pull_advanced']
assert not load('credential-scan.json')['matched_artifacts']
for web in hooks['web_hooks'].values():
    assert web['resource_hashes_and_mounts']=='ok' and web['target_in_effective_configuration']
    assert all(v['parsed_directive_matches'] and v['crowdsec_call_present'] for v in web['phases'].values())
assert all(v['exit']==0 and v['stdout']=='200' for v in final['origin_http_checks'].values())
assert all((root/name).is_file() and sha(root/name)==expected for name,expected in comparison['local_source_hashes'].items())
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip()==comparison['local_head']
scripts=list((folder/'scripts').glob('*.py'))
for p in scripts:ast.parse(p.read_text(),filename=str(p))
json_files=list(folder.glob('*.json'))
for p in json_files:json.loads(p.read_text())
links=[]
for doc in [report,index]:
    for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',doc.read_text()):
        if target.startswith(('https://','http://','#')):continue
        path=(doc.parent/target.split('#',1)[0]);assert path.exists(),(doc,target);links.append(target)
subprocess.run(['git','diff','--check'],cwd=root,check=True)
for p in folder.rglob('*'):p.chmod(0o700 if p.is_dir() else 0o600)
folder.chmod(0o700);report.chmod(0o644)
for p in [folder,*folder.rglob('*')]:assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600)
verification={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'scripts_ast_checked':len(scripts),'json_files_checked_before_seal':len(json_files),'local_links_checked':len(links),'local_source_hashes_checked':len(comparison['local_source_hashes']),'remote_services_pids_unchanged':True,'remote_sources_unchanged':True,'config_hash_comparisons':len(comparison['protected_config_hashes_unchanged']),'evidence_permissions':'directories 0700; files 0600','git_diff_check':'passed','product_code_modified':False,'production_changes':False,'full_suite_rerun':False}
p=folder/'verification.json';p.write_text(json.dumps(verification,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
manifest={'sealed_at':verification['verified_at'],'files':{str(p.relative_to(folder)):sha(p) for p in sorted(folder.rglob('*')) if p.is_file() and p.name!='manifest.json'},'supporting_documents':{str(p.relative_to(root)):sha(p) for p in [report,index]},'local_source':comparison['local_source_hashes'],'head':comparison['local_head']}
p=folder/'manifest.json';p.write_text(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
for name,value in manifest['files'].items():assert sha(folder/name)==value
for name,value in manifest['supporting_documents'].items():assert sha(root/name)==value
print(json.dumps(dict(verification,evidence_files_sealed=len(manifest['files']),manifest_sha256=sha(p)),ensure_ascii=False,indent=2))
