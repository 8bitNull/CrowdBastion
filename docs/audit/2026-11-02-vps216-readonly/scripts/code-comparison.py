from pathlib import Path
import hashlib,json,subprocess
ROOT=Path('/projects/script/CrowdBastion')
FOLDER=ROOT/'docs/audit/2026-11-02-vps216-readonly'
def load(name):return json.loads((FOLDER/name).read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
a=load('inventory-before.json');b=load('inventory-after.json');d=load('detail.json');final=load('final.json')
local={str(p.relative_to(ROOT)):sha(p) for p in sorted([ROOT/'crowdbastion.sh',*[p for p in (ROOT/'lib').iterdir() if p.is_file() and p.suffix in ['.py','.sh','.lua']]])}
remote=a['source_roots']['/root/crowdsec-1key']['files'];release=a['source_roots']['/opt/crowdbastion/releases/review-20261030-vps4']['files']
common=sorted(set(local)&set(remote))
r={'local_head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'local_source_hashes':local,'matches':[name for name in common if local[name]==remote[name]['sha256']],'different':[name for name in common if local[name]!=remote[name]['sha256']],'missing_on_remote':sorted(set(local)-set(remote)),'root_release_common_hashes_match':{name:remote[name]['sha256']==release[name]['sha256'] for name in sorted(set(remote)&set(release))},'source_roots_unchanged':{name:a['source_roots'][name]==b['source_roots'][name] for name in a['source_roots']},'service_identities_unchanged':{name:a['services'][name]==b['services'][name] for name in a['services']},'containers_unchanged':a['containers']==b['containers'],'protected_paths_unchanged':{name:item==final['protected_files'][name] for name,item in d['protected_files'].items()},'protected_paths':len(d['protected_files']),'protected_existing_paths':sum(item['exists'] for item in d['protected_files'].values()),'filter_rules_unchanged':d['filter_rules']==final['filter_rules'],'initial_all_table_digest_equal':d['all_table_rule_digests']==final['all_table_rule_digests'],'initial_all_table_digest_limit':'Initial table digests retained policy counters. Unequal digests alone do not establish a rule change. The before/after filter checks use iptables -S and omit counters. Additional snapshots explicitly normalize policy counters.','historical_56_file_manifest_all_match':all(all(item.values()) for item in final['historical_source_matches'].values()),'product_changes_this_round':False}
assert all(r['source_roots_unchanged'].values()) and all(r['service_identities_unchanged'].values()) and r['containers_unchanged']
assert all(r['protected_paths_unchanged'].values()) and r['filter_rules_unchanged'] and r['historical_56_file_manifest_all_match']
p=FOLDER/'code-comparison.json';assert not p.exists();p.write_text(json.dumps(r,ensure_ascii=False,indent=2)+'\n');p.chmod(0o600)
print(json.dumps({key:(len(value) if isinstance(value,(dict,list)) else value) for key,value in r.items() if key!='local_source_hashes'},ensure_ascii=False,indent=2))
