from pathlib import Path
import ast,datetime,hashlib,json,re,stat,subprocess
from urllib.parse import unquote
ROOT=Path('/projects/script/CrowdBastion-vps167-optimize')
MAIN=Path('/projects/script/CrowdBastion')
NAME='docs/audit/2026-11-02-vps167-optimize-review'
FOLDER=ROOT/NAME
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
result=json.loads((FOLDER/'full-suite-result.json').read_text())
assert result['exit']==0 and result['source_unchanged']
before=json.loads((FOLDER/'source-before.json').read_text());after=json.loads((FOLDER/'source-after.json').read_text());assert before==after
assert len(before)==175
asts=shells=0
for relative,digest in before.items():
 for root in [ROOT,MAIN]:assert sha(root/relative)==digest,relative
 p=ROOT/relative
 if p.suffix=='.py':ast.parse(p.read_text(),filename=relative);asts+=1
 if p.suffix=='.sh':subprocess.run(['bash','-n',str(p)],check=True);shells+=1
for p in (FOLDER/'scripts').glob('*.py'):ast.parse(p.read_text(),filename=str(p))
old_name='docs/audit/2026-11-02-vps167-optimize'
old=json.loads((ROOT/(old_name+'/manifest.json')).read_text())
for root in [ROOT,MAIN]:
 assert sha(root/(old_name+'/manifest.json'))=='f12aea1b2cfbc6289946a194f2b79e22c1841a46f4ebc93f926a34f951dca4d8'
 for relative,digest in old['files'].items():assert sha(root/old_name/relative)==digest,relative
 for relative,digest in old['supporting_documents'].items():
  path=root/relative if relative!='docs/audit/README.md' else root/NAME/'prior-audit-index.md'
  assert sha(path)==digest,relative
 for relative,digest in old['local_source'].items():assert sha(root/relative)==digest,relative
 historical={'2026-11-02-vps45-repair':'168843511dbc8684649a6acd9255f1fc2410dcb6712555a4c3e978ffadc9e248','2026-11-02-vps45-readonly':'d859c967ff2c6dcaba6b84974fed86d931bc9bf8cd557c7d3c77019cd4b63c05','2026-11-02-vps167-readonly':'e9ff72d0af676fc6e6b930b9b5d14665ba0c313f0be782fb539a6e7da0f8ad9e'}
 for name,digest in historical.items():assert sha(root/'docs/audit'/name/'manifest.json')==digest,name
 subprocess.run(['git','diff','--check'],cwd=root,check=True)
 for p in (root/NAME).rglob('*'):
  assert not p.is_symlink()
  assert stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600),str(p)
 for relative in [NAME+'.md','docs/audit/README.md','tests/test_vps167_rollback_review.py']:
  assert stat.S_IMODE((root/relative).stat().st_mode)==0o644
  assert (root/relative).read_bytes()==(ROOT/relative).read_bytes()
 for p in (ROOT/NAME).rglob('*'):
  if p.is_file() and p.name not in ['local-verification.json','manifest.json']:
   assert sha(p)==sha(root/NAME/p.relative_to(ROOT/NAME)),str(p)
links=0
for p in [ROOT/(NAME+'.md'),ROOT/'docs/audit/README.md']:
 for target in re.findall(r'\[[^\]]*\]\(([^)]+)\)',p.read_text()):
  target=target.strip('<>').split('#')[0]
  if not target or '://' in target:continue
  assert (p.parent/unquote(target)).exists(),(str(p),target)
  links+=1
v=json.loads((FOLDER/'verification.json').read_text());health=json.loads(v['health']['stdout'])
assert v['protected_items_unchanged'] and v['rules_unchanged'] and v['health']['exit']==2
assert health['checks']['traffic']=='pending' and all(value=='ok' for key,value in health['checks'].items() if key!='traffic')
assert v['acquisition']['state']=='ok'
assert v['rollback_check']['result']['check_only']
install=json.loads((FOLDER/'installation.json').read_text());seal=json.loads((FOLDER/'remote-seal.json').read_text())
assert install['check_exit']==0 and install['original_stable_items_rechecked']==312
assert not install['active_state_changed'] and not install['production_rollback_executed']
assert seal['original_stable_items_unchanged']==312 and not seal['production_rollback_executed']
assert install['template_sha256']==sha(FOLDER/'scripts/rollback-manager-v2.py')
locks=json.loads((FOLDER/'lock-refusal.json').read_text());assert locks['daily_cli']['exit']==75 and locks['source_operation']['exit']==75 and locks['rollback_check']['exit']!=0
assert json.loads((FOLDER/'autonomous-sync.json').read_text())['firewall_pull_advanced']
scan=json.loads((FOLDER/'credential-scan.json').read_text());assert scan['distinct_credentials_checked']==5 and not scan['matched_artifacts'] and not scan['values_disclosed']
for relative,digest in scan['scanned_artifacts'].items():assert sha(ROOT/relative)==digest,relative
log=(FOLDER/'full-suite.txt').read_text();assert 'Ran 1458 tests' in log and 'OK (skipped=89)' in log
r={'verified_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'full_suite_tests':1458,'passed':1369,'skipped':89,'failed':0,'source_files':len(before),'source_asts':asts,'bash_syntax':shells,'audit_script_asts':len(list((FOLDER/'scripts').glob('*.py'))),'local_links':links,'old_optimize_evidence_unchanged':len(old['files']),'old_supporting_index_preserved_in':'prior-audit-index.md','historical_manifest_hashes_unchanged':True,'main_worktree_copies_match':True,'remote_original_stable_items_unchanged':312,'credential_scan_artifacts':scan['artifacts_checked'],'traffic':'pending','committed_or_pushed':False}
with (FOLDER/'local-verification.json').open('x') as stream:stream.write(json.dumps(r,indent=2)+'\n')
(FOLDER/'local-verification.json').chmod(0o600)
print(json.dumps(r,indent=2))
