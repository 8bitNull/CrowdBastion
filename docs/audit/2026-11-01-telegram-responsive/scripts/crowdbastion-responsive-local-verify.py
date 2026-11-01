from pathlib import Path
import ast,hashlib,json,os,re,shutil,stat,subprocess,time
root=Path('/projects/script/CrowdBastion')
folder=root/'docs/audit/2026-11-01-telegram-responsive'
for path in sorted(Path('/tmp').glob('crowdbastion-responsive-*.py')):
    target=folder/'scripts'/path.name
    shutil.copyfile(path,target);target.chmod(0o600)
source=json.loads((folder/'source-validated.json').read_text())
assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in source.items())
result=json.loads((folder/'full-suite-result.json').read_text());assert result['exit']==0
log=(folder/'full-suite.txt').read_text()
assert 'Ran 1406 tests' in log and 'OK (skipped=89)' in log
subprocess.run(['git','diff','--check'],cwd=root,check=True,capture_output=True)
documents=['docs/2026-10-13-custom-telegram-bot.md','docs/audit/README.md','docs/audit/2026-11-01-telegram-responsive.md','docs/superpowers/plans/2026-11-01-telegram-responsive.md','docs/superpowers/specs/2026-11-01-telegram-responsive-design.md']
links=0
for name in documents:
    path=root/name
    for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)(?:\s+"[^\"]*")?\)',path.read_text()):
        if target.startswith(('https:','http:','mailto:','#')):continue
        target=target.split('#',1)[0]
        assert (path.parent/target).exists(),(name,target)
        links+=1
scripts=list((folder/'scripts').glob('*.py'))
for script in scripts:ast.parse(script.read_text(),filename=str(script))
for path in [folder,*folder.rglob('*')]:
    assert not path.is_symlink()
    expected=0o700 if path.is_dir() else 0o600
    assert stat.S_IMODE(path.stat().st_mode)==expected,str(path)
patterns=[rb'\b[0-9]{7,12}:[A-Za-z0-9_-]{20,}\b',rb'-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----']
files=[root/name for name in documents]+[p for p in folder.rglob('*') if p.is_file()]
assert not [str(p.relative_to(root)) for p in files if any(re.search(pattern,p.read_bytes()) for pattern in patterns)]
remote=json.loads((folder/'vps-verification.json').read_text())
assert remote['stale_result_suppressed'] and remote['fresh_sample_completed_later']
assert remote['poller']['status']=='healthy' and len(remote['instances'])==1
output={'checked_at':time.time(),'full_suite_total':1406,'passed':1317,'skipped':89,'source_files':len(source),'source_hashes_stable':True,
        'archived_python_scripts':len(scripts),'documents_checked':len(documents),'local_links_checked':links,'git_diff_check':True,
        'private_permissions_valid':True,'sensitive_pattern_files_checked':len(files),'sensitive_pattern_matches':0}
path=folder/'final-verification.json';path.write_text(json.dumps(output,indent=2)+'\n');path.chmod(0o600)
print(json.dumps(output,indent=2))
