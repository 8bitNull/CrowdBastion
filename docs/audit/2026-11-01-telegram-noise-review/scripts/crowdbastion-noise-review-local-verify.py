from pathlib import Path
import ast,hashlib,json,re,shutil,stat,subprocess,time
root=Path('/projects/script/CrowdBastion')
folder=root/'docs/audit/2026-11-01-telegram-noise-review'
scripts=folder/'scripts';scripts.mkdir(mode=0o700,exist_ok=True);scripts.chmod(0o700)
for path in Path('/tmp').glob('crowdbastion-noise-review-*.py'):
    destination=scripts/path.name
    shutil.copyfile(path,destination);destination.chmod(0o600);ast.parse(destination.read_bytes())
static=json.loads((folder/'static-checks.json').read_text())
assert all(hashlib.sha256((root/name).read_bytes()).hexdigest()==digest for name,digest in static['source_hashes'].items())
full=json.loads((folder/'full-suite-result.json').read_text())
assert full['exit']==0 and full['stable']
validated=json.loads((folder/'source-validated.json').read_text())
assert all(static['source_hashes'][name]==digest for name,digest in validated.items())
support=['docs/audit/2026-11-01-telegram-noise-review.md','docs/audit/README.md','docs/telegram-noise-control.md','docs/superpowers/plans/2026-11-01-telegram-noise-review.md','docs/superpowers/specs/2026-11-01-telegram-noise-design.md']
links=0
for name in support:
    path=root/name
    for raw in re.findall(r'\[[^\]\n]+\]\(([^)\n]+)\)',path.read_text()):
        target=raw.split('#',1)[0]
        if not target or '://' in target:continue
        assert (path.parent/target).exists(),(name,target)
        links+=1
subprocess.run(['git','diff','--check'],cwd=root,check=True)
assert not re.search(r'^- \[ \]',(root/support[3]).read_text(),re.M)
report={'checked_at':time.time(),'full_suite':full,'source_files_verified':len(static['source_hashes']),'scripts_ast':len(list(scripts.glob('*.py'))),'documents':len(support),'local_links_verified':links,'diff_check':True}
path=folder/'local-final-verification.json';path.write_text(json.dumps(report,indent=2)+'\n');path.chmod(0o600)
for path in folder.rglob('*'):path.chmod(0o700 if path.is_dir() else 0o600)
assert stat.S_IMODE(folder.stat().st_mode)==0o700
files={str(path.relative_to(folder)):hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(folder.rglob('*')) if path.is_file() and path.name!='manifest.json'}
manifest={'sealed_at':time.time(),'files':files,'supporting_documents':{name:hashlib.sha256((root/name).read_bytes()).hexdigest() for name in support},'source':static['source_hashes']}
path=folder/'manifest.json';path.write_text(json.dumps(manifest,indent=2)+'\n');path.chmod(0o600)
assert all(hashlib.sha256((folder/name).read_bytes()).hexdigest()==digest for name,digest in files.items())
assert all(stat.S_IMODE(p.stat().st_mode)==(0o700 if p.is_dir() else 0o600) for p in folder.rglob('*'))
print(json.dumps({**report,'evidence_files':len(files),'private_permissions_verified':True,'manifest_sha256':hashlib.sha256(path.read_bytes()).hexdigest()},indent=2))
