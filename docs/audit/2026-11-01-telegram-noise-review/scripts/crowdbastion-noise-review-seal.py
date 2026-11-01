from pathlib import Path
import hashlib,json,sqlite3,stat,time
meta=json.loads(Path('/tmp/crowdbastion-noise-review-deployment.json').read_text())
backup=Path(meta['backup'])
assert stat.S_IMODE(backup.stat().st_mode)==0o700 and backup.stat().st_uid==0
for database in backup.glob('consistent-*.sqlite3'):
    with sqlite3.connect(database.as_uri()+'?mode=ro&immutable=1',uri=True) as connection:
        assert connection.execute('PRAGMA quick_check').fetchone()==('ok',)
files={}
for path in sorted(backup.rglob('*')):
    assert not path.is_symlink()
    if path.is_file() and path.name!='final-manifest.json':
        assert stat.S_IMODE(path.stat().st_mode)==0o600 and path.stat().st_uid==0
        files[str(path.relative_to(backup))]=hashlib.sha256(path.read_bytes()).hexdigest()
manifest=backup/'final-manifest.json'
assert not manifest.exists()
manifest.write_text(json.dumps({'sealed_at':time.time(),'files':files},indent=2)+'\n');manifest.chmod(0o600)
assert all(hashlib.sha256((backup/name).read_bytes()).hexdigest()==sha for name,sha in files.items())
print(json.dumps({'backup':str(backup),'files':len(files),'consistent_sqlite_quick_check':'ok','private_permissions_verified':True,'manifest':str(manifest),'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest()},indent=2))
