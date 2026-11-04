"""Seal only this review backup; verify the original sealed backup read-only."""
from pathlib import Path
import datetime
import hashlib
import json
import sqlite3
import subprocess

original = Path('/var/backups/crowdbastion/vps144-20261103T103358Z')
review = Path('/var/backups/crowdbastion/vps144-static-review-20261103T113133Z')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


old = json.loads((original / 'manifest.json').read_text())
drift = {name: digest(original / name) for name, expected in old['backup_files'].items()
         if digest(original / name) != expected}
extra = sorted(str(p.relative_to(original)) for p in original.rglob('*')
               if p.is_file() and p.name != 'manifest.json'
               and str(p.relative_to(original)) not in old['backup_files'])
assert not drift and not extra, (drift, extra)
databases = [original / 'crowdsec-consistent.sqlite3']
assert databases
sqlite_checks = {}
for path in databases:
    with sqlite3.connect(path.as_uri() + '?mode=ro&immutable=1', uri=True) as connection:
        result = connection.execute('PRAGMA quick_check').fetchall()
    assert result == [('ok',)], (path.name, result)
    sqlite_checks[str(path.relative_to(original))] = 'ok'
deployment = json.loads((review / 'deploy-result.json').read_text())
live = {name: digest(Path(name)) for name in deployment['new_files']}
assert live == deployment['new_files']
service = subprocess.run(
    ['systemctl', 'show', 'crowdbastion-static-policy', '-p', 'ActiveState',
     '-p', 'SubState', '-p', 'ExecMainStatus', '-p', 'UnitFileState',
     '-p', 'Restart', '-p', 'StartLimitIntervalUSec'],
    capture_output=True, text=True, check=True, timeout=15).stdout
assert 'ActiveState=active\n' in service and 'ExecMainStatus=0\n' in service
summary = {
    'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
    'backup': str(review), 'original_backup_drift': drift,
    'original_backup_extra_files': extra, 'sqlite_checks': sqlite_checks,
    'live_hashes': live, 'static_service': service,
}
(review / 'seal-result.json').write_text(json.dumps(summary, indent=2) + '\n')
files = {str(p.relative_to(review)): digest(p) for p in review.rglob('*')
         if p.is_file() and p.name != 'manifest.json'}
(review / 'manifest.json').write_text(json.dumps(
    {'at': summary['at'], 'live_hashes': live, 'backup_files': files}, indent=2) + '\n')
for path in review.rglob('*'):
    if path.is_file():
        path.chmod(0o600)
assert all(digest(review / name) == value for name, value in files.items())
summary['sealed_files'] = len(files)
summary['manifest_sha256'] = digest(review / 'manifest.json')
summary['status'] = 'sealed_and_verified'
print(json.dumps(summary, indent=2))
