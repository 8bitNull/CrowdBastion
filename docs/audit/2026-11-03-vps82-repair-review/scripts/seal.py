"""Seal this repair's private backup and verify the exact one-line edit."""
from pathlib import Path
import datetime
import hashlib
import json
import stat

backup = Path('/var/backups/crowdbastion/vps82-sysctl-review-iqdvz68q')
info = backup.lstat()
assert stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_mode & 0o077 == 0


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


result = json.loads((backup / 'repair-result.json').read_text())
acknowledgement = json.loads((backup / 'historical-failure-ack.json').read_text())
before = backup / 'source-before.conf'
live = Path('/etc/sysctl.d/99-network-optimize.conf')
assert digest(before) == result['before_sha256'] and digest(live) == result['after_sha256']
assert before.read_bytes().replace(b'net.core.netdev_budget_usecs = 6000\n',
                                 b'net.core.netdev_budget_usecs = 8000\n', 1) == live.read_bytes()
assert acknowledgement['status'] == 'historical_failure_acknowledged'
assert result['status'] == 'applied_and_verified' and result['targeted_apply']['exit'] == 0
assert result['runtime_before'] == result['runtime_after']
assert not (backup / 'manifest.json').exists()
(backup / 'source-after.conf').write_bytes(live.read_bytes())
summary = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'backup': str(backup),
           'live_sha256': digest(live), 'exact_one_assignment_changed': True,
           'runtime_values_unchanged': len(result['runtime_before']),
           'full_unit_restarted': False, 'historical_failure_acknowledged': True}
(backup / 'seal-result.json').write_text(json.dumps(summary, indent=2) + '\n')
manifest = {str(p.relative_to(backup)): digest(p) for p in backup.rglob('*')
            if p.is_file() and p.name != 'manifest.json'}
(backup / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
for p in backup.rglob('*'):
    if p.is_file():
        p.chmod(0o600)
assert all(digest(backup / name) == value for name, value in manifest.items())
print(json.dumps({**summary, 'sealed_files': len(manifest),
                  'manifest_sha256': digest(backup / 'manifest.json'), 'status': 'sealed_and_verified'}, indent=2))
