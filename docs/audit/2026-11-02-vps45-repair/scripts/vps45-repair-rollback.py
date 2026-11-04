BACKUP='/var/backups/crowdbastion/vps45-repair-20261102T024205Z'
STAGE_SHA256='3a15ba7dbcb3805fe361131f91029fe8c53f15109afa35eeb869e19410ed719f'
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
os.umask(0o077)
backup=Path(BACKUP);stage=json.loads((backup/'stage.json').read_text());release=Path(stage['release']);sys.path.insert(0,str(release/'lib'))
from crowdsec_bot_runtime import maintenance_guard
from crowdbastion_ux import code_fingerprint
from crowdsec_maintenance import fingerprint
# Code rollback intentionally retains the repaired static policy and disabled
# restore cron. No live configuration, database, offset or audit is restored.
assert hashlib.sha256((backup/'stage.json').read_bytes()).hexdigest()==STAGE_SHA256
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 root=Path(stage['root']);before=backup/'source-directory.before';current=Path('/usr/local/lib/crowdsec-1key/current');entry=Path('/usr/local/bin/crowdbastion')
 deployed=json.loads((backup/'manager-committed.json').read_text())
 assert code_fingerprint(root/'crowdbastion.sh')==stage['fingerprint']
 assert fingerprint(before)==stage['original_source_fingerprint']
 assert os.readlink(current)==stage['maintenance']
 assert entry.is_file() and not entry.is_symlink() and hashlib.sha256(entry.read_bytes()).hexdigest()==deployed['entry_sha256']
 failed=backup/'source-directory.manual-rollback';assert not failed.exists()
 link=current.parent/('.vps45-rollback-'+stage['stamp']);assert not link.exists() and not link.is_symlink()
 link.symlink_to(stage['old_pointer'])
 root.rename(failed)
 try:before.rename(root)
 except BaseException:failed.rename(root);link.unlink();raise
 os.replace(link,current);entry.unlink()
 result={'rolled_back_at':time.time(),'static_policy_retained':True,'live_config_or_state_restored':False}
 (backup/'manual-code-rollback.json').write_text(json.dumps(result)+'\n')
 print(json.dumps(result))
