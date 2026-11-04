BACKUP='/var/backups/crowdbastion/vps45-repair-20261102T024205Z'
import hashlib,json,os,stat,time
from pathlib import Path
backup=Path(BACKUP);manifest=backup/'sealed-manifest.json';assert not manifest.exists();entries={}
for p in sorted(backup.rglob('*')):
 s=p.lstat();assert s.st_uid==0
 if p.is_symlink():entries[str(p.relative_to(backup))]={'link':os.readlink(p)};continue
 assert not s.st_mode&0o077,(str(p),oct(s.st_mode))
 if p.is_dir():continue
 assert p.is_file();entries[str(p.relative_to(backup))]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'mode':oct(stat.S_IMODE(s.st_mode))}
manifest.write_text(json.dumps({'sealed_at':time.time(),'files':entries},indent=2)+'\n');manifest.chmod(0o600)
for name,item in entries.items():
 p=backup/name
 if 'link' in item:assert p.is_symlink() and os.readlink(p)==item['link']
 else:assert hashlib.sha256(p.read_bytes()).hexdigest()==item['sha256']
print(json.dumps({'backup':str(backup),'files_and_links':len(entries),'manifest_sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'all_stable_hashes_verified':True,'root_private_permissions_verified':True,'active_state_restored':False,'sealed_at':time.time()}))
