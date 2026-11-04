import hashlib,json,os,runpy,stat,time
from pathlib import Path
os.umask(0o077)
backup=Path('/var/backups/crowdbastion/vps167-optimize-20261102T034616Z')
rollback=runpy.run_path(str(backup/'rollback-manager.py'),run_name='vps167_rollback_module');stage=rollback['load_stage']()
from crowdsec_maintenance import fingerprint
from crowdsec_bot_runtime import maintenance_guard

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def record(p):
 s=p.lstat();r={'uid':s.st_uid,'gid':s.st_gid,'mode':stat.S_IMODE(s.st_mode)}
 if p.is_symlink():r['target']=os.readlink(p)
 elif p.is_file():r['sha256']=sha(p);r['size']=s.st_size
 else:assert p.is_dir();r['directory']=True
 return r
with maintenance_guard('/run/lock/crowdsec-1key.lock','/var/lib/crowdbastion/firewall-migration'):
 original=backup/'source-directory.before'
 assert fingerprint(original)==stage['original_source_fingerprint']
 assert fingerprint(Path(stage['root']))==stage['prepared_source_fingerprint']
 assert record(backup)['mode']==0o700 and record(backup)['uid']==0
 for p in [backup,*backup.rglob('*')]:
  if p==original or original in p.parents:continue
  assert not p.is_symlink()
  s=p.stat();assert s.st_uid==0 and stat.S_IMODE(s.st_mode)==(0o700 if p.is_dir() else 0o600),str(p)
 roots=[backup,Path(stage['release']),Path(stage['maintenance']),Path(stage['root'])]
 paths=set()
 for root in roots:paths.update([root,*root.rglob('*')])
 paths.update([Path(stage['entry']),Path(stage['cron']),Path(stage['runtime'])/'.crowdsec-1key-managed',Path(stage['runtime'])/'current'])
 paths.discard(backup/'manifest.json')
 records={str(p):record(p) for p in sorted(paths)}
 manifest={'sealed_at':time.time(),'items':records,'original_source_fingerprint_preserved':True,'backup_outer_root0700':True,'new_backup_material_private':True,'original_source_permissions_preserved':True,'active_state_restored':False}
 p=backup/'manifest.json';assert not p.exists();p.write_text(json.dumps(manifest,indent=2)+'\n');p.chmod(0o600)
 for name,value in records.items():assert record(Path(name))==value,name
 print(json.dumps({'backup':str(backup),'manifest_sha256':sha(p),'stable_items_sealed':len(records),'stable_files_or_links':sum('sha256' in row or 'target' in row for row in records.values()),'original_source_preserved':True,'private_backup_material_verified':True,'stable_records_rechecked':True,'active_state_restored':False,'sealed_at':manifest['sealed_at']},ensure_ascii=False))
