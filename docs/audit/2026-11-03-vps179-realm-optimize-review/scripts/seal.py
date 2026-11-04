from pathlib import Path
import json,hashlib,datetime
base=Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z');private=base/'review-20261103'
old=json.loads((base/'manifest.json').read_text());drift=[]
for name,digest in old.items():
 p=base/name
 if not p.is_file() or hashlib.sha256(p.read_bytes()).hexdigest()!=digest:drift.append(name)
if drift!=['rollback.py'] and set(drift)!={'rollback.py'}:raise RuntimeError('unexpected historical backup changes '+repr(drift))
paths=[base/'rollback.py',base/'enforcement-review-result.json',*(p for p in private.rglob('*') if p.is_file() and p.name!='review-manifest.json')]
r={'at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'historical_manifest_preserved':True,'expected_historical_drift':drift,'files':{str(p.relative_to(base)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}}
(private/'review-manifest.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps(r,indent=2))
