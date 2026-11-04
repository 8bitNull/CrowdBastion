import ast,hashlib,json,subprocess
from pathlib import Path
backup=Path('/var/backups/crowdbastion/vps167-optimize-20261102T034616Z')
p=subprocess.run(['python3','-B',str(backup/'rollback-manager.py'),'--check'],capture_output=True,text=True,timeout=15)
assert p.returncode==0
print(json.dumps({'rollback_check':{'exit':p.returncode,'data':json.loads(p.stdout)},'rollback_ast':bool(ast.parse((backup/'rollback-manager.py').read_text()))},ensure_ascii=False))
