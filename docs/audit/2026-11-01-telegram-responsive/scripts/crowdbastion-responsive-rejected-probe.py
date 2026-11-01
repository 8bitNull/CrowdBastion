from pathlib import Path
import hashlib,json,sys,time
meta=json.loads(Path('/tmp/crowdbastion-responsive-deployment.json').read_text())
backup=Path(meta['backup']);sys.path.insert(0,str(Path(meta['release'])/'lib'))
from crowdbastion_ux import code_fingerprint,redact
output=(backup/'bot-update-output.private.txt').read_text()
(backup/'bot-update-first-rejected.private.txt').write_text(output)
old='29689b60aa5410dc1baa296594fecd519be4f1b3e8d715bd5d2851804a34e573'
root_fingerprint=code_fingerprint('/root/crowdsec-1key/crowdbastion.sh')
bot_fingerprint=code_fingerprint('/usr/local/lib/crowdsec-1key-bot/runtime/current/manager.sh')
assert root_fingerprint==bot_fingerprint==old
assert Path('/usr/local/bin/crowdbastion').read_bytes()==(backup/'entry.before').read_bytes()
assert '另一个 CrowdSec 管理操作正在执行' in output
print(json.dumps({'checked_at':time.time(),'cause':'Parent deployment guard already held the same lock which the CLI attempted to acquire again.',
    'product_refused_before_update':True,'root_and_entry_restored':True,'bot_manager_still_previous_release':True,
    'output':redact(output)},ensure_ascii=False,indent=2))
