from pathlib import Path
from urllib.request import urlopen
import json,hashlib
b=Path(__file__).resolve().parent
requests=[('sing-t uic'.replace(' ',''),'https://raw.githubusercontent.com/wyx2685/sing-box_mod/v1.13.0-alpha.5/protocol/tuic/inbound.go'),('sing-hysteria','https://raw.githubusercontent.com/wyx2685/sing-box_mod/v1.13.0-alpha.5/protocol/hysteria/inbound.go'),('sing-anytls','https://raw.githubusercontent.com/wyx2685/sing-box_mod/v1.13.0-alpha.5/protocol/anytls/inbound.go'),('quic-hysteria','https://raw.githubusercontent.com/SagerNet/sing-quic/v0.5.0/hysteria/service.go'),('quic-hysteria2','https://raw.githubusercontent.com/SagerNet/sing-quic/v0.5.0/hysteria2/service.go'),('quic-tuic','https://raw.githubusercontent.com/SagerNet/sing-quic/v0.5.0/tuic/service.go')]
records=[]
for name,url in requests:
 try:
  data=urlopen(url,timeout=20).read();(b/(name+'.go')).write_bytes(data);records.append(dict(name=name,url=url,sha256=hashlib.sha256(data).hexdigest(),status='downloaded'))
 except Exception as error:records.append(dict(name=name,url=url,status=type(error).__name__))
old=Path('/tmp/v2bx-real-lab/source/wyx2685-V2bX-3deccaa')
for name,path in [('hy2-auth','core/hy2/user.go'),('hy2-log','core/hy2/logger.go')]:
 data=(old/path).read_bytes();(b/(name+'.go')).write_bytes(data);records.append(dict(name=name,url='https://github.com/wyx2685/V2bX/blob/3deccaae00d168fd049f8a8659656664f25ee301/'+path,status='release-source',sha256=hashlib.sha256(data).hexdigest()))
(b/'log-source-check.json').write_text(json.dumps(records,indent=2)+'\n');print(records)
