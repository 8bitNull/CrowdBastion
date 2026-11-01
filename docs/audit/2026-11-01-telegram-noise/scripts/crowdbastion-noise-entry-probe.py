from pathlib import Path
import json
p=Path('/usr/local/bin/crowdbastion')
print(json.dumps({'entry':p.read_text()}))
