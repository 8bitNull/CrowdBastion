"""Provision test-only loopback forwarding workload in a marked disposable guest."""
import json
import pathlib
import subprocess
import sys
import time
import types
from relay_network_lab import Processes
from verify_relay_network import start_forwarder
from relay_soak_guest import main, validate_manifest
from vps_guest_runtime import run_bounded

config=validate_manifest(json.loads(pathlib.Path('/opt/test/soak-manifest.json').read_text()))
rc,out,_=run_bounded(['systemd-detect-virt','--vm'],timeout=5)
if rc or out.strip()!='qemu' or pathlib.Path('/run/crowdsec-vps-lab').read_text().strip()!=config['lab_id']:
    raise SystemExit('Disposable guest marker required')
with Processes(grace=3) as owned:
    directory=pathlib.Path('/opt/test/soak-workload');directory.mkdir(exist_ok=False)
    for protocol in ('tcp','udp'):
        owned.start([sys.executable,'/opt/test/benchmark_relay.py','--echo',protocol,'29000','1024','--echo-host','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    args=types.SimpleNamespace(gost='/opt/test/gost',realm='/opt/test/realm')
    for path in config['endpoints']:
        tool,protocol=path.split('_');port=config['endpoints'][path][1]
        if tool=='gost' and protocol=='udp':
            owned.start([args.gost,'-L',f'udp://127.0.0.1:{port}/127.0.0.1:29000?keepAlive=true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:start_forwarder(args,owned,directory,tool,protocol,'127.0.0.1','127.0.0.1',port,29000)
    if any(p.poll() is not None for p in owned.children):raise SystemExit('Workload process exited')
    sys.argv=[sys.argv[0],'--manifest','/opt/test/soak-manifest.json','--output','/opt/test/soak-result.json']
    raise SystemExit(main())
