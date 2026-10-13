import sys,pathlib,subprocess,os,json
sys.path.insert(0,'/data/project/script/crowdsec-1key/tests')
from verify_vps_systemd import qemu_command
name=sys.argv[1];lab=pathlib.Path('/tmp/crowdsec-core-diagnostic');root=pathlib.Path('/tmp/crowdsec-qemu-lab/host');qemu=root/'usr/bin/qemu-system-x86_64'
argv=qemu_command(str(qemu),str(lab/(name+'.qcow2')),str(lab/'fixed-observer.iso'),1024)
argv=[a.replace(',snapshot=on','') for a in argv]+['-L',str(root/'usr/share/qemu'),'-bios',str(root/'usr/share/seabios/bios.bin')]
env={**os.environ,'LD_LIBRARY_PATH':str(root/'usr/lib/x86_64-linux-gnu')+':'+str(root/'lib/x86_64-linux-gnu')}
p=lab/(name+'.serial.log');fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600);timeout=False
with os.fdopen(fd,'w') as stream:
 child=subprocess.Popen(argv,stdout=stream,stderr=subprocess.STDOUT,env=env)
 try:child.wait(timeout=1800)
 except subprocess.TimeoutExpired:
  timeout=True;child.terminate()
  try:child.wait(timeout=10)
  except subprocess.TimeoutExpired:child.kill();child.wait()
(lab/(name+'-runner.json')).write_text(json.dumps({'qemu_exit_code':child.returncode,'timed_out':timeout,'scope':'core diagnostic guest, preserved task-owned disk'})+'\n')
print(name,child.returncode,'timeout',timeout)
