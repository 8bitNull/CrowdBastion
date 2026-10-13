import sys,pathlib,subprocess,os,json,time
sys.path.insert(0,'/data/project/script/crowdsec-1key/tests')
from verify_vps_rpm_arm import qemu_command
l=pathlib.Path('/tmp/crowdsec-arm-recovery');old=pathlib.Path('/tmp/crowdsec-vps-rpm-arm-lab')
a=qemu_command('debian13-arm64',old,l/'guest-v2.qcow2',l/'seed.iso');a=[v.replace(',snapshot=on','') for v in a]
env=os.environ.copy();env['LD_LIBRARY_PATH']='/tmp/crowdsec-qemu-lab/host/usr/lib/x86_64-linux-gnu:/tmp/crowdsec-qemu-lab/host/lib/x86_64-linux-gnu'
t=time.monotonic();timeout=False
with (l/'serial.log').open('w') as s:
 p=subprocess.Popen(a,stdout=s,stderr=subprocess.STDOUT,env=env)
 (l/'pid').write_text(str(p.pid))
 try:p.wait(timeout=1500)
 except subprocess.TimeoutExpired:
  timeout=True;p.terminate()
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:p.kill();p.wait()
(l/'runner.json').write_text(json.dumps({'qemu_exit_code':p.returncode,'timed_out':timeout,'elapsed_seconds':round(time.monotonic()-t,2),'ram_mib':1024,'vcpus':1,'accel':'tcg'},indent=2)+'\n')
print((l/'runner.json').read_text())
