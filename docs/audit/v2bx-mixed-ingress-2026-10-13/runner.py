from pathlib import Path
import os,subprocess,time,json,sys
lab=Path('/tmp/v2bx-mixed-ingress-20261013');qroot=Path('/tmp/crowdsec-qemu-lab/host')
args=[str(qroot/'usr/bin/qemu-system-x86_64'),'-L',str(qroot/'usr/share/qemu'),'-bios',str(qroot/'usr/share/seabios/bios.bin'),'-accel','tcg','-machine','q35','-cpu','max','-m','1536','-smp','2','-nographic','-monitor','none','-nic','none','-kernel','/tmp/crowdsec-remote-lapi-lab/root/boot/vmlinuz-6.1.0-47-amd64','-initrd',str(lab/'boot.gz'),'-append','console=ttyS0 panic=-1','-drive',f'file={lab}/disk.raw,format=raw,if=virtio,snapshot=on']
env=os.environ.copy();env['LD_LIBRARY_PATH']=str(qroot/'usr/lib/x86_64-linux-gnu')+':'+str(qroot/'lib/x86_64-linux-gnu')
start=time.monotonic()
with (lab/'serial.log').open('w') as log:
 process=subprocess.Popen(args,env=env,stdout=log,stderr=subprocess.STDOUT)
 timed_out=False
 try:code=process.wait(timeout=1800)
 except subprocess.TimeoutExpired:
  timed_out=True;process.terminate()
  try:process.wait(timeout=10)
  except subprocess.TimeoutExpired:process.kill();process.wait()
  code=process.returncode
(lab/'runner.json').write_text(json.dumps({'qemu_exit_code':code,'timed_out':timed_out,'elapsed_seconds':round(time.monotonic()-start,2),'ram_mib':1536,'network':'no NIC','acceleration':'TCG','argv':args},indent=2)+'\n')
print((lab/'runner.json').read_text())
