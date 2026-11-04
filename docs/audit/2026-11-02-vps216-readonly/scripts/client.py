from pathlib import Path
import json,subprocess,sys,time
SSH=['ssh','-F','/dev/null','-p','53322','-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/root/.ssh/known_hosts','-o','ConnectTimeout=10','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-i','/root/.ssh/crowdbastion_vps_216_238_52_230','root@192.0.2.19']
if __name__=='__main__':
    script,destination=map(Path,sys.argv[1:3]);started=time.time()
    result=subprocess.run(SSH+['env PYTHONDONTWRITEBYTECODE=1 python3 -B -'],input=script.read_bytes(),capture_output=True,timeout=100)
    destination.parent.mkdir(parents=True,exist_ok=True,mode=0o700);destination.parent.chmod(0o700)
    destination.write_bytes(result.stdout);destination.chmod(0o600)
    err=destination.with_suffix('.stderr.txt');err.write_bytes(result.stderr);err.chmod(0o600)
    print(json.dumps({'ssh_exit':result.returncode,'seconds':round(time.time()-started,3),'saved':str(destination),'bytes':len(result.stdout)}))
    if result.stderr:print(result.stderr.decode(errors='replace')[-1500:])
    raise SystemExit(result.returncode)
