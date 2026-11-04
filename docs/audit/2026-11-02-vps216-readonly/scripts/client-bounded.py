from pathlib import Path
import json,subprocess,sys,time
SSH=['ssh','-C','-F','/dev/null','-p','53322','-o','BatchMode=yes','-o','PreferredAuthentications=publickey','-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','IdentitiesOnly=yes','-o','StrictHostKeyChecking=yes','-o','UserKnownHostsFile=/root/.ssh/known_hosts','-o','ConnectTimeout=10','-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2','-i','/root/.ssh/crowdbastion_vps_216_238_52_230','root@192.0.2.19']
if __name__=='__main__':
    script,destination=map(Path,sys.argv[1:3]);started=time.time();timed_out=False
    try:
        result=subprocess.run(SSH+['env PYTHONDONTWRITEBYTECODE=1 python3 -B -'],input=script.read_bytes(),capture_output=True,timeout=45)
        code,output,error=result.returncode,result.stdout,result.stderr
    except subprocess.TimeoutExpired as exc:
        code,output,error=124,exc.stdout or b'',exc.stderr or b'';timed_out=True
    try:
        json.loads(output);target=destination
    except (ValueError,UnicodeError):target=destination.with_suffix('.stdout.txt')
    for path,content in [(target,output),(destination.with_suffix('.stderr.txt'),error)]:
        path.write_bytes(content);path.chmod(0o600)
    record={'ssh_exit':code,'seconds':round(time.time()-started,3),'client_timeout':timed_out,'saved':str(target),'bytes':len(output)}
    execution=destination.with_suffix('.execution.json');execution.write_text(json.dumps(record,indent=2)+'\n');execution.chmod(0o600)
    print(json.dumps(record));raise SystemExit(code)
