#!/usr/bin/env python3
"""Real legacy-iptables packets with a synthetic decision fixture; isolated only."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time
import verify_relay_network as network
from relay_network_lab import DecisionAPI, Processes, command, guard

def bouncer_set(name):
    return re.fullmatch(r'crowdsec6?-blacklists(?:-\d+)?',name) is not None

def drop_packets(data):
    total=0
    for line in data.splitlines():
        match=re.match(r'^\[(\d+):\d+\]\s+(.+)$',line)
        if not match: continue
        words=shlex.split(match[2])
        # An inverted match cannot establish source blacklist enforcement.
        if '!' in words: continue
        try:
            index=words.index('--match-set')
            jump=words.index('-j')
            if bouncer_set(words[index+1]) and words[index+2]=='src' and words[jump+1]=='DROP':
                total+=int(match[1])
        except (ValueError,IndexError): pass
    return total

def has_address(data,address):
    target=ipaddress.ip_address(address)
    for line in data.splitlines():
        words=shlex.split(line)
        if len(words)<3 or words[0]!='add' or not bouncer_set(words[1]): continue
        try:
            if ipaddress.ip_network(words[2],strict=False).num_addresses==1 and ipaddress.ip_address(words[2].split('/')[0])==target: return True
        except ValueError: pass
    return False

def counter():
    return sum(drop_packets(command([binary,'-c'],timeout=10)) for binary in ('iptables-save','ip6tables-save'))

def wait_set(address,enabled):
    deadline=time.monotonic()+20
    while time.monotonic()<deadline:
        if has_address(command(['ipset','save'],timeout=10),address)==enabled: return
        time.sleep(.2)
    raise RuntimeError('iptables blacklist synchronization timeout')

def worker(args,report):
    guard(args.original_inode,args.original_mount_inode)
    import yaml
    report['firewall_versions']={binary:command([binary,'--version'],timeout=10).strip() for binary in ('iptables','ip6tables','ipset')}
    if not all('(legacy)' in report['firewall_versions'][binary] for binary in ('iptables','ip6tables')):
        raise RuntimeError('legacy backend required; observed different iptables implementation')
    report['versions']={}
    for name,flag in [('gost','-V'),('realm','--version'),('bouncer','-version')]:
        result=subprocess.run([getattr(args,name),flag],capture_output=True,text=True,timeout=10)
        report['versions'][name]=(result.stdout+result.stderr).strip()[:1000]
    network.setup()
    # Reuse the exact traffic matrix; replace only backend-specific evidence.
    network.counter=counter
    network.wait_set=wait_set
    report['probe_process_wall_seconds']=[]
    def measured_client(namespace,host,port,protocol):
        argv=['ip','netns','exec',namespace,sys.executable,str(Path(network.__file__).resolve()),'--probe',host,str(port),protocol]
        start=time.monotonic()
        result=subprocess.run(argv,capture_output=True,text=True,timeout=15)
        report['probe_process_wall_seconds'].append(round(time.monotonic()-start,3))
        return json.loads(result.stdout) if result.returncode==0 else None
    network.client=measured_client
    with tempfile.TemporaryDirectory(prefix='relay-iptables-') as tmp, Processes(grace=3) as owned, DecisionAPI() as api:
        directory=Path(tmp)
        config=dict(mode='iptables',update_frequency='1s',api_url=api.url,api_key=api.key,
                    log_mode='stdout',log_level='info',disable_ipv6=False,deny_action='DROP',
                    blacklists_ipv4='crowdsec-blacklists',blacklists_ipv6='crowdsec6-blacklists',
                    ipset_type='nethash',iptables_chains=['INPUT','FORWARD'])
        cfg=directory/'bouncer.yaml';cfg.write_text(yaml.safe_dump(config));cfg.chmod(0o600)
        with (directory/'bouncer.log').open('w+') as log:
            try:
                bouncer=owned.start([args.bouncer,'-c',str(cfg)],stdout=log,stderr=log)
                time.sleep(2)
                if bouncer.poll() is not None: raise RuntimeError('official iptables bouncer exited at startup')
                for family in (4,6):
                    for protocol in ('tcp','udp'):
                        owned.start(['ip','netns','exec','backend',sys.executable,str(Path(network.__file__).resolve()),'--echo','10.231.3.2' if family==4 else 'fd42:231:3::2','29000',protocol],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                network.execute_matrix(args,report,directory,owned,api)
                report['firewall_versions']={binary:command([binary,'--version'],timeout=10).strip() for binary in ('iptables','ip6tables','ipset')}
                report['drop_packets']=counter()
            finally:
                log.flush();log.seek(0);report['bouncer_log']=log.read().replace(api.key,'<redacted>')[-18000:]

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original-inode',type=int,help=argparse.SUPPRESS)
    p.add_argument('--original-mount-inode',type=int,help=argparse.SUPPRESS)
    for name in ('gost','realm','bouncer'): p.add_argument('--'+name,default='/bin/'+('crowdsec-firewall-bouncer' if name=='bouncer' else name))
    p.add_argument('--output')
    args=p.parse_args()
    report=dict(schema=1,validation_level='real-firewall-synthetic-decision-api',backend='iptables-legacy/ipset',cases=[],scope='fresh sessions; isolated namespaces; legacy iptables filter and nft NAT; no real remote LAPI or systemd installation claim')
    if args.original_inode is None:
        argv=[sys.executable,str(Path(__file__).resolve()),'--original-inode',str(os.stat('/proc/self/ns/net').st_ino),'--original-mount-inode',str(os.stat('/proc/self/ns/mnt').st_ino)]
        for name in ('gost','realm','bouncer'): argv.extend(['--'+name,getattr(args,name)])
        with Processes(grace=8) as owned:
            process=owned.start(['unshare','--net','--mount','--',*argv],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            try:
                stdout,stderr=process.communicate(timeout=600)
                report=json.loads(stdout)
            except subprocess.TimeoutExpired: report['error']='isolated worker timeout';report['status']='failed';report['exit_code']=1
            except ValueError: report['error']=stderr[-2000:];report['status']='unverified';report['exit_code']=2
    else:
        try: worker(args,report)
        except Exception as exc: report['error']=str(exc)
        code=0 if len(report['cases'])==12 and all(c['status']=='passed' for c in report['cases']) and not report.get('error') else 1
        report['exit_code']=code;report['status']='passed' if code==0 else 'failed'
    output=json.dumps(report,indent=2)+'\n'
    if args.output: Path(args.output).write_text(output)
    print(output,end='');return report['exit_code']

if __name__=='__main__':sys.exit(main())
