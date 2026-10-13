#!/usr/bin/env python3
"""Bounded IPv4 same-host relay benchmark; no production services or firewall changes."""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import platform
import random
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from relay_network_lab import Processes, DecisionAPI, command, free_port, guard, wait_set
from verify_relay_network import setup, start_forwarder


def schedule(tools, protocols, sizes, repeats, seed):
    rng = random.Random(seed)
    runs = []
    for block in range(repeats):
        conditions = [dict(block=block, tool=t, protocol=p, ban_count=n)
                      for t in tools for p in protocols for n in [None]+sizes]
        rng.shuffle(conditions)
        runs.extend(conditions)
    return runs


def snapshot(pid):
    text = Path('/proc/%s/stat' % pid).read_text().rsplit(')',1)[1].split()
    return dict(cpu_seconds=(int(text[11])+int(text[12]))/os.sysconf('SC_CLK_TCK'),
                rss_bytes=int(text[21])*os.sysconf('SC_PAGE_SIZE'))


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size-len(data))
        if not part:
            raise OSError('early EOF')
        data.extend(part)
    return bytes(data)


def echo(protocol, port, size, host):
    def connection(conn):
        with conn:
            try:
                while True:
                    data = receive(conn,size)
                    conn.sendall(data)
            except OSError:
                pass
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as sock:
        sock.bind((host,port))
        if protocol=='tcp':
            sock.listen(128)
        while True:
            if protocol=='udp':
                data,peer=sock.recvfrom(65535)
                sock.sendto(data,peer)
            else:
                conn,_=sock.accept()
                threading.Thread(target=connection,args=(conn,),daemon=True).start()


def load(host, port, protocol, duration, concurrency, size):
    payload = os.urandom(size)
    start=time.monotonic()
    deadline=start+duration
    def worker():
        ok=errors=0
        reasons={}
        samples=[]
        rng=random.Random()
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                sock.connect((host,port))
                while time.monotonic()<deadline:
                    before=time.monotonic()
                    try:
                        sock.sendall(payload)
                        result=receive(sock,size) if protocol=='tcp' else sock.recv(65535)
                        if result!=payload:
                            raise OSError('payload mismatch')
                        latency=(time.monotonic()-before)*1000
                        ok+=1
                        # Bounded reservoir for long runs, each worker equally represented in raw samples.
                        if len(samples)<4096:
                            samples.append(latency)
                        else:
                            index=rng.randrange(ok)
                            if index<len(samples):
                                samples[index]=latency
                    except OSError as exc:
                        errors+=1
                        reason="timeout" if isinstance(exc,TimeoutError) else "payload_mismatch" if str(exc)=="payload mismatch" else "socket_error"
                        reasons[reason]=reasons.get(reason,0)+1
                        break
        except OSError:
            errors+=1
            reasons["connect_error"]=1
        return dict(ok=ok,errors=errors,latency_ms=samples,error_reasons=reasons)
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results=list(pool.map(lambda _:worker(),range(concurrency)))
    reasons={}
    for result in results:
        for name,count in result['error_reasons'].items():
            reasons[name]=reasons.get(name,0)+count
    return dict(error_reasons=reasons,ok=sum(r['ok'] for r in results), errors=sum(r['errors'] for r in results),
                bytes=sum(r['ok'] for r in results)*size,elapsed=time.monotonic()-start,
                latency_ms=[v for r in results for v in r['latency_ms']],
                latency_weights=[r['ok']/len(r['latency_ms']) for r in results if r['latency_ms'] for _ in r['latency_ms']])


def summarize(samples):
    ok=sum(s['ok'] for s in samples)
    errors=sum(s['errors'] for s in samples)
    elapsed=sum(s['elapsed'] for s in samples)
    latency=sorted((v,w) for s in samples for v,w in zip(s['latency_ms'],s.get('latency_weights',[1]*len(s['latency_ms']))))
    def quantile(fraction):
        if not latency:
            return None
        target=sum(w for _,w in latency)*fraction
        cumulative=0
        for value,weight in latency:
            cumulative+=weight
            if cumulative>=target:
                return value
        return latency[-1][0]
    return dict(status='passed' if ok and not errors else 'failed',
                goodput_mbps=sum(s['bytes'] for s in samples)*8/elapsed/1e6 if elapsed else 0,
                transactions_per_second=ok/elapsed if elapsed else 0,
                error_rate=errors/(ok+errors) if ok+errors else None,
                p50_ms=quantile(.5),p95_ms=quantile(.95),
                latency_estimator='weighted per-worker bounded reservoir')


def comparisons(runs):
    baseline={(r['tool'],r['protocol'],r['block']):r for r in runs
              if r['ban_count'] is None and r['status']=='passed'}
    grouped={}
    for r in runs:
        if r['ban_count'] is None or r['status']!='passed':
            continue
        base=baseline.get((r['tool'],r['protocol'],r['block']))
        if not base or base['goodput_mbps']<=0:
            continue
        grouped.setdefault((r['tool'],r['protocol'],r['ban_count']),[]).append(
            100*(r['goodput_mbps']-base['goodput_mbps'])/base['goodput_mbps'])
    return [dict(tool=t,protocol=p,ban_count=n,pairs=len(values),
                 paired_goodput_change_percent=values,
                 median_change_percent=statistics.median(values),
                 interpretation='descriptive same-host pairs, no capacity or significance claim')
            for (t,p,n),values in sorted(grouped.items())]


def measured_load(invocation,owned,monitored,directory,timeout=90):
    resource_start=time.monotonic()
    before={name:snapshot(process.pid) for name,process in monitored.items()}
    peak={name:value['rss_bytes'] for name,value in before.items()}
    with open(directory/'load.json','w+') as output, open(directory/'load.err','w+') as errors:
        measured=owned.start(invocation,stdout=output,stderr=errors,text=True)
        while measured.poll() is None:
            if time.monotonic()-resource_start>timeout:
                raise RuntimeError('workload timeout')
            for name,process in monitored.items():
                peak[name]=max(peak[name],snapshot(process.pid)['rss_bytes'])
            time.sleep(.05)
        measured.wait()
        if measured.returncode:
            errors.seek(0)
            raise RuntimeError('workload failed: '+errors.read()[:500])
        output.seek(0)
        sample=json.load(output)
    resource_elapsed=time.monotonic()-resource_start
    resources={}
    for name,process in monitored.items():
        after=snapshot(process.pid)
        resources[name]=dict(cpu_percent_one_core=100*(after['cpu_seconds']-before[name]['cpu_seconds'])/resource_elapsed,
                             peak_sampled_rss_bytes=peak[name],sample_interval_seconds=.05,
                             measured_wall_seconds=resource_elapsed)
    return sample,resources


def run(args, report):
    full=not args.forward_only
    if full:
        guard(args.original_inode,args.original_mount_inode)
        setup()
    sizes=[] if args.forward_only else args.ban_sizes
    report['schedule']=schedule(args.tools,args.protocols,sizes,args.repeats,args.seed)
    for condition in report['schedule']:
        report['active_condition']=condition
        report['phase']='startup'
        with tempfile.TemporaryDirectory(prefix='relay-bench-') as temp, Processes(grace=3) as owned:
            directory=Path(temp)
            protocol=condition['protocol']
            backend='10.231.3.2' if full else '127.0.0.1'
            target='10.231.1.1' if full else '127.0.0.1'
            backend_port=29000 if full else free_port(backend,protocol)
            port=30000 if full else free_port(target,protocol)
            prefix=['ip','netns','exec','backend'] if full else []
            owned.start(prefix+[sys.executable,str(Path(__file__).resolve()),'--echo',protocol,str(backend_port),str(args.payload),'--echo-host',backend],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            if condition['tool']=='gost' and protocol=='udp':
                listener='0.0.0.0' if full else target
                owned.start([args.gost,'-L',f'udp://{listener}:{port}/{backend}:{backend_port}?keepAlive=true'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            else:
                start_forwarder(args,owned,directory,condition['tool'],protocol,'0.0.0.0' if full else target,backend,port,backend_port)
            forwarder=owned.children[-1]
            import contextlib
            with DecisionAPI() if full and condition['ban_count'] is not None else contextlib.nullcontext() as api:
                bouncer=None
                if api:
                    import yaml
                    for i in range(condition['ban_count']):
                        address='198.18.%s.%s' % (i//256,i%256)
                        api.set_ban(address,True)
                        api.active[address]['id']=i+1
                    config=dict(mode='nftables',update_frequency='1s',api_url=api.url,api_key=api.key,
                                log_mode='stdout',log_level='error',disable_ipv6=True,deny_action='DROP',
                                blacklists_ipv4='crowdsec-blacklists',blacklists_ipv6='crowdsec6-blacklists',
                                nftables_hooks=['input','forward'],
                                nftables=dict(ipv4={'enabled':True,'set-only':False,'table':'crowdsec','chain':'crowdsec-chain','priority':-10},ipv6={'enabled':False}))
                    config_path=directory/'bouncer.yaml'
                    config_path.write_text(yaml.safe_dump(config))
                    bouncer=owned.start([args.bouncer,'-c',str(config_path)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                    deadline=time.monotonic()+20
                    while time.monotonic()<deadline:
                        rules=json.loads(command(['nft','-j','list','ruleset']))
                        if any(item.get('chain',{}).get('table')=='crowdsec' for item in rules['nftables']):
                            break
                        if bouncer.poll() is not None:
                            raise RuntimeError('benchmark bouncer exited during startup')
                        time.sleep(.1)
                    else:
                        raise RuntimeError('benchmark bouncer rules not ready')
                    if condition['ban_count']:
                        wait_set('198.18.0.0',True)
                        wait_set('198.18.%s.%s'%((condition['ban_count']-1)//256,(condition['ban_count']-1)%256),True)
                report['phase']='warmup'
                invocation=[sys.executable,str(Path(__file__).resolve()),'--load',target,str(port),protocol,str(args.duration),str(args.concurrency),str(args.payload)]
                if full:
                    invocation=['ip','netns','exec','bad']+invocation
                # Readiness then a fixed warmup outside the measured interval.
                for _ in range(30):
                    ready=subprocess.run(invocation[:-3]+['0.05','1',str(args.payload)],capture_output=True,text=True)
                    if ready.returncode==0 and json.loads(ready.stdout)['ok']:
                        break
                    time.sleep(.1)
                else:
                    raise RuntimeError('forwarder/backend not ready')
                if args.warmup:
                    subprocess.run(invocation[:-3]+[str(args.warmup),str(args.concurrency),str(args.payload)],capture_output=True,check=True)
                monitored={'forwarder':forwarder}
                if bouncer:
                    monitored['bouncer']=bouncer
                report['phase']='measurement'
                sample,resources=measured_load(invocation,owned,monitored,directory)
                report['runs'].append(dict(condition,**summarize([sample]),raw=sample,resources=resources))
                report.pop('active_condition',None)
                report.pop('phase',None)
            # Bouncer must exit and release its rules before the next baseline.
        if full:
            rules=json.loads(command(['nft','-j','list','ruleset']))
            for family,table in { (v['table']['family'],v['table']['name']) for v in rules['nftables'] if 'table' in v and v['table']['name'] in ('crowdsec','crowdsec6') }:
                command(['nft','delete','table',family,table])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gost',default='gost'); parser.add_argument('--realm',default='realm')
    parser.add_argument('--bouncer',default='crowdsec-firewall-bouncer')
    parser.add_argument('--tools',default='gost,realm'); parser.add_argument('--protocols',default='tcp,udp')
    parser.add_argument('--ban-sizes',default='0,1000')
    parser.add_argument('--duration',type=float,default=5); parser.add_argument('--warmup',type=float,default=.5)
    parser.add_argument('--concurrency',type=int,default=4); parser.add_argument('--payload',type=int,default=1024)
    parser.add_argument('--repeats',type=int,default=3); parser.add_argument('--seed',type=int,default=17)
    parser.add_argument('--forward-only',action='store_true'); parser.add_argument('--output')
    parser.add_argument('--original-inode',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--original-mount-inode',type=int,help=argparse.SUPPRESS)
    parser.add_argument('--echo',nargs=3,help=argparse.SUPPRESS); parser.add_argument('--echo-host',default='127.0.0.1',help=argparse.SUPPRESS)
    parser.add_argument('--load',nargs=6,help=argparse.SUPPRESS)
    args=parser.parse_args()
    if args.echo:
        protocol,port,size=args.echo; echo(protocol,int(port),int(size),args.echo_host); return 0
    if args.load:
        host,port,protocol,duration,concurrency,size=args.load
        print(json.dumps(load(host,int(port),protocol,float(duration),int(concurrency),int(size))))
        return 0
    report=dict(schema=1,status='unverified',runs=[],environment=dict(kernel=platform.release(),machine=platform.machine(),logical_cpus=os.cpu_count()),
                forwarder_settings={'gost_udp_keepAlive':True,'realm_udp':True},
                scope='same-host IPv4 closed-loop echo goodput; not WAN capacity or full CrowdSec engine cost',
                decision_api='synthetic loopback fixture; official bouncer' if not args.forward_only else None)
    for name,path in [('cgroup_cpu_max','/sys/fs/cgroup/cpu.max'),('cgroup_memory_max','/sys/fs/cgroup/memory.max')]:
        try:
            report['environment'][name]=Path(path).read_text().strip()
        except OSError:
            report['environment'][name]=None
    report['environment']['load_average_start']=os.getloadavg()
    report['environment']['memory_total_kib']=next((int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemTotal:')),None)
    code=2
    try:
        args.tools=args.tools.split(','); args.protocols=args.protocols.split(','); args.ban_sizes=[int(v) for v in args.ban_sizes.split(',')]
        if len(set(args.tools))!=len(args.tools) or len(set(args.protocols))!=len(args.protocols) or len(set(args.ban_sizes))!=len(args.ban_sizes):
            raise ValueError('duplicate selectors')
        if not args.tools or any(v not in ('gost','realm') for v in args.tools) or any(v not in ('tcp','udp') for v in args.protocols):
            raise ValueError('invalid tools/protocols')
        if not (.1<=args.duration<=60 and 0<=args.warmup<=10 and 1<=args.concurrency<=64 and 1<=args.payload<=1200 and 1<=args.repeats<=10 and all(0<=n<=10000 for n in args.ban_sizes)):
            raise ValueError('invalid duration/warmup/concurrency/payload/repeats/ban sizes')
        report['parameters']={key:getattr(args,key) for key in ('tools','protocols','ban_sizes','duration','warmup','concurrency','payload','repeats','seed','forward_only')}
        if not args.forward_only:
            try:
                import yaml
            except ImportError as exc:
                raise FileNotFoundError('missing Python module: yaml (PyYAML)') from exc
        report['versions']={}
        for name in args.tools+([] if args.forward_only else ['bouncer']):
            binary=shutil.which(getattr(args,name))
            if not binary:
                raise FileNotFoundError('missing executable: '+name)
            setattr(args,name,str(Path(binary).resolve()))
            report['versions'][name]=command([binary,'-V' if name=='gost' else '--version' if name=='realm' else '-version']).strip()
        if not args.forward_only and args.original_inode is None:
            for name in ('unshare','ip','nft','mount'):
                if not shutil.which(name):
                    raise FileNotFoundError('missing executable: '+name)
            invocation=[sys.executable,str(Path(__file__).resolve())]+sys.argv[1:]
            # Worker emits to stdout; parent alone writes the caller's output path.
            if '--output' in invocation:
                index=invocation.index('--output'); del invocation[index:index+2]
            invocation+=['--original-inode',str(os.stat('/proc/self/ns/net').st_ino),'--original-mount-inode',str(os.stat('/proc/self/ns/mnt').st_ino)]
            with Processes() as owned:
                worker=owned.start(['unshare','--net','--mount','--']+invocation,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                stdout,stderr=worker.communicate()
            if stdout.strip():
                report=json.loads(stdout); code=worker.returncode
            else:
                report['error']=stderr.strip(); code=2
        else:
            run(args,report)
            code=0 if report['runs'] and all(r['status']=='passed' for r in report['runs']) else 1
    except (FileNotFoundError,PermissionError) as exc:
        report['error']=str(exc); code=2
    except (Exception,KeyboardInterrupt) as exc:
        report['error']=str(exc); code=1
    report['comparisons']=comparisons(report['runs'])
    report['status']={0:'passed',1:'failed',2:'unverified'}[code]; report['exit_code']=code
    data=json.dumps(report,indent=2)+'\n'
    if args.output:
        Path(args.output).write_text(data)
    print(data,end='')
    return code

if __name__=='__main__':
    sys.exit(main())
