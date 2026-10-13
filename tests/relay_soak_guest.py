#!/usr/bin/env python3
"""Read-only soak observer plus bounded decision probes, restricted to disposable QEMU guests.

Endpoint/service provisioning is external and immutable. This observer never installs
packages or changes services/firewalls directly. Decision commands require the lab marker.
"""
import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import statistics
import sys
import threading
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from vps_guest_runtime import run_bounded, service_healthy

PATHS=('gost_tcp','gost_udp','realm_tcp','realm_udp')
RECOVERIES=('center_disconnect','bouncer_restart','center_restart')


def number(value):
    return type(value) in (int,float) and math.isfinite(value)


def trend(values):
    # Twenty-minute medians damp short noise; repeated directional change still fails.
    windows=[statistics.median(values[i:i+20]) for i in range(0,len(values)-19,20)]
    if len(windows)<3:return {'slope_per_hour':None,'correlation':None,'directional_fraction':None}
    x=list(range(len(windows)));mx=statistics.mean(x);my=statistics.mean(windows)
    covariance=sum((a-mx)*(b-my) for a,b in zip(x,windows))
    xx=sum((a-mx)**2 for a in x);yy=sum((b-my)**2 for b in windows)
    slope=covariance/xx*3
    correlation=covariance/(xx*yy)**.5 if xx and yy else 0
    changes=[b-a for a,b in zip(windows,windows[1:])]
    fraction=sum((v<0 if slope<0 else v>0) for v in changes)/len(changes)
    return {'slope_per_hour':slope,'correlation':correlation,'directional_fraction':fraction}


def sustained(trend_data,direction):
    slope=trend_data['slope_per_hour'];r=trend_data['correlation']
    return slope is not None and slope*direction>0 and r*direction>=.8 and trend_data['directional_fraction']>=.75


def assess(report):
    failures=[]
    def require(condition,reason):
        if not condition:failures.append(reason)
    duration=report.get('duration_seconds');elapsed=report.get('elapsed_seconds')
    if not number(duration) or duration<60 or duration>86400:
        return {'status':'failed','qualified_24h':False,'failures':['Invalid duration.']}
    require(number(elapsed) and elapsed>=duration,'Early termination.')
    require(report.get('complete') is True,'Missing completion.')
    require(type(report.get('exit_code')) is int and report['exit_code']==0,'Missing or invalid exit.')
    mode=report.get('mode');require(mode in ('remote','local','baseline'),'Invalid mode.')
    setup=report.get('setup',{})
    require(isinstance(setup,dict) and set(setup)=={'ready','elapsed_seconds','budget_seconds','paths'} and
            setup.get('ready') is True and type(setup.get('budget_seconds')) is int and setup['budget_seconds']==30 and
            number(setup.get('elapsed_seconds')) and 0<=setup['elapsed_seconds']<=30 and
            isinstance(setup.get('paths'),dict) and set(setup['paths'])==set(PATHS) and
            all(value is True for value in setup['paths'].values()),'Endpoint setup missing, unready or late.')
    expected=() if mode=='baseline' else ('crowdsec-firewall-bouncer',) if mode=='remote' else ('crowdsec','crowdsec-firewall-bouncer')
    samples=report.get('samples',[])
    require(isinstance(samples,list) and len(samples)==int(duration//60)+1,'Missing minute samples.')
    if not isinstance(samples,list) or not samples:return {'status':'failed','qualified_24h':False,'failures':failures+['No samples.']}
    first=samples[0];previous=None
    for index,row in enumerate(samples):
        t=row.get('elapsed')
        require(number(t) and index*60<=t<=index*60+10,'Sample missing or late.')
        total=row.get('mem_total_kib');available=row.get('mem_available_kib')
        require(type(total) is int and total>0 and total==first.get('mem_total_kib') and type(available) is int and 0<=available<=total,'Invalid memory sample.')
        require(type(row.get('oom_kills')) is int and row['oom_kills']>=0 and row['oom_kills']==first.get('oom_kills'),'OOM occurred or measurement missing.')
        require(type(row.get('rules')) is int and row['rules']>=0,'Missing firewall measurement.')
        services=row.get('services',{})
        require(isinstance(services,dict) and set(services)==set(expected),'Missing services.')
        for name in expected:
            item=services.get(name,{})
            base=first.get('services',{}).get(name,{})
            require(item.get('healthy') is True and type(item.get('pid')) is int and item['pid']>0 and item['pid']==base.get('pid'),'Service stopped or PID changed.')
            require(type(item.get('restarts')) is int and item['restarts']==base.get('restarts'),'Unexpected service restart.')
            require(type(item.get('rss_bytes')) is int and item['rss_bytes']>0 and number(item.get('cpu_seconds')) and item['cpu_seconds']>=0,'Missing process resources.')
        paths=row.get('paths',{})
        require(isinstance(paths,dict) and set(paths)==set(PATHS),'Missing relay paths.')
        for path in PATHS:
            counts=paths.get(path,{})
            ok=counts.get('ok');errors=counts.get('errors')
            valid=type(ok) is int and ok>=0 and type(errors) is int and errors>=0
            require(valid,'Invalid traffic count.')
            if not valid:continue
            if previous:
                old=previous.get('paths',{}).get(path,{})
                require(ok>=old.get('ok',0) and errors>=old.get('errors',0),'Traffic counters regressed.')
                delta=ok+errors-old.get('ok',0)-old.get('errors',0)
                dt=t-previous.get('elapsed',0) if number(t) and number(previous.get('elapsed')) else 60
                require(delta>=dt*.98,'Minute workload gap.')
            if index==len(samples)-1:
                require(ok+errors>=duration*.98,'Missing workload attempts.')
                require(ok/(ok+errors)>=.999 if ok+errors else False,'Connection success below 99.9%.')
        previous=row
    final=report.get('final_observation',{})
    require(isinstance(final,dict) and number(final.get('elapsed')) and final['elapsed']>=duration,'Missing or early final observation.')
    if isinstance(final,dict):
        require(type(final.get('oom_kills')) is int and final['oom_kills']>=0 and final['oom_kills']==first.get('oom_kills'),'Final OOM measurement failed.')
        final_services=final.get('services',{})
        require(isinstance(final_services,dict) and set(final_services)==set(expected),'Missing final services.')
        for unit in expected:
            item=final_services.get(unit,{}) if isinstance(final_services,dict) else {}
            base=first.get('services',{}).get(unit,{})
            require(item.get('healthy') is True and type(item.get('pid')) is int and item['pid']==base.get('pid') and type(item.get('restarts')) is int and item['restarts']==base.get('restarts'),'Final service unhealthy or restarted.')
    if duration==86400:
        for path in PATHS:
            counts=samples[-1].get('burst_paths',{}).get(path,{})
            ok=counts.get('ok');errors=counts.get('errors')
            valid=type(ok) is int and ok>=0 and type(errors) is int and errors>=0
            require(valid,'Missing burst measurement.')
            if valid:
                require(ok+errors>=3*4*60*.98,'Missing six-hour burst workload.')
                require(ok/(ok+errors)>=.999 if ok+errors else False,'Burst success below 99.9%.')
    sync=report.get('sync',[])
    expected_hours=set(range(1,int(duration//3600)+1)) if mode!='baseline' else set()
    require(isinstance(sync,list) and len(sync)==len(expected_hours) and {r.get('hour') for r in sync}==expected_hours,'Missing or extra hourly synchronization.')
    for row in sync:
        require(row.get('add') is True and row.get('delete') is True and all(number(row.get(k)) and 0<=row[k]<=60 for k in ('add_seconds','delete_seconds')),'Synchronization failed or exceeded 60 seconds.')
    for row in report.get('recoveries',[]):
        require(row.get('case') in RECOVERIES and row.get('passed') is True and number(row.get('recovery_seconds')) and 0<=row['recovery_seconds']<=120,'Recovery failed or exceeded 120 seconds.')
    # Explicit conservative gate, not a capacity estimate. Compare final six-hour halves.
    plateau=False;memory_trend=None;rss_trends={}
    if duration==86400 and len(samples)>=361:
        old=samples[-361:-181];new=samples[-181:]
        limit=max(16384,first.get('mem_total_kib',0)*.05)
        plateau=statistics.median(r.get('mem_available_kib',0) for r in new)>=statistics.median(r.get('mem_available_kib',0) for r in old)-limit
        for name in expected:
            old_rss=[r.get('services',{}).get(name,{}).get('rss_bytes',0) for r in old]
            new_rss=[r.get('services',{}).get(name,{}).get('rss_bytes',0) for r in new]
            plateau=plateau and statistics.median(new_rss)<=statistics.median(old_rss)+limit*1024
        memory_trend=trend([r.get('mem_available_kib',0) for r in samples[-361:]])
        plateau=plateau and not sustained(memory_trend,-1)
        for name in expected:
            rss_trends[name]=trend([r.get('services',{}).get(name,{}).get('rss_bytes',0) for r in samples[-361:]])
            plateau=plateau and not sustained(rss_trends[name],1)
        require(plateau,'Final six-hour memory plateau not established.')
    return {'status':'failed' if failures else 'passed','qualified_24h':not failures and duration==86400 and plateau,'failures':sorted(set(failures)),
            'resources':{'minimum_mem_available_kib':min(r.get('mem_available_kib',0) for r in samples),'peak_rss_bytes':{name:max(r.get('services',{}).get(name,{}).get('rss_bytes',0) for r in samples) for name in expected},'final_six_hour_available_memory_trend':memory_trend,'final_six_hour_rss_trends':rss_trends},
            'recovery_qualified':set(r.get('case') for r in report.get('recoveries',[]) if r.get('passed') is True)==set(RECOVERIES)}


class Traffic:
    """Persistent TCP/UDP connections; bounded one-second exchange and 1 KiB payload."""
    def __init__(self,endpoints):
        self.endpoints=endpoints;self.counts={p:{'ok':0,'errors':0} for p in PATHS}
        self.burst_counts={p:{'ok':0,'errors':0} for p in PATHS}
        self.lock=threading.Lock();self.stop=threading.Event();self.burst=threading.Event();self.threads=[]
    def __enter__(self):
        for path in PATHS:
            for worker in range(4):
                t=threading.Thread(target=self.worker,args=(path,worker),daemon=True);t.start();self.threads.append(t)
        return self
    def worker(self,path,worker):
        sock=None;payload=b'x'*1024
        try:
            while not self.stop.is_set():
                started=time.monotonic();exchange_deadline=started+1
                if worker and not self.burst.is_set():self.stop.wait(.1);continue
                ok=False
                try:
                    if sock is None:
                        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if path.endswith('tcp') else socket.SOCK_DGRAM)
                        sock.settimeout(1);sock.connect(tuple(self.endpoints[path]))
                    sock.settimeout(max(.001,exchange_deadline-time.monotonic()))
                    sock.sendall(payload)
                    if path.endswith('tcp'):
                        result=b''
                        while len(result)<1024:
                            remaining=exchange_deadline-time.monotonic()
                            if remaining<=0:raise TimeoutError('exchange deadline')
                            sock.settimeout(remaining)
                            part=sock.recv(1024-len(result))
                            if not part:raise OSError('early EOF')
                            result+=part
                    else:
                        sock.settimeout(max(.001,exchange_deadline-time.monotonic()))
                        result=sock.recv(65535)
                    ok=result==payload
                except OSError:
                    if sock is not None:sock.close();sock=None
                with self.lock:
                    key='ok' if ok else 'errors'
                    if worker==0:self.counts[path][key]+=1
                    if self.burst.is_set():self.burst_counts[path][key]+=1
                self.stop.wait(max(0,1-(time.monotonic()-started)))
        finally:
            if sock is not None:sock.close()
    def snapshot(self):
        with self.lock:return {p:dict(c) for p,c in self.counts.items()}
    def burst_snapshot(self):
        with self.lock:return {p:dict(c) for p,c in self.burst_counts.items()}
    def sample(self,origin=None):
        with self.lock:
            return {'elapsed':0 if origin is None else time.monotonic()-origin,
                    'paths':{p:dict(c) for p,c in self.counts.items()},
                    'burst_paths':{p:dict(c) for p,c in self.burst_counts.items()}}
    def __exit__(self,*_):
        self.stop.set()
        for thread in self.threads:thread.join(timeout=2)


def wait_endpoints_ready(endpoints,timeout=30):
    """Check the full echo chain before measuring; never forgive measured errors."""
    start=time.monotonic();deadline=start+timeout;paths={path:False for path in PATHS}
    payload=b'x'*1024
    while time.monotonic()<deadline:
        paths={path:False for path in PATHS}
        for path in PATHS:
            if time.monotonic()>=deadline:break
            exchange_deadline=min(deadline,time.monotonic()+1)
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM if path.endswith('tcp') else socket.SOCK_DGRAM) as sock:
                    sock.settimeout(max(.001,exchange_deadline-time.monotonic()))
                    sock.connect(tuple(endpoints[path]));sock.sendall(payload)
                    result=b''
                    while len(result)<len(payload):
                        remaining=exchange_deadline-time.monotonic()
                        if remaining<=0:raise TimeoutError('readiness deadline')
                        sock.settimeout(remaining)
                        chunk=sock.recv(len(payload)-len(result) if path.endswith('tcp') else 65535)
                        if not chunk:raise OSError('early EOF')
                        result+=chunk
                        if path.endswith('udp'):break
                    paths[path]=result==payload and time.monotonic()<=exchange_deadline
            except OSError:pass
        if all(paths.values()) and time.monotonic()<=deadline:
            return {'ready':True,'elapsed_seconds':time.monotonic()-start,'budget_seconds':timeout,'paths':paths}
        time.sleep(min(.1,max(0,deadline-time.monotonic())))
    return {'ready':False,'elapsed_seconds':time.monotonic()-start,'budget_seconds':timeout,'paths':paths}


def observe(services,traffic,*,origin=None):
    from benchmark_relay import snapshot
    memory={line.split(':')[0]:int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines()}
    vmstat=dict(line.split() for line in Path('/proc/vmstat').read_text().splitlines())
    rc,rules,_=run_bounded(['nft','-j','list','ruleset'],timeout=5)
    if rc:raise RuntimeError('Firewall measurement failed')
    nft=json.loads(rules)
    resources={}
    for unit in services:
        rc,out,_=run_bounded(['systemctl','show',unit,'-p','ActiveState','-p','SubState','-p','Result','-p','NRestarts','-p','MainPID'],timeout=5)
        if rc:raise RuntimeError('Service measurement failed')
        props=dict(line.split('=',1) for line in out.splitlines() if '=' in line)
        pid=int(props['MainPID'])
        resources[unit]={'healthy':service_healthy(out),'restarts':int(props['NRestarts']),'pid':pid,**snapshot(pid)}
    return {**traffic.sample(origin),'mem_total_kib':memory['MemTotal'],'mem_available_kib':memory['MemAvailable'],'oom_kills':int(vmstat['oom_kill']),
            'rules':sum('rule' in item for item in nft['nftables']),'services':resources}


def synchronize(cscli,address,action):
    start=time.monotonic();deadline=start+60
    args=cscli+['decisions',action,'--ip',address]
    if action=='add':args+=['--duration','10m']
    rc,_,_=run_bounded(args,timeout=20)
    if rc:return False,time.monotonic()-start
    while time.monotonic()<deadline:
        rc,out,_=run_bounded(['nft','-j','list','ruleset'],timeout=min(5,deadline-time.monotonic()))
        if rc==0 and (address in out)==(action=='add') and time.monotonic()<=deadline:return True,time.monotonic()-start
        time.sleep(min(1,max(0,deadline-time.monotonic())))
    return False,time.monotonic()-start


def validate_manifest(config):
    if set(config)!={'mode','duration_seconds','endpoints','cscli','lab_id'}:raise ValueError('Invalid immutable soak manifest')
    if config['mode'] not in ('local','remote','baseline') or type(config['duration_seconds']) is not int or config['duration_seconds'] not in (120,3600,86400):raise ValueError('Invalid mode/duration')
    if set(config['endpoints'])!=set(PATHS):raise ValueError('All four relay paths required')
    for host,port in config['endpoints'].values():
        if host!='127.0.0.1' or type(port) is not int or not 1024<=port<=65535:raise ValueError('Only disposable guest loopback endpoints permitted')
    if config['mode']!='baseline' and (not isinstance(config['cscli'],list) or not config['cscli'] or config['cscli'][0] not in ('/usr/bin/cscli','/opt/test/bin/cscli') or any(not isinstance(s,str) for s in config['cscli'])):raise ValueError('Invalid decision command')
    return config


class BurstSchedule:
    def __init__(self,duration):
        self.duration=duration;self.next_start=21600;self.end=None
    def update(self,elapsed):
        if self.end is not None and elapsed>=self.end:
            self.end=None;return 'end'
        if self.end is None and elapsed>=self.next_start and self.next_start<self.duration:
            self.end=elapsed+60;self.next_start+=21600;return 'start'
        return None


def hourly_sync(cscli,hour):
    add,add_t=synchronize(cscli,'198.51.100.80','add')
    delete,delete_t=synchronize(cscli,'198.51.100.80','delete')
    return {'hour':hour,'add':add,'delete':delete,'add_seconds':add_t,'delete_seconds':delete_t}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    config=validate_manifest(json.loads(a.manifest.read_text()))
    rc,virt,_=run_bounded(['systemd-detect-virt','--vm'],timeout=5)
    marker=Path('/run/crowdsec-vps-lab')
    if rc or virt.strip()!='qemu' or not marker.is_file() or marker.read_text().strip()!=config['lab_id']:p.error('Only explicitly provisioned disposable QEMU guests permitted')
    events=a.output.with_suffix('.jsonl')
    if a.output.exists() or events.exists():p.error('Refusing to overwrite soak evidence')
    services=[] if config['mode']=='baseline' else ['crowdsec-firewall-bouncer'] if config['mode']=='remote' else ['crowdsec','crowdsec-firewall-bouncer']
    report={'mode':config['mode'],'duration_seconds':config['duration_seconds'],'complete':False,'samples':[],'sync':[],'recoveries':[],
            'manifest_sha256':hashlib.sha256(a.manifest.read_bytes()).hexdigest(),'observer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'exit_code':1}
    start=None;duration=config['duration_seconds'];next_sample=60;next_sync=3600;burst=BurstSchedule(duration);future=None
    with events.open('x') as log:
        def event(kind,value):log.write(json.dumps({'kind':kind,**value})+'\n');log.flush()
        try:
            # No long baseline is inferred from benchmark_relay's <=60s load command.
            setup=wait_endpoints_ready(config['endpoints'])
            report['setup']=setup;event('setup',setup)
            if not setup['ready']:raise RuntimeError('Endpoint setup failed')
            traffic=Traffic(config['endpoints'])
            sample=observe(services,traffic);report['samples'].append(sample);event('sample',sample)
            start=time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, traffic:
                while time.monotonic()-start<duration or next_sample<=duration or future is not None:
                    elapsed=time.monotonic()-start
                    if elapsed>=next_sample and next_sample<=duration:
                        sample=observe(services,traffic,origin=start);report['samples'].append(sample);event('sample',sample);next_sample+=60
                    if elapsed>=next_sync and next_sync<=duration and config['mode']!='baseline' and future is None:
                        future=executor.submit(hourly_sync,config['cscli'],next_sync//3600);next_sync+=3600
                    if future is not None and future.done():
                        item=future.result();report['sync'].append(item);event('sync',item);future=None
                    elapsed=time.monotonic()-start
                    change=burst.update(elapsed)
                    if change=='start':traffic.burst.set()
                    elif change=='end':traffic.burst.clear()
                    if elapsed>=duration and next_sample>duration and future is None:break
                    time.sleep(.1)
                final=observe(services,traffic,origin=start)
                initial=report['samples'][0]
                final_ok=final['oom_kills']==initial['oom_kills'] and all(final['services'][u]['healthy'] and final['services'][u]['pid']==initial['services'][u]['pid'] and final['services'][u]['restarts']==initial['services'][u]['restarts'] for u in services)
                report['final_observation']=final;event('final_observation',final)
            report.update(complete=final_ok,exit_code=0 if final_ok else 1)
        except (Exception,KeyboardInterrupt) as error:
            # Avoid raw exceptions/config/command output in externally archived evidence.
            report['failure_category']=type(error).__name__
        finally:
            report['elapsed_seconds']=0 if start is None else time.monotonic()-start
            report['assessment']=assess(report);event('complete',{'complete':report['complete'],'assessment':report['assessment']})
            with a.output.open('x') as f:f.write(json.dumps(report,indent=2)+'\n')
    print('VPS_SOAK_COMPLETE '+json.dumps({k:report[k] for k in ('mode','duration_seconds','elapsed_seconds','complete','exit_code','manifest_sha256','observer_sha256')}),flush=True)
    return 0 if report['assessment']['status']=='passed' else 1

if __name__=='__main__':raise SystemExit(main())
