import copy
import importlib.util
from pathlib import Path
import unittest

class SoakTests(unittest.TestCase):
    def load(self):
        p=Path(__file__).with_name('relay_soak_guest.py')
        self.assertTrue(p.exists(),'soak observer is missing')
        s=importlib.util.spec_from_file_location('soak',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
    def fixture(self):
        services={'crowdsec-firewall-bouncer':{'healthy':True,'restarts':0,'pid':42,'rss_bytes':10000,'cpu_seconds':1}}
        def sample(t):return {'elapsed':t,'mem_total_kib':250000,'mem_available_kib':150000,'oom_kills':0,'rules':1,'services':copy.deepcopy(services),'paths':{p:{'ok':int(t),'errors':0} for p in ('gost_tcp','gost_udp','realm_tcp','realm_udp')},'burst_paths':{p:{'ok':0,'errors':0} for p in ('gost_tcp','gost_udp','realm_tcp','realm_udp')}}
        return {'duration_seconds':120,'elapsed_seconds':120,'mode':'remote','complete':True,'samples':[sample(0),sample(60),sample(120)],'final_observation':sample(120),'sync':[],'recoveries':[],'exit_code':0,'setup':{'ready':True,'elapsed_seconds':1,'budget_seconds':30,'paths':{p:True for p in ('gost_tcp','gost_udp','realm_tcp','realm_udp')}}}
    def test_complete_short_run_does_not_claim_long_soak(self):
        m=self.load();r=m.assess(self.fixture())
        self.assertEqual(r['status'],'passed');self.assertFalse(r['qualified_24h'])
    def test_missing_sample_or_completion_is_failure(self):
        m=self.load()
        for kind in ('sample','complete','early','exit'):
            r=self.fixture()
            if kind=='sample':r['samples'].pop(1)
            elif kind=='complete':r['complete']=False
            elif kind=='early':r['elapsed_seconds']=119
            else:r['exit_code']=False
            self.assertEqual(m.assess(r)['status'],'failed',kind)
    def test_restart_oom_and_connection_failure_are_rejected(self):
        m=self.load()
        for kind in ('restart','pid','oom','success','missing_path','missing_attempts'):
            r=self.fixture();last=r['samples'][-1]
            if kind=='restart':last['services']['crowdsec-firewall-bouncer']['restarts']=1
            elif kind=='pid':last['services']['crowdsec-firewall-bouncer']['pid']=43
            elif kind=='oom':last['oom_kills']=1
            elif kind=='success':last['paths']['gost_tcp']['errors']=1
            elif kind=='missing_path':last['paths'].pop('realm_udp')
            else:last['paths']['realm_udp']['ok']=0
            self.assertEqual(m.assess(r)['status'],'failed',kind)
    def test_workload_gap_and_invalid_oom_measurement_are_rejected(self):
        m=self.load()
        r=self.fixture()
        for path in m.PATHS:r['samples'][1]['paths'][path]['ok']=0
        self.assertEqual(m.assess(r)['status'],'failed')
        r=self.fixture()
        for row in r['samples']:row['oom_kills']=-1
        self.assertEqual(m.assess(r)['status'],'failed')

    def test_final_observation_is_required_and_independent(self):
        m=self.load()
        for kind in ('missing','failed','oom','pid','restart','early'):
            r=self.fixture()
            if kind=='missing':r.pop('final_observation')
            elif kind=='failed':r['final_observation']['services']['crowdsec-firewall-bouncer']['healthy']=False
            elif kind=='oom':r['final_observation']['oom_kills']=1
            elif kind=='pid':r['final_observation']['services']['crowdsec-firewall-bouncer']['pid']=99
            elif kind=='restart':r['final_observation']['services']['crowdsec-firewall-bouncer']['restarts']=1
            else:r['final_observation']['elapsed']=119
            self.assertEqual(m.assess(r)['status'],'failed',kind)

    def test_sync_and_recovery_budget(self):
        m=self.load()
        for kind in ('sync','recovery'):
            r=self.fixture()
            if kind=='sync':r['sync']=[{'hour':1,'add_seconds':61,'delete_seconds':1,'add':True,'delete':True}]
            else:r['recoveries']=[{'case':'center_disconnect','passed':True,'recovery_seconds':121}]
            self.assertEqual(m.assess(r)['status'],'failed')
    def test_long_run_requires_hourly_sync_and_memory_plateau(self):
        m=self.load();r=self.fixture();r.update(duration_seconds=86400,elapsed_seconds=86400)
        r['samples']=[dict(copy.deepcopy(r['samples'][0]),elapsed=t,paths={p:{'ok':t,'errors':0} for p in m.PATHS}) for t in range(0,86401,60)]
        self.assertEqual(m.assess(r)['status'],'failed')
        r['sync']=[{'hour':h,'add':True,'delete':True,'add_seconds':1,'delete_seconds':1} for h in range(1,25)]
        for row in r['samples']:
            row['burst_paths']={p:{'ok':4*sum(min(60,max(0,row['elapsed']-start)) for start in (21600,43200,64800)),'errors':0} for p in m.PATHS}
        r['final_observation']=copy.deepcopy(r['samples'][-1])
        self.assertEqual(m.assess(r)['status'],'passed');self.assertTrue(m.assess(r)['qualified_24h'])
        for row in r['samples'][-180:]:row['mem_available_kib']=50000
        self.assertEqual(m.assess(r)['status'],'failed')

    def test_missing_burst_workload_cannot_qualify_long_run(self):
        m=self.load();r=self.fixture();r.update(duration_seconds=86400,elapsed_seconds=86400)
        r['samples']=[dict(copy.deepcopy(r['samples'][0]),elapsed=t,paths={p:{'ok':t,'errors':0} for p in m.PATHS}) for t in range(0,86401,60)]
        r['sync']=[{'hour':h,'add':True,'delete':True,'add_seconds':1,'delete_seconds':1} for h in range(1,25)]
        self.assertEqual(m.assess(r)['status'],'failed')

    def test_slow_continuous_memory_decline_is_not_plateau(self):
        m=self.load();r=self.fixture();r.update(duration_seconds=86400,elapsed_seconds=86400)
        first=r['samples'][0]
        r['samples']=[dict(copy.deepcopy(first),elapsed=t,mem_available_kib=150000-int(t/86400*50000),paths={p:{'ok':t,'errors':0} for p in m.PATHS}) for t in range(0,86401,60)]
        r['sync']=[{'hour':h,'add':True,'delete':True,'add_seconds':1,'delete_seconds':1} for h in range(1,25)]
        for row in r['samples']:
            row['burst_paths']={p:{'ok':4*sum(min(60,max(0,row['elapsed']-start)) for start in (21600,43200,64800)),'errors':0} for p in m.PATHS}
        result=m.assess(r)
        self.assertIn('Final six-hour memory plateau not established.',result['failures'])
        self.assertEqual(result['status'],'failed');self.assertFalse(result['qualified_24h'])

    def test_burst_uses_actual_start_time_after_delayed_sync(self):
        m=self.load();self.assertTrue(hasattr(m,'BurstSchedule'))
        schedule=m.BurstSchedule(86400)
        self.assertEqual(schedule.update(21620),'start')
        self.assertIsNone(schedule.update(21660))
        self.assertEqual(schedule.update(21680),'end')
        self.assertEqual(schedule.update(43200),'start')

    def test_setup_evidence_cannot_be_missing_unready_or_late(self):
        m=self.load()
        for kind in ('missing','unready','late','path'):
            r=self.fixture()
            if kind=='missing':r.pop('setup')
            elif kind=='unready':r['setup']['ready']=False
            elif kind=='late':r['setup']['elapsed_seconds']=31
            else:r['setup']['paths']['realm_udp']=False
            self.assertEqual(m.assess(r)['status'],'failed',kind)


class TrafficTests(unittest.TestCase):
    def test_real_persistent_loopback_echo(self):
        import socket,threading,time
        m=SoakTests().load()
        sockets=[];threads=[];endpoints={};stopped=threading.Event()
        def server(sock,protocol):
            sock.settimeout(.1)
            while not stopped.is_set():
                try:
                    if protocol=='udp':
                        data,peer=sock.recvfrom(65535);sock.sendto(data,peer)
                    else:
                        conn,_=sock.accept();conn.settimeout(.1)
                        with conn:
                            while not stopped.is_set():
                                try:
                                    data=conn.recv(1024)
                                    if not data:break
                                    conn.sendall(data)
                                except socket.timeout:continue
                except socket.timeout:continue
        try:
            for path in m.PATHS:
                protocol=path.split('_')[1];sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1',0));endpoints[path]=list(sock.getsockname());sockets.append(sock)
                if protocol=='tcp':sock.listen(1)
                thread=threading.Thread(target=server,args=(sock,protocol),daemon=True);thread.start();threads.append(thread)
            with m.Traffic(endpoints) as traffic:
                time.sleep(1.15);counts=traffic.snapshot()
            for path in m.PATHS:self.assertGreaterEqual(counts[path]['ok'],2);self.assertEqual(counts[path]['errors'],0)
            self.assertFalse(any(t.is_alive() for t in traffic.threads))
        finally:
            stopped.set()
            for thread in threads:thread.join(timeout=1)
            for sock in sockets:sock.close()

class SetupAndSamplingTests(unittest.TestCase):
    def test_readiness_waits_for_real_delayed_echo_and_has_a_deadline(self):
        import socket, threading, time
        m=SoakTests().load()
        self.assertTrue(hasattr(m,'wait_endpoints_ready'),'Measured load requires actual endpoint readiness')
        sockets=[];threads=[];endpoints={};stop=threading.Event()
        def echo(sock,protocol):
            if stop.wait(.15):return
            if protocol=='tcp':sock.listen(4)
            sock.settimeout(.05)
            while not stop.is_set():
                try:
                    if protocol=='udp':
                        data,peer=sock.recvfrom(2048);sock.sendto(data,peer)
                    else:
                        conn,_=sock.accept()
                        with conn:
                            conn.settimeout(.1)
                            data=conn.recv(2048);conn.sendall(data)
                except (socket.timeout,OSError):continue
        try:
            for path in ('gost_tcp','gost_udp','realm_tcp','realm_udp'):
                protocol=path.split('_')[1]
                sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM if protocol=='tcp' else socket.SOCK_DGRAM)
                sock.bind(('127.0.0.1',0));sockets.append(sock);endpoints[path]=list(sock.getsockname())
                thread=threading.Thread(target=echo,args=(sock,protocol),daemon=True);thread.start();threads.append(thread)
            ready=m.wait_endpoints_ready(endpoints,timeout=2)
            self.assertTrue(ready['ready']);self.assertTrue(all(ready['paths'].values()))
            self.assertGreaterEqual(ready['elapsed_seconds'],.1)
            unavailable=socket.socket();unavailable.bind(('127.0.0.1',0))
            try:
                broken=dict(endpoints,gost_tcp=list(unavailable.getsockname()))
                start=time.monotonic();refused=m.wait_endpoints_ready(broken,timeout=.2)
                self.assertFalse(refused['ready']);self.assertLess(time.monotonic()-start,.6)
            finally:unavailable.close()
        finally:
            stop.set()
            for thread in threads:thread.join(timeout=1)
            for sock in sockets:sock.close()

    def test_sample_time_matches_counters_after_slow_external_queries(self):
        import os
        from unittest.mock import patch
        import inspect
        m=SoakTests().load();clock={'now':10.0}
        self.assertIn('origin',inspect.signature(m.observe).parameters,'Counters require observation-completion time')
        traffic=m.Traffic({p:['127.0.0.1',30001+i] for i,p in enumerate(m.PATHS)})
        def query(argv,**kwargs):
            clock['now']+=3
            for counts in traffic.counts.values():counts['ok']+=3
            if argv[0]=='nft':return 0,'{"nftables":[]}',False
            return 0,'ActiveState=active\nSubState=running\nResult=success\nNRestarts=0\nMainPID='+str(os.getpid())+'\n',False
        with patch.object(m,'run_bounded',side_effect=query),patch.object(m.time,'monotonic',side_effect=lambda:clock['now']):
            row=m.observe(['crowdsec-firewall-bouncer'],traffic,origin=10.0)
        self.assertEqual(row['elapsed'],6.0)
        self.assertEqual(row['paths']['gost_tcp']['ok'],6)
