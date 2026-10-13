"""Throwaway probe: packet-source/enforcement paths, not V2bX core behavior."""
import http.server,json,os,subprocess,sys,tempfile,time
from pathlib import Path
sys.path.insert(0,'/workspace/tests')
from relay_network_lab import Processes,DecisionAPI,command,drop_packets,guard
from verify_relay_network import setup,client,start_forwarder
from types import SimpleNamespace

def backend_rules():
    return command(['ip','netns','exec','backend','nft','-j','list','ruleset'])

def wait_backend(address,enabled):
    end=time.monotonic()+15
    while time.monotonic()<end:
        if (address in backend_rules())==enabled:return
        time.sleep(.2)
    raise RuntimeError('Landing Bouncer synchronization timeout')

def run(original_net,original_mount):
    guard(original_net,original_mount)
    setup()
    report={'scope':'landing namespace real official Bouncer; synthetic decision API; direct/routed DNAT preserve/gost proxy; fresh sessions only; no protocol auth detection','cases':[],'decision_api':'synthetic isolated fixture'}
    import yaml
    with tempfile.TemporaryDirectory() as temp,Processes(grace=3) as owned:
        base=Path(temp)
        api=DecisionAPI()
        handler=api.server.RequestHandlerClass
        api.server.server_close()
        api.server=http.server.ThreadingHTTPServer(('10.231.3.1',0),handler)
        api.url='http://10.231.3.1:%s/'%api.server.server_port
        with api:
            config=dict(mode='nftables',update_frequency='1s',api_url=api.url,api_key=api.key,log_mode='stdout',log_level='info',disable_ipv6=False,deny_action='DROP',blacklists_ipv4='crowdsec-blacklists',blacklists_ipv6='crowdsec6-blacklists',nftables_hooks=['input'],nftables={family:{'enabled':True,'set-only':False,'table':table,'chain':'crowdsec-chain','priority':-10} for family,table in [('ipv4','crowdsec'),('ipv6','crowdsec6')]})
            path=base/'bouncer.yaml';path.write_text(yaml.safe_dump(config));path.chmod(0o600)
            with (base/'bouncer.log').open('w') as log:
                proc=owned.start(['ip','netns','exec','backend','/bin/crowdsec-firewall-bouncer','-c',str(path)],stdout=log,stderr=log)
                for family in (4,6):
                    host='10.231.3.2' if family==4 else 'fd42:231:3::2'
                    for protocol in ('tcp','udp'):
                        owned.start(['ip','netns','exec','backend',sys.executable,'/workspace/tests/verify_relay_network.py','--echo',host,'29000',protocol],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                for family in (4,6):
                    host='10.231.3.2' if family==4 else 'fd42:231:3::2'
                    ban='10.231.1.2' if family==4 else 'fd42:231:1::2'
                    peer_relay='10.231.3.1' if family==4 else 'fd42:231:3::1'
                    ingress='10.231.1.1' if family==4 else 'fd42:231:1::1'
                    good_ingress='10.231.2.1' if family==4 else 'fd42:231:2::1'
                    for protocol in ('tcp','udp'):
                        for kind in ('direct','preserve-dnat','proxy-gost'):
                            port=31000+(family*10)+(1 if protocol=='udp' else 0)+(2 if kind=='proxy-gost' else 0)
                            target=host if kind=='direct' else ingress
                            target_good=host if kind=='direct' else good_ingress
                            connect_port=29000 if kind=='direct' else port
                            if kind=='preserve-dnat':
                                table='preserve%s'%port
                                rules='add table inet %s\nadd chain inet %s pre { type nat hook prerouting priority -100; }\nadd rule inet %s pre %s dport %s dnat %s to %s:29000\n'%(table,table,table,protocol,port,'ip' if family==4 else 'ip6',host if family==4 else '['+host+']')
                                command(['nft','-f','-'],input=rules)
                            elif kind=='proxy-gost':
                                start_forwarder(SimpleNamespace(gost='/bin/gost'),owned,base,'gost',protocol,'0.0.0.0' if family==4 else '::',host,port)
                            normal=None
                            for _ in range(40):
                                if proc.poll() is not None:raise RuntimeError('Landing Bouncer exited')
                                normal=client('bad',target,connect_port,protocol)
                                if normal:break
                                time.sleep(.1)
                            case={'path':kind,'family':family,'protocol':protocol,'backend_peer':normal.get('peer') if normal else None,'assertions':{}}
                            report['cases'].append(case)
                            a=case['assertions']
                            a['normal_bad']=bool(normal)
                            a['source_matches']=bool(normal) and normal['peer']==(peer_relay if kind=='proxy-gost' else ban)
                            a['normal_good']=bool(client('good',target_good,connect_port,protocol))
                            api.set_ban(ban,True)
                            try:
                                wait_backend(ban,True)
                                before=drop_packets(json.loads(backend_rules()))
                                during=bool(client('bad',target,connect_port,protocol))
                                after=drop_packets(json.loads(backend_rules()))
                                case['drop_counts']={'before':before,'after':after}
                                if kind=='proxy-gost':
                                    a['landing_user_ban_cannot_block_proxy']=during and after==before
                                else:
                                    a['blocked_bad']=not during
                                    a['counter_increased']=after>before
                                a['healthy_good']=bool(client('good',target_good,connect_port,protocol))
                            finally:api.set_ban(ban,False)
                            wait_backend(ban,False)
                            a['recovered_bad']=bool(client('bad',target,connect_port,protocol))
                            a['recovered_good']=bool(client('good',target_good,connect_port,protocol))
                            case['status']='passed' if all(a.values()) else 'failed'
                            print('LANDING_CASE '+json.dumps(case),flush=True)
                            if kind=='preserve-dnat':command(['nft','delete','table','inet',table])
    report['status']='passed' if len(report['cases'])==12 and all(c['status']=='passed' for c in report['cases']) else 'failed'
    return report

if len(sys.argv)==1:
    p=subprocess.run(['unshare','--net','--mount','--',sys.executable,__file__,str(os.stat('/proc/self/ns/net').st_ino),str(os.stat('/proc/self/ns/mnt').st_ino)],timeout=300)
    sys.exit(p.returncode)
try:
    report=run(int(sys.argv[1]),int(sys.argv[2]))
except Exception as error:
    report={'status':'failed','error':str(error)}
Path('/tmp/landing-results.json').write_text(json.dumps(report,indent=2)+'\n')
sys.exit(0 if report['status']=='passed' else 1)
