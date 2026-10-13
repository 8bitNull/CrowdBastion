#!/usr/bin/env python3
"""Official remote LAPI acceptance. Mutations require private net AND mount namespaces."""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import time
from relay_network_lab import Processes, command, counter, guard, wait_set
from verify_relay_network import setup, execute_matrix, client, echo_server

REQUIRED = ('matrix', 'expiry', 'disconnected_expiry', 'generated_remote_config', 'disconnect_retains_ban', 'disconnect_healthy',
            'reconnect_unban', 'wrong_key_rejected', 'bouncer_restart', 'lapi_restart')

def accepted_remote(conditions):
    return all(conditions.get(name) is True for name in REQUIRED)

def authentication_rejected(returncode, log):
    return returncode != 0 and any(marker in log.lower() for marker in ('403', '401', 'access forbidden', 'unauthorized'))

def stage_core_state(config, directory):
    cfg = copy.deepcopy(config)
    credentials = directory/'credentials.yaml'
    shutil.copyfile(cfg['api']['client']['credentials_path'], credentials)
    credentials.chmod(0o600)
    cfg['api']['client']['credentials_path'] = str(credentials)
    data_dir = directory/'data'
    shutil.copytree(cfg['config_paths']['data_dir'], data_dir)
    cfg['config_paths']['data_dir'] = str(data_dir)
    source_database = Path(cfg['db_config']['db_path'])
    database = data_dir/'remote-lab.db'
    shutil.copyfile(source_database, database)
    cfg['db_config']['db_path'] = str(database)
    log_dir = directory/'logs'; log_dir.mkdir(); cfg['common']['log_dir'] = str(log_dir)
    return cfg

class RealAPI:
    def __init__(self, config): self.config = config
    def cli(self, *args):
        return command(['ip', 'netns', 'exec', 'central', '/bin/cscli', '-c', str(self.config), *args], timeout=20)
    def set_ban(self, address, enabled, duration='1h'):
        print('remote decision %s %s' % ('add' if enabled else 'delete', address), file=sys.stderr, flush=True)
        self.cli('decisions', 'add', '--ip', address, '--duration', duration) if enabled else self.cli('decisions', 'delete', '--ip', address)


def run(args, report):
    guard(args.original_inode, args.original_mount_inode)
    import yaml
    setup()
    command(['ip', 'netns', 'add', 'central'])
    command(['ip', 'link', 'add', 'rc', 'type', 'veth', 'peer', 'name', 'cc'])
    command(['ip', 'link', 'set', 'cc', 'netns', 'central'])
    command(['ip', 'addr', 'add', '10.231.4.1/24', 'dev', 'rc'])
    command(['ip', 'link', 'set', 'rc', 'up'])
    for argv in (['addr', 'add', '10.231.4.2/24', 'dev', 'cc'], ['link', 'set', 'cc', 'up'], ['link', 'set', 'lo', 'up']):
        command(['ip', '-n', 'central', *argv])
    with tempfile.TemporaryDirectory(prefix='remote-lapi-') as temp, Processes(grace=3) as owned:
        directory = Path(temp)
        cfg = stage_core_state(yaml.safe_load(Path(args.core_config).read_text()), directory)
        cfg['api']['server']['listen_uri'] = '10.231.4.2:8080'
        credentials = Path(cfg['api']['client']['credentials_path'])
        creds = yaml.safe_load(credentials.read_text()); creds['url'] = 'http://10.231.4.2:8080/'
        credentials.write_text(yaml.safe_dump(creds))
        config = directory/'core.yaml'; config.write_text(yaml.safe_dump(cfg)); config.chmod(0o600)
        api = RealAPI(config)
        corelog = open(directory/'core.log', 'w+')
        bounce_log = open(directory/'bouncer.log', 'w+')
        secrets = []
        def core_start():
            return owned.start(['ip','netns','exec','central','/bin/crowdsec','-c',str(config),'-no-cs'], stdout=corelog, stderr=corelog)
        def stop(process):
            process.terminate(); process.wait(timeout=10)
        try:
            core = core_start()
            for _ in range(80):
                try:
                    key = api.cli('bouncers', 'add', 'remote-lab', '-o', 'raw').strip()
                    break
                except subprocess.CalledProcessError:
                    if core.poll() is not None: raise RuntimeError('official LAPI exited during startup')
                    time.sleep(.25)
            else: raise RuntimeError('official LAPI readiness timeout')
            secrets.append(key)
            import urllib.request
            for _ in range(80):
                try:
                    request = urllib.request.Request('http://10.231.4.2:8080/v1/decisions/stream?startup=true', headers={'X-Api-Key': key})
                    with urllib.request.urlopen(request, timeout=2) as response:
                        if response.status == 200:
                            idle=json.loads(response.read()); report['idle_stream_shape']={name:type(value).__name__ for name,value in idle.items()}; break
                except OSError: time.sleep(.25)
            else: raise RuntimeError('remote authenticated LAPI readiness timeout')
            bcfg = dict(mode='nftables', update_frequency='1s', api_url='http://10.231.4.2:8080/', api_key=key,
                        log_mode='stdout', log_level='info', disable_ipv6=False, deny_action='DROP',
                        blacklists_ipv4='crowdsec-blacklists', blacklists_ipv6='crowdsec6-blacklists',
                        nftables_hooks=['input','forward'], nftables={family: dict(enabled=True, **{'set-only':False}, table=table, chain='crowdsec-chain', priority=-10) for family,table in [('ipv4','crowdsec'),('ipv6','crowdsec6')]})
            base_config={**bcfg,'api_key':'base-placeholder-invalid','api_url':'http://127.0.0.1:1/'}
            bpath = directory/'bouncer.yaml'; bpath.write_text(yaml.safe_dump(base_config)); bpath.chmod(0o600)
            helper=Path(args.remote_helper)
            credentials_json=json.dumps({'url':bcfg['api_url'],'key':key})
            result=subprocess.run([sys.executable,str(helper),'apply',str(bpath)],input=credentials_json,capture_output=True,text=True,timeout=15)
            report['conditions']['generated_remote_config']=result.returncode==0 and Path(str(bpath)+'.local').is_file()
            if result.returncode: raise RuntimeError('installer helper real LAPI preflight/apply failed: '+result.stderr)
            def bounce_start(path=bpath):
                return owned.start([args.bouncer,'-c',str(path)], stdout=bounce_log, stderr=bounce_log)
            bouncer = bounce_start(); time.sleep(2)
            for family in (4,6):
                for protocol in ('tcp','udp'):
                    owned.start(['ip','netns','exec','backend',sys.executable,str(Path(__file__).resolve()),'--echo','10.231.3.2' if family==4 else 'fd42:231:3::2','29000',protocol],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            execute_matrix(args,report,directory,owned,api)
            conditions=report['conditions']; conditions['matrix']=len(report['cases'])==12 and all(c['status']=='passed' for c in report['cases'])
            address='10.231.1.2'; host='10.231.1.1'; port=30001
            api.set_ban(address,True,'5s'); wait_set(address,True); wait_set(address,False)
            conditions['expiry']=bool(client('bad',host,port,'tcp'))
            api.set_ban(address,True,'5s'); wait_set(address,True)
            command(['ip','link','set','rc','down']); time.sleep(7)
            conditions['disconnected_expiry']=address not in command(['nft','-j','list','ruleset']) and bool(client('bad',host,port,'tcp'))
            command(['ip','link','set','rc','up']); time.sleep(2)
            api.set_ban(address,True); wait_set(address,True)
            command(['ip','link','set','rc','down']); time.sleep(3)
            conditions['disconnect_retains_ban']=not bool(client('bad',host,port,'tcp'))
            conditions['disconnect_healthy']=bool(client('good','10.231.2.1',port,'tcp'))
            api.set_ban(address,False)
            command(['ip','link','set','rc','up']); wait_set(address,False)
            conditions['reconnect_unban']=bool(client('bad',host,port,'tcp'))
            api.set_ban(address,True); wait_set(address,True)
            stop(bouncer); bouncer=bounce_start(); wait_set(address,True)
            before=counter(); blocked=not bool(client('bad',host,port,'tcp'))
            after=counter(); report['restart_drop_packets']={'before':before,'after':after}
            conditions['bouncer_restart']=blocked and after>before and bool(client('good','10.231.2.1',port,'tcp'))
            stop(core); core=core_start(); time.sleep(3)
            api.set_ban(address,False); wait_set(address,False)
            conditions['lapi_restart']=bool(client('bad',host,port,'tcp'))
            stop(bouncer)
            bcfg['api_key']='deliberately-invalid-lab-key'; wrong=directory/'wrong.yaml'; wrong.write_text(yaml.safe_dump(bcfg)); wrong.chmod(0o600)
            bounce_log.flush(); bounce_log.seek(0,2); wrong_start=bounce_log.tell()
            wrong_bouncer=bounce_start(wrong)
            try: wrong_bouncer.wait(timeout=15)
            except subprocess.TimeoutExpired: stop(wrong_bouncer)
            bounce_log.flush(); bounce_log.seek(wrong_start); logtext=bounce_log.read()
            report['wrong_key_observation']={'returncode':wrong_bouncer.returncode,'log':logtext}
            conditions['wrong_key_rejected']=authentication_rejected(wrong_bouncer.returncode, logtext)
        finally:
            for label, log in [('core_log',corelog),('bouncer_log',bounce_log)]:
                log.flush(); log.seek(0); data=log.read()
                for secret in secrets+[str(creds.get('password',''))]:
                    if secret: data=data.replace(secret,'<redacted>')
                report[label]=data[-18000:]; log.close()


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--original-inode',type=int); p.add_argument('--original-mount-inode',type=int)
    p.add_argument('--remote-helper',default=str(Path(__file__).resolve().parent.parent/'lib/crowdsec_remote_bouncer.py')); p.add_argument('--output'); p.add_argument('--core-config',default='/opt/core/etc/config.yaml')
    p.add_argument('--bouncer',default='/bin/crowdsec-firewall-bouncer'); p.add_argument('--gost',default='/bin/gost'); p.add_argument('--realm',default='/bin/realm')
    p.add_argument('--echo',nargs=3)
    args=p.parse_args()
    if args.echo: echo_server(args.echo[0],int(args.echo[1]),args.echo[2]); return 0
    report=dict(schema=1,decision_api='official CrowdSec LAPI on separate central network namespace',scope='no-NIC QEMU; fresh sessions; gost/realm/NAT IPv4/IPv6 TCP/UDP; no throughput or long-term stability claim',cases=[],conditions={},versions={})
    if args.original_inode is None:
        argv=[sys.executable,str(Path(__file__).resolve()),'--original-inode',str(os.stat('/proc/self/ns/net').st_ino),'--original-mount-inode',str(os.stat('/proc/self/ns/mnt').st_ino),'--core-config',args.core_config,'--bouncer',args.bouncer,'--gost',args.gost,'--realm',args.realm,'--remote-helper',args.remote_helper]
        with Processes(grace=8) as owned:
            worker=owned.start(['unshare','--net','--mount','--',*argv],stdout=subprocess.PIPE,text=True)
            try:
                stdout,_=worker.communicate(timeout=600)
                report=json.loads(stdout)
            except (ValueError, subprocess.TimeoutExpired) as exc:
                report['error']='isolated worker failed: '+str(exc); report['status']='failed'; report['exit_code']=1
    else:
        try:
            for name,binary,flag in [('crowdsec','/bin/crowdsec','-version'),('cscli','/bin/cscli','version'),('bouncer',args.bouncer,'-version'),('gost',args.gost,'-V'),('realm',args.realm,'--version')]:
                r=subprocess.run([binary,flag],capture_output=True,text=True,timeout=10); report['versions'][name]=(r.stdout+r.stderr).strip()[:1000]
            run(args,report)
        except Exception as exc: report['error']=str(exc)
        report['exit_code']=0 if accepted_remote(report['conditions']) and not report.get('error') else 1
        report['status']='passed' if report['exit_code']==0 else 'failed'
    text=json.dumps(report,indent=2)+'\n'
    if args.output: Path(args.output).write_text(text)
    print(text,end=''); return report['exit_code']

if __name__=='__main__': sys.exit(main())
