VERIFICATION={'file_hashes_match': True, 'runtime_match': True, 'managed_keys': 64, 'changes': {'net.ipv4.tcp_syn_retries': '6', 'net.ipv4.tcp_synack_retries': '5', 'net.ipv4.tcp_orphan_retries': '0', 'net.ipv4.tcp_fin_timeout': '60', 'net.ipv4.tcp_autocorking': '1', 'net.ipv4.tcp_no_metrics_save': '0', 'net.ipv4.tcp_tw_reuse': '2'}, 'tcp_mem_unchanged': True, 'unique_active_network_settings': 64, 'boot_config_matches': True, 'services': 'MainPID=661\nNRestarts=0\nId=V2bX.service\nActiveState=active\n\nMainPID=6185\nNRestarts=0\nId=crowdsec.service\nActiveState=active\n\nMainPID=1306\nNRestarts=0\nId=crowdsec-firewall-bouncer.service\nActiveState=active\n\nMainPID=700\nNRestarts=0\nId=docker.service\nActiveState=active', 'service_pids_unchanged': True, 'private_policy': 'gost public-access policy verify complete', 'private_ports_dualstack_loopback': True, 'crowdsec_first_rules_preserved': True, 'qdisc': 'qdisc fq 0: root refcnt 2 limit 10000p flow_limit 100p buckets 1024 orphan_mask 1023 quantum 3028b initial_quantum 15140b low_rate_threshold 550Kbit refill_delay 40ms timer_slack 10us horizon 10s horizon_drop \n Sent 271247747 bytes 1887404 pkt (dropped 0, overlimits 0 requeues 0) \n backlog 0b 0p requeues 0\n  flows 254 (inactive 254 throttled 0)\n  gc 41 highprio 0 throttled 1698 latency 20.4us', 'api_samples': [{'records': 15350, 'seconds': 0.511}, {'records': 15350, 'seconds': 0.501}, {'records': 15350, 'seconds': 0.427}], 'decision_membership': {'expected': 15350, 'kernel': 15350, 'missing': 0, 'state': 'ok'}, 'counter_delta': {'Tcp:OutSegs': 416, 'Tcp:RetransSegs': 0, 'Udp:RcvbufErrors': 0, 'Udp:SndbufErrors': 0, 'UdpLite:RcvbufErrors': 0, 'UdpLite:SndbufErrors': 0, 'TcpExt:ListenOverflows': 0, 'TcpExt:ListenDrops': 0, 'TcpExt:TCPAbortOnMemory': 0, 'TcpExt:TCPMemoryPressures': 0, 'Udp6InErrors': 0, 'Udp6RcvbufErrors': 0, 'Udp6SndbufErrors': 0}, 'sockstat': 'sockets: used 151\nTCP: inuse 14 orphan 0 tw 46 alloc 29 mem 131\nUDP: inuse 2 mem 0\nUDPLITE: inuse 0\nRAW: inuse 0\nFRAG: inuse 0 memory 0', 'v2bx_memory_bytes': '72585216', 'vmstat': 'procs -----------memory---------- ---swap-- -----io---- -system-- ------cpu-----\n r  b   swpd   free   buff  cache   si   so    bi    bo   in   cs us sy id wa st\n 2  0 179776  93452    828 531000    0    1    83    10  107  170  1  0 95  5  0\n 1  0 179776  93452    828 531000    0    0     0     0   70  123  1  0 99  0  0\n 1  0 179776  93452    828 531000    0    0     0     0  264  374  1  0 99  0  0', 'verification_scope': 'configuration, low-load service stability and decision membership; no relay throughput benchmark'}
EXTERNAL={'5244': 'TimeoutError', '8443': 'reachable', '51080': 'TimeoutError', '53322': 'reachable', 'public_https': {'exit': 0, 'http_code': '200'}}
import fcntl,json,hashlib,os,subprocess
from pathlib import Path
base=Path('/var/backups/crowdbastion/tcp-retune-20261103')
lock=open(base/'lock','a');fcntl.flock(lock,fcntl.LOCK_EX)
assert (base/'applied').exists() and not (base/'rollback-result.json').exists()
m=json.loads((base/'manifest.json').read_text())
for f in m['files']:assert hashlib.sha256(Path(f['path']).read_bytes()).hexdigest()==f['after']
for k,v in m['settings'].items():assert ' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split())==v
assert VERIFICATION['decision_membership']['state']=='ok' and VERIFICATION['boot_config_matches'] is True
assert EXTERNAL['53322']=='reachable' and EXTERNAL['8443']=='reachable'
assert EXTERNAL['5244']=='TimeoutError' and EXTERNAL['51080']=='TimeoutError'
assert EXTERNAL['public_https']=={'exit':0,'http_code':'200'}
for name,payload in [('verification.json',VERIFICATION),('external.json',EXTERNAL)]:
 p=base/name
 with p.open('x') as stream:json.dump(payload,stream,indent=2);stream.flush();os.fsync(stream.fileno())
 p.chmod(0o600)
with (base/'committed').open('x') as stream:stream.write('configuration and independent stability checks passed; relay throughput not benchmarked\n');stream.flush();os.fsync(stream.fileno())
dirfd=os.open(base,os.O_DIRECTORY);os.fsync(dirfd);os.close(dirfd)
subprocess.run(['systemctl','stop','crowdbastion216-retune-rollback.timer'],capture_output=True,check=True,timeout=15)
check=subprocess.run(['systemctl','is-active','crowdbastion216-retune-rollback.timer'],capture_output=True,text=True,timeout=10)
assert check.stdout.strip()=='inactive'
print(json.dumps({'committed':True,'backup':str(base),'runtime_changes':len(m['changes']),'managed_keys':len(m['settings']),'rollback_timer':'inactive','tcp_mem_unchanged':True}))
