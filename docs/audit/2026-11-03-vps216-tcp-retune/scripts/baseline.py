import subprocess,json,time,sys,hashlib,re
from pathlib import Path
sys.path.insert(0,'/root/crowdsec-1key/lib')
import crowdsec_firewall_evidence as evidence
config=Path('/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml')
keys=['net.ipv4.tcp_syn_retries','net.ipv4.tcp_synack_retries','net.ipv4.tcp_orphan_retries','net.ipv4.tcp_fin_timeout','net.ipv4.tcp_autocorking','net.ipv4.tcp_no_metrics_save','net.ipv4.tcp_tw_reuse','net.ipv4.tcp_mem','net.ipv4.tcp_moderate_rcvbuf','net.ipv4.tcp_rmem','net.ipv4.tcp_wmem','net.core.rmem_max','net.core.wmem_max','net.ipv4.tcp_notsent_lowat','net.ipv4.tcp_congestion_control','net.core.default_qdisc']
def values():return {k:' '.join(Path('/proc/sys/'+k.replace('.','/')).read_text().split()) for k in keys}
def counters():
 r={}
 for name in ['snmp','netstat']:
  rows=Path('/proc/net/'+name).read_text().splitlines()
  for head,data in zip(rows[::2],rows[1::2]):
   hs,ds=head.split(),data.split()
   for k,v in zip(hs[1:],ds[1:]):
    if k in ['RetransSegs','OutSegs','InErrors','RcvbufErrors','SndbufErrors','TCPMemoryPressures','TCPAbortOnMemory','ListenOverflows','ListenDrops']:r[hs[0]+k]=int(v)
 return r
r={'values':values(),'counter_before':counters(),'samples':[]}
for i in range(3):
 start=time.monotonic()
 try:
  rows=evidence.live(config);item={'api_ok':True,'records':len(rows)}
 except Exception as e:item={'api_ok':False,'error':type(e).__name__}
 item.update(seconds=round(time.monotonic()-start,3),sockstat=Path('/proc/net/sockstat').read_text().strip())
 r['samples'].append(item);print(json.dumps({'sample':i,**item}),flush=True)
 if i<2:time.sleep(3)
r['counter_after']=counters()
for f in ['/etc/sysctl.conf','/etc/sysctl.d/99-bbr-ultimate.conf','/etc/sysctl.d/99-network-optimize.conf']:
 r.setdefault('config_hashes',{})[f]=hashlib.sha256(Path(f).read_bytes()).hexdigest()
print(json.dumps({'baseline':r},ensure_ascii=False),flush=True)
