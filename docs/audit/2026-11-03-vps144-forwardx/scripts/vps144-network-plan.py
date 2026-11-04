from pathlib import Path
import subprocess,json,os
b=Path('/var/backups/crowdbastion/vps144-20261103T103358Z');release=Path('/opt/crowdbastion/releases/20261103-vps144')
p=subprocess.run(['systemctl','show','systemd-sysctl','-p','ExecStart','--value'],capture_output=True,text=True,check=True);assert '/systemd-sysctl' in p.stdout
roles=Path('/var/lib/crowdbastion/node-roles.json')
if not roles.exists():subprocess.run(['python3',str(release/'lib/crowdbastion_node.py'),'save',str(roles),'relay'],check=True,capture_output=True)
profile={'version':1,'loader':'systemd','keys':['net.ipv4.tcp_syn_retries','net.ipv4.tcp_synack_retries','net.ipv4.tcp_orphan_retries','net.ipv4.tcp_fin_timeout','net.ipv4.tcp_autocorking','net.ipv4.tcp_no_metrics_save','net.ipv4.tcp_tw_reuse'],'sources':['/etc/sysctl.d/60-realm-tune.conf','/etc/sysctl.d/99-bbr-ultimate.conf','/etc/sysctl.d/99-network-optimize.conf','/etc/sysctl.d/99-sysctl.conf']}
p=Path('/var/lib/crowdbastion/network.json');assert not p.exists();p.write_text(json.dumps(profile,indent=2)+'\n');p.chmod(0o600)
x=subprocess.run(['crowdbastion','--network-plan'],capture_output=True,text=True,timeout=60);(b/'network-plan.json').write_text(x.stdout);(b/'network-plan.stderr').write_text(x.stderr)
print(json.dumps({'exit':x.returncode,'output':x.stdout[-13000:],'stderr':x.stderr[-1000:]}));assert x.returncode==0
