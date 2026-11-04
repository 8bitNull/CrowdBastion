"""Restrict the existing Docker-published gost port on eth0; never flush tables."""
import subprocess,sys
COMMENT='crowdbastion216-private-gost'
def call(args,check=True):
 return subprocess.run(args,capture_output=True,text=True,check=check,timeout=10)
def rules():
 for binary in ('iptables','ip6tables'):
  yield binary,'INPUT',['-i','eth0','-p','tcp','--dport','51080','-m','comment','--comment',COMMENT,'-j','DROP']
  yield binary,'DOCKER-USER',['-i','eth0','-p','tcp','-m','conntrack','--ctdir','ORIGINAL','--ctorigdstport','51080','-m','comment','--comment',COMMENT,'-j','DROP']
def apply():
 call(['ip','link','show','eth0'])
 for binary,chain,rule in rules():
  before=call([binary,'-w','5','-S',chain]).stdout.splitlines()
  present=call([binary,'-w','5','-C',chain,*rule],check=False)
  if present.returncode==0:continue
  if present.returncode!=1:raise RuntimeError('rule inspection failed')
  entries=[s for s in before if s.startswith('-A '+chain+' ')]
  position='2' if entries and entries[0]=='-A '+chain+' -j CROWDSEC_CHAIN' else '1'
  call([binary,'-w','5','-I',chain,position,*rule])
 verify()
def verify():
 for binary,chain,rule in rules():call([binary,'-w','5','-C',chain,*rule])
def remove():
 for binary,chain,rule in reversed(list(rules())):
  for _ in range(8):
   present=call([binary,'-w','5','-C',chain,*rule],check=False)
   if present.returncode==1:break
   if present.returncode!=0:raise RuntimeError('cannot inspect rollback rule')
   call([binary,'-w','5','-D',chain,*rule])
  else:raise RuntimeError('too many rule copies')
if __name__=='__main__':
 {'apply':apply,'verify':verify,'remove':remove}[sys.argv[1]]()
 print('gost public-access policy '+sys.argv[1]+' complete')
