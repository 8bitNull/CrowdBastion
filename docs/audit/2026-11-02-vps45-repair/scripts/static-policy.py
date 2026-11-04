#!/usr/bin/env python3
"""VPS45 static INPUT baseline only; never restore dynamic firewall tables."""
import os
import shlex
import signal
import subprocess

CHAIN='CB45_STATIC'
RULES=[
    ['-i','lo','-j','ACCEPT'],
    ['-m','conntrack','--ctstate','RELATED,ESTABLISHED','-j','ACCEPT'],
    ['-p','tcp','-m','tcp','--dport','53322','-j','ACCEPT'],
    ['-p','tcp','-m','tcp','--dport','29726','-j','ACCEPT'],
    ['-p','udp','-m','udp','--dport','443','-j','ACCEPT'],
    ['-p','tcp','-m','tcp','--dport','443','-j','ACCEPT'],
    ['-p','tcp','-m','tcp','--dport','80','-j','ACCEPT'],
    ['-p','tcp','-j','DROP'],
    ['-p','udp','-j','DROP'],
]

def command(argv):
    return subprocess.run(argv,capture_output=True,text=True,timeout=15)

def apply(execute=command):
    added=[];created=[]
    def checked(argv):
        result=execute(argv)
        if result.returncode:raise RuntimeError('Static policy command failed.')
        return result
    try:
        for binary in ('iptables','ip6tables'):
            prefix=[binary,'-w','5']
            present=execute(prefix+['-S',CHAIN])
            if present.returncode not in (0,1):raise RuntimeError('Cannot inspect static chain.')
            if present.returncode==0:
                actual=[shlex.split(s) for s in present.stdout.splitlines() if s.startswith('-A ')]
                expected=[['-A',CHAIN,*rule] for rule in RULES]
                if actual!=expected[:len(actual)]:raise RuntimeError('Foreign static chain rules.')
            else:
                checked(prefix+['-N',CHAIN]);created.append(prefix)
            for parent,rule in [(CHAIN,r) for r in RULES]+[('INPUT',['-j',CHAIN])]:
                exists=execute(prefix+['-C',parent,*rule])
                if exists.returncode==0:continue
                if exists.returncode!=1:raise RuntimeError('Cannot inspect static rule.')
                checked(prefix+['-A',parent,*rule]);added.append((prefix,parent,rule))
    except BaseException:
        for prefix,parent,rule in reversed(added):
            try:execute(prefix+['-D',parent,*rule])
            except BaseException:pass
        for prefix in reversed(created):
            try:execute(prefix+['-X',CHAIN])
            except BaseException:pass
        raise

if __name__=='__main__':
    if os.geteuid()!=0:raise SystemExit('Root required.')
    os.umask(0o077)
    def interrupted(signum,frame):raise RuntimeError('Static policy interrupted.')
    signal.signal(signal.SIGTERM,interrupted);signal.signal(signal.SIGINT,interrupted)
    apply()
