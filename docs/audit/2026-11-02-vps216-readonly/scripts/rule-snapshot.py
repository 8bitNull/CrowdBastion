import hashlib,json,os,re,subprocess,time
r={'checked_at':time.time(),'families':{},'method':'iptables-save output; generation comments omitted; chain declaration packet/byte counters normalized to [0:0]; no rule counters requested; ipset membership excluded'}
for binary in ['iptables','ip6tables']:
    p=subprocess.run([binary+'-save'],capture_output=True,text=True,timeout=15,env=dict(os.environ,LC_ALL='C'))
    lines=[line for line in p.stdout.splitlines() if not line.startswith('#')]
    normalized=[re.sub(r'^(\S+\s+\S+\s+)\[\d+:\d+\]$',r'\g<1>[0:0]',line) if line.startswith(':') else line for line in lines]
    r['families'][binary]={'exit':p.returncode,'raw_digest_excluding_generation_comments':hashlib.sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),'normalized_rule_sha256':hashlib.sha256(('\n'.join(normalized)+'\n').encode()).hexdigest(),'tables':[line[1:] for line in lines if line.startswith('*')],'lines':len(lines),'policy_counter_declarations':[line for line in lines if re.match(r'^:\S+\s+\S+\s+\[\d+:\d+\]$',line)]}
print(json.dumps(r,indent=2))
