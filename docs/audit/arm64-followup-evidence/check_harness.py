import pathlib,json,types
lab=pathlib.Path('/tmp/crowdsec-arm-followup')
def probe(name):
 text=(lab/name).read_text();start=text.index("rc,out=run(cs+['decisions','add'");end=text.index('old=local.read_bytes()',start)
 cases=[]
 def run(argv,**kwargs):return (1,'operation not permitted') if argv[0]=='nft' else (0,'')
 def emit(case,rc,**assertions):cases.append(dict(case=case,rc=rc,assertions=assertions))
 exec(text[start:end],{'cs':['cscli'],'run':run,'emit':emit,'time':types.SimpleNamespace(sleep=lambda _:None)})
 return cases
old=probe('attempt1/guest.py');new=probe('guest.py')
assert old[1]['assertions']['absent'] is True
assert all(not any(c['assertions'].values()) for c in new)
result={'old_harness_false_positive_reproduced':True,'corrected_harness_rejects_failed_nft_reads':True,'old':old,'corrected':new}
(lab/'harness-regression.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
