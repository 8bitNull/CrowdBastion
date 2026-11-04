import json,os,pathlib,time
print(json.dumps({'checked_at':time.time(),'uid':os.geteuid(),'os_release':pathlib.Path('/etc/os-release').read_text(),'manager_exists':pathlib.Path('/root/crowdsec-1key/crowdbastion.sh').is_file()},indent=2))
