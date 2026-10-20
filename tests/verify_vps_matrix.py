#!/usr/bin/env python3
"""Execute isolated Bash branch fixtures, never claim real VPS/OS acceptance."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import sys

import test_workflows

ROOT=Path(__file__).resolve().parents[1]
OS_IDS=('debian','ubuntu','centos','rhel','almalinux','rocky','fedora')
SECRET='matrix-private-fixture-key'


def manifest():
    cases=[]
    for os_id in OS_IDS:
        managers=('apt-get',) if os_id in ('debian','ubuntu') else ('dnf','yum')
        for manager in managers:
            for backend in ('nftables','iptables'):
                for state in ('fresh','existing'):
                    cases.append({'id':f'{os_id}-{manager}-{backend}-{state}', 'os_id':os_id,'package_manager':manager,'backend':backend,'install_state':state,'scenario':'package_backend','validation_level':'fixture','cli':[]})
            cases.append({'id':f'{os_id}-{manager}-already-installed','os_id':os_id,'package_manager':manager,'backend':None,'install_state':'existing','scenario':'package_skip','validation_level':'fixture','cli':[]})
        for scenario,option in [('remote_cancel','--configure-relay-bouncer'),('override_refusal','--configure-relay-bouncer'),('readonly_help','--help'),('readonly_status','--relay-bouncer-status'),('readonly_unverified','--relay-status'),('remote_restart_rollback','--configure-relay-bouncer'),('managed_remove','--remove-relay-bouncer')]:
            cases.append({'id':f'{os_id}-{scenario}','os_id':os_id,'package_manager':managers[0],'backend':'iptables','install_state':'existing','scenario':scenario,'validation_level':'fixture','cli':[option]})
    return cases


def accept(exit_code,expected_exit,assertions):
    failures=[name for name,passed in assertions.items() if passed is not True]
    if not assertions: failures.append('no_assertions')
    if exit_code!=expected_exit: failures.append('unexpected_exit_code')
    return {'status':'fail' if failures else 'pass','exit_code':exit_code,'expected_exit_code':expected_exit,'assertions':assertions,'failure_cause':', '.join(failures) if failures else None}


def validate_results(cases,results):
    wanted=[c['id'] for c in cases]; actual=[r['id'] for r in results]
    if len(set(wanted))!=len(wanted) or len(set(actual))!=len(actual) or set(wanted)!=set(actual):
        raise ValueError('missing, duplicate or unexpected matrix results')
    for result in results:
        if result.get('validation_level')!='fixture':
            raise ValueError('fixture evidence cannot be relabeled')
        if not all(key in result for key in ('status','exit_code','expected_exit_code','assertions')):
            raise ValueError('incomplete result acceptance fields')
        accepted=accept(result['exit_code'],result['expected_exit_code'],result['assertions'])
        if result['status']!=accepted['status']:
            raise ValueError('status contradicts acceptance assertions')


def snapshot(directory):
    return {str(path.relative_to(directory)):path.read_bytes() for path in directory.rglob('*') if path.is_file()}


def managed_overlay(base):
    local=Path(str(base)+'.local');state=Path(str(base)+'.remote.json')
    local.write_text('api_url: https://fixture.example/\napi_key: '+SECRET+'\n')
    state.write_text(json.dumps({'manager':'crowdsec-1key-remote-v1','sha256':hashlib.sha256(local.read_bytes()).hexdigest()}))
    local.chmod(0o600);state.chmod(0o600)
    return local,state


def run_case(case):
    fixture=test_workflows.Workflows(methodName='runTest')
    fixture.setUp()
    try:
        (fixture.base/'etc/os-release').write_text('ID='+case['os_id']+'\n')
        directory=fixture.config/'bouncers';directory.mkdir()
        base=directory/'crowdsec-firewall-bouncer.yaml'
        backend=case['backend'] or 'nftables'
        base.write_text(f'mode: {backend}\napi_key: unrelated-original-key\niptables_chains: [INPUT]\n')
        scenario=case['scenario'];manager=case['package_manager']
        # command discovery is explicitly simulated, so a host nft/dnf cannot
        # affect the chosen branch. All mutation commands are shell functions.
        overrides=f'''OS_ID={shlex.quote(case['os_id'])}
command() {{
 if [[ "$1" == -v && "$2" == nft ]]; then [[ {shlex.quote(backend)} == nftables ]]; return; fi
 if [[ "$1" == -v && "$2" == dnf ]]; then [[ {shlex.quote(manager)} == dnf ]]; return; fi
 builtin command "$@"
}}
modprobe() {{ record modprobe "$@"; return 1; }}
'''
        expected=0;action='';before=None
        if scenario=='package_backend':
            if case['install_state']=='fresh': base.unlink()
            action='install_bouncer_package'
        elif scenario=='package_skip':
            overrides+='dpkg-query() { printf "install ok installed"; }; rpm() { return 0; }\n'
            action='install_packages crowdsec-firewall-bouncer-nftables nftables'
        elif scenario=='remote_cancel':
            action='main --configure-relay-bouncer';expected=1
        elif scenario=='override_refusal':
            Path(str(base)+'.local').write_text('api_key: unmanaged-private-key\nmode: nftables\n')
            action='main --configure-relay-bouncer';expected=1
        elif scenario=='readonly_help': action='main --help'
        elif scenario=='readonly_status':
            managed_overlay(base);action='main --relay-bouncer-status'
        elif scenario=='readonly_unverified':
            action='main --relay-status';expected=2
            overrides+='check_relay_status() { record audit fixture-unverified; return 2; }; locked_operation() { record unexpected-lock; return 99; }\n'
        elif scenario=='remote_restart_rollback':
            managed_overlay(base);action='main --configure-relay-bouncer';expected=1
            overrides+='''
remote_bouncer_input() { printf '{}' > "$1"; }
remote_bouncer_tool() {
 case "$1" in
 guard|preflight) return 0 ;;
 apply) printf 'api_key: matrix-private-fixture-key\\n' > "$REMOTE_CONFIG.local"; printf '{}' > "$REMOTE_CONFIG.remote.json" ;;
 esac
}
restart_seen=false
systemctl() {
 record systemctl "$@"
 if [[ "$1" == is-enabled ]]; then echo enabled-runtime; return 0; fi
 if [[ "$1" == restart && "$restart_seen" == false ]]; then restart_seen=true; return 1; fi
 return 0
}
'''
        elif scenario=='managed_remove': managed_overlay(base);action='main --remove-relay-bouncer'
        else: raise ValueError('unknown fixture scenario')
        before=snapshot(fixture.config)
        result=fixture.run_shell(action,overrides=overrides,timeout=15)
        after=snapshot(fixture.config);trace=fixture.commands();commands=trace.splitlines()
        assertions={'no_secret_output':all(secret not in result.stdout+result.stderr+trace for secret in (SECRET,'unrelated-original-key','unmanaged-private-key'))}
        package_commands=[c for c in commands if c.startswith(('apt-get ','dnf ','yum '))]
        if scenario=='package_backend':
            # A fresh install now selects iptables even when nft is available;
            # existing configurations still retain their effective backend.
            selected_backend='iptables' if case['install_state']=='fresh' else backend
            package='crowdsec-firewall-bouncer-'+('nftables' if selected_backend=='nftables' else 'iptables')
            expected_packages='nftables '+package if selected_backend=='nftables' else 'iptables ipset '+package
            expected_command=('apt-get install -y --no-upgrade ' if manager=='apt-get' else manager+' install -y ')+expected_packages
            assertions.update({'correct_backend_and_manager':package_commands==[expected_command], 'configuration_preserved':before==after,'no_core_package':all(not re.search(r'(?<![\w-])crowdsec(?![\w-])',c) for c in package_commands)})
        elif scenario=='package_skip': assertions.update({'installed_packages_not_reinstalled':not package_commands,'configuration_preserved':before==after})
        elif scenario in ('remote_cancel','override_refusal','readonly_help','readonly_status','readonly_unverified'):
            forbidden=re.search(r'^(?:systemctl (?:restart|start|stop|enable|disable|daemon-reload)|apt-get |dnf |yum |cscli .* (?:add|delete|remove)|nft |iptables |ip6tables |ipset )',trace,re.M)
            assertions.update({'configuration_preserved':before==after,'no_mutating_commands':forbidden is None})
            if scenario=='readonly_help': assertions['help_lists_remote_entry']='--install-relay-bouncer' in result.stdout
            if scenario=='readonly_unverified': assertions['unverified_exit_propagated_without_lock']='unexpected-lock' not in trace
            if scenario=='readonly_status': assertions['no_management_lock_created']=not (fixture.base/'run/lock/crowdsec-1key.lock').exists()
            if scenario=='override_refusal': assertions['refused_before_service_queries']=not any(c.startswith('systemctl ') for c in commands)
        elif scenario=='remote_restart_rollback':
            assertions.update({'configuration_restored':before==after,'failed_restart_and_restore_attempted':trace.count('systemctl restart crowdsec-firewall-bouncer')==2,'no_enablement_changed':not re.search(r'^systemctl (?:enable|disable) ',trace,re.M),'core_service_untouched':not re.search(r'^systemctl (?:restart|start|stop|enable|disable) crowdsec$',trace,re.M),'no_core_account_commands':not any(c.startswith('cscli ') for c in commands)})
        elif scenario=='managed_remove':
            removed={str(base.relative_to(fixture.config))+'.local',str(base.relative_to(fixture.config))+'.remote.json'}
            assertions.update({'only_managed_files_removed':after=={k:v for k,v in before.items() if k not in removed},'bouncer_stopped_and_disabled':all(c in commands for c in ('systemctl stop crowdsec-firewall-bouncer','systemctl disable crowdsec-firewall-bouncer')),'no_core_or_other_bouncer_changes':not any(c.startswith('cscli ') or re.search(r'^systemctl (?:restart|start|stop|enable|disable) crowdsec$',c) for c in commands)})
        evidence={'command_trace':commands,'configuration_files_before':len(before),'configuration_files_after':len(after),'fixture_root':'temporary directory, removed after case','readonly_audit':'stubbed exit propagation only' if scenario=='readonly_unverified' else 'not a firewall audit', 'auth_preflight':'stubbed for rollback; not an authentication test' if scenario=='remote_restart_rollback' else 'not performed','systemd':'shell function stub; no booted operating system'}
        return {**case,'distribution_version':None,'architecture':None,'kernel':None,'ram_mib':None,**accept(result.returncode,expected,assertions),'evidence':evidence}
    except Exception as error:
        return {**case,'distribution_version':None,'architecture':None,'kernel':None,'ram_mib':None,**accept(None,0,{'fixture_execution_completed':False}),'evidence':{'exception_type':type(error).__name__,'systemd':'shell function stub; no booted operating system'}}
    finally: fixture.doCleanups()


def cli_inventory(cases):
    source=(ROOT/'install-crowdsec-1panel.sh').read_text()
    body=source[source.index('main_operation()'):]
    options=sorted(set(re.findall(r'--[a-z][a-z0-9-]*',body)) | {'-h','(interactive menu)'})
    covered={option:[c['id'] for c in cases if option in c['cli']] for option in options}
    def category(option):
        if option in ('--help','-h'): return 'help'
        if option=='(interactive menu)': return 'interactive_menus'
        if any(s in option for s in ('telegram',)): return 'notifications'
        if 'relay-bouncer' in option:return 'remote_bouncer'
        if any(s in option for s in ('real-ip','logs','allowlist','self-report','docker-endpoints')):return 'logs_identity_network'
        if any(s in option for s in ('web','appsec','waf','baseline','reset-56')):return 'web_appsec'
        if any(s in option for s in ('install-core','install-relay','repair-bouncer')):return 'core_local_bouncer'
        if option in ('--status','--relay-status','--relay-path'):return 'readonly_health_path'
        return 'maintenance_cleanup'
    return [{'option':option,'category':category(option),'coverage':'fixture' if covered[option] else 'not_exercised_by_this_matrix','case_ids':covered[option]} for option in options]


def archive_import(path):
    # Integrity/provenance metadata only. Imported evidence is never rerun,
    # never counted as a passing fixture and never relabeled as a real OS test.
    content=Path(path).read_bytes();json.loads(content)
    return {'source':str(path),'sha256':hashlib.sha256(content).hexdigest(),'validation_level':'archive_reference_only','rerun':False,'status':'not_evaluated_by_fixture_runner'}


def run_matrix():
    cases=manifest();results=[run_case(case) for case in cases]
    validate_results(cases,results)
    counts=Counter(r['status'] for r in results)
    return {'schema_version':1,'generated_at':datetime.now(timezone.utc).isoformat(),'validation_level':'fixture','scope':'Bash OS/package/configuration branches in temporary path fixtures; no real distro, architecture, RAM, kernel, systemd, firewall enforcement, downloads, or external messages tested','matrix_manifest':cases,'results':results,'summary':{'total':len(results),'passed':counts['pass'],'failed':counts['fail']},'cli_inventory':cli_inventory(cases),'actual_archive_imports':[],'not_validated':['booted distro versions','amd64/arm64 execution','RAM capacity','actual package repositories/install scripts','real systemd boot and enablement','real firewall rule enforcement','real remote LAPI authentication','web/Docker/AppSec workflows','Telegram/email delivery','long-term stability or WAN bandwidth']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--actual-archive',type=Path,action='append',default=[])
    args=parser.parse_args()
    report=run_matrix();report['actual_archive_imports']=[archive_import(path) for path in args.actual_archive]
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(report['summary']))
    return 1 if report['summary']['failed'] else 0

if __name__=='__main__': sys.exit(main())
