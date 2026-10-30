"""Isolated review reproductions: temporary files, command stubs and loopback HTTP.
Run from the repo root with lib and the PyYAML site-packages directory in
PYTHONPATH. Web cases require the hash-pinned archives used by test_web_install.
The JSON output describes the observed behavior; these are review probes,
not assertions that the buggy behavior should remain.
"""
import sys, json, threading, http.server
from pathlib import Path
ROOT = Path(__file__).resolve().parents[3]
sys.path[:0] = [str(ROOT/'tests'), str(ROOT/'lib')]
import test_notify, test_v2bx_alerts
import crowdsec_config, crowdsec_remote_bouncer

case = test_notify.NotificationInstallation()
case.setUp()
try:
    notification = case.setup_telegram()
    case.trace.write_text('')
    overrides = '''
systemctl() {
 record systemctl "$@"
 case "$*" in
  show*) echo 'LoadState=not-found';;
  'enable crowdbastion-notify.service') ln -s "$NOTIFY_UNIT" "$NOTIFY_UNIT.enabled";;
  'restart crowdbastion-notify.service') touch "$NOTIFY_UNIT.active";;
  'stop crowdbastion-notify.service') rm -f "$NOTIFY_UNIT.active";;
  'disable crowdbastion-notify.service') rm -f "$NOTIFY_UNIT.enabled";;
 esac
 return 0
}
crowdsec() { return 1; }
'''
    result = case.enable(overrides)
    unit = case.base/'etc/systemd/system/crowdbastion-notify.service'
    print(json.dumps({'case':'notify_core_validation_rollback', 'exit':result.returncode,
        'unit_exists':unit.exists(), 'still_active':Path(str(unit)+'.active').exists(),
        'enabled_link':Path(str(unit)+'.enabled').is_symlink(), 'commands':case.commands()}, ensure_ascii=False))
finally: case.doCleanups()

case = test_notify.NotificationInstallation()
case.setUp()
try:
    notification = case.setup_telegram()
    original = notification.read_bytes()
    overrides = case.OVERRIDES + '''
notify_tool() {
 python3 "$SCRIPT_DIR/lib/crowdsec_notify_setup.py" "$@" || return $?
 if [[ "$1" == prepare ]]; then kill -TERM "$BASHPID"; fi
}
'''
    result = case.run_shell('locked_operation enable_smart_notifications', overrides=overrides)
    print(json.dumps({'case':'notify_sigterm_during_enable', 'exit':result.returncode,
        'route_restored':notification.read_bytes()==original, 'webhook_route':'/alerts' in notification.read_text(),
        'unit_exists':(case.base/'etc/systemd/system/crowdbastion-notify.service').exists()}, ensure_ascii=False))
finally: case.doCleanups()

case = test_v2bx_alerts.AlertManagement()
case.setUp()
try:
    case.manager.enable()
    crowdsec_config.main(['profiles', str(case.profiles), 'enable'])
    result = {'case':'telegram_changes_observation_guard', 'semantic_decisions':list(__import__('yaml').safe_load_all(case.profiles.read_text()))[0]['decisions']}
    for name in ('check_managed', 'disable'):
        try: getattr(case.manager,name)(); result[name]='ok'
        except Exception as e: result[name]=str(e)
    print(json.dumps(result,ensure_ascii=False))
finally: case.doCleanups()

payload=json.dumps({'new':[{'id':i,'origin':'CAPI','type':'ban','scope':'Ip','value':'198.51.100.1','duration':'4h','scenario':'crowdsecurity/http-probing'} for i in range(10000)],'deleted':[]}).encode()
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.send_header('Content-Length',str(len(payload)));self.end_headers()
        try:self.wfile.write(payload)
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass
server=http.server.HTTPServer(('127.0.0.1',0),Handler)
thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
try:
    try:crowdsec_remote_bouncer.preflight(f'http://127.0.0.1:{server.server_port}/','dummy');result='ok'
    except Exception as e:result=str(e)
    print(json.dumps({'case':'remote_large_valid_stream','decisions':10000,'bytes':len(payload),'result':result},ensure_ascii=False))
finally:server.shutdown();server.server_close();thread.join()

from test_native_workflows import NativeWorkflows
case=NativeWorkflows();case.setUp()
try:
    overrides=case.fixture()
    installed=case.run_shell('install_docker_web_bouncer','openresty\ny\n',overrides)
    assert installed.returncode==0, installed.stderr
    case.trace.write_text('')
    overrides=overrides.replace("'exec '*' nginx -s reload') nginx_test_reload;;", "'exec '*' nginx -s reload') record reload_rejected_but_signal_success;;")
    result=case.run_shell('remove_docker_web_bouncer','openresty\ny\n',overrides)
    print(json.dumps({'case':'native_remove_reload_not_accepted','exit':result.returncode,'claims_success':'[SUCCESS]' in result.stdout,
        'reload_rejected':'reload_rejected_but_signal_success' in case.commands(),
        'account_deleted':'bouncers delete cs-web-1key-' in case.commands(),
        'assets_exist':(case.base/'web/data/crowdsec-1key').exists(),
        'checked_workers':'docker top ' in case.commands()},ensure_ascii=False))
finally:case.doCleanups()

from test_workflows import Workflows
case=Workflows();case.setUp()
try:
    units=[]
    for name in ('crowdsec-v2bx-observer','crowdsec-v2bx-alerts'):
        unit=case.base/f'etc/systemd/system/{name}.service';unit.parent.mkdir(parents=True,exist_ok=True)
        unit.write_text('[Service]\nExecStart=/test\n');units.append(unit)
    result=case.run_shell('deep_purge_residuals','y\n')
    print(json.dumps({'case':'purge_leaves_v2bx_services','exit':result.returncode,'config_exists':case.config.exists(),
        'units_exist':[p.exists() for p in units], 'v2bx_stop_called':'stop crowdsec-v2bx-' in case.commands(),
        'v2bx_disable_called':'disable crowdsec-v2bx-' in case.commands()},ensure_ascii=False))
finally:case.doCleanups()
