"""Shared workflow fixture; all system effects stay inside a fresh temporary tree."""
import fnmatch
import glob
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install-crowdsec-1panel.sh"


class WorkflowFixtureMixin:
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="crowdsec-workflows-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        source = SCRIPT.read_text()
        source = re.sub(r'^main "\$@"\s*$', '', source, flags=re.M)
        # Rewrite absolute paths once; /data/logs inside an NPM mount is a suffix.
        source = re.sub(r'(?<![\w./-])(?:/(?:etc|var|opt|run|home|usr/local)/|/data/logs)',
                        lambda match: str(self.base) + match.group(0), source)
        self.source = self.base / "manager.sh"
        self.source.write_text(source)
        (self.base / "lib").mkdir()
        (self.base / "proc").mkdir()
        for helper in (ROOT/'lib').glob('*'):
            if helper.is_file() and helper.suffix in ('.py', '.sh', '.lua'):
                helper_source = helper.read_text()
                # Keep process discovery inside the fixture like config/systemd.
                # Concurrent config-validation subprocesses belong to other tests.
                if helper.name == 'crowdsec_bot_settings.py':
                    helper_source = helper_source.replace("Path('/proc')", f"Path({str(self.base/'proc')!r})")
                (self.base/'lib'/helper.name).write_text(helper_source)
        self.trace = self.base / "trace"
        self.trace.touch()
        self.config = self.base / "etc/crowdsec"
        self.config.mkdir(parents=True)
        (self.base / "etc/cron.d").mkdir(parents=True)
        (self.config / "config.yaml").write_text('api:\n  client:\n    credentials_path: '+str(self.config/'local_api_credentials.yaml')+'\n  server:\n    listen_uri: 127.0.0.1:8080\nprometheus:\n  enabled: false\n  listen_addr: 0.0.0.0\n  listen_port: 6060\n  level: aggregated\n')
        with (self.config/'config.yaml').open('a') as config_file:
            config_file.write(yaml.safe_dump({'crowdsec_service': {
                'acquisition_path': str(self.config/'acquis.yaml'),
                'acquisition_dir': str(self.config/'acquis.d')}}))
        (self.config / "local_api_credentials.yaml").write_text('url: http://127.0.0.1:8080/\nlogin: webui-legitimate-host\npassword: test-password\n')
        (self.config / "profiles.yaml").write_text('name: default_ip_remediation\nfilters:\n  - Alert.Remediation == true\ndecisions:\n  - type: ban\n    duration: 4h\non_success: break\n')


    def run_shell(self, action, user_input='', overrides='', timeout=15):
        stub = r'''
# Host firewall effects are mocked, like the package and systemd commands below.
environment_tool() { printf '{"state":"stable"}\n'; }
repair_firewall_startup() { record repair_firewall_startup; return 0; }
firewall_write_startup() { record firewall_write_startup; return 0; }
check_firewall_runtime() { record check_firewall_runtime; return 0; }
nginx_test_reload() {
 local generation=100; [[ ! -f "$TRACE.workers" ]] || read -r generation < "$TRACE.workers"
 echo "$((generation+1))" > "$TRACE.workers"
 printf '2026/10/20 00:00:00 [notice] 42#42: reconfiguring\n2026/10/20 00:00:00 [notice] 42#42: start worker processes\n2026/10/20 00:00:00 [notice] 42#42: start worker process %s\n' "$((generation+1))" >> "$TRACE.nginx-error"
}
nginx_test_processes() {
 local generation=100; [[ ! -f "$TRACE.workers" ]] || read -r generation < "$TRACE.workers"
 mkdir -p "$TRACE.proc/42" "$TRACE.proc/$generation"
 printf 'NSpid:\t42\n' > "$TRACE.proc/42/status"
 printf 'NSpid:\t%s\n' "$generation" > "$TRACE.proc/$generation/status"
 printf 'PID PPID STAT COMMAND\n42 1 Ss nginx: master process nginx\n%s 42 S nginx: worker process\n' "$generation"
}
# Fake process metadata and the discovered log file; production cursor parsing,
# inode checks, fresh master/cohort evidence and PID correlation still run.
nginx_reload_tool() { timeout --signal=KILL "$1" python3 "$SCRIPT_DIR/lib/crowdsec_nginx_reload.py" --proc-root "$TRACE.proc" "${@:2}"; }
nginx_reload_log_source() {
 mkdir -p "$TRACE.proc/42"
 printf 'NSpid:\t42\n' > "$TRACE.proc/42/status"
 touch "$TRACE.nginx-error"
 printf '%s\n' "$TRACE.nginx-error"
}
timeout() { [[ "$1" != --signal=KILL ]] || shift; shift; "$@"; }
ps() { if [[ "$*" == '-eo pid,ppid,stat,args' ]]; then nginx_test_processes; else command ps "$@"; fi; }
record() { printf '%s\n' "$*" >> "$TRACE"; }
cscli() {
 record cscli "$@"
 case "$*" in
  'machines list -o json') echo '[{"machineId":"webui-legitimate-host"},{"machineId":"webui-other-owner"}]' ;;
  'collections list -o json') echo '[]' ;;
  'collections install '*) mkdir -p "$CS_DIR/hub"; printf '%s\n' "$*" > "$CS_DIR/hub/test-installed" ;;
  'metrics show acquisition -o json') echo '{"acquisition":{}}' ;;
  'metrics show appsec -o json') echo '{"appsec":{}}' ;;
  'bouncers add '*'-o raw') echo '0123456789abcdef0123456789abcdef' ;;
 esac
 return 0
}
crowdsec() { record crowdsec "$@"; return 0; }
systemctl() {
 record systemctl "$@"
 if [[ "$1" == is-enabled ]]; then
  [[ "$*" == *--quiet* ]] || echo enabled
  return 0
 fi
 if [[ "$1" == show && "$*" == *crowdsec-v2bx-* ]]; then
  printf 'LoadState=not-found\nActiveState=inactive\nUnitFileState=\n'; return 0
 fi
 if [[ "$1" == show && "$*" == *MainPID* ]]; then echo 42; return 0; fi
 if [[ "$1" == reload && ( "$2" == nginx || "$2" == openresty ) ]]; then nginx_test_reload; fi
 if [[ "$1" == show && "$*" == *crowdsec-1key-bot.service* ]]; then
  if [[ -f "$CUSTOM_BOT_UNIT" ]]; then printf 'LoadState=loaded\nFragmentPath=%s\n' "$CUSTOM_BOT_UNIT"; else echo 'LoadState=not-found'; fi
 fi
 return 0
}
docker() {
 record docker "$@"
 case "$*" in
  'image inspect --format {{json .RepoDigests}} '*) echo '["ghcr.io/theduffman85/crowdsec-web-ui@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]' ;;
  inspect*) echo false ;;
 esac
 return 0
}
apt-get() { record apt-get "$@"; return 0; }
yum() { record yum "$@"; return 0; }
dnf() { record dnf "$@"; return 0; }
nft() { record nft "$@"; [[ "$*" == "list tables" ]]; }
iptables() { record iptables "$@"; [[ "$*" == "-S" ]]; }
ip6tables() { record ip6tables "$@"; [[ "$*" == "-S" ]]; }
ipset() { record ipset "$@"; return 0; }
ip() { record ip "$@"; echo "[]"; }
modprobe() { return 0; }
curl() { record curl "$@"; [[ "$*" != *'/api/health'* ]] || echo '{"status":"ok"}'; return 0; }
pkill() { record pkill "$@"; return 0; }
pgrep() { return 1; }
dpkg-query() { return 1; }
rpm() { return 1; }
ss() { if [[ "$*" == '-H -lnt' ]]; then echo 'LISTEN 0 128 127.0.0.1:7422 0.0.0.0:*'; fi; }
sleep() { :; }
clear() { :; }
journalctl() { record journalctl "$@"; }
'''
        env = {**os.environ, 'TRACE': str(self.trace), 'TERM': 'dumb', 'SSH_CLIENT': '', 'SSH_CONNECTION': ''}
        cmd = f'source {shlex.quote(str(self.source))}\n' + stub + '\nOS_ID=debian\n' + overrides + '\n' + action
        return subprocess.run(['bash', '-c', cmd], input=user_input, text=True, capture_output=True, env=env, timeout=timeout)


    def run_optimizer(self, user_input='', overrides='', timeout=15):
        """Exercise transactions with a fixed pending preliminary health result.

        Health report and end-to-end optimizer tests must keep using run_shell.
        Caller overrides still apply after this explicit diagnostic replacement.
        """
        diagnostic = 'check_health_status() { record optimizer-health; return 2; }\n'
        return self.run_shell('smart_audit_and_optimize', user_input,
                              diagnostic + overrides, timeout)


    def commands(self):
        return self.trace.read_text()


    def webui_docker(self, running='true healthy', previous='', existing=True):
        return ('docker() { record docker "$@"; case "$*" in '
                "'container inspect crowdsec-web-ui') return "+('0' if existing else '1')+';; '
                "'image inspect '* ) echo '[\"ghcr.io/theduffman85/crowdsec-web-ui@sha256:"+'a'*64+"\"]';; "
                '*State.Running*) echo '+shlex.quote(running)+';; '
                "*'{{.Image}}'*) echo "+shlex.quote(previous)+";; esac; return 0; }")


    def appsec_docker_stub(self, mounted=False, network='host', hook=True, waf=True, reload_succeeds=True):
        config = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        if mounted:
            config.parent.mkdir(exist_ok=True)
            config.write_text('API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n')
        mounts = json.dumps([{'Type': 'bind', 'Source': str(config), 'Destination': str(config)}] if mounted else [])
        effective = ('init_by_lua_block { require "crowdsec" }\naccess_by_lua_block { cs.Allow(ngx.var.remote_addr) }\n' if hook else '')
        if waf:
            effective += 'access_by_lua_file /usr/local/openresty/1pwaf/waf.lua;\n'
        reload_command = 'nginx_test_reload; return 0' if reload_succeeds else 'return 1'
        return '''docker() {
 record docker "$@"
 case "$1" in
 top) nginx_test_processes;;
 ps) echo 'web123 1panel/openresty:test openresty';;
 inspect) case "$3" in
 *NetworkMode*) echo '''+shlex.quote(network)+''';;
 *Mounts*) printf '%s\\n' '''+shlex.quote(mounts)+''';;
 *Running*) echo true;; esac;;
 exec) case "$4" in
 -T) printf '%s\\n' '''+shlex.quote(effective)+''';;
 -t) return 0;;
 -s) '''+reload_command+''';; esac;;
 esac
}'''


    def make_webui(self):
        ui = self.base/'opt/crowdsec-web-ui'
        (ui/'data').mkdir(parents=True)
        (ui/'data/webui_api_credentials.yaml').write_text('url: http://127.0.0.1:8080/\nlogin: webui-owned\npassword: valid-test-password\n')
        (ui/'docker-compose.yml').write_text('services:\n  crowdsec-web-ui:\n    image: ghcr.io/theduffman85/crowdsec-web-ui:old\n')
        return ui


    def web_log(self, relative):
        path = self.base/relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('test HTTP log\n')
        return path


    def repaired_sources(self):
        path = self.config/'acquis.d/crowdsec-1key-log-repair.yaml'
        return [(name, doc['labels']['type'])
                for doc in yaml.safe_load_all(path.read_text())
                for name in doc.get('filenames', [])]


