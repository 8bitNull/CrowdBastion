"""User workflow regression tests; all system effects are confined to a temporary tree."""
import fnmatch
import glob
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

import yaml

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "install-crowdsec-1panel.sh"


class Workflows(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="crowdsec-workflows-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        source = SCRIPT.read_text()
        source = re.sub(r'^main "\$@"\s*$', '', source, flags=re.M)
        # Rewrite absolute paths once; /data/logs inside an NPM mount is a suffix.
        source = re.sub(r'(?<![\w./-])(?:/(?:etc|var|opt|run|home)/|/data/logs)',
                        lambda match: str(self.base) + match.group(0), source)
        self.source = self.base / "manager.sh"
        self.source.write_text(source)
        (self.base / "lib").mkdir()
        for helper in (ROOT/'lib').glob('*'):
            if helper.is_file() and helper.suffix in ('.py', '.sh'):
                (self.base/'lib'/helper.name).write_text(helper.read_text())
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

    def run_shell(self, action, user_input='', overrides='', timeout=5):
        stub = r'''
record() { printf '%s\n' "$*" >> "$TRACE"; }
cscli() {
 record cscli "$@"
 case "$*" in
  'machines list -o json') echo '[{"machineId":"webui-legitimate-host"},{"machineId":"webui-other-owner"}]' ;;
  'collections list -o json') echo '[]' ;;
  'bouncers add '*'-o raw') echo '0123456789abcdef0123456789abcdef' ;;
 esac
 return 0
}
crowdsec() { record crowdsec "$@"; return 0; }
systemctl() { record systemctl "$@"; return 0; }
docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; case "$*" in inspect*) echo false;; esac; return 0; }
apt-get() { record apt-get "$@"; return 0; }
yum() { record yum "$@"; return 0; }
dnf() { record dnf "$@"; return 0; }
nft() { record nft "$@"; [[ "$*" == "list tables" ]]; }
iptables() { record iptables "$@"; [[ "$*" == "-S" ]]; }
ip6tables() { record ip6tables "$@"; [[ "$*" == "-S" ]]; }
ipset() { record ipset "$@"; return 0; }
ip() { record ip "$@"; echo "[]"; }
modprobe() { return 0; }
curl() { record curl "$@"; [[ "$*" == *"/api/health"* ]] && printf 200; return 0; }
pkill() { record pkill "$@"; return 0; }
pgrep() { return 1; }
dpkg-query() { return 1; }
rpm() { return 1; }
ss() { if [[ "$*" == '-H -lnt' ]]; then echo 'LISTEN 0 128 127.0.0.1:7422 0.0.0.0:*'; fi; }
sleep() { :; }
clear() { :; }
journalctl() { record journalctl "$@"; }
'''
        env = {**os.environ, 'TRACE': str(self.trace), 'TERM': 'dumb'}
        cmd = f'source {shlex.quote(str(self.source))}\n' + stub + '\nOS_ID=debian\n' + overrides + '\n' + action
        return subprocess.run(['bash', '-c', cmd], input=user_input, text=True, capture_output=True, env=env, timeout=timeout)

    def commands(self):
        return self.trace.read_text()

    def test_help_is_successful_and_read_only(self):
        p = self.run_shell('main --help')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('--telegram-test', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_cli_propagates_failure(self):
        p = self.run_shell('main --install-waf', overrides='cscli() { record cscli "$@"; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('SUCCESS', p.stdout)

    def test_main_eof_exits(self):
        p = self.run_shell('show_main_menu', timeout=1)
        self.assertEqual(p.returncode, 0)

    def test_invalid_cron_does_not_write(self):
        p = self.run_shell('manage_auto_update', '2\n99\n27\n\n0\n')
        self.assertFalse((self.base/'etc/cron.d/crowdsec-autoupdate').exists(), p.stdout)

    def test_failed_ban_is_not_reported_successful(self):
        p = self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n\n0\n', 'cscli() { record cscli "$@"; return 1; }')
        self.assertNotIn('SUCCESS', p.stdout)

    def test_invalid_ip_is_rejected_before_api_call(self):
        self.run_shell('manage_firewall_ops', '4\nnot-an-ip\n4h\ntest\n\n0\n')
        self.assertNotIn('decisions add', self.commands())

    def test_failed_console_enrollment_does_not_mutate_identity(self):
        p = self.run_shell('bind_crowdsec_console', 'invalid-token\n\n', 'cscli() { record cscli "$@"; return 1; }')
        self.assertNotIn('machines add', self.commands())
        self.assertNotIn('machines delete', self.commands())
        self.assertNotIn('SUCCESS', p.stdout)

    def test_health_check_is_read_only(self):
        self.run_shell('check_health_status', '\n')
        self.assertNotRegex(self.commands(), r'machines (add|delete)|systemctl restart|docker rm')

    def test_valid_host_login_name_does_not_trigger_repair(self):
        p = self.run_shell('verify_and_heal_host_core true')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertNotIn('machines add', self.commands())

    def test_log_paths_are_not_duplicated(self):
        self.run_shell('configure_log_acquis')
        docs = list(yaml.safe_load_all((self.config/'acquis.d/web-sites.yaml').read_text()))
        filenames = [f for doc in docs for f in doc.get('filenames', [])]
        self.assertEqual(len(filenames), len(set(filenames)))
        for filename in filenames:
            if not glob.has_magic(filename):
                self.assertFalse(any(
                    other != filename and fnmatch.fnmatchcase(filename, other)
                    for other in filenames
                ), filename)

    def test_1panel_http_logs_are_acquired_once_without_stream_or_php_logs(self):
        # Reproduce the host paths supplied in the user's acquisition failure.
        http_logs = [
            'opt/1panel/apps/openresty/openresty/log/access.log',
            'opt/1panel/apps/openresty/openresty/log/error.log',
            'opt/1panel/www/sites/shop.example.com/log/access.log',
            'opt/1panel/www/sites/shop.example.com/log/error.log',
            'opt/1panel/www/sites/second.example.com/log/access.log',
            'opt/1panel/www/sites/second.example.com/log/error.log',
            # Actual /www mount reported by the user: /opt/1panel/1panel/www.
            'opt/1panel/1panel/www/sites/bob.example.com/log/access.log',
            'opt/1panel/1panel/www/sites/bob.example.com/log/error.log',
        ]
        other_logs = [
            'opt/1panel/apps/openresty/openresty/log/stream-access.log',
            'opt/1panel/runtime/php/php84/log/fpm.error.log',
        ]
        for name in http_logs + other_logs:
            path = self.base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        p = self.run_shell('configure_log_acquis')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        docs = list(yaml.safe_load_all((self.config/'acquis.d/web-sites.yaml').read_text()))
        acquired = [
            (path, doc['labels']['type'])
            for doc in docs for pattern in doc.get('filenames', [])
            for path in glob.glob(pattern)
        ]
        self.assertCountEqual(acquired, [
            (str(self.base/name), 'nginx') for name in http_logs
        ])

    def test_baseline_keeps_custom_scenarios(self):
        scenario = self.config/'scenarios/custom.yaml'
        scenario.parent.mkdir()
        scenario.write_text('name: custom/my-rule\n')
        self.run_shell('reset_waf_to_core_baseline true', '\n')
        self.assertTrue(scenario.exists())
        self.assertNotIn('collections remove', self.commands())

    def test_ldnmp_default_http_logs_are_acquired_with_nginx_label(self):
        paths = ['home/web/log/nginx/access.log', 'home/web/log/nginx/error.log']
        for name in paths:
            path = self.base/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.assertEqual(self.run_shell('configure_log_acquis').returncode, 0)
        docs = list(yaml.safe_load_all((self.config/'acquis.d/web-sites.yaml').read_text()))
        acquired = [(path, doc['labels']['type'])
                    for doc in docs for pattern in doc.get('filenames', [])
                    for path in glob.glob(pattern)]
        self.assertCountEqual(acquired, [(str(self.base/name), 'nginx') for name in paths])

    def test_npm_presets_acquire_http_logs_without_stream_or_global_logs(self):
        roots = ['home/docker/npm/data/logs', 'opt/npm/data/logs',
                 'opt/nginx-proxy-manager/data/logs', 'data/logs',
                 'var/log/nginx-proxy-manager']
        http_names = ['proxy-host-1_access.log', 'proxy-host-1_error.log',
                      'redirection-host-2_access.log', 'redirection-host-2_error.log',
                      'dead-host-3_access.log', 'dead-host-3_error.log',
                      'default-host_access.log', 'default-host_error.log',
                      'fallback_http_access.log', 'fallback_http_error.log',
                      'letsencrypt-requests_access.log', 'letsencrypt-requests_error.log']
        excluded_names = ['stream-4_access.log', 'stream-4_error.log',
                          'fallback_stream_access.log', 'fallback_error.log']
        for root in roots:
            directory = self.base/root
            directory.mkdir(parents=True)
            for name in http_names + excluded_names:
                (directory/name).touch()
        self.assertEqual(self.run_shell('configure_log_acquis').returncode, 0)
        docs = list(yaml.safe_load_all((self.config/'acquis.d/web-sites.yaml').read_text()))
        acquired = [(path, doc['labels']['type'])
                    for doc in docs for pattern in doc.get('filenames', [])
                    for path in glob.glob(pattern)]
        self.assertCountEqual(acquired, [(str(self.base/root/name), 'nginx-proxy-manager')
                                       for root in roots for name in http_names])

    def test_metrics_bind_to_loopback_and_preserve_other_settings(self):
        self.run_shell('enable_prometheus_metrics')
        config = yaml.safe_load((self.config/'config.yaml').read_text())
        self.assertEqual(config['prometheus']['listen_addr'], '127.0.0.1')
        self.assertEqual(config['api']['server']['listen_uri'], '127.0.0.1:8080')

    def test_bouncer_repair_never_deletes_other_bouncers(self):
        self.run_shell('repair_firewall_bouncer true', overrides="cscli() { record cscli \"$@\"; if [[ \"$*\" == *list* ]]; then echo 'nginx-bouncer,valid'; else echo '0123456789abcdef0123456789abcdef'; fi; }")
        self.assertNotIn('bouncers delete nginx-bouncer', self.commands())

    def test_webui_failed_pull_preserves_existing_machine(self):
        ui = self.base/'opt/crowdsec-web-ui/data'
        ui.mkdir(parents=True)
        (ui/'webui_api_credentials.yaml').write_text('url: http://127.0.0.1:8080/\nlogin: webui-owned\npassword: abcdefghijklmnopqrst\n')
        self.run_shell('deploy_web_ui', '3000\ny\n\n', 'docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; [[ "$1" != pull ]]; }')
        self.assertNotIn('machines delete', self.commands())
        self.assertNotIn('docker rm', self.commands())

    def test_webui_uninstall_requires_confirmation(self):
        self.run_shell('uninstall_web_ui', 'n\n')
        self.assertNotIn('docker rm', self.commands())
        self.assertNotIn('machines delete', self.commands())

    def test_purge_requires_confirmation_and_never_kills_script(self):
        self.run_shell('deep_purge_residuals', 'n\n')
        self.assertNotIn('pkill', self.commands())
        self.assertNotIn('apt-get', self.commands())

    def test_notification_profile_is_top_level_and_existing_routes_survive(self):
        profile = self.config/'profiles.yaml'
        profile.write_text(profile.read_text()+'notifications:\n  - existing_email\n')
        p = self.run_shell('setup_telegram_notification', '123456:ABC_DEF\n-12345\nhttps://telegram.example/proxy\nn\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        doc = yaml.safe_load(profile.read_text())
        self.assertIn('existing_email', doc['notifications'])
        self.assertIn('crowdsec_1key_telegram', doc['notifications'])

    def test_telegram_invalid_token_does_not_write(self):
        self.run_shell('setup_telegram_notification', 'bad-token\n123\nhttps://api.telegram.org\nn\n')
        self.assertFalse((self.config/'notifications/crowdsec-1key-telegram.yaml').exists())
        self.assertFalse((self.config/'notifications/http.yaml').exists())

    def test_config_validation_failure_prevents_restart(self):
        self.run_shell('setup_telegram_notification', '123456:ABC_DEF\n-12345\nhttps://api.telegram.org\nn\n', 'crowdsec() { record crowdsec "$@"; return 1; }')
        self.assertNotIn('systemctl restart', self.commands())
        self.assertFalse((self.config/'notifications/crowdsec-1key-telegram.yaml').exists())

    def test_appsec_configuration_uses_official_datasource(self):
        p = self.run_shell('setup_appsec', '0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        doc = yaml.safe_load((self.config/'acquis.d/crowdsec-1key-appsec.yaml').read_text())
        self.assertEqual(doc['source'], 'appsec')
        self.assertEqual(doc['listen_addr'], '127.0.0.1:7422')
        self.assertEqual(doc['appsec_configs'], ['crowdsecurity/appsec-default'])
        self.assertIn('appsec-virtual-patching', self.commands())
        self.assertIn('appsec-generic-rules', self.commands())

    def test_appsec_existing_external_listener_is_preserved(self):
        d = self.config/'acquis.d'
        d.mkdir()
        (d/'external.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels:\n  type: appsec\nappsec_configs: [custom/existing]\n')
        self.run_shell('setup_appsec', '0\n')
        self.assertFalse((d/'crowdsec-1key-appsec.yaml').exists())
        self.assertNotIn('collections install', self.commands())

    def appsec_docker_stub(self, mounted=False, network='host', hook=True, waf=True):
        config = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        if mounted:
            config.parent.mkdir(exist_ok=True)
            config.write_text('API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n')
        mounts = json.dumps([{'Type': 'bind', 'Source': str(config), 'Destination': str(config)}] if mounted else [])
        effective = ('init_by_lua_block { require "crowdsec" }\naccess_by_lua_block { cs.Allow(ngx.var.remote_addr) }\n' if hook else '')
        if waf:
            effective += 'access_by_lua_file /usr/local/openresty/1pwaf/waf.lua;\n'
        return '''docker() {
 record docker "$@"
 case "$1" in
 ps) echo 'web123 1panel/openresty:test openresty';;
 inspect) case "$3" in
 *NetworkMode*) echo '''+shlex.quote(network)+''';;
 *Mounts*) printf '%s\\n' '''+shlex.quote(mounts)+''';;
 *Running*) echo true;; esac;;
 exec) case "$4" in
 -T) printf '%s\\n' '''+shlex.quote(effective)+''';;
 -t) return 0;;
 -s) return 0;; esac;;
 esac
}'''

    def test_appsec_container_missing_bouncer_has_guidance_not_host_options(self):
        p = self.run_shell('setup_appsec', '0\n', self.appsec_docker_stub(hook=False))
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('2. 接入宿主机 OpenResty Bouncer', p.stdout)
        self.assertIn('1Panel WAF', p.stdout+p.stderr)
        self.assertIn('host 网络', p.stdout+p.stderr)
        self.assertIn('缺少 CrowdSec Web Bouncer', p.stdout+p.stderr)
        self.assertNotIn('数据源已加载，监听', p.stdout)
        self.assertNotIn('docker cp', self.commands())

    def test_appsec_setup_without_listener_does_not_claim_engine_ready(self):
        p = self.run_shell('setup_appsec', '0\n', 'ss() { return 0; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('[SUCCESS]', p.stdout)
        self.assertIn('未监听', p.stdout+p.stderr)

    def test_appsec_uses_active_custom_acquisition_directory(self):
        active = self.base/'custom-acquis'
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'crowdsec_service': {'acquisition_dir': str(active)}}))
        p = self.run_shell('setup_appsec', '0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((active/'crowdsec-1key-appsec.yaml').exists())
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())

    def test_appsec_existing_container_bouncer_is_linked_and_secret_preserved(self):
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', self.appsec_docker_stub(mounted=True))
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        content = (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text()
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', content)
        self.assertIn('API_KEY=keep-secret', content)
        self.assertNotIn('keep-secret', p.stdout+p.stderr)
        self.assertIn('docker exec web123 nginx -t', self.commands())
        self.assertIn('docker exec web123 nginx -s reload', self.commands())

    def test_appsec_container_bridge_is_not_given_loopback_url(self):
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', self.appsec_docker_stub(mounted=True, network='bridge'))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertNotIn('nginx -s reload', self.commands())
        self.assertIn('仅支持 host 网络', p.stdout+p.stderr)

    def test_appsec_container_bouncer_without_hook_is_not_modified(self):
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', self.appsec_docker_stub(mounted=True, hook=False))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertNotIn('nginx -s reload', self.commands())
        self.assertIn('缺少 CrowdSec Web Bouncer 请求处理调用', p.stdout+p.stderr)

    def test_appsec_container_reload_failure_restores_config(self):
        stub = self.appsec_docker_stub(mounted=True).replace('-s) return 0', '-s) return 1')
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertFalse((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())

    def test_appsec_container_disable_restores_previous_url_and_reloads(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('disable_appsec', 'y\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())
        self.assertFalse((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())

    def test_appsec_container_disable_core_failure_restores_runtime_url(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('disable_appsec', 'y\n', stub+'\ncrowdsec() { record crowdsec "$@"; return 1; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertTrue((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())

    def test_appsec_container_disable_preserves_manual_url_change(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.write_text(file.read_text().replace('http://127.0.0.1:7422', 'http://user.example:7422'))
        p = self.run_shell('disable_appsec', 'y\n', stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('http://user.example:7422', file.read_text())
        self.assertTrue((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())

    def test_appsec_container_link_cancel_does_not_change_bouncer(self):
        p = self.run_shell('setup_appsec', '3\nweb123\nn\n', self.appsec_docker_stub(mounted=True))
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_appsec_recreated_container_can_restore_same_persistent_config(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        recreated = stub.replace("web123 1panel", "web456 1panel").replace('inspect) case', 'inspect) [[ "$4" == web123 ]] && return 1; case')
        p = self.run_shell('disable_appsec', 'y\n', recreated)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertIn('docker exec openresty nginx -s reload', self.commands())

    def test_appsec_disable_staging_failure_reloads_restored_host_config(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        host = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        host.write_text('APPSEC_URL=http://127.0.0.1:7422\n')
        (self.config/'crowdsec-1key-appsec-links.yaml').write_text(yaml.safe_dump({str(host): 'http://host-old.example:7422'}))
        overrides = stub+'\nnginx() { record nginx "$@"; return 0; }\nmktemp() { if [[ "$1" == -d ]]; then command mktemp "$@"; else return 1; fi; }'
        p = self.run_shell('disable_appsec', 'y\n', overrides)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', host.read_text())
        self.assertGreaterEqual(self.commands().count('systemctl reload nginx'), 2)

    def test_appsec_disable_source_removal_failure_restores_and_reloads_container(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        overrides = stub+'\nrm() { if [[ "$*" == *crowdsec-1key-appsec.yaml ]]; then return 1; else command rm "$@"; fi; }'
        p = self.run_shell('disable_appsec', 'y\n', overrides)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertTrue((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())
        self.assertGreaterEqual(self.commands().count('docker exec openresty nginx -s reload'), 2)

    def test_appsec_repeated_container_link_preserves_original_url(self):
        stub = self.appsec_docker_stub(mounted=True)
        for _ in range(2):
            p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('disable_appsec', 'y\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())

    def test_appsec_relink_updates_changed_container_config_destination(self):
        stub = self.appsec_docker_stub(mounted=True)
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        config = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        old_mounts = json.dumps([{'Type': 'bind', 'Source': str(config), 'Destination': str(config)}])
        new_mounts = json.dumps([{'Type': 'bind', 'Source': str(config), 'Destination': str(self.config/'bouncers/crowdsec-nginx-bouncer.conf')}])
        remounted = stub.replace(shlex.quote(old_mounts), shlex.quote(new_mounts))
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', remounted)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('disable_appsec', 'y\n', remounted)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', config.read_text())

    def test_appsec_status_without_source_reports_missing_and_stays_read_only(self):
        p = self.run_shell('check_appsec_status', overrides=self.appsec_docker_stub(hook=False))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('没有启用的 AppSec 数据源', p.stdout+p.stderr)
        self.assertNotRegex(self.commands(), 'systemctl (restart|reload)|nginx -s|collections install')

    def test_appsec_container_unpersisted_config_is_not_linked(self):
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', self.appsec_docker_stub(hook=True))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('持久化', p.stdout+p.stderr)
        self.assertNotIn('nginx -s reload', self.commands())

    def test_appsec_container_tmpfs_child_shadows_parent_mount(self):
        stub = self.appsec_docker_stub(mounted=True)
        original = json.dumps([{'Type': 'bind', 'Source': str(self.config/'bouncers/crowdsec-openresty-bouncer.conf'), 'Destination': str(self.config/'bouncers/crowdsec-openresty-bouncer.conf')}])
        mounts = json.dumps([
            {'Type': 'bind', 'Source': str(self.config), 'Destination': str(self.config)},
            {'Type': 'tmpfs', 'Source': '', 'Destination': str(self.config/'bouncers')}])
        stub = stub.replace(shlex.quote(original), shlex.quote(mounts))
        p = self.run_shell('setup_appsec', '3\nweb123\ny\n', stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', (self.config/'bouncers/crowdsec-openresty-bouncer.conf').read_text())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_purge_with_managed_container_appsec_links_stops_before_changes(self):
        (self.config/'crowdsec-1key-appsec-docker-links.yaml').write_text('custom-path:\n  container: web123\n')
        p = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('systemctl stop', self.commands())
        self.assertIn('容器 Web Bouncer', p.stdout+p.stderr)

    def test_all_main_menu_entries_dispatch(self):
        names = ['install_crowdsec_core','manage_web_ui','manage_waf_rules','manage_auto_update','manage_firewall_ops','bind_crowdsec_console','manage_telegram','smart_audit_and_optimize','check_health_status','manage_uninstall_center']
        overrides = '\n'.join(f'{name}() {{ record invoked {name}; }}' for name in names)
        p = self.run_shell('show_main_menu', '\n'.join(map(str, range(1,11)))+'\n0\n', overrides)
        self.assertEqual(p.returncode, 0)
        for name in names:
            self.assertIn('invoked '+name, self.commands())

    def make_webui(self):
        ui = self.base/'opt/crowdsec-web-ui'
        (ui/'data').mkdir(parents=True)
        (ui/'data/webui_api_credentials.yaml').write_text('url: http://127.0.0.1:8080/\nlogin: webui-owned\npassword: valid-test-password\n')
        (ui/'docker-compose.yml').write_text('services:\n  crowdsec-web-ui:\n    image: ghcr.io/theduffman85/crowdsec-web-ui:old\n')
        return ui

    def test_purge_preserves_config_when_web_bouncer_is_installed(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=http://127.0.0.1:7422\n')
        p = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(file.exists())
        self.assertNotIn('systemctl stop', self.commands())

    def test_external_appsec_bouncer_is_not_disconnected(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=http://127.0.0.1:7422\n')
        self.run_shell('disable_appsec', 'y\n')
        self.assertEqual(file.read_text(), 'APPSEC_URL=http://127.0.0.1:7422\n')
        self.assertNotIn('reload nginx', self.commands())

    def test_ipv6_default_table_is_detected(self):
        p = self.run_shell('firewall_status', overrides="nft() { record nft \"$@\"; [[ \"$*\" == 'list tables' ]] && echo 'table ip6 crowdsec6'; }")
        self.assertEqual(p.returncode, 0)

    def test_webui_credential_check_uses_webui_credentials(self):
        self.make_webui()
        p = self.run_shell('reset_webui_credentials', 'n\n', 'cscli() { record cscli "$@"; [[ "$1" != -c ]]; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('-c', self.commands())

    def test_webui_invalid_credentials_stop_update(self):
        self.make_webui()
        p = self.run_shell('deploy_web_ui', '3000\ny\n', 'cscli() { record cscli "$@"; [[ "$1" != -c ]]; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('compose -f', self.commands())

    def test_webui_running_failure_restores_previous_compose_and_container(self):
        ui = self.make_webui()
        original = (ui/'docker-compose.yml').read_text()
        p = self.run_shell('deploy_web_ui', '3000\ny\n')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual((ui/'docker-compose.yml').read_text(), original)
        self.assertGreaterEqual(self.commands().count(' up -d'), 2)

    def test_all_submenus_exit_on_eof(self):
        for name in ['manage_web_ui','manage_waf_rules','manage_auto_update','manage_firewall_ops','manage_telegram','manage_uninstall_center']:
            with self.subTest(menu=name):
                self.assertEqual(self.run_shell(name, timeout=1).returncode, 0)

    def test_valid_cron_leading_zero_is_decimal(self):
        p = self.run_shell('enable_auto_update 08 09')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('8 9 * * * root', (self.base/'etc/cron.d/crowdsec-autoupdate').read_text())

    def test_telegram_setup_is_idempotent_and_disable_preserves_other_routes(self):
        for _ in range(2):
            self.assertEqual(self.run_shell('setup_telegram_notification', '123456:ABC_DEF\n-123\nhttps://telegram.example/proxy\nn\n').returncode, 0)
        docs = list(yaml.safe_load_all((self.config/'profiles.yaml').read_text()))
        self.assertEqual(docs[0]['notifications'].count('crowdsec_1key_telegram'), 1)
        self.assertEqual(self.run_shell('disable_telegram_notification', 'y\n').returncode, 0)
        self.assertFalse((self.config/'notifications/crowdsec-1key-telegram.yaml').exists())
        self.assertNotIn('notifications', yaml.safe_load((self.config/'profiles.yaml').read_text()))

    def test_core_install_failure_stops_before_starting_services(self):
        p = self.run_shell('install_crowdsec_core', '203.0.113.2\n', 'apt-get() { record apt-get "$@"; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('systemctl enable', self.commands())

    def test_optimize_cancel_does_not_change_configuration(self):
        before = (self.config/'config.yaml').read_text()
        self.run_shell('smart_audit_and_optimize', 'n\n')
        self.assertEqual((self.config/'config.yaml').read_text(), before)
        self.assertNotIn('collections install', self.commands())
        self.assertNotIn('systemctl restart', self.commands())

    def test_optimize_without_yaml_can_diagnose_and_cancel(self):
        before = (self.config/'config.yaml').read_text()
        p = self.run_shell('smart_audit_and_optimize', 'n\n',
                           'require_yaml() { return 1; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('cscli metrics', self.commands())
        self.assertEqual((self.config/'config.yaml').read_text(), before)
        self.assertNotIn('collections install', self.commands())
        self.assertNotIn('apt-get', self.commands())
        self.assertNotIn('systemctl restart', self.commands())

    def test_optimize_without_yaml_stops_before_applying_changes(self):
        before = (self.config/'config.yaml').read_text()
        p = self.run_shell('smart_audit_and_optimize', 'y\n',
                           'require_yaml() { return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('cscli metrics', self.commands())
        self.assertEqual((self.config/'config.yaml').read_text(), before)
        self.assertNotIn('collections install', self.commands())
        self.assertNotIn('apt-get', self.commands())
        self.assertNotIn('systemctl restart', self.commands())

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

    def test_optimize_repairs_missing_1panel_log_acquisition(self):
        log = self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        original = self.config/'acquis.d/web-sites.yaml'
        original.parent.mkdir()
        original.write_text('# Keep my custom settings\nfilenames: [/custom/access.log]\nlabels: {type: nginx, site: custom}\n')
        before = original.read_bytes()
        p = self.run_shell('smart_audit_and_optimize', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn((str(log), 'nginx'), self.repaired_sources())
        self.assertEqual(original.read_bytes(), before)
        self.assertIn('systemctl restart crowdsec', self.commands())

    def test_log_repair_discovers_custom_docker_mounts_and_excludes_stream_logs(self):
        nginx_log = self.web_log('srv/custom panel/www/sites/bob.example.com/log/access.log')
        npm_log = self.web_log('srv/custom-npm/logs/proxy-host-1_access.log')
        self.web_log('srv/custom-npm/logs/stream-1_access.log')
        self.web_log('srv/custom-npm/logs/fallback_stream_access.log')
        nginx_mounts = json.dumps([{'Source': str(self.base/'srv/custom panel/www'), 'Destination': '/www'}])
        npm_mounts = json.dumps([{'Source': str(self.base/'srv/custom-npm/logs'), 'Destination': '/data/logs'}])
        override = '''docker() {
 record docker "$@"
 case "$*" in
  'ps --format {{.ID}} {{.Image}}') printf '%s\\n' 'web1 1panel/openresty:latest' 'web2 jc21/nginx-proxy-manager:latest' 'other cloudflare/cloudflared:latest' ;;
  'inspect --format {{json .Mounts}} web1') printf '%s\\n' ''' + shlex.quote(nginx_mounts) + ''' ;;
  'inspect --format {{json .Mounts}} web2') printf '%s\\n' ''' + shlex.quote(npm_mounts) + ''' ;;
  *) return 1 ;;
 esac
}'''
        p = self.run_shell('main --repair-logs', 'y\n', override)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertCountEqual(self.repaired_sources(), [(str(nginx_log), 'nginx'),
                                                       (str(npm_log), 'nginx-proxy-manager')])

    def test_log_repair_is_idempotent_and_skips_logs_already_acquired_via_alias(self):
        directory = self.base/'opt/1panel/1panel/www/sites/bob.example.com/log'
        covered = self.web_log(str(directory.relative_to(self.base)/'access.log'))
        added = self.web_log(str(directory.relative_to(self.base)/'error.log'))
        alias = self.base/'alias-access.log'
        alias.symlink_to(covered)
        original = self.config/'acquis.d/custom.yaml'
        original.parent.mkdir()
        original.write_text(yaml.safe_dump({'filenames': [str(alias)], 'labels': {'type': 'nginx'}}))
        before = original.read_bytes()
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.repaired_sources(), [(str(added), 'nginx')])
        repair = self.config/'acquis.d/crowdsec-1key-log-repair.yaml'
        first = repair.read_bytes()
        self.trace.write_text('')
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(repair.read_bytes(), first)
        self.assertEqual(original.read_bytes(), before)
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_cancel_keeps_acquisition_and_services_unchanged(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        p = self.run_shell('repair_log_acquis', 'n\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_validation_failure_restores_existing_repair_config(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        repair = self.config/'acquis.d/crowdsec-1key-log-repair.yaml'
        repair.parent.mkdir()
        repair.write_text('# Previous repair\nfilenames: [/custom/other.log]\nlabels: {type: nginx}\n')
        before = repair.read_bytes()
        p = self.run_shell('repair_log_acquis', 'y\n',
                           'crowdsec() { record crowdsec "$@"; return 1; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('crowdsec -t', self.commands())
        self.assertEqual(repair.read_bytes(), before)
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_with_unavailable_docker_still_finds_existing_preset_logs(self):
        log = self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        p = self.run_shell('repair_log_acquis', 'y\n',
                           'docker() { record docker "$@"; return 1; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn((str(log), 'nginx'), self.repaired_sources())

    def test_log_repair_malformed_mount_data_stops_without_writing_config(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        p = self.run_shell('repair_log_acquis', 'y\n', '''docker() {
 record docker "$@"
 case "$1" in ps) echo 'web1 1panel/openresty:latest';; inspect) echo 'not-json';; esac
}''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('docker inspect --format', self.commands())
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_respects_active_acquisition_paths_from_config_local(self):
        covered = self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        added = self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/error.log')
        active = self.base/'srv/crowdsec-acquis'
        active.mkdir(parents=True)
        single = self.base/'srv/custom-acquisition.yaml'
        single.write_text(yaml.safe_dump({'filenames': [str(covered)], 'labels': {'type': 'nginx'}}))
        override = self.config/'config.yaml.local'
        override.write_text(yaml.safe_dump({'crowdsec_service': {
            'acquisition_path': str(single), 'acquisition_dir': str(active)}}))
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        repair = active/'crowdsec-1key-log-repair.yaml'
        self.assertTrue(repair.exists(), p.stdout+p.stderr)
        docs = list(yaml.safe_load_all(repair.read_text()))
        self.assertEqual([name for doc in docs for name in doc['filenames']], [str(added)])
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())

    def test_log_repair_excludes_files_hidden_by_more_specific_docker_mounts(self):
        self.web_log('home/docker/npm/data/logs/proxy-host-1_access.log')
        self.web_log('opt/1panel/www/sites/old.example.com/log/access.log')
        npm_log = self.web_log('srv/active-npm/proxy-host-2_access.log')
        nginx_log = self.web_log('srv/active-sites/bob.example.com/log/access.log')
        npm_mounts = json.dumps([
            {'Source': str(self.base/'home/docker/npm/data'), 'Destination': '/data'},
            {'Source': str(self.base/'srv/active-npm'), 'Destination': '/data/logs'}])
        nginx_mounts = json.dumps([
            {'Source': str(self.base/'opt/1panel/www'), 'Destination': '/www'},
            {'Source': str(self.base/'srv/active-sites'), 'Destination': '/www/sites'}])
        override = '''docker() {
 record docker "$@"
 case "$1" in
  ps) printf '%s\\n' 'web1 1panel/openresty:latest' 'web2 jc21/nginx-proxy-manager:latest' ;;
  inspect) case "${@: -1}" in
   web1) printf '%s\\n' '''+shlex.quote(nginx_mounts)+''' ;;
   web2) printf '%s\\n' '''+shlex.quote(npm_mounts)+''' ;;
   esac ;;
 esac
}'''
        p = self.run_shell('repair_log_acquis', 'y\n', override)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertCountEqual(self.repaired_sources(), [(str(nginx_log), 'nginx'),
                                                       (str(npm_log), 'nginx-proxy-manager')])

    def test_log_repair_skips_single_filename_and_go_escaped_existing_sources(self):
        cases = [('filename', 'bob.example.com', None),
                 ('filenames', 'bob[one]', r'bob\[one\]'),
                 ('filenames', 'bob!', 'bob[!x]'),
                 ('filenames', 'b', '[^z-a]')]
        for key, folder, pattern_folder in cases:
            with self.subTest(key=key, folder=folder):
                self.web_log('opt/1panel/1panel/www/sites/'+folder+'/log/access.log')
        original = self.config/'acquis.d/other.yaml'
        original.parent.mkdir()
        docs = []
        for key, folder, pattern_folder in cases:
            pattern = str(self.base/'opt/1panel/1panel/www/sites')+'/'+(pattern_folder or folder)+'/log/access.log'
            docs.append({key: pattern if key == 'filename' else [pattern], 'labels': {'type': 'nginx'}})
        docs.append({'filenames': [str(self.base/'opt/1panel/1panel/www/sites')+'/[z-a]/log/access.log'],
                     'labels': {'type': 'nginx'}})
        original.write_text(yaml.safe_dump_all(docs))
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_rejects_symlink_destination_without_changing_target(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        target = self.base/'external-acquisition.yaml'
        target.write_text('filenames: [/custom/old.log]\nlabels: {type: nginx}\n')
        before = target.read_bytes()
        repair = self.config/'acquis.d/crowdsec-1key-log-repair.yaml'
        repair.parent.mkdir()
        repair.symlink_to(target)
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertEqual(target.read_bytes(), before)
        self.assertTrue(repair.is_symlink())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_ignores_unrelated_tmpfs_mounts(self):
        log = self.web_log('srv/custom-nginx/access.log')
        mounts = json.dumps([
            {'Type': 'bind', 'Source': str(self.base/'srv/custom-nginx'), 'Destination': '/var/log/nginx'},
            {'Type': 'tmpfs', 'Source': '', 'Destination': '/tmp'}])
        override = '''docker() {
 case "$1" in ps) echo 'web1 nginx:alpine';;
 inspect) printf '%s\\n' '''+shlex.quote(mounts)+''' ;;
 esac
}'''
        p = self.run_shell('repair_log_acquis', 'y\n', override)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.repaired_sources(), [(str(log), 'nginx')])

    def test_log_repair_disabled_acquisition_directory_stops_without_writes(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        (self.config/'config.yaml.local').write_text('crowdsec_service:\n  acquisition_dir: null\n')
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_missing_acquisition_directory_stops_without_writes(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        config = self.config/'config.yaml'
        data = yaml.safe_load(config.read_text())
        del data['crowdsec_service']['acquisition_dir']
        config.write_text(yaml.safe_dump(data))
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_disabled_agent_stops_without_writes(self):
        self.web_log('opt/1panel/1panel/www/sites/bob.example.com/log/access.log')
        (self.config/'config.yaml.local').write_text('crowdsec_service:\n  enable: false\n')
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_log_repair_outputs_go_escaped_literal_paths(self):
        self.web_log(r'opt/1panel/1panel/www/sites/bob[one]\two/log/access.log')
        p = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        expected = str(self.base)+r'/opt/1panel/1panel/www/sites/bob\[one\]\\two/log/access.log'
        self.assertEqual(self.repaired_sources(), [(expected, 'nginx')])

    def test_collection_removal_cancel_preserves_rules(self):
        self.run_shell('uninstall_specific_waf_collection', 'crowdsecurity/wordpress\nn\n')
        self.assertNotIn('collections remove', self.commands())

    def test_node_cleanup_preserves_host_machine(self):
        p = self.run_shell('check_and_clean_redundant_instances', 'webui-legitimate-host\ny\n')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('machines delete', self.commands())

    def test_notification_test_propagates_plugin_error(self):
        (self.config/'notifications').mkdir()
        (self.config/'notifications/crowdsec-1key-telegram.yaml').write_text('type: http\n')
        p = self.run_shell('test_telegram_notification', overrides='cscli() { return 1; }')
        self.assertNotEqual(p.returncode, 0)

    def test_appsec_disable_restores_only_recorded_bouncer_url(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=http://127.0.0.1:7300\n')
        p = self.run_shell('setup_appsec', '1\n', 'nginx() { record nginx "$@"; return 0; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('disable_appsec', 'y\n', 'nginx() { record nginx "$@"; return 0; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(file.read_text(), 'APPSEC_URL=http://127.0.0.1:7300\n')

    def test_appsec_disable_validation_failure_restores_runtime_bouncer(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=\n')
        self.run_shell('setup_appsec', '1\n', 'nginx() { return 0; }')
        self.trace.write_text('')
        p = self.run_shell('disable_appsec', 'y\n', 'nginx() { return 0; }; crowdsec() { record crowdsec "$@"; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(file.read_text(), 'APPSEC_URL=http://127.0.0.1:7422\n')
        self.assertGreaterEqual(self.commands().count('reload nginx'), 2)

    def test_bouncer_uses_local_override_and_preserves_package_defaults(self):
        file = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        file.parent.mkdir()
        original = 'mode: iptables\napi_key: existing-key\napi_url: http://127.0.0.1:9000/\niptables_chains: [INPUT]\n'
        file.write_text(original)
        self.run_shell('repair_firewall_bouncer', overrides='iptables() { record iptables "$@"; return 0; }')
        self.assertEqual(file.read_text(), original)
        local = yaml.safe_load(Path(str(file)+'.local').read_text())
        self.assertEqual(local['api_url'], 'http://127.0.0.1:8080/')
        self.assertIn('DOCKER-USER', local.get('iptables_v4_chains', []))
        self.assertNotIn('iptables_chains', local)  # Do not add an IPv4-only chain to IPv6.

    def test_metrics_respects_local_overrides(self):
        local = self.config/'config.yaml.local'
        local.write_text('prometheus:\n  listen_addr: 0.0.0.0\nother: keep-me\n')
        self.run_shell('enable_prometheus_metrics')
        doc = yaml.safe_load(local.read_text())
        self.assertEqual(doc['prometheus']['listen_addr'], '127.0.0.1')
        self.assertEqual(doc['other'], 'keep-me')

    def test_core_success_writes_whitelist_and_starts_services(self):
        p = self.run_shell('install_crowdsec_core', '203.0.113.2\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        whitelist = yaml.safe_load((self.config/'parsers/s02-enrich/99-admin-whitelist.yaml').read_text())
        self.assertIn('203.0.113.2', whitelist['whitelist']['ip'])
        self.assertIn('enable --now crowdsec-firewall-bouncer', self.commands())

    def test_webui_success_reuses_credentials(self):
        ui = self.make_webui()
        old = (ui/'data/webui_api_credentials.yaml').read_text()
        p = self.run_shell('deploy_web_ui', '3000\ny\n', 'docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((ui/'data/webui_api_credentials.yaml').read_text(), old)
        compose = yaml.safe_load((ui/'docker-compose.yml').read_text())
        env = compose['services']['crowdsec-web-ui']['environment']
        self.assertEqual(env['CONFIG_INSTANCE_LAPI_AUTH_USERNAME'], 'webui-owned')
        self.assertNotIn('machines add', self.commands())

    def test_manual_ban_valid_go_duration_submits_decision(self):
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n168h\ntest\n0\n')
        self.assertIn('decisions add --ip 203.0.113.5 --duration 168h', self.commands())

    def test_current_ssh_ip_cannot_be_banned(self):
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n0\n', 'SSH_CLIENT="203.0.113.5 12345 22"')
        self.assertNotIn('decisions add', self.commands())

    def test_console_success_does_not_delete_nodes(self):
        p = self.run_shell('bind_crowdsec_console', 'test-token\n')
        self.assertEqual(p.returncode, 0)
        self.assertIn('console enroll test-token', self.commands())
        self.assertNotIn('machines delete', self.commands())

    def test_residual_check_never_offers_or_runs_purge(self):
        self.run_shell('audit_crowdsec_residuals', 'y\n')
        self.assertTrue(self.config.exists())
        self.assertNotIn('systemctl stop', self.commands())
        self.assertNotIn('apt-get', self.commands())

    def test_confirmed_uninstall_only_removes_managed_data(self):
        other = self.base/'opt/other-app'
        other.mkdir(parents=True)
        p = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(self.config.exists())
        self.assertTrue(other.exists())
        self.assertNotIn('pkill', self.commands())

    def test_webui_uninstall_only_unregisters_its_machine(self):
        self.make_webui()
        p = self.run_shell('uninstall_web_ui', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('machines delete webui-owned', self.commands())
        self.assertNotIn('machines delete webui-other-owner', self.commands())

    def test_webui_rollback_pins_previous_image(self):
        self.make_webui()
        image = 'sha256:'+'a'*64
        stub = 'docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; if [[ "$*" == *"{{.Image}}"* ]]; then echo '+image+'; elif [[ "$*" == *"State.Running"* ]]; then echo false; fi; return 0; }'
        self.run_shell('deploy_web_ui', '3000\ny\n', stub)
        self.assertIn('--pull never', self.commands())

    def test_custom_nft_table_is_detected(self):
        cfg = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        cfg.parent.mkdir()
        cfg.write_text('mode: nftables\nnftables:\n  ipv4:\n    table: my_custom_table\n')
        p = self.run_shell('firewall_status', overrides="nft() { record nft \"$@\"; [[ \"$*\" == 'list tables' ]] && echo 'table ip my_custom_table'; }")
        self.assertEqual(p.returncode, 0)

    def test_web_bouncer_missing_does_not_claim_full_waf_ready(self):
        p = self.run_shell('setup_appsec', '1\n')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('未安装对应 Web Bouncer', p.stderr)

    def test_extra_cli_arguments_are_rejected(self):
        p = self.run_shell('main --install-waf --purge')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(self.commands(), '')

    def test_sqlite_wal_uses_official_configuration(self):
        path = self.config/'config.yaml'
        doc = yaml.safe_load(path.read_text())
        doc['db_config'] = {'type': 'sqlite', 'db_path': '/tmp/local-test.db'}
        path.write_text(yaml.safe_dump(doc))
        p = self.run_shell('enable_sqlite_wal', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue(yaml.safe_load(path.read_text())['db_config']['use_wal'])
        self.assertIn('crowdsec -t', self.commands())
        self.assertNotIn('VACUUM', self.commands())

    def test_webui_new_deployment_creates_only_one_dedicated_machine(self):
        stub = r'''
docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; if [[ "$*" == 'container inspect crowdsec-web-ui' ]]; then return 1; fi; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }
cscli() {
 record cscli "$@"
 if [[ "$1 $2" == 'machines add' ]]; then
  local machine="$3" file='' arg
  shift 3
  while (($#)); do arg="$1"; shift; if [[ "$arg" == -f ]]; then file="$1"; shift; fi; done
  printf 'url: http://127.0.0.1:8080/\nlogin: %s\npassword: fresh-test-password\n' "$machine" > "$file"
 fi
 return 0
}
'''
        p = self.run_shell('deploy_web_ui', '3000\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().count('machines add'), 1)
        creds = yaml.safe_load((self.base/'opt/crowdsec-web-ui/data/webui_api_credentials.yaml').read_text())
        self.assertTrue(creds['login'].startswith('webui-1key-'))
        self.assertEqual((self.config/'local_api_credentials.yaml').read_text().split('login: ')[1].splitlines()[0], 'webui-legitimate-host')

    def test_webui_rotation_deletes_old_machine_only_after_success(self):
        self.make_webui()
        stub = r'''
docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }
cscli() {
 record cscli "$@"
 if [[ "$1 $2" == 'machines add' ]]; then
  local machine="$3" file='' arg
  shift 3
  while (($#)); do arg="$1"; shift; if [[ "$arg" == -f ]]; then file="$1"; shift; fi; done
  printf 'url: http://127.0.0.1:8080/\nlogin: %s\npassword: rotated-test-password\n' "$machine" > "$file"
 fi
 return 0
}
'''
        p = self.run_shell('deploy_web_ui rotate', '3000\ny\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        trace = self.commands()
        self.assertIn('machines add', trace)
        self.assertIn('machines delete webui-owned', trace)
        self.assertLess(trace.index('State.Running'), trace.index('machines delete webui-owned'))

    def test_bouncer_invalid_api_key_does_not_claim_repaired(self):
        file = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        file.parent.mkdir()
        file.write_text('mode: nftables\napi_key: invalid-key\n')
        p = self.run_shell('repair_firewall_bouncer', overrides='curl() { record curl "$@"; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('SUCCESS', p.stdout)
        self.assertNotIn('systemctl restart', self.commands())

    def test_equivalent_ipv6_ssh_ip_cannot_be_banned(self):
        self.run_shell('manage_firewall_ops', '4\n2001:0db8:0:0:0:0:0:1\n4h\ntest\n0\n', 'SSH_CLIENT="2001:db8::1 12345 22"')
        self.assertNotIn('decisions add', self.commands())

    def test_purge_checks_custom_tables_before_package_removes_config(self):
        cfg = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        cfg.parent.mkdir()
        cfg.write_text('mode: nftables\nnftables:\n  ipv4:\n    table: lingering_custom_table\n')
        stub = 'dpkg-query() { echo "install ok installed"; }; apt-get() { record apt-get "$@"; rm -f '+shlex.quote(str(cfg))+'; }; nft() { record nft "$@"; [[ "$*" == "list tables" ]] && echo "table ip lingering_custom_table"; }'
        p = self.run_shell('deep_purge_residuals', 'y\n', stub)
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(cfg.exists())
        self.assertNotIn('apt-get purge', self.commands())


if __name__ == '__main__':
    unittest.main()
