"""User workflow regression tests; all system effects are confined to a temporary tree."""
import fnmatch
import glob
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
        for prefix in ['/etc/', '/var/', '/opt/', '/run/', '/home/', '/data/logs']:
            source = source.replace(prefix, str(self.base) + prefix)
        self.source = self.base / "manager.sh"
        self.source.write_text(source)
        (self.base / "lib").mkdir()
        helper = ROOT / "lib/crowdsec_config.py"
        if helper.exists():
            (self.base / "lib/crowdsec_config.py").write_text(helper.read_text())
        self.trace = self.base / "trace"
        self.trace.touch()
        self.config = self.base / "etc/crowdsec"
        self.config.mkdir(parents=True)
        (self.base / "etc/cron.d").mkdir(parents=True)
        (self.config / "config.yaml").write_text('api:\n  client:\n    credentials_path: '+str(self.config/'local_api_credentials.yaml')+'\n  server:\n    listen_uri: 127.0.0.1:8080\nprometheus:\n  enabled: false\n  listen_addr: 0.0.0.0\n  listen_port: 6060\n  level: aggregated\n')
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
docker() { record docker "$@"; case "$*" in inspect*) echo false;; esac; return 0; }
apt-get() { record apt-get "$@"; return 0; }
yum() { record yum "$@"; return 0; }
dnf() { record dnf "$@"; return 0; }
nft() { record nft "$@"; return 1; }
iptables() { record iptables "$@"; return 1; }
ip6tables() { record ip6tables "$@"; return 1; }
ipset() { record ipset "$@"; return 1; }
modprobe() { return 0; }
curl() { record curl "$@"; return 0; }
pkill() { record pkill "$@"; return 0; }
pgrep() { return 1; }
dpkg-query() { return 1; }
rpm() { return 1; }
ss() { return 0; }
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
        self.run_shell('deploy_web_ui', '3000\n\n', 'docker() { record docker "$@"; [[ "$1" != pull ]]; }')
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
        p = self.run_shell('firewall_status', overrides="nft() { record nft \"$@\"; [[ \"$*\" == 'list table ip6 crowdsec6' ]]; }")
        self.assertEqual(p.returncode, 0)

    def test_webui_credential_check_uses_webui_credentials(self):
        self.make_webui()
        p = self.run_shell('reset_webui_credentials', 'n\n', 'cscli() { record cscli "$@"; [[ "$1" != -c ]]; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('-c', self.commands())

    def test_webui_invalid_credentials_stop_update(self):
        self.make_webui()
        p = self.run_shell('deploy_web_ui', '3000\n', 'cscli() { record cscli "$@"; [[ "$1" != -c ]]; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('compose -f', self.commands())

    def test_webui_running_failure_restores_previous_compose_and_container(self):
        ui = self.make_webui()
        original = (ui/'docker-compose.yml').read_text()
        p = self.run_shell('deploy_web_ui', '3000\n')
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
        p = self.run_shell('deploy_web_ui', '3000\n', 'docker() { record docker "$@"; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }')
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
        stub = 'docker() { record docker "$@"; if [[ "$*" == *"{{.Image}}"* ]]; then echo '+image+'; elif [[ "$*" == *"State.Running"* ]]; then echo false; fi; return 0; }'
        self.run_shell('deploy_web_ui', '3000\n', stub)
        self.assertIn('--pull never', self.commands())

    def test_custom_nft_table_is_detected(self):
        cfg = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        cfg.parent.mkdir()
        cfg.write_text('mode: nftables\nnftables:\n  ipv4:\n    table: my_custom_table\n')
        p = self.run_shell('firewall_status', overrides="nft() { record nft \"$@\"; [[ \"$*\" == 'list table ip my_custom_table' ]]; }")
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
docker() { record docker "$@"; if [[ "$*" == 'container inspect crowdsec-web-ui' ]]; then return 1; fi; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }
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
        p = self.run_shell('deploy_web_ui', '3000\n', stub)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().count('machines add'), 1)
        creds = yaml.safe_load((self.base/'opt/crowdsec-web-ui/data/webui_api_credentials.yaml').read_text())
        self.assertTrue(creds['login'].startswith('webui-1key-'))
        self.assertEqual((self.config/'local_api_credentials.yaml').read_text().split('login: ')[1].splitlines()[0], 'webui-legitimate-host')

    def test_webui_rotation_deletes_old_machine_only_after_success(self):
        self.make_webui()
        stub = r'''
docker() { record docker "$@"; if [[ "$*" == *State.Running* ]]; then echo true; fi; return 0; }
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
        p = self.run_shell('deploy_web_ui rotate', '3000\n', stub)
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
        stub = 'dpkg-query() { echo "install ok installed"; }; apt-get() { record apt-get "$@"; rm -f '+shlex.quote(str(cfg))+'; }; nft() { record nft "$@"; [[ "$*" == "list table ip lingering_custom_table" ]]; }'
        p = self.run_shell('deep_purge_residuals', 'y\n', stub)
        self.assertNotEqual(p.returncode, 0)
        self.assertTrue(cfg.exists())
        self.assertNotIn('apt-get purge', self.commands())


if __name__ == '__main__':
    unittest.main()
