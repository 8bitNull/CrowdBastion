"""Effective operation regressions using temporary configurations and command fixtures."""
import subprocess
import yaml
import unittest
import test_workflows
ROOT = test_workflows.ROOT


class AuditOps(unittest.TestCase):
    # Reuse only fixture helpers; keep the baseline suite independent.
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    web_log = test_workflows.Workflows.web_log
    make_webui = test_workflows.Workflows.make_webui
    def helper(self, *args):
        return subprocess.run(['python3', str(ROOT/'lib/crowdsec_config.py'), *map(str, args)], text=True, capture_output=True)

    def test_empty_local_metrics_and_wal(self):
        config = self.config/'config.yaml'
        data = yaml.safe_load(config.read_text())
        data['db_config'] = {'type': 'sqlite'}
        config.write_text(yaml.safe_dump(data))
        local = self.config/'config.yaml.local'
        local.write_text('# empty override\n')
        for operation in ['metrics', 'wal']:
            p = self.helper(operation, config)
            self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(yaml.safe_load(local.read_text())['db_config']['use_wal'])

    def test_nonmapping_config_reports_clear_error(self):
        (self.config/'config.yaml.local').write_text('- bad\n')
        p = self.helper('metrics', self.config/'config.yaml')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('mapping', p.stderr)
        self.assertNotIn('Traceback', p.stderr)

    def active_telegram(self):
        profiles = self.base/'active/profiles.yaml'
        profiles.parent.mkdir()
        profiles.write_text((self.config/'profiles.yaml').read_text())
        local = profiles.with_name(profiles.name+'.local')
        local.write_text('name: earlier\nfilters: [Alert.Remediation == true]\non_success: break\nnotifications: [other]\n')
        notifications = self.base/'active/notifications'
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'api': {'server': {'profiles_path': str(profiles)}}, 'config_paths': {'notification_dir': str(notifications)}}))
        return profiles, local, notifications

    def test_telegram_uses_active_paths_and_earlier_local_profiles(self):
        profiles, local, notifications = self.active_telegram()
        p = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\nn\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        for path in [profiles, local]:
            self.assertIn('crowdsec_1key_telegram', yaml.safe_load(path.read_text()).get('notifications', []))
        self.assertTrue((notifications/'crowdsec-1key-telegram.yaml').exists())
        self.assertNotIn('notifications', yaml.safe_load((self.config/'profiles.yaml').read_text()))
        p = self.run_shell('disable_telegram_notification', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(yaml.safe_load(local.read_text())['notifications'], ['other'])
        self.assertFalse((notifications/'crowdsec-1key-telegram.yaml').exists())

    def test_telegram_setup_failed_test_returns_failure(self):
        p = self.run_shell('setup_telegram_notification', '123:ABC\n-123\n\ny\n', 'cscli() { record cscli "$@"; [[ "$1 $2" != "notifications test" ]]; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((self.config/'notifications/crowdsec-1key-telegram.yaml').exists())

    def test_core_install_uses_active_acquisition_and_mounts(self):
        active = self.base/'active/acquis'
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'crowdsec_service': {'acquisition_dir': str(active)}}))
        self.web_log('opt/1panel/www/sites/example/log/access.log')
        p = self.run_shell('install_crowdsec_core', '203.0.113.2\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((active/'crowdsec-1key-log-repair.yaml').exists())
        self.assertFalse((self.config/'acquis.d/web-sites.yaml').exists())

    def test_webui_compose_requires_auth_and_custom_port_healthcheck(self):
        path = self.base/'compose.yml'
        p = self.helper('compose', path, self.base, 'http://127.0.0.1:8080', 'user', 'secret', '3100')
        self.assertEqual(p.returncode, 0, p.stderr)
        service = yaml.safe_load(path.read_text())['services']['crowdsec-web-ui']
        self.assertEqual(service['environment'].get('CONFIG_AUTH_ENABLED'), 'true')
        self.assertIn('3100/api/health', str(service['healthcheck']))

    def test_webui_running_without_http_readiness_fails(self):
        self.make_webui()
        p = self.run_shell('deploy_web_ui', '3000\ny\n', 'docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; [[ "$*" == *State.Running* ]] && echo true; return 0; }; curl() { record curl "$@"; echo 503; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('machines delete webui-owned', self.commands())

    def test_webui_public_exposure_requires_confirmation(self):
        self.make_webui()
        p = self.run_shell('deploy_web_ui', '3000\nn\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('docker pull', self.commands())
        self.assertNotIn('machines add', self.commands())

    def test_webui_compose_uses_exact_image_identity(self):
        path = self.base/'pinned-compose.yml'
        image = 'sha256:'+'a'*64
        p = self.helper('compose', path, self.base, 'http://127.0.0.1:8080', 'user', 'secret', '3100', image)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(yaml.safe_load(path.read_text())['services']['crowdsec-web-ui']['image'], image)

    def test_webui_rotation_failed_new_lapi_preserves_old_machine(self):
        self.make_webui()
        override = r'''docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; [[ "$*" == *State.Running* ]] && echo true; return 0; }
cscli() {
 record cscli "$@"
 if [[ "$1 $2" == 'machines add' ]]; then
  local machine="$3" file=''; shift 3
  while (($#)); do if [[ "$1" == -f ]]; then file="$2"; shift; fi; shift; done
  printf 'url: http://127.0.0.1:8080/\nlogin: %s\npassword: new-password\n' "$machine" > "$file"
 fi
 [[ "$1" != -c ]]
}'''
        p = self.run_shell('deploy_web_ui rotate', '3000\ny\n', override)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('machines delete webui-owned', self.commands())
        self.assertEqual(yaml.safe_load((self.base/'opt/crowdsec-web-ui/data/webui_api_credentials.yaml').read_text())['login'], 'webui-owned')

    def test_health_fails_for_deployed_exited_webui(self):
        self.make_webui()
        p = self.run_shell('check_health_status', overrides='firewall_status() { return 0; }; docker() { record docker "$@"; if [[ "$1 $2" == "image inspect" ]]; then printf "sha256:%064d\n" 0; return 0; fi; [[ "$*" == *State.Running* ]] && echo false; return 0; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)

    def test_health_core_only_does_not_require_optional_firewall(self):
        p = self.run_shell('check_health_status', overrides='''systemctl() { record systemctl "$@"; [[ "$*" != 'is-active crowdsec-firewall-bouncer' ]]; }
firewall_status() { record firewall-status; return 1; }''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('Firewall Bouncer: 未部署', p.stdout)
        self.assertNotIn('firewall-status', self.commands())
        self.assertNotIn('is-active crowdsec-firewall-bouncer', self.commands())

    def test_health_checks_firewall_when_unit_is_installed(self):
        p = self.run_shell('check_health_status', overrides='''systemctl() { record systemctl "$@"; if [[ "$1" == list-unit-files ]]; then echo 'crowdsec-firewall-bouncer.service enabled'; elif [[ "$*" == 'is-active crowdsec-firewall-bouncer' ]]; then return 1; fi; return 0; }
firewall_status() { record firewall-status; return 0; }''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('firewall-status', self.commands())

    def test_health_checks_appsec_under_effective_custom_acquisition_directory(self):
        active = self.base/'active/acquis'
        active.mkdir(parents=True)
        (active/'external-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n')
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'crowdsec_service': {'acquisition_dir': str(active)}}))
        p = self.run_shell('check_health_status', overrides='firewall_status() { return 0; }; check_appsec_status() { record appsec-status; return 1; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('appsec-status', self.commands())

    def test_health_fails_when_effective_appsec_sources_cannot_be_read(self):
        (self.config/'config.yaml.local').write_text('- invalid config mapping\n')
        p = self.run_shell('check_health_status', overrides='firewall_status() { return 0; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('无法读取有效 AppSec 数据源', p.stdout+p.stderr)

    def test_health_fails_when_optional_firewall_deployment_is_unknown(self):
        p = self.run_shell('check_health_status', overrides='''systemctl() { record systemctl "$@"; [[ "$1" != list-unit-files ]]; }
firewall_status() { return 0; }''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('无法确认 Firewall Bouncer', p.stdout+p.stderr)
        self.assertNotIn('Firewall Bouncer: 未部署', p.stdout)
