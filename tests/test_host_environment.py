"""Host compatibility and failed transaction regression coverage."""
import os
from pathlib import Path
import shlex
import unittest

import yaml

import test_workflows


class HostEnvironment(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    make_webui = test_workflows.Workflows.make_webui

    def bouncer(self, content='mode: nftables\napi_key: ""\n'):
        path = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        path.parent.mkdir(exist_ok=True)
        path.write_text(content)
        return path

    def test_reinstall_keeps_existing_firewall_backend(self):
        self.bouncer('mode: iptables\n')
        result = self.run_shell('install_bouncer_package')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('crowdsec-firewall-bouncer-iptables', self.commands())
        self.assertNotIn('crowdsec-firewall-bouncer-nftables', self.commands())

    def test_reinstall_keeps_admin_whitelist_and_custom_expressions(self):
        path = self.config/'parsers/s02-enrich/99-admin-whitelist.yaml'
        path.parent.mkdir(parents=True)
        path.write_text('name: custom/admin-whitelist\nwhitelist:\n  reason: custom\n  ip: [203.0.113.9]\n  expression: ["evt.Meta.source_ip == \'203.0.113.10\'"]\n')
        result = self.run_shell('install_crowdsec_core', '203.0.113.2\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        rules = yaml.safe_load(path.read_text())['whitelist']
        self.assertIn('203.0.113.9', rules['ip'])
        self.assertIn('203.0.113.2', rules['ip'])
        self.assertEqual(rules['reason'], 'custom')
        self.assertTrue(rules['expression'])

    def test_reinstall_uses_custom_acquisition_directory_without_overwriting(self):
        directory = self.config/'custom-acquis'
        directory.mkdir()
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'crowdsec_service': {'acquisition_dir': str(directory)}}))
        path = directory/'web-sites.yaml'
        content = 'source: syslog\nlisten_addr: 127.0.0.1:1514\nlabels: {type: syslog}\n'
        path.write_text(content)
        result = self.run_shell('install_crowdsec_core', '203.0.113.2\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(path.read_text(), content)
        self.assertFalse((self.config/'acquis.d/web-sites.yaml').exists())

    def test_old_presets_migrate_and_keep_unacquired_ssh_logs(self):
        web = self.base/'opt/1panel/1panel/www/sites/example/log/access.log'
        auth = self.base/'var/log/auth.log'
        for path in [web, auth]:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.assertEqual(self.run_shell('configure_log_acquis').returncode, 0)
        result = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse((self.config/'acquis.d/web-sites.yaml').exists())
        docs = list(yaml.safe_load_all((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').read_text()))
        self.assertEqual({doc['labels']['type'] for doc in docs}, {'nginx', 'syslog'})
        self.assertCountEqual([name for doc in docs for name in doc['filenames']], [str(web), str(auth)])
        self.assertEqual(self.run_shell('repair_log_acquis', 'y\n').returncode, 0)

    def test_duplicate_managed_logs_removed_when_external_wildcard_covers_them(self):
        log = self.base/'opt/1panel/1panel/www/sites/example/log/access.log'
        log.parent.mkdir(parents=True)
        log.touch()
        directory = self.config/'acquis.d'
        directory.mkdir()
        external = directory/'custom.yaml'
        original = yaml.safe_dump({'filenames': [str(log.parent/'*.log')], 'labels': {'type': 'nginx'}})
        external.write_text(original)
        managed = directory/'crowdsec-1key-log-repair.yaml'
        managed.write_text(yaml.safe_dump({'filenames': [str(log)], 'labels': {'type': 'nginx'}}))
        result = self.run_shell('repair_log_acquis', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(external.read_text(), original)
        self.assertEqual(managed.read_text(), '')

    def test_migration_validation_failure_restores_both_acquisition_files(self):
        self.run_shell('configure_log_acquis')
        path = self.config/'acquis.d/web-sites.yaml'
        original = path.read_text()
        result = self.run_shell('repair_log_acquis', 'y\n', 'crowdsec() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), original)
        self.assertFalse((path.parent/'crowdsec-1key-log-repair.yaml').exists())

    def test_empty_local_override_is_supported_and_mode_is_preserved(self):
        local = self.config/'config.yaml.local'
        local.write_text('# reserved for overrides\n')
        local.chmod(0o640)
        if os.geteuid() == 0:
            os.chown(local, 0, 65534)
        owner = local.stat()
        result = self.run_shell('enable_prometheus_metrics')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(yaml.safe_load(local.read_text())['prometheus']['enabled'])
        self.assertEqual(local.stat().st_mode & 0o777, 0o640)
        self.assertEqual((local.stat().st_uid, local.stat().st_gid), (owner.st_uid, owner.st_gid))

    def test_failed_backup_revokes_new_bouncer_without_restarting_service(self):
        self.bouncer()
        result = self.run_shell('repair_firewall_bouncer', overrides='begin_config_change() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(self.commands(), r'bouncers delete crowdsec-1key-firewall-')
        self.assertNotIn('restart crowdsec-firewall-bouncer', self.commands())

    def test_failed_config_edit_revokes_new_bouncer_and_restores_config(self):
        path = self.bouncer('mode: invalid\napi_key: ""\n')
        original = path.read_text()
        result = self.run_shell('repair_firewall_bouncer')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(path.read_text(), original)
        self.assertFalse(Path(str(path)+'.local').exists())
        self.assertRegex(self.commands(), r'bouncers delete crowdsec-1key-firewall-')

    def test_failed_webui_permissions_revokes_new_machine_and_restores_credentials(self):
        directory = self.make_webui()
        credentials = directory/'data/webui_api_credentials.yaml'
        original = credentials.read_text()
        stub = r'''
cscli() {
 record cscli "$@"
 if [[ "$1 $2" == 'machines add' ]]; then
  local machine="$3" arg file=''
  shift 3
  while (($#)); do arg="$1"; shift; if [[ "$arg" == -f ]]; then file="$1"; shift; fi; done
  printf 'url: http://127.0.0.1:8080/\nlogin: %s\npassword: test-password\n' "$machine" > "$file"
 fi
}
chmod() { if [[ "$1" == 600 ]]; then return 1; fi; command chmod "$@"; }
'''
        result = self.run_shell('deploy_web_ui rotate', '3000\ny\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(credentials.read_text(), original)
        self.assertRegex(self.commands(), r'machines delete webui-1key-')
        self.assertNotIn('machines delete webui-owned', self.commands())

    def test_backup_restores_dangling_symlink(self):
        path = self.base/'link'
        path.symlink_to(self.base/'missing')
        quoted = shlex.quote(str(path))
        result = self.run_shell(f'begin_config_change {quoted} && rm {quoted} && touch {quoted} && restore_config_change')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(path.is_symlink())
        self.assertEqual(os.readlink(path), str(self.base/'missing'))

    def test_health_checks_external_appsec_in_custom_directory(self):
        directory = self.config/'custom'
        directory.mkdir()
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({'crowdsec_service': {'acquisition_dir': str(directory)}}))
        (directory/'external.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels: {type: appsec}\n')
        self.run_shell('check_health_status')
        self.assertIn('cscli metrics show appsec', self.commands())

    def test_appsec_menu_rejects_overriding_host_local_url(self):
        path = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        path.parent.mkdir()
        path.write_text('API_KEY=existing\nAPPSEC_URL=http://old.example:7422\n')
        Path(str(path)+'.local').write_text('APPSEC_URL=http://other.example:7422\n')
        result = self.run_shell('setup_appsec', '1\n', 'nginx() { record nginx "$@"; return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('APPSEC_URL=http://old.example:7422', path.read_text())
        self.assertNotIn('systemctl reload nginx', self.commands())


if __name__ == '__main__':
    unittest.main()
