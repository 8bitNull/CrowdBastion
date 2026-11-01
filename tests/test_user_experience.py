"""User-visible progress, confirmations and private UX artifacts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_workflows
import test_node_guidance

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))


class Interaction(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    roles = test_node_guidance.Guidance.roles
    run_terminal = test_node_guidance.Guidance.run_terminal

    def test_install_cancel_previews_changes_without_packages_or_writes(self):
        before = (self.config/'config.yaml').read_bytes()
        p = self.run_shell('install_crowdsec_core', '203.0.113.2\nn\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('本次变更预览', p.stdout)
        self.assertIn('203.0.113.2', p.stdout)
        self.assertIn('已有', p.stdout)
        self.assertNotRegex(self.commands(), r'apt-get|curl|enable|restart|collections install')
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)

    def test_invalid_admin_address_stops_before_installing_dependencies(self):
        p = self.run_shell('install_crowdsec_core', 'bad-ip\ny\n')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertNotRegex(self.commands(), r'apt-get|curl|enable|restart')

    def test_guidance_reads_service_state_without_claiming_deployment_pass(self):
        self.roles('relay')
        p = self.run_shell('guided_setup', '0\n', '''
systemctl() { record systemctl "$@"; if [[ "$*" == 'is-active crowdsec' ]]; then echo inactive; return 3; fi; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('服务未运行', p.stdout)
        self.assertIn('待验证', p.stdout)
        self.assertNotRegex(self.commands(), r'apt-get|enable|restart|reload')

    def test_returning_from_website_bouncer_does_not_suggest_success(self):
        p = self.run_shell('guided_website_setup', '1\n3\n0\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('2. 私有连接地址（不适用', p.stdout)
        self.assertIn('未检测到配置变化', p.stdout)
        self.assertNotIn('操作已返回，请选择下一步', p.stdout)
        self.assertNotRegex(self.commands(), r'apt-get|enable|restart|reload')

    def test_successful_service_start_refreshes_report_once(self):
        self.roles('relay')
        p = self.run_terminal('interactive_health_check', '1\ny\n0\n', '''
check_health_status_raw() {
 record report-run
 health_expect core
 if [[ -f "$TRACE.started" ]]; then health_event core ok; else health_event core fault; fi
 return 2
}
health_service_state() { echo inactive; }
systemctl() { record systemctl "$@"; [[ "$1" != start ]] || touch "$TRACE.started"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.commands().count('report-run'), 2, p.stdout+self.commands())
        self.assertIn('自动复查', p.stdout)
        self.assertNotIn('处理后请选择 3', p.stdout)

    def test_declining_service_start_does_not_repeat_report(self):
        self.roles('relay')
        p = self.run_terminal('interactive_health_check', '1\nn\n0\n', '''
check_health_status_raw() { record report-run; health_expect core; health_event core fault; return 1; }
health_service_state() { echo inactive; }
''')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.commands().count('report-run'), 1)
        self.assertNotIn('systemctl start', self.commands())

    def test_runtime_sync_preserves_exact_cron_contents(self):
        cron = self.base/'etc/cron.d/crowdsec-autoupdate'
        runner = self.base/'usr/local/lib/crowdsec-1key/current/manager.sh'
        cron.write_text(f'17 4 * * * root /bin/bash {runner} --update-hub >/dev/null 2>&1\n')
        before = cron.read_bytes()
        p = self.run_shell('sync_maintenance_runtime', 'y\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(cron.read_bytes(), before)
        self.assertTrue((self.base/'usr/local/lib/crowdsec-1key/current/manager.sh').is_file())
        self.assertNotRegex(self.commands(), r'apt-get|restart|reload')

    def test_runtime_sync_repairs_incomplete_managed_copy(self):
        cron = self.base/'etc/cron.d/crowdsec-autoupdate'
        runner = self.base/'usr/local/lib/crowdsec-1key/current/manager.sh'
        cron.write_text(f'17 4 * * * root /bin/bash {runner} --update-hub\n')
        setup = self.run_shell('install_maintenance_runtime')
        self.assertEqual(setup.returncode, 0, setup.stdout+setup.stderr)
        shutil.rmtree(runner.parent/'lib')
        result = self.run_shell('sync_maintenance_runtime', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue((runner.parent/'lib/crowdbastion_ux.py').is_file())
        self.assertIn('维护副本已同步', result.stdout)

    def test_runtime_sync_refuses_unrelated_or_disabled_cron(self):
        cron = self.base/'etc/cron.d/crowdsec-autoupdate'
        runner = self.base/'usr/local/lib/crowdsec-1key/current/manager.sh'
        for contents in ('17 4 * * * root /some/custom/command --flag\n',
                         f'# 17 4 * * * root /bin/bash {runner} --update-hub\n'):
            with self.subTest(contents=contents):
                cron.write_text(contents)
                result = self.run_shell('sync_maintenance_runtime', 'y\n')
                self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
                self.assertEqual(cron.read_text(), contents)
                self.assertFalse(runner.exists())
                self.assertNotIn('维护副本已同步', result.stdout)

    def test_generator_creates_config_and_keeps_service_start_separate(self):
        destination = self.base/'observer.json'
        log = self.base/'access.log'
        log.write_text('')
        p = self.run_shell('generate_v2bx_observer_config',
                           f'xray\n{log}\n+08:00\n198.51.100.5/32\n{destination}\ny\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        config = json.loads(destination.read_text())
        self.assertEqual(config['sources'][0]['relay_cidrs'], '198.51.100.5/32')
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertNotIn('systemctl enable', self.commands())
        self.assertIn('持续记录菜单选 1', p.stdout)

    def test_report_export_writes_private_redacted_artifact(self):
        destination = self.base/'diagnosis.txt'
        p = self.run_shell('export_health_details "$CAPTURE"', f'{destination}\n', '''
CAPTURE=$(mktemp)
printf '%s\\n' 'API_KEY=unique-test-secret' 'source 198.51.100.9' > "$CAPTURE"
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        report = destination.read_text()
        self.assertNotIn('unique-test-secret', report)
        self.assertNotIn('198.51.100.9', report)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)

    def test_quick_actions_hold_maintenance_lock_for_mutating_menus(self):
        p = self.run_shell('manage_quick_actions', '1\n4\n0\n', '''
manage_firewall_maintenance() { record firewall-lock "${MAINTENANCE_LOCK_HELD:-missing}"; }
manage_real_ip() { record realip-lock "${MAINTENANCE_LOCK_HELD:-missing}"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('firewall-lock true', self.commands())
        self.assertIn('realip-lock true', self.commands())

    def test_generator_path_is_reused_by_observer_menu(self):
        destination = self.base/'observer.json'
        log = self.base/'access.log'
        log.write_text('')
        answers = f'5\nxray\n{log}\n+08:00\n\n{destination}\ny\n1\n0\n'
        p = self.run_shell('manage_v2bx_observer', answers, '''
v2bx_observer_service() { record observer "$1" "$V2BX_OBSERVER_CONFIG"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn(f'observer install {destination}', self.commands())

    def test_config_generator_cancel_does_not_create_target(self):
        target = self.base/'observer.json'
        p = self.run_shell('generate_v2bx_observer_config', 'q\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(target.exists())
        self.assertNotRegex(self.commands(), r'apt-get|enable|restart|reload')


class Artifacts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def ux(self):
        import crowdbastion_ux
        return crowdbastion_ux

    def test_long_diagnostic_line_redacts_without_stalling(self):
        result = subprocess.run(
            [sys.executable, '-c', 'from crowdbastion_ux import redact; text="a"*131072; assert redact(text) == text'],
            env=dict(os.environ, PYTHONPATH=str(ROOT/'lib'), PYTHONDONTWRITEBYTECODE='1'),
            capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_export_removes_secrets_addresses_and_terminal_controls(self):
        raw = 'api_key: my-secret\npassword: "two words"\nAuthorization: Bearer abcdef\nsource=198.51.100.8 target=2001:db8::1\nhttps://user:pass@example.org/path?token=secret\n\\x1b[31m'.replace('\\x1b', '\x1b')
        clean = self.ux().redact(raw)
        for secret in ('my-secret', 'two words', 'abcdef', '198.51.100.8', '2001:db8::1', 'user:pass', 'token=secret', '\x1b'):
            self.assertNotIn(secret, clean)

    def test_report_masks_spaced_keys_cookies_and_control_split_credentials(self):
        raw = 'API Key: Q7k9xV1w\napi_\x00key: B6m2zH8n\nCookie: session=D4s8cR3p\nSet-Cookie: session=F9a1jT5v\n'
        clean = self.ux().redact(raw)
        for secret in ('Q7k9xV1w', 'B6m2zH8n', 'D4s8cR3p', 'F9a1jT5v'):
            with self.subTest(secret=secret):
                self.assertNotIn(secret, clean)

    def test_report_keeps_evidence_after_terminal_hyperlinks(self):
        raw = '\x1b]8;;https://example.org\x1b\\diagnostic label\x1b]8;;\x1b\\\nnext check evidence\n'
        clean = self.ux().redact(raw)
        self.assertIn('diagnostic label', clean)
        self.assertIn('next check evidence', clean)
        self.assertNotIn('\x1b', clean)
        self.assertNotIn('https://', clean)

    def test_private_creation_refuses_existing_files_and_symlink_parents(self):
        ux = self.ux()
        path = self.base/'report.txt'
        ux.create_private(path, 'first')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises((ValueError, OSError)):
            ux.create_private(path, 'second')
        self.assertEqual(path.read_text(), 'first')
        link = self.base/'link'
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            ux.create_private(link/'other.txt', 'unsafe')
        self.assertFalse((self.base/'other.txt').exists())

    def test_private_artifacts_refuse_writable_ancestors_before_creating_directories(self):
        ux = self.ux()
        writable = self.base/'shared'
        private = writable/'owned'
        private.mkdir(parents=True, mode=0o700)
        writable.chmod(0o777)
        with self.subTest(artifact='report'):
            with self.assertRaises((ValueError, OSError)):
                ux.create_private(private/'report.txt', 'private diagnostic contents')
            self.assertFalse((private/'report.txt').exists())
        scope = dict(target='198.51.100.1', port=443, protocol='TCP', family='ip', hook='input')
        with self.subTest(artifact='acceptance'):
            with self.assertRaises((ValueError, OSError)):
                ux.save_acceptance(writable/'new/acceptance.json', self.base, scope, 0)
            self.assertFalse((writable/'new').exists())

    def test_config_fingerprint_rejects_dangling_root_and_unreadable_subtrees(self):
        ux = self.ux()
        root = self.base/'config'
        root.symlink_to(self.base/'missing', target_is_directory=True)
        with self.subTest(root='dangling_link'):
            with self.assertRaises((ValueError, OSError)):
                ux.tree_fingerprint(root)
        root.unlink()
        root.mkdir()
        with self.subTest(root='unreadable'):
            with patch('os.scandir', side_effect=PermissionError('unreadable subtree')):
                with self.assertRaises(PermissionError):
                    ux.tree_fingerprint(root)

    def test_runtime_fingerprint_detects_helper_changes_and_ignores_pycache(self):
        ux = self.ux()
        source = self.base/'source'
        target = self.base/'target'
        for folder, name in ((source, 'crowdbastion.sh'), (target, 'manager.sh')):
            (folder/'lib').mkdir(parents=True)
            (folder/name).write_text('main')
            (folder/'lib/helper.py').write_text('one')
        first = ux.code_fingerprint(source/'crowdbastion.sh')
        self.assertEqual(first, ux.code_fingerprint(target/'manager.sh'))
        (source/'lib/__pycache__').mkdir()
        (source/'lib/__pycache__/helper.pyc').write_bytes(b'noise')
        self.assertEqual(first, ux.code_fingerprint(source/'crowdbastion.sh'))
        (target/'lib/helper.py').write_text('two')
        self.assertNotEqual(first, ux.code_fingerprint(target/'manager.sh'))

    def test_runtime_fingerprint_rejects_unreadable_helper_subtrees(self):
        ux = self.ux()
        manager = self.base/'manager.sh'
        manager.write_text('#!/bin/bash\n')
        (self.base/'lib').mkdir()
        with patch('os.scandir', side_effect=PermissionError('unreadable helper subtree')):
            with self.assertRaises(PermissionError):
                ux.code_fingerprint(manager)

    def test_compatibility_entry_has_same_runtime_fingerprint(self):
        manager = self.base/'crowdbastion.sh'
        manager.write_text('#!/bin/bash\n')
        (self.base/'lib').mkdir()
        (self.base/'lib/helper.py').write_text('print(1)\n')
        legacy = self.base/'install-crowdsec-1panel.sh'
        legacy.symlink_to(manager)
        self.assertEqual(self.ux().code_fingerprint(legacy), self.ux().code_fingerprint(manager))

    def test_report_masks_ipv6_followed_by_punctuation_or_scope(self):
        text = self.ux().redact('连接来自 2001:db8::5.\n来源为 2001:db8::6%eth0\n')
        self.assertNotIn('2001:db8', text)
        self.assertNotIn('eth0', text)

    def test_invalid_observer_source_leaves_no_config(self):
        ux = self.ux()
        path = self.base/'observer.json'
        with self.assertRaises((ValueError, OSError)):
            ux.observer_config(path, 'xray', '/missing/file', 'bad-zone', '', 'V2bX.service', write=True)
        self.assertFalse(path.exists())

    def test_valid_observer_config_passes_real_service_validator(self):
        import crowdsec_v2bx_service as service
        log = self.base/'access.log'
        log.write_text('')
        path = self.base/'observer.json'
        self.ux().observer_config(path, 'xray', str(log), '+08:00', '203.0.113.0/24', 'V2bX.service', write=True)
        result = service.load_config(path)
        self.assertEqual(result['sources'][0]['timezone'], '+08:00')
        self.assertEqual(result['sources'][0]['relay_cidrs'], '203.0.113.0/24')
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_acceptance_history_never_becomes_current_health_evidence(self):
        ux = self.ux()
        config = self.base/'config'
        config.mkdir()
        (config/'config.yaml').write_text('api: {}')
        path = self.base/'acceptance.json'
        scope = dict(target='198.51.100.1', port=443, protocol='TCP', family='ip', hook='input', source='1.1.1.1', control='8.8.8.8')
        ux.save_acceptance(path, config, scope, 0, now=1000)
        text = ux.acceptance_summary(path, config, now=1001)
        self.assertIn('历史验收', text)
        self.assertIn('人工确认', text)
        self.assertIn('443', text)
        self.assertIn('TCP', text)
        self.assertIn('IPv4', text)
        self.assertIn('过期', ux.acceptance_summary(path, config, now=1000+25*3600))
        (config/'config.yaml').write_text('api: {server: {listen_uri: localhost:8081}}')
        self.assertIn('配置变化', ux.acceptance_summary(path, config, now=1001))
        self.assertNotIn('1.1.1.1', path.read_text())


if __name__ == '__main__':
    unittest.main()
