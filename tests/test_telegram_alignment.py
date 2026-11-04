"""TG alignment regressions; host commands and Telegram stay isolated."""
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import test_custom_bot_flow

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


class MaintenanceGuard(unittest.TestCase):
    setUp = test_custom_bot_flow.ConfirmedFlows.setUp
    telegram = test_custom_bot_flow.ConfirmedFlows.telegram
    message = test_custom_bot_flow.ConfirmedFlows.message
    callback = test_custom_bot_flow.ConfirmedFlows.callback
    request = test_custom_bot_flow.ConfirmedFlows.request

    def paths(self):
        self.bot.MAINTENANCE_LOCK = str(self.base / 'maintenance.lock')
        self.bot.MIGRATION_STATE = str(self.base / 'migration')

    def confirmed(self):
        self.paths()
        yes, _ = self.request(self.message('/unban 203.0.113.8'))
        return yes

    def result_text(self):
        return '\n'.join(payload.get('text', '') for _, payload in self.sent)

    def test_sticky_lock_directory_allows_safe_shared_lock_but_not_private_reports(self):
        from crowdsec_bot_runtime import maintenance_guard, MaintenanceRefused
        from crowdbastion_ux import create_private
        directory = self.base / 'shared-locks'
        directory.mkdir()
        directory.chmod(0o1777)
        lock = directory / 'maintenance.lock'
        migration = self.base / 'migration'
        for existing in (False, True):
            with self.subTest(existing=existing):
                lock.unlink(missing_ok=True)
                if existing:
                    lock.write_text('')
                    lock.chmod(0o644)
                with maintenance_guard(lock, migration):
                    with lock.open() as contender:
                        with self.assertRaises(BlockingIOError):
                            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with lock.open() as contender:
                    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with self.assertRaises(ValueError):
            create_private(directory / 'report.txt', 'private')
        directory.chmod(0o777)
        with self.assertRaises(MaintenanceRefused):
            with maintenance_guard(lock, migration):
                self.fail('non-sticky writable directory accepted')
        directory.chmod(0o1777)
        lock.chmod(0o666)
        with self.assertRaises(MaintenanceRefused):
            with maintenance_guard(lock, migration):
                self.fail('writable lock accepted')

    def test_busy_main_lock_refuses_confirmed_mutation(self):
        yes = self.confirmed()
        with open(self.bot.MAINTENANCE_LOCK, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.object(self.bot, 'run_cmd') as command:
                self.bot.handle_update(self.callback(yes))
                command.assert_not_called()
        self.assertIn('未执行', self.result_text())
        self.assertIn('管理操作', self.result_text())
        self.assertEqual(self.bot.get_action_store().unfinished(), [])

    def test_unfinished_migration_refuses_mutation(self):
        yes = self.confirmed()
        Path(self.bot.MIGRATION_STATE).mkdir()
        with patch.object(self.bot, 'run_cmd') as command:
            self.bot.handle_update(self.callback(yes))
            command.assert_not_called()
        self.assertIn('迁移', self.result_text())
        self.assertIn('未执行', self.result_text())

    def test_completed_migration_permits_mutation_and_releases_shared_lock(self):
        yes = self.confirmed()
        directory = Path(self.bot.MIGRATION_STATE)
        directory.mkdir()
        (directory / 'committed').touch()
        self.bot._HEALTH_COLLECTOR = ('old-cache', object())
        with patch.object(self.bot, 'run_cmd', return_value='') as command:
            self.bot.handle_update(self.callback(yes))
            self.assertEqual(command.call_count, 1)
        self.assertIsNone(self.bot._HEALTH_COLLECTOR)
        with open(self.bot.MAINTENANCE_LOCK, 'r') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_lock_symlink_is_refused_without_touching_target(self):
        yes = self.confirmed()
        target = self.base / 'foreign'
        target.write_text('keep')
        Path(self.bot.MAINTENANCE_LOCK).symlink_to(target)
        with patch.object(self.bot, 'run_cmd') as command:
            self.bot.handle_update(self.callback(yes))
            command.assert_not_called()
        self.assertEqual(target.read_text(), 'keep')
        self.assertIn('未执行', self.result_text())

    def test_unknown_migration_file_or_link_is_refused(self):
        for kind in ('file', 'link'):
            with self.subTest(kind=kind):
                yes = self.confirmed()
                directory = Path(self.bot.MIGRATION_STATE)
                if kind == 'file':
                    directory.write_text('unknown')
                else:
                    directory.symlink_to(self.base / 'absent')
                try:
                    with patch.object(self.bot, 'run_cmd') as command:
                        self.bot.handle_update(self.callback(yes))
                        command.assert_not_called()
                finally:
                    directory.unlink()


class SharedHealth(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def payload(self, checks=None):
        from crowdbastion_health import summarize
        checks = checks or {'core': 'ok', 'firewall_paths': 'fault', 'traffic': 'pending'}
        return {'version': 1, 'checked_at': 1750000000.0,
                'config_path': str(self.base / 'config.yaml'), 'checks': checks, 'required': [],
                'summary': summarize(list(checks.items()), 1, 'overall', 'relay'),
                'scope': '本地中转'}

    def manager(self, payload, status=1):
        path = self.base / 'manager with space.sh'
        import shlex
        path.write_text("printf '%s\\n' " + shlex.quote(json.dumps(payload)) + '\nexit ' + str(status) + '\n')
        return path

    def test_renderer_reports_round_trip_without_losing_required_observations(self):
        from crowdbastion_health import structured_report
        from crowdsec_bot_runtime import read_manager_report
        for roles in ('', 'web', 'relay', 'remote', 'node', 'relay node', 'remote node'):
            for state in ('ok', 'fault', 'missing', 'unknown'):
                with self.subTest(roles=roles, state=state):
                    records = [('core', 'required'), ('core', state),
                               ('traffic', 'required'), ('traffic', 'pending')]
                    status = 1 if state == 'fault' else 2
                    payload = structured_report(records, status, 'overall', roles, str(self.base / 'config.yaml'))
                    result = read_manager_report(self.manager(payload, status), payload['config_path'])
                    self.assertEqual(result['summary'], payload['summary'])
                    self.assertEqual(result['checks'], payload['checks'])

    def test_collector_reads_canonical_firewall_and_node_observations(self):
        import crowdsec_bot_health
        payload = self.payload()
        manager = self.manager(payload)
        collector = crowdsec_bot_health.HealthCollector(payload['config_path'], manager_path=str(manager))
        result = collector.collect()
        self.assertEqual(result['checks'], payload['checks'])
        self.assertEqual(result['summary']['verdict'], '发现问题，需要处理')
        self.assertEqual(collector.collect(), result)

    def test_invalid_or_mismatched_manager_report_cannot_fall_back_to_healthy(self):
        import crowdsec_bot_health
        payloads = [self.payload(), self.payload(), self.payload()]
        payloads[0]['version'] = 99
        payloads[1]['config_path'] = '/different/config.yaml'
        payloads[2]['checks']['core'] = 'arbitrary-private-output'
        for required in (None, {}, ['core', 'core'], ['unknown-key'], [['core']]):
            payload = self.payload()
            payload['required'] = required
            payloads.append(payload)
        for payload in payloads:
            with self.subTest(payload=payload):
                manager = self.manager(payload)
                result = crowdsec_bot_health.HealthCollector(str(self.base / 'config.yaml'), manager_path=str(manager)).collect()
                self.assertEqual(result['checks']['check'], 'unknown')
                self.assertIn('未完成', result['summary']['verdict'])
                self.assertNotIn('arbitrary-private-output', json.dumps(result))

    def test_manager_timeout_returns_incomplete_without_exposing_output(self):
        import crowdsec_bot_runtime
        manager = self.base / 'manager.sh'
        manager.write_text('echo private-diagnostic\nsleep 10\n')
        with self.assertRaises((ValueError, RuntimeError, subprocess.SubprocessError)):
            crowdsec_bot_runtime.read_manager_report(str(manager), str(self.base / 'config.yaml'), timeout=0.1)


class CanonicalHealthCLI(unittest.TestCase):
    from workflow_fixture import WorkflowFixtureMixin
    setUp = WorkflowFixtureMixin.setUp
    run_shell = WorkflowFixtureMixin.run_shell

    def test_json_cli_uses_same_readonly_collection_without_leaking_details(self):
        fixture = '''check_health_status_raw() {
          NODE_ROLES=relay
          printf 'private-diagnostic API Key: Q7k9xV1w\\n'
          health_expect core; health_event core ok
          health_expect firewall_paths; health_event firewall_paths fault
          health_expect traffic; health_event traffic pending
          return 1
        }'''
        result = self.run_shell('main --status-json', overrides=fixture)
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report['version'], 1)
        self.assertEqual(report['config_path'], str(self.config / 'config.yaml'))
        self.assertEqual(report['checks']['firewall_paths'], 'fault')
        self.assertEqual(report['checks']['traffic'], 'pending')
        self.assertIn('本地中转', report['scope'])
        self.assertEqual(report['summary']['status'], 1)
        self.assertNotIn('Q7k9xV1w', result.stdout + result.stderr)
        import shlex
        from crowdsec_bot_runtime import read_manager_report
        manager = self.base / 'canonical-report.sh'
        manager.write_text("printf '%s\\n' "+shlex.quote(result.stdout)+'\nexit 1\n')
        accepted = read_manager_report(manager, report['config_path'])
        self.assertEqual(accepted['summary'], report['summary'])
        self.assertEqual(accepted['checks'], report['checks'])


class BotDeployment(unittest.TestCase):
    from workflow_fixture import WorkflowFixtureMixin
    from test_custom_bot import BotService
    setUp = WorkflowFixtureMixin.setUp
    run_shell = WorkflowFixtureMixin.run_shell
    commands = WorkflowFixtureMixin.commands
    setup_bot = BotService.setup_bot

    @property
    def botroot(self):
        return self.base / 'usr/local/lib/crowdsec-1key-bot'

    def config_bytes(self):
        return (self.config / 'crowdsec-1key-bot.json').read_bytes()

    def test_conflict_scan_isolates_host_processes_and_still_detects_fixture_bot(self):
        process = subprocess.Popen(['python3', '-c', 'import time; time.sleep(30)', 'crowdsec_bot.py'],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            result = self.setup_bot()
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        finally:
            process.terminate()
            process.wait(timeout=5)
        entry = self.base / 'proc/424242'
        entry.mkdir(parents=True)
        (entry / 'cmdline').write_bytes(b'python3\0/foreign/crowdsec_bot.py\0')
        before = self.config_bytes()
        result = self.setup_bot()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('PID 424242', result.stdout+result.stderr)
        self.assertEqual(self.config_bytes(), before)

    def test_install_includes_canonical_runtime_and_paths(self):
        result = self.setup_bot()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        config = json.loads(self.config_bytes())
        self.assertEqual(config['maintenance_lock'], str(self.base / 'run/lock/crowdsec-1key.lock'))
        self.assertEqual(config['migration_state'], str(self.base / 'var/lib/crowdbastion/firewall-migration'))
        manager = Path(config['manager_script'])
        self.assertEqual(manager, self.botroot / 'runtime/current/manager.sh')
        self.assertEqual(manager.read_bytes(), self.source.read_bytes())
        env = dict(os.environ, PYTHONPATH=str(self.botroot), PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run(['python3', '-c', 'import crowdsec_bot_health, crowdsec_bot_runtime; print("self-contained")'],
                                cwd='/', env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('self-contained', result.stdout)

    def test_version_check_detects_program_helper_and_runtime_drift(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        config_before = self.config_bytes()
        result = self.run_shell('custom_bot_code_status')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('一致', result.stdout)
        for relative in ('crowdsec_bot.py', 'crowdsec_bot_health.py', 'runtime/current/lib/crowdbastion_health.py'):
            path = self.botroot / relative
            original = path.read_bytes()
            try:
                path.write_bytes(original + b'\n# drift\n')
                result = self.run_shell('custom_bot_code_status')
                self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
                self.assertIn('不同', result.stdout)
            finally:
                path.write_bytes(original)
        self.assertEqual(self.config_bytes(), config_before)

    def test_update_preserves_config_and_state(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        config_before = self.config_bytes()
        state = self.base / 'var/lib/crowdsec-1key-bot/synthetic-offset'
        state.write_text('41')
        (self.botroot / 'crowdsec_bot.py').write_text('# old code\n')
        result = self.run_shell('update_custom_bot', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.config_bytes(), config_before)
        self.assertEqual(state.read_text(), '41')
        self.assertEqual((self.botroot / 'crowdsec_bot.py').read_bytes(), (self.base / 'lib/crowdsec_bot.py').read_bytes())
        self.assertEqual(self.run_shell('custom_bot_code_status').returncode, 0)

    def test_update_cancel_keeps_code_config_and_service(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        config_before = self.config_bytes()
        installed = self.botroot / 'crowdsec_bot.py'
        installed.write_text('# old code\n')
        self.trace.write_text('')
        result = self.run_shell('update_custom_bot', '\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(installed.read_text(), '# old code\n')
        self.assertEqual(self.config_bytes(), config_before)
        self.assertNotIn('systemctl restart', self.commands())
        self.assertNotIn('systemctl enable', self.commands())

    def test_update_does_not_enable_or_start_an_inactive_disabled_service(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        self.trace.write_text('')
        override = '''systemctl() { record systemctl "$@";
          case "$1" in
            show) printf 'LoadState=loaded\\nFragmentPath=%s\\n' "$CUSTOM_BOT_UNIT";;
            is-active) return 3;;
            is-enabled) [[ "$*" == *--quiet* ]] || echo disabled; return 1;;
          esac
          return 0
        }'''
        result = self.run_shell('update_custom_bot', 'y\n', override)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        for command in ('systemctl enable ', 'systemctl restart ', 'systemctl start '):
            self.assertNotIn(command, self.commands())
        self.assertIn('保留', result.stdout)

    def test_failed_update_restores_helpers_config_and_runtime_link(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        installed = self.botroot / 'crowdsec_bot_health.py'
        installed.write_text('# old installed helper\n')
        before = self.config_bytes()
        current = self.botroot / 'runtime/current'
        old_link = os.readlink(current)
        self.trace.write_text('')
        override = '''systemctl() { record systemctl "$@";
          [[ "$1" != show ]] || printf 'LoadState=loaded\\nFragmentPath=%s\\n' "$CUSTOM_BOT_UNIT"
          [[ "$1" != is-enabled ]] || echo enabled
          [[ "$*" != 'restart crowdsec-1key-bot.service' ]]
        }'''
        result = self.run_shell('update_custom_bot', 'y\n', override)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.config_bytes(), before)
        self.assertEqual(installed.read_text(), '# old installed helper\n')
        self.assertEqual(os.readlink(current), old_link)
        self.assertIn('systemctl restart crowdsec-1key-bot.service', self.commands())

    def test_nonstandard_enabled_states_refuse_update_before_writes(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        before = self.config_bytes()
        current = self.botroot / 'runtime/current'
        old_link = os.readlink(current)
        for state in ('enabled-runtime', 'linked', 'linked-runtime', 'alias', 'static', 'indirect', 'generated', 'transient'):
            with self.subTest(state=state):
                self.trace.write_text('')
                override = '''systemctl() { record systemctl "$@";
                  case "$1" in
                    show) printf 'LoadState=loaded\\nFragmentPath=%%s\\n' "$CUSTOM_BOT_UNIT";;
                    is-enabled) [[ "$*" == *--quiet* ]] || echo %s;;
                  esac
                  return 0
                }''' % state
                result = self.run_shell('update_custom_bot', 'y\n', override)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertEqual(self.config_bytes(), before)
                self.assertEqual(os.readlink(current), old_link)
                self.assertNotIn('systemctl stop', self.commands())
                self.assertNotIn('systemctl enable', self.commands())

    def test_service_state_query_errors_refuse_update_before_writes(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        before = self.config_bytes()
        current = self.botroot / 'runtime/current'
        old_link = os.readlink(current)
        for failed_query in ('is-active', 'is-enabled'):
            with self.subTest(query=failed_query):
                self.trace.write_text('')
                override = '''systemctl() { record systemctl "$@";
                  case "$1" in
                    show) printf 'LoadState=loaded\\nFragmentPath=%%s\\n' "$CUSTOM_BOT_UNIT";;
                    is-active) %s;;
                    is-enabled) return 1;;
                  esac
                }''' % ('return 1' if failed_query == 'is-active' else 'return 3')
                result = self.run_shell('update_custom_bot', 'y\n', override)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.config_bytes(), before)
                self.assertEqual(os.readlink(current), old_link)
                self.assertNotIn('systemctl stop', self.commands())

    def test_legacy_config_update_preserves_bytes_and_uses_bundled_manager(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        filename = self.config / 'crowdsec-1key-bot.json'
        document = json.loads(filename.read_text())
        document.pop('manager_script')
        filename.write_text(json.dumps(document, indent=3)+'\n')
        before = filename.read_bytes()
        result = self.run_shell('update_custom_bot', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(filename.read_bytes(), before)
        env = dict(os.environ, PYTHONPATH=str(self.botroot), PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run(['python3', '-c',
            'import sys, crowdsec_bot as bot; bot.load_settings(sys.argv[1]); print(bot.MANAGER_SCRIPT)', str(filename)],
            cwd='/', env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), str(self.botroot / 'runtime/current/manager.sh'))

    def test_update_repairs_runtime_with_missing_helpers(self):
        import shutil
        self.assertEqual(self.setup_bot().returncode, 0)
        shutil.rmtree(self.botroot / 'runtime/current/lib')
        result = self.run_shell('custom_bot_code_status')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        result = self.run_shell('update_custom_bot', 'y\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.run_shell('custom_bot_code_status').returncode, 0)

    def test_version_check_refuses_foreign_runtime_pointer_even_if_code_matches(self):
        import shutil
        self.assertEqual(self.setup_bot().returncode, 0)
        current = self.botroot / 'runtime/current'
        foreign = self.base / 'foreign-release'
        shutil.copytree(current.resolve(), foreign)
        current.unlink()
        current.symlink_to(foreign)
        result = self.run_shell('custom_bot_code_status')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.trace.write_text('')
        result = self.run_shell('update_custom_bot', 'y\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('systemctl stop', self.commands())
        self.assertEqual(current.resolve(), foreign)

    def test_interrupted_update_restores_runtime_and_original_service(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        current = self.botroot / 'runtime/current'
        old_link = os.readlink(current)
        before = self.config_bytes()
        self.trace.write_text('')
        override = '''cp() {
          if [[ "${!#}" == "$CUSTOM_BOT_SCRIPT" && ! -f "$TRACE.interrupted" ]]; then
            touch "$TRACE.interrupted"
            kill -TERM "$BASHPID"
          fi
          command cp "$@"
        }'''
        result = self.run_shell('update_custom_bot', 'y\n', override)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(Path(str(self.trace)+'.interrupted').exists())
        self.assertEqual(os.readlink(current), old_link)
        self.assertEqual(self.config_bytes(), before)
        self.assertIn('systemctl restart crowdsec-1key-bot.service', self.commands())

    def test_stop_failure_attempts_to_recover_original_service(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        self.trace.write_text('')
        override = '''systemctl() { record systemctl "$@";
          [[ "$1" != show ]] || printf 'LoadState=loaded\\nFragmentPath=%s\\n' "$CUSTOM_BOT_UNIT"
          [[ "$1" != is-enabled ]] || echo enabled
          [[ "$*" != 'stop crowdsec-1key-bot.service' ]]
        }'''
        result = self.run_shell('update_custom_bot', 'y\n', override)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemctl restart crowdsec-1key-bot.service', self.commands())

    def test_purge_removes_managed_runtime_but_refuses_foreign_runtime(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        runtime = self.botroot / 'runtime'
        result = self.run_shell('purge_custom_bot')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(runtime.exists())

    def test_purge_refuses_unknown_runtime_before_stopping_service(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        runtime = self.botroot / 'runtime'
        (runtime / '.crowdsec-1key-managed').unlink()
        self.trace.write_text('')
        result = self.run_shell('purge_custom_bot')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.botroot / 'crowdsec_bot.py').exists())
        self.assertNotIn('systemctl disable', self.commands())

    def test_null_maintenance_paths_are_rejected_by_config_validation(self):
        self.assertEqual(self.setup_bot().returncode, 0)
        filename = self.config / 'crowdsec-1key-bot.json'
        original = json.loads(filename.read_text())
        for key in ('maintenance_lock', 'migration_state'):
            with self.subTest(key=key):
                document = {**original, key: None}
                filename.write_text(json.dumps(document))
                result = self.run_shell('python3 "$CUSTOM_BOT_SCRIPT" --config "$CUSTOM_BOT_CONFIG" --check-config')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('123:ABC', result.stdout+result.stderr)

    def test_unknown_runtime_directory_refuses_setup_before_config_write(self):
        runtime = self.botroot / 'runtime'
        runtime.mkdir(parents=True)
        (runtime / 'foreign').write_text('keep')
        result = self.setup_bot()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.config / 'crowdsec-1key-bot.json').exists())
        self.assertEqual((runtime / 'foreign').read_text(), 'keep')


if __name__ == '__main__':
    unittest.main()
