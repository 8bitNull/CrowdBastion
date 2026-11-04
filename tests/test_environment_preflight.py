"""Sample actual proc-shaped fixtures; guard refusal must precede writes."""
import importlib
import json
from pathlib import Path
import tempfile
import unittest

import workflow_fixture as test_workflows

try:
    environment = importlib.import_module('crowdbastion_environment')
except ModuleNotFoundError:
    environment = None


class EnvironmentSampling(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(environment, 'environment preflight is not implemented')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'pressure').mkdir()
        self.tick = 0

    def sample(self, waits, *, pressure=None, memory=512000):
        def write(index):
            # Total CPU ticks advance by 100 per interval; guest is already
            # included in user ticks and must not be counted twice.
            wait = sum(waits[:index])
            (self.root/'stat').write_text(f'cpu {10000+index*100-wait} 0 0 0 {wait} 0 0 0 9000 0\nprocs_blocked 0\n')
            (self.root/'meminfo').write_text(f'MemTotal: 1024000 kB\nMemAvailable: {memory} kB\n')
            if pressure is not None:
                total = sum(pressure[:index])
                (self.root/'pressure/io').write_text(f'some avg10=99.0 avg60=99.0 avg300=99.0 total={total}\nfull avg10=99.0 avg60=99.0 avg300=99.0 total={total}\n')
        write(0)
        def advance(_seconds):
            self.tick += 1
            write(self.tick)
        return environment.check_environment(self.root, interval=0.25,
                                             sleep=advance, clock=lambda: float(self.tick))

    def test_persistent_wait_is_rejected_using_deltas_not_historical_ticks(self):
        report = self.sample([40, 40])
        self.assertEqual(report['state'], 'unstable')
        self.assertEqual(report['error_code'], 'persistent_io_wait')
        self.assertEqual([w['iowait_percent'] for w in report['windows']], [40.0, 40.0])
        with self.assertRaises(environment.EnvironmentNotReady):
            environment.require_stable(report)

    def test_single_wait_spike_is_distinguished_from_persistent_wait(self):
        report = self.sample([60, 0])
        self.assertEqual(report['state'], 'stable')
        self.assertTrue(report['transient_pressure'])
        self.assertEqual(environment.require_stable(report), report)

    def test_missing_optional_psi_does_not_block_healthy_stat_and_memory(self):
        report = self.sample([0, 0])
        self.assertEqual(report['state'], 'stable')
        self.assertIn('io_pressure', report['unavailable'])

    def test_psi_uses_sampled_totals_instead_of_avg10(self):
        report = self.sample([0, 0], pressure=[0, 0])
        self.assertEqual(report['state'], 'stable')
        self.assertEqual(report['windows'][0]['io_pressure_percent'], 0.0)

    def test_persistent_sampled_io_pressure_is_rejected(self):
        report = self.sample([0, 0], pressure=[400000, 400000])
        self.assertEqual(report['state'], 'unstable')
        self.assertEqual(report['error_code'], 'persistent_io_pressure')

    def test_persistent_memory_exhaustion_is_rejected(self):
        report = self.sample([0, 0], memory=1000)
        self.assertEqual(report['state'], 'unstable')
        self.assertEqual(report['error_code'], 'persistent_memory_pressure')

    def test_missing_counters_are_unknown_and_cannot_pass_guard(self):
        report = environment.check_environment(self.root, sleep=lambda _: None)
        self.assertEqual(report['state'], 'unknown')
        with self.assertRaises(environment.EnvironmentNotReady):
            environment.require_stable(report)
        self.assertNotIn(str(self.root), json.dumps(report))

    def test_counter_reset_is_unknown_instead_of_a_negative_wait(self):
        (self.root/'stat').write_text('cpu 100 0 0 100 0 0 0 0\nprocs_blocked 0\n')
        (self.root/'meminfo').write_text('MemTotal: 1000 kB\nMemAvailable: 500 kB\n')
        def reset(_):
            (self.root/'stat').write_text('cpu 1 0 0 1 0 0 0 0\nprocs_blocked 0\n')
        report = environment.check_environment(self.root, sleep=reset)
        self.assertEqual(report['state'], 'unknown')
        self.assertEqual(report['error_code'], 'counters_unavailable')

    def test_invalid_sample_budget_is_refused_before_reading(self):
        for options in ({'samples': 1000}, {'interval': 30}, {'samples': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                environment.check_environment(self.root, **options)

    def test_guard_cli_returns_75_for_unknown_and_prints_safe_report(self):
        import contextlib
        import io
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = environment.main(['--guard', '--proc-root', str(self.root)])
        self.assertEqual(status, 75)
        self.assertEqual(json.loads(output.getvalue())['state'], 'unknown')


class EnvironmentWorkflow(unittest.TestCase):
    setUp = test_workflows.WorkflowFixtureMixin.setUp
    run_shell = test_workflows.WorkflowFixtureMixin.run_shell
    commands = test_workflows.WorkflowFixtureMixin.commands

    def test_readonly_environment_status_bypasses_lock_and_mutation(self):
        result = self.run_shell('main --environment-status', overrides='locked_operation() { exit 98; }; environment_tool() { printf \'{"state":"stable"}\\n\'; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['state'], 'stable')
        self.assertEqual(self.commands(), '')

    def test_optimize_refusal_under_lock_writes_no_configuration(self):
        before = (self.config/'config.yaml').read_bytes()
        result = self.run_shell('smart_audit_and_optimize', 'n\nn\ny\ny\n', overrides='environment_tool() { [[ "$MAINTENANCE_LOCK_HELD" == true ]] || exit 98; return 75; }')
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)
        self.assertNotIn('systemctl restart', self.commands())
        self.assertFalse((self.base/'var/backups').exists())

    def test_existing_repair_refusal_under_lock_runs_no_write_tool(self):
        override = '''environment_tool() { [[ "$MAINTENANCE_LOCK_HELD" == true ]] || exit 98; return 75; }
existing_deployment_tool() { record existing "$@"; case "$1" in plan) printf '{"cron_risks":[],"restore_services":[]}';; esac; }'''
        result = self.run_shell('repair_existing_deployment', 'y\n', overrides=override)
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertNotIn('cron-disable', self.commands())
        self.assertNotIn('repair_firewall_startup', self.commands())
        self.assertFalse((self.base/'var/backups').exists())

    def test_status_json_does_not_consult_the_mutation_guard(self):
        result = self.run_shell('main --status-json', overrides='environment_change_guard() { exit 98; }')
        self.assertIn(result.returncode, (0, 1, 2), result.stdout+result.stderr)
        self.assertEqual(json.loads(result.stdout)['version'], 1)
