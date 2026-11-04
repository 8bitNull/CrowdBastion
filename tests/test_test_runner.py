"""Contracts for shared fixtures and the local test entrypoint."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowFixtureContract(unittest.TestCase):
    def test_fixture_has_no_discoverable_test_case_or_test_method(self):
        spec = importlib.util.find_spec('workflow_fixture')
        self.assertIsNotNone(spec, 'shared fixture must be independent of test classes')
        module = __import__('workflow_fixture')
        fixture = module.WorkflowFixtureMixin
        self.assertFalse(issubclass(fixture, unittest.TestCase))
        self.assertFalse(any(name.startswith('test_') for name in dir(fixture)))
        self.assertEqual(unittest.defaultTestLoader.loadTestsFromModule(module).countTestCases(), 0)

import json
import tempfile


class TestEntrypoint(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='crowdbastion-test-entrypoint-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.tests = self.base / 'tests'
        self.tests.mkdir()
        self.marker = self.base / 'executed'
        for name in ('quick', 'normal', 'integration', 'archive'):
            (self.tests / f'test_{name}.py').write_text(
                'import unittest\nfrom pathlib import Path\n'
                'class Case(unittest.TestCase):\n'
                f'    def test_{name}(self):\n'
                f'        Path({str(self.marker)!r}).write_text({name!r})\n')
        self.manifest = self.base / 'tiers.json'
        self.config = {'version': 1, 'quick': ['test_quick'],
                       'integration': ['test_integration'], 'archive': ['test_archive']}
        self.manifest.write_text(json.dumps(self.config))

    def run_entrypoint(self, *args):
        # Separate interpreters prevent unittest discovery caching temporary modules.
        import subprocess
        import sys
        bootstrap = ('import sys;sys.path.insert(0,sys.argv[1]);import run_tests;'
                     'raise SystemExit(run_tests.main(sys.argv[4:],'
                     'test_dir=sys.argv[2],tiers_path=sys.argv[3]))')
        result = subprocess.run([sys.executable, '-c', bootstrap, str(ROOT/'tests'),
                                 str(self.tests), str(self.manifest), *args],
                                text=True, capture_output=True, timeout=10)
        return result

    def test_tiers_and_module_filters_list_without_running_setup(self):
        for tier, count in (('full', 4), ('quick', 1), ('integration', 1), ('archive', 1)):
            with self.subTest(tier=tier):
                result = self.run_entrypoint('--tier', tier, '--list')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len(result.stdout.splitlines()), count)
                if tier != 'full':
                    self.assertIn(f'test_{tier}.Case.test_{tier}', result.stdout)
                self.assertFalse(self.marker.exists())
        result = self.run_entrypoint('--module', 'test_normal', '--list')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'test_normal.Case.test_normal')

    def test_default_runs_full_suite_and_writes_per_test_timings(self):
        report = self.base / 'results' / 'timings.json'
        result = self.run_entrypoint('--timings', str(report), '--top', '1')
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(report.read_text())
        self.assertEqual(data['counts']['run'], 4)
        self.assertTrue(data['accepted'])
        self.assertEqual(len(data['tests']), 4)
        self.assertEqual({row['status'] for row in data['tests']}, {'passed'})
        self.assertTrue(all(row['seconds'] >= 0 for row in data['tests']))
        self.assertGreaterEqual(data['seconds'], 0)
        self.assertTrue(self.marker.exists())

    def test_failures_subtests_and_fixture_errors_cannot_be_reported_as_success(self):
        (self.tests/'test_bad.py').write_text('''import unittest
class Failures(unittest.TestCase):
    def test_subtest(self):
        with self.subTest(value=1): self.assertEqual(1, 2)
    def test_error(self):
        raise RuntimeError('intentional test error')
''')
        (self.tests/'test_fixture.py').write_text('''import unittest
def setUpModule(): raise RuntimeError('intentional fixture error')
class Fixture(unittest.TestCase):
    def test_not_run(self): pass
''')
        report = self.base/'timings.json'
        result = self.run_entrypoint('--timings', str(report))
        self.assertEqual(result.returncode, 1, result.stderr)
        data = json.loads(report.read_text())
        self.assertFalse(data['accepted'])
        self.assertEqual(data['counts']['failures'], 1)
        self.assertEqual(data['counts']['errors'], 2)
        self.assertIn('failed', {row['status'] for row in data['tests']})
        self.assertIn('error', {row['status'] for row in data['tests']})
        fixture = next(row for row in data['tests'] if 'setUpModule' in row['id'])
        self.assertIsNone(fixture['seconds'])

    def test_skip_reason_is_visible_and_strict_mode_rejects_skips(self):
        (self.tests/'test_skipped.py').write_text('''import unittest
class Optional(unittest.TestCase):
    @unittest.skip('official binary unavailable')
    def test_optional(self): pass
''')
        for strict, expected in ((False, 0), (True, 1)):
            with self.subTest(strict=strict):
                report = self.base/'timings.json'
                args = ['--timings', str(report)]
                if strict: args.append('--require-no-skips')
                result = self.run_entrypoint(*args)
                self.assertEqual(result.returncode, expected, result.stderr)
                data = json.loads(report.read_text())
                self.assertEqual(data['counts']['skipped'], 1)
                self.assertEqual(data['accepted'], not strict)
                row = next(row for row in data['tests'] if row['status'] == 'skipped')
                self.assertEqual(row['skip_reasons'], ['official binary unavailable'])
                self.assertIn('official binary unavailable', result.stderr)

    def test_invalid_manifest_or_unknown_module_fails_before_running(self):
        variants = [dict(self.config, quick=['test_typo']),
                    dict(self.config, quick=['test_quick', 'test_quick']),
                    dict(self.config, integration=['test_quick']),
                    dict(self.config, quick='test_quick'),
                    dict(self.config, version=2)]
        for config in variants:
            with self.subTest(config=config):
                self.manifest.write_text(json.dumps(config))
                result = self.run_entrypoint('--list')
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertFalse(self.marker.exists())
        self.manifest.write_text(json.dumps(self.config))
        result = self.run_entrypoint('--module', 'test_missing')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_empty_selection_and_broken_import_are_not_successful(self):
        result = self.run_entrypoint('--tier', 'quick', '--module', 'test_normal')
        self.assertEqual(result.returncode, 2, result.stderr)
        (self.tests/'test_broken.py').write_text('raise ImportError("broken dependency")\n')
        result = self.run_entrypoint('--tier', 'quick', '--list')
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('broken dependency', result.stderr)

    def test_expected_failure_and_unexpected_success_preserve_unittest_semantics(self):
        (self.tests/'test_expected.py').write_text('''import unittest
class Expected(unittest.TestCase):
    @unittest.expectedFailure
    def test_expected(self): self.fail('known')
    @unittest.expectedFailure
    def test_unexpected(self): pass
''')
        report = self.base/'timings.json'
        result = self.run_entrypoint('--timings', str(report))
        self.assertEqual(result.returncode, 1, result.stderr)
        data = json.loads(report.read_text())
        self.assertEqual(data['counts']['expected_failures'], 1)
        self.assertEqual(data['counts']['unexpected_successes'], 1)
        self.assertIn('unexpected_success', {row['status'] for row in data['tests']})

    def test_unwritable_timing_report_is_an_error(self):
        # A directory at the requested filename also fails reliably as root.
        result = self.run_entrypoint('--timings', str(self.tests))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('report', result.stderr.lower())


import workflow_fixture


class OptimizerFixtureContract(workflow_fixture.WorkflowFixtureMixin, unittest.TestCase):
    def test_transaction_fixture_runs_metrics_without_health_report_processes(self):
        self.assertTrue(callable(getattr(self, 'run_optimizer', None)),
                        'explicit optimizer transaction fixture is required')
        result = self.run_optimizer('n\nn\ny\ny\n', overrides=r'''
python3() {
 if [[ "${1##*/}" == crowdbastion_health.py ]]; then
  record unexpected-health-process; return 91
 fi
 command python3 "$@"
}
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(workflow_fixture.yaml.safe_load((self.config/'config.yaml').read_text())['prometheus']['enabled'])
        self.assertNotIn('unexpected-health-process', self.commands())
        self.assertEqual(self.commands().count('optimizer-health\n'), 1)
        self.assertEqual(self.commands().count('systemctl restart crowdsec\n'), 1)

    def test_caller_can_override_diagnostic_status_without_bypassing_transaction(self):
        self.assertTrue(callable(getattr(self, 'run_optimizer', None)),
                        'explicit optimizer transaction fixture is required')
        result = self.run_optimizer('n\nn\ny\ny\n', overrides='''
check_health_status() { record caller-health; return 1; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(workflow_fixture.yaml.safe_load((self.config/'config.yaml').read_text())['prometheus']['enabled'])
        self.assertNotIn('optimizer-health', self.commands())
        self.assertEqual(self.commands().count('caller-health\n'), 1)
        self.assertEqual(self.commands().count('systemctl restart crowdsec\n'), 1)
