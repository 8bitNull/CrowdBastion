#!/usr/bin/env python3
"""Run existing unittest coverage with explicit subsets and optional timing evidence."""
import argparse
import json
from pathlib import Path
import sys
import time
import unittest

TEST_DIR = Path(__file__).resolve().parent
TIERS_PATH = TEST_DIR / 'test_tiers.json'
TIERS = ('quick', 'integration', 'archive')


def flatten(suite):
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from flatten(item)
        else:
            yield item


def select_tests(test_dir, tiers_path, tier, modules):
    loader = unittest.TestLoader()
    suite = loader.discover(str(test_dir))
    if loader.errors:
        raise ValueError('test discovery failed:\n' + '\n'.join(loader.errors))
    cases = list(flatten(suite))
    ids = [case.id() for case in cases]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate test IDs discovered')
    available = {name.split('.')[0] for name in ids}
    config = json.loads(Path(tiers_path).read_text())
    if not isinstance(config, dict) or set(config) != {'version', *TIERS}:
        raise ValueError('tier manifest must contain version, quick, integration, archive')
    if type(config['version']) is not int or config['version'] != 1:
        raise ValueError('unsupported tier manifest version')
    assigned = set()
    for name in TIERS:
        values = config[name]
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
            raise ValueError(f'{name}: expected a list of module names')
        if len(set(values)) != len(values) or assigned.intersection(values):
            raise ValueError(f'{name}: duplicate or overlapping module assignments')
        if set(values) - available:
            raise ValueError(f'{name}: unknown or empty modules: {sorted(set(values) - available)}')
        assigned.update(values)
    if set(modules) - available:
        raise ValueError(f'unknown modules: {sorted(set(modules) - available)}')
    selected = available if tier == 'full' else set(config[tier])
    if modules:
        selected = selected.intersection(modules)
    cases = [case for case in cases if case.id().split('.')[0] in selected]
    if not cases:
        raise ValueError('selection contains no tests')
    return unittest.TestSuite(cases)


class TimingResult(unittest.TextTestResult):
    """Measure test setup/body/cleanup; retain fixture errors without inventing timings."""
    priority = {'passed': 0, 'expected_failure': 1, 'skipped': 2,
                'unexpected_success': 3, 'failed': 4, 'error': 5}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.records = []
        self.active = None
        self.started = None

    def startTest(self, test):
        self.active = {'id': test.id(), 'seconds': None, 'status': 'passed', 'skip_reasons': []}
        self.records.append(self.active)
        self.started = time.perf_counter()
        super().startTest(test)

    def stopTest(self, test):
        self.active['seconds'] = time.perf_counter() - self.started
        self.active = None
        super().stopTest(test)

    def outcome(self, test, status, reason=None):
        record = self.active
        if record is None:
            record = {'id': test.id(), 'seconds': None, 'status': status, 'skip_reasons': []}
            self.records.append(record)
        if self.priority[status] > self.priority[record['status']]:
            record['status'] = status
        if reason is not None:
            record['skip_reasons'].append(reason)

    def addFailure(self, test, err):
        self.outcome(test, 'failed')
        super().addFailure(test, err)

    def addError(self, test, err):
        self.outcome(test, 'error')
        super().addError(test, err)

    def addSkip(self, test, reason):
        self.outcome(test, 'skipped', reason)
        super().addSkip(test, reason)

    def addExpectedFailure(self, test, err):
        self.outcome(test, 'expected_failure')
        super().addExpectedFailure(test, err)

    def addUnexpectedSuccess(self, test):
        self.outcome(test, 'unexpected_success')
        super().addUnexpectedSuccess(test)

    def addSubTest(self, test, subtest, err):
        if err is not None:
            self.outcome(test, 'failed' if issubclass(err[0], test.failureException) else 'error')
        super().addSubTest(test, subtest, err)


def main(argv=None, *, test_dir=TEST_DIR, tiers_path=TIERS_PATH):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tier', choices=('full', *TIERS), default='full')
    parser.add_argument('--module', action='append', default=[], help='module name; repeat to select several')
    parser.add_argument('--list', action='store_true', help='list selected IDs without running fixtures')
    parser.add_argument('--timings', type=Path, help='write timing/status JSON')
    parser.add_argument('--top', type=int, default=10, help='number of slow tests to display (default: 10)')
    parser.add_argument('--require-no-skips', action='store_true', help='return failure if any selected check skips')
    args = parser.parse_args(argv)
    if args.top < 0:
        parser.error('--top must be nonnegative')
    if args.list and args.timings:
        parser.error('--list cannot produce execution timings')
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
    started = time.perf_counter()
    try:
        suite = select_tests(Path(test_dir).resolve(), tiers_path, args.tier, args.module)
    except (OSError, ValueError, ImportError) as exc:
        print(f'test selection error: {exc}', file=sys.stderr)
        return 2
    if args.list:
        for case in flatten(suite):
            print(case.id())
        return 0
    print(f'Tier: {args.tier}; selected {suite.countTestCases()} tests', file=sys.stderr)
    result = unittest.TextTestRunner(resultclass=TimingResult, verbosity=1).run(suite)
    accepted = result.wasSuccessful() and not (args.require_no_skips and result.skipped)
    report = {'version': 1, 'tier': args.tier, 'modules': args.module,
              'seconds': time.perf_counter() - started, 'accepted': bool(accepted),
              'require_no_skips': args.require_no_skips,
              'counts': {'run': result.testsRun, 'failures': len(result.failures),
                         'errors': len(result.errors), 'skipped': len(result.skipped),
                         'expected_failures': len(result.expectedFailures),
                         'unexpected_successes': len(result.unexpectedSuccesses)},
              'tests': result.records}
    if result.skipped:
        print('Skipped checks:', file=sys.stderr)
        for reason in sorted({reason for _, reason in result.skipped}):
            print(f'  {sum(reason == value for _, value in result.skipped)}: {reason}', file=sys.stderr)
    if args.require_no_skips and result.skipped:
        print('Required checks skipped; rejecting this run.', file=sys.stderr)
    slowest = sorted((row for row in result.records if row['seconds'] is not None),
                     key=lambda row: row['seconds'], reverse=True)[:args.top]
    if slowest:
        print('Slowest tests (setup/body/cleanup):', file=sys.stderr)
        for row in slowest:
            print(f"  {row['seconds']:.3f}s {row['id']}", file=sys.stderr)
    if args.timings:
        try:
            args.timings.parent.mkdir(parents=True, exist_ok=True)
            args.timings.write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n')
        except OSError as exc:
            print(f'timing report error: {exc}', file=sys.stderr)
            return 2
    return 0 if accepted else 1


if __name__ == '__main__':
    raise SystemExit(main())
