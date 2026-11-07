"""A packet acceptance report must not pass on missing paths or controls."""
import copy
import contextlib
import importlib.util
import io
import inspect
import os
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


FILE = Path(__file__).with_name('verify_docker_network.py')


def complete_report():
    cases = []
    for kind in ('host', 'docker'):
        for family in (4, 6):
            for protocol in ('tcp', 'udp'):
                cases.append(dict(kind=kind, family=family, protocol=protocol,
                                  normal_bad=True, normal_good=True, blocked_bad=False,
                                  healthy_good=True, recovered_bad=True, recovered_good=True,
                                  counter_increased=True, counter_before=7, counter_after=8,
                                  backend_peer='10.231.1.2' if family == 4 else 'fd42:231:1::2',
                                  dnat_verified=kind == 'docker'))
    probes = [dict(family=family, protocol=protocol, banned_reachable=False, control_reachable=True)
              for family in (4, 6) for protocol in ('tcp', 'udp')]
    lifecycle = dict(docker_restarted=True, initial_seconds=15, renewed_seconds=45,
                     original_deadline_elapsed=17.0, renewed_timeouts={'4': 40, '6': 40},
                     renewal_probes=probes,
                     expiry_probes=[dict(row, banned_reachable=True) for row in probes],
                     kernel_sets_expired=True)
    return dict(cases=cases, path_coverage='ok', docker_version='27.5.1',
                cleanup_complete=True, lifecycle=lifecycle)


class DockerAcceptance(unittest.TestCase):
    def setUp(self):
        self.assertTrue(FILE.exists(), 'real Docker acceptance entry is missing')
        spec = importlib.util.spec_from_file_location('docker_acceptance_under_test', FILE)
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)

    def test_complete_dual_stack_host_and_published_paths_are_accepted(self):
        self.assertTrue(self.tool.accept_report(complete_report()))

    def test_empty_missing_duplicate_and_unexpected_cases_are_rejected(self):
        base = complete_report()
        for rows in ([], base['cases'][:-1], base['cases'] + [base['cases'][0]],
                     base['cases'][:-1] + [dict(base['cases'][0], kind='forward-only')]):
            report = copy.deepcopy(base)
            report['cases'] = rows
            self.assertFalse(self.tool.accept_report(report))

    def test_every_control_and_recovery_is_required(self):
        for field in ('normal_bad', 'normal_good', 'healthy_good', 'recovered_bad', 'recovered_good'):
            report = complete_report()
            report['cases'][-1][field] = False
            self.assertFalse(self.tool.accept_report(report), field)

    def test_reachable_banned_source_cannot_pass(self):
        report = complete_report()
        report['cases'][-1]['blocked_bad'] = True
        self.assertFalse(self.tool.accept_report(report))

    def test_claimed_counter_growth_needs_numeric_evidence(self):
        for before, after in ((8, 8), (8, 1), (False, 2), (0, True), ('7', 8)):
            report = complete_report()
            report['cases'][0].update(counter_before=before, counter_after=after)
            self.assertFalse(self.tool.accept_report(report))

    def test_published_path_requires_dnat_and_original_source(self):
        for changes in ({'dnat_verified': False}, {'backend_peer': '127.0.0.1'},
                        {'backend_peer': '10.231.2.2'}):
            report = complete_report()
            report['cases'][4].update(changes)
            self.assertFalse(self.tool.accept_report(report))

    def test_unknown_path_cleanup_failure_or_outer_error_cannot_pass(self):
        for change in ({'path_coverage': 'unknown'}, {'cleanup_complete': False},
                       {'docker_version': ''}, {'error': 'worker failed'}):
            report = complete_report()
            report.update(change)
            self.assertFalse(self.tool.accept_report(report))

    def test_guard_refuses_current_network_and_mount_before_setup(self):
        from argparse import Namespace
        descriptors = [os.open(path, os.O_RDONLY) for path in ('/proc/self/ns/net', '/proc/self/ns/mnt')]
        try:
            args = Namespace(net_fd=descriptors[0], mount_fd=descriptors[1],
                             original_inode=os.stat('/proc/self/ns/net').st_ino,
                             original_mount_inode=os.stat('/proc/self/ns/mnt').st_ino)
            with self.assertRaisesRegex(RuntimeError, 'original network namespace'):
                self.tool.worker(args, {})
        finally:
            for descriptor in descriptors:
                os.close(descriptor)

    def test_nonnumeric_families_and_malformed_rows_are_rejected(self):
        for change in ({'family': '4'}, {'family': True}, {'protocol': 'icmp'}):
            report = complete_report()
            report['cases'][0].update(change)
            self.assertFalse(self.tool.accept_report(report))
        for value in (None, [], {'cases': [None]}):
            self.assertFalse(self.tool.accept_report(value))

    def test_missing_docker_is_unverified_without_a_packet_success(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)/'result.json'
            result = subprocess.run([sys.executable, str(FILE), '--docker', '/missing/cb-docker',
                                     '--output', str(output)], capture_output=True, text=True,
                                    timeout=5)
            report = json.loads(output.read_text())
            self.assertEqual(result.returncode, 2)
            self.assertEqual(report['status'], 'unverified')
            self.assertEqual(report['cases'], [])

    def test_restart_renewal_and_natural_expiry_need_observed_evidence(self):
        base = complete_report()
        missing = copy.deepcopy(base)
        missing.pop('lifecycle')
        self.assertFalse(self.tool.accept_report(missing))
        for changes in ({'docker_restarted': False}, {'original_deadline_elapsed': 14},
                        {'renewed_timeouts': {'4': 40, '6': 5}}, {'kernel_sets_expired': False},
                        {'renewal_probes': []}, {'expiry_probes': []}):
            report = copy.deepcopy(base)
            report['lifecycle'].update(changes)
            self.assertFalse(self.tool.accept_report(report), changes)

    def test_lifecycle_udp_or_ipv6_failure_and_missing_controls_cannot_pass(self):
        for field in ('renewal_probes', 'expiry_probes'):
            for change in ({'control_reachable': False},
                           {'banned_reachable': field == 'renewal_probes'}):
                report = complete_report()
                report['lifecycle'][field][-1].update(change)
                self.assertFalse(self.tool.accept_report(report))

    def test_integer_worker_options_cannot_skip_namespace_creation(self):
        with patch.object(self.tool.network, 'setup', side_effect=RuntimeError('unsafe setup reached')):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    self.tool.main(['--original-inode', '0', '--original-mount-inode', '0'])
        self.assertEqual(raised.exception.code, 2)

    def test_docker_info_exit_zero_without_server_is_not_ready(self):
        self.assertTrue(hasattr(self.tool, 'daemon_ready'), 'daemon readiness validation is missing')
        for reply in ('', '{"ServerVersion":"","ServerErrors":["cannot connect"]}',
                      '{"ServerVersion":"27.5.1","ServerErrors":["failed"]}'):
            docker = [sys.executable, '-c', 'print('+repr(reply)+')']
            self.assertIsNone(self.tool.daemon_ready(docker))
        docker = [sys.executable, '-c', 'print(\'{"ServerVersion":"27.5.1","ServerErrors":null}\')']
        self.assertEqual(self.tool.daemon_ready(docker), '27.5.1')

    def test_timeout_retains_checkpoint_cases_and_marks_failure(self):
        self.assertTrue(hasattr(self.tool, 'execute_worker'), 'bounded worker supervision is missing')
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory)/'checkpoint.jsonl'
            script = ('import json,pathlib,sys,time\n'
                      'pathlib.Path(sys.argv[1]).write_text(json.dumps({"cases":[{"kind":"docker"}]})+"\\n")\n'
                      'print("worker diagnostic",file=sys.stderr,flush=True)\n'
                      'time.sleep(60)\n')
            report, code = self.tool.execute_worker([sys.executable, '-c', script, str(checkpoint)],
                                                     (), checkpoint, timeout=.5, cleanup_timeout=.5)
            self.assertEqual(code, 1)
            self.assertEqual(report['cases'], [{'kind': 'docker'}])
            self.assertIn('timeout', report['error'])
            self.assertIn('worker diagnostic', report['worker_stderr'])

    def test_isolation_failure_with_an_empty_checkpoint_stays_unverified(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Path(directory)/'empty.jsonl'
            checkpoint.touch()
            script = 'import sys;print("isolation denied",file=sys.stderr);sys.exit(1)'
            report, code = self.tool.execute_worker([sys.executable, '-c', script], (), checkpoint)
            self.assertEqual(code, 2)
            self.assertEqual(report['cases'], [])
            self.assertIn('isolation denied', report['error'])

    def test_original_expiry_wait_is_anchored_after_initial_set_installation(self):
        clock = [0.0]
        observed = []
        def sleep(seconds):
            clock[0] += seconds
        def wait(*args):
            clock[0] += 7
        def probes():
            observed.append(clock[0])
            return []
        with patch.object(self.tool, 'timed_ban'), patch.object(self.tool, 'wait_set', side_effect=wait), \
                patch.object(self.tool, 'set_timeouts', return_value={'4': 44, '6': 44}), \
                patch.object(self.tool, 'lifecycle_probes', side_effect=probes), \
                patch.object(self.tool, 'command', return_value=''), \
                patch.object(self.tool.time, 'monotonic', side_effect=lambda: clock[0]), \
                patch.object(self.tool.time, 'sleep', side_effect=sleep):
            self.tool.observe_lifecycle(type('API', (), {'set_ban': lambda *args: None})())
        self.assertGreaterEqual(observed[0], 31)

    def test_timeout_supervisor_reaps_detached_orphan_grandchildren(self):
        from relay_network_lab import Processes
        self.assertIn('subreaper', inspect.signature(Processes).parameters,
                      'descendant ownership is missing from timeout supervision')
        child = ('import subprocess,sys\n'
                 'p=subprocess.Popen([sys.executable,"-c",'
                 '"import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(60)"],'
                 'start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n'
                 'print(p.pid,flush=True)\n')
        manager = ('import sys,time\nsys.path.insert(0,sys.argv[1])\n'
                   'from relay_network_lab import Processes\n'
                   'with Processes(grace=.2,subreaper=True) as owned:\n'
                   ' p=owned.start([sys.executable,"-c",sys.argv[2]],stdout=-1,text=True)\n'
                   ' print(p.stdout.readline().strip(),flush=True)\n'
                   ' p.wait();p.stdout.close()\n'
                   ' time.sleep(60)\n')
        process = subprocess.Popen([sys.executable, '-c', manager, str(FILE.parent), child],
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        orphan = None
        try:
            orphan = int(process.stdout.readline())
            import time
            time.sleep(.1)
            process.terminate()
            process.wait(timeout=8)
            with self.assertRaises(ProcessLookupError):
                os.kill(orphan, 0)
        finally:
            process.stdout.close()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if orphan is not None:
                import signal
                try:
                    os.kill(orphan, signal.SIGKILL)
                except ProcessLookupError:
                    pass


if __name__ == '__main__':
    unittest.main()
