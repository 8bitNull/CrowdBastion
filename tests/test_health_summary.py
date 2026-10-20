"""Verdicts reflect evidence, with a single useful next step and read-only details."""
import sys
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_workflows
import test_node_guidance

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


class Verdicts(unittest.TestCase):
    def setUp(self):
        import crowdbastion_health
        self.health = crowdbastion_health

    def report(self, *events, status=2):
        return self.health.summarize([('core', 'required'), ('logs', 'required'),
                                     ('rules', 'required'), *events], status, 'overall', 'relay')

    def test_complete_static_evidence_still_requires_traffic_validation(self):
        report = self.report(('core', 'ok'), ('logs', 'ok'), ('rules', 'ok'))
        self.assertEqual(report['verdict'], '运行检查通过，实际拦截待验证')
        self.assertEqual(report['action'], 'verify')
        self.assertEqual(report['status'], 2)

    def test_stopped_bouncer_has_concrete_reason_impact_and_logs_action(self):
        report = self.report(('core', 'ok'), ('logs', 'ok'), ('rules', 'ok'), ('bouncer', 'fault'))
        self.assertEqual(report['verdict'], '发现问题，需要处理')
        self.assertIn('防火墙防护服务没有运行', report['attention'])
        self.assertIn('IP 封禁', report['impact'])
        self.assertEqual(report['action'], 'bouncer_logs')
        self.assertEqual(report['status'], 1)

    def test_missing_core_and_unknown_core_are_different(self):
        missing = self.report(('core', 'missing'), status=1)
        unknown = self.report(('core', 'unknown'), status=1)
        self.assertEqual(missing['verdict'], '部署尚未完成')
        self.assertEqual(missing['action'], 'install_relay')
        self.assertEqual(unknown['verdict'], '检查未完成，暂时无法判断')
        self.assertEqual(unknown['action'], 'details')

    def test_idle_logs_and_missing_observations_never_claim_runtime_pass(self):
        for events in [(('core', 'ok'), ('logs', 'pending'), ('rules', 'ok')), ()]:
            with self.subTest(events=events):
                report = self.report(*events, status=0)
                self.assertEqual(report['verdict'], '检查未完成，暂时无法判断')
                self.assertEqual(report['status'], 2)

    def test_optional_absence_is_silent_and_fault_wins_over_missing(self):
        report = self.report(('core', 'ok'), ('logs', 'ok'), ('rules', 'ok'), ('appsec', 'optional'))
        self.assertEqual(report['verdict'], '运行检查通过，实际拦截待验证')
        self.assertNotIn('AppSec', str(report))
        report = self.report(('core', 'missing'), ('bouncer', 'fault'), status=1)
        self.assertEqual(report['verdict'], '发现问题，需要处理')

    def test_nonzero_without_reason_cannot_invent_a_fault_or_pass(self):
        report = self.report(('core', 'ok'), ('logs', 'ok'), ('rules', 'ok'), status=1)
        self.assertEqual(report['verdict'], '检查未完成，暂时无法判断')
        self.assertEqual(report['status'], 1)


class SummaryWorkflow(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    roles = test_node_guidance.Guidance.roles
    run_terminal = test_node_guidance.Guidance.run_terminal

    def test_missing_core_is_concise_and_advises_correct_installation(self):
        self.roles('relay')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('main --status')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('检查结论：部署尚未完成', p.stdout)
        self.assertIn('--install-relay', p.stdout)
        self.assertNotIn('IPv4 INPUT', p.stdout)
        self.assertNotIn('AppSec', p.stdout)
        self.assertNotIn('请选择', p.stdout)
        self.assertNotRegex(self.commands(), r'restart|reload|decisions add|machines add')

    def test_good_relay_is_concise_and_only_recommends_external_validation(self):
        self.roles('relay')
        (self.config/'bouncers').mkdir()
        (self.config/'bouncers/crowdsec-firewall-bouncer.yaml').write_text('mode: nftables\n')
        p = self.run_shell('main --status', overrides='''
cscli() {
 record cscli "$@"
 if [[ "$*" == 'metrics show acquisition -o json' ]]; then echo '{"acquisition":{"file:/var/log/auth.log":{"reads":96,"parsed":96}}}'; fi
 return 0
}
check_relay_status() { health_event rules ok; return 2; }
check_firewall_backend() { health_event renewal ok; return 0; }
nft() { record nft "$@"; if [[ "$*" == 'list tables' ]]; then echo 'table ip crowdsec'; return 0; fi; return 1; }
''')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('运行检查通过，实际拦截待验证', p.stdout)
        self.assertIn('日志读取与解析正常', p.stdout)
        self.assertIn('本次未发现需要修复的问题', p.stdout)
        self.assertNotIn('AppSec', p.stdout)
        self.assertNotIn('WebUI', p.stdout)
        self.assertNotIn('IPv4 INPUT', p.stdout)
        self.assertEqual(p.stdout.count('下一步：'), 1)
        self.assertNotRegex(self.commands(), r'restart|reload|decisions add|curl')

    def test_service_failure_recommends_logs_and_keeps_raw_output_in_details(self):
        self.roles('relay')
        (self.config/'bouncers').mkdir()
        (self.config/'bouncers/crowdsec-firewall-bouncer.yaml').write_text('mode: nftables\n')
        override = '''systemctl() {
 record systemctl "$@"
 if [[ "$*" == 'is-active crowdsec-firewall-bouncer' ]]; then echo inactive; return 3; fi
 return 0
}
check_relay_status() { return 2; }
'''
        p = self.run_shell('main --status', overrides=override)
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('检查结论：发现问题，需要处理', p.stdout)
        self.assertIn('防火墙防护服务没有运行', p.stdout)
        self.assertIn('journalctl', p.stdout)
        self.assertNotIn('核心服务:', p.stdout)
        p = self.run_shell('main --status-details', overrides=override)
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('核心服务:', p.stdout)

    def test_details_selection_uses_captured_output_and_cleans_private_files(self):
        self.roles('relay')
        p = self.run_terminal('interactive_health_check', '2\n0\n', '''
check_health_status_raw() {
 record check-once
 record "$CROWDBASTION_HEALTH_EVENTS"
 printf 'DETAIL MARKER\\n'
 health_expect core
 health_event core ok
 return 2
}
''')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertEqual(self.commands().count('check-once'), 1)
        self.assertIn('DETAIL MARKER', p.stdout)
        self.assertIn('2. 查看检查详情', p.stdout)
        self.assertNotIn('按回车', p.stdout)
        report_dir = Path(self.commands().splitlines()[1]).parent
        self.assertFalse(report_dir.exists())

    def test_unreadable_service_does_not_report_stopped_or_normal(self):
        self.roles('relay')
        (self.config/'bouncers').mkdir()
        (self.config/'bouncers/crowdsec-firewall-bouncer.yaml').write_text('mode: nftables\n')
        p = self.run_shell('main --status', overrides='''
systemctl() { record systemctl "$@"; if [[ "$*" == 'is-active crowdsec' ]]; then return 1; fi; }
check_relay_status() { return 2; }
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('检查未完成，暂时无法判断', p.stdout)
        self.assertNotIn('服务没有运行', p.stdout)
        self.assertNotIn('本次未发现需要修复', p.stdout)

    def test_unknown_helper_result_cannot_claim_normal(self):
        self.roles('remote', 'node')
        p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { return 0; }
check_remote_firewall_status() { return 2; }
diagnose_v2bx() { return 2; }
''')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('检查未完成，暂时无法判断', p.stdout)

    def test_remote_missing_setup_avoids_local_core_and_repair(self):
        self.roles('remote')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('main --status', overrides='check_remote_firewall_status() { return 2; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('部署尚未完成', p.stdout)
        self.assertIn('远端检测中心连接', p.stdout)
        self.assertNotIn('cscli', self.commands())
        self.assertNotRegex(self.commands(), r'apt-get|restart|reload|decisions add')

    def test_registered_stopped_web_container_has_a_clear_fault(self):
        self.roles('remote')
        (self.config/'crowdsec-1key-web-installs.json').write_text('{"site":{"status":"installed"}}')
        p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { health_event remote ok; health_event bouncer ok; return 0; }
check_remote_firewall_status() { health_event rules ok; return 2; }
docker() { record docker "$@"; return 0; }
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('发现问题，需要处理', p.stdout)
        self.assertIn('网站容器没有运行', p.stdout)

    def test_reporter_failure_still_has_one_conclusion_and_exit_one(self):
        self.roles('relay')
        p = self.run_shell('main --status', overrides='''
python3() {
 if [[ "$1" == *crowdbastion_health.py && "$2" != event ]]; then return 42; fi
 command python3 "$@"
}
check_relay_status() { return 2; }
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('检查结论：检查未完成，暂时无法判断', p.stdout)
        self.assertEqual(p.stdout.count('检查结论：'), 1)

    def test_online_web_cannot_pass_when_registered_container_is_unreadable(self):
        self.roles('web')
        (self.config/'crowdsec-1key-web-installs.json').write_text('{"site":{"status":"installed"}}')
        p = self.run_shell('main --status', overrides='''
cscli() {
 record cscli "$@"
 case "$*" in
 'metrics show acquisition -o json') echo '{"acquisition":{"file:/var/log/nginx/access.log":{"reads":100,"parsed":100}}}' ;;
 'metrics show appsec -o json') echo '{}' ;;
 esac
 return 0
}
check_log_inventory() { return 0; }
docker() { record docker "$@"; return 1; }
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('检查未完成，暂时无法判断', p.stdout)
        self.assertNotIn('本次未发现需要修复的问题', p.stdout)


class RealObservations(unittest.TestCase):
    def test_standalone_node_can_check_runtime_without_optional_firewall(self):
        import test_v2bx_diagnosis
        import crowdbastion_health as health
        fixture = test_v2bx_diagnosis.V2bXDiagnosis()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.write_config()
        fixture.command('systemctl', 'LoadState=loaded\nActiveState=active\nMainPID=123\nWorkingDirectory=/\n')
        events = fixture.base/'events'
        events.touch(mode=0o600)
        env = {**os.environ, 'PATH': str(fixture.bin), 'CROWDBASTION_HEALTH_EVENTS': str(events)}
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_v2bx.py'), '--config', str(fixture.config), '--cs-dir', str(fixture.cs), '--bouncer-only', '--firewall-optional'], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'node', 'node')
        self.assertEqual(report['verdict'], '运行检查通过，实际拦截待验证')
        self.assertNotIn('bouncer', events.read_text())

    def test_missing_firewall_config_is_not_optional_if_service_is_installed(self):
        import test_v2bx_diagnosis
        import crowdbastion_health as health
        fixture = test_v2bx_diagnosis.V2bXDiagnosis()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.write_config()
        fixture.command('systemctl', 'LoadState=loaded\nActiveState=active\nMainPID=123\nWorkingDirectory=/\n')
        service_tool = fixture.bin/'systemctl'
        original = service_tool.read_text()
        service_tool.write_text(original.replace('#!/bin/sh\n', '#!/bin/sh\nif [ "$1" = list-unit-files ]; then echo "crowdsec-firewall-bouncer.service enabled"; exit 0; fi\n', 1))
        events = fixture.base/'events'
        events.touch(mode=0o600)
        env = {**os.environ, 'PATH': str(fixture.bin), 'CROWDBASTION_HEALTH_EVENTS': str(events)}
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_v2bx.py'), '--config', str(fixture.config), '--cs-dir', str(fixture.cs), '--bouncer-only', '--firewall-optional'], env=env, capture_output=True, text=True)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'node', 'node')
        self.assertEqual(report['verdict'], '部署尚未完成')
        self.assertIn('bouncer\tmissing', events.read_text())

    def test_stopped_v2bx_is_a_fault_with_service_logs_as_next_step(self):
        import test_v2bx_diagnosis
        import crowdbastion_health as health
        fixture = test_v2bx_diagnosis.V2bXDiagnosis()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.write_config()
        fixture.command('systemctl', 'LoadState=loaded\nActiveState=inactive\nMainPID=0\n')
        events = fixture.base/'events'
        events.touch(mode=0o600)
        env = {**os.environ, 'PATH': str(fixture.bin), 'CROWDBASTION_HEALTH_EVENTS': str(events)}
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_v2bx.py'), '--config', str(fixture.config), '--cs-dir', str(fixture.cs)], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'node', 'node')
        self.assertEqual(report['verdict'], '发现问题，需要处理')
        self.assertEqual(report['action'], 'v2bx_logs')

    def test_unreadable_declared_node_log_prevents_runtime_pass(self):
        import test_v2bx_diagnosis
        import crowdbastion_health as health
        fixture = test_v2bx_diagnosis.V2bXDiagnosis()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.write_config(cores=[{'Type': 'sing', 'Log': {'Output': str(fixture.base/'missing.log')}}])
        fixture.command('systemctl', 'LoadState=loaded\nActiveState=active\nMainPID=123\nWorkingDirectory=/\n')
        events = fixture.base/'events'
        events.touch(mode=0o600)
        env = {**os.environ, 'PATH': str(fixture.bin), 'CROWDBASTION_HEALTH_EVENTS': str(events)}
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_v2bx.py'), '--config', str(fixture.config), '--cs-dir', str(fixture.cs), '--bouncer-only', '--firewall-optional'], env=env, capture_output=True, text=True)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'node', 'node')
        self.assertEqual(report['verdict'], '检查未完成，暂时无法判断')
        self.assertEqual(report['action'], 'details')

    def test_origin_suffixed_rules_do_not_hide_unknown_renewal_status(self):
        import test_relay_mode
        import crowdbastion_health as health
        fixture = test_relay_mode.RelayAudit()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.file.write_text('mode: nftables\ndisable_ipv6: true\nnftables: {ipv4: {enabled: true}}\n')
        records = [{'set': {'family': 'ip', 'table': 'crowdsec', 'name': 'crowdsec-blacklists-CAPI'}}]
        for chain in ('input', 'forward'):
            records += [{'chain': {'family': 'ip', 'table': 'crowdsec', 'name': chain, 'hook': chain}},
                        {'rule': {'family': 'ip', 'table': 'crowdsec', 'chain': chain, 'expr': [
                            {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@crowdsec-blacklists-CAPI'}}, {'drop': None}]}}]
        fixture.tool('nft', json.dumps({'nftables': records}))
        events = fixture.base/'events'
        events.touch(mode=0o600)
        env = {**os.environ, 'PATH': str(fixture.bin)+':'+os.environ['PATH'], 'CROWDBASTION_HEALTH_EVENTS': str(events)}
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_relay.py'), 'audit', str(fixture.config)], env=env, capture_output=True, text=True)
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'relay', 'relay')
        self.assertEqual(report['verdict'], '检查未完成，暂时无法判断')
        self.assertIn('续封', report['attention'])
        self.assertIn('封禁规则', report['confirmed'])
        # Missing the configured FORWARD path must lose the pass verdict.
        fixture.tool('nft', json.dumps({'nftables': records[:-2]}))
        events.write_text('')
        p = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_relay.py'), 'audit', str(fixture.config)], env=env, capture_output=True, text=True)
        report = health.summarize([line.split('\t') for line in events.read_text().splitlines()], p.returncode, 'relay', 'relay')
        self.assertEqual(report['verdict'], '检查未完成，暂时无法判断')

    def test_invalid_counts_cannot_be_accepted_as_good_parsing(self):
        import crowdsec_maintenance as maintenance
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'metrics'
            for value in (-3, True, '96'):
                path.write_text(json.dumps({'acquisition': {'file:/var/log/auth.log': {'reads': value, 'parsed': value}}}))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    maintenance.system_health_metrics(path)

    def test_nginx_source_with_reads_and_no_parsing_is_not_idle(self):
        import crowdsec_maintenance as maintenance
        with tempfile.TemporaryDirectory() as tmp:
            acquisition, appsec, events = [Path(tmp)/name for name in ('acquisition', 'appsec', 'events')]
            acquisition.write_text(json.dumps({'acquisition': {'journalctl:nginx.service': {'reads': 10, 'parsed': 0}}}))
            appsec.write_text('{}')
            events.touch(mode=0o600)
            with patch.dict(os.environ, CROWDBASTION_HEALTH_EVENTS=str(events)):
                self.assertEqual(maintenance.health_metrics(acquisition, appsec), 1)
            self.assertIn('logs\tfault', events.read_text())

    def test_unconfirmed_effective_web_hook_does_not_prove_runtime_pass(self):
        import crowdsec_request_audit as audit
        with tempfile.TemporaryDirectory() as tmp:
            paths = {name: Path(tmp)/name for name in ('state', 'effective', 'installs', 'mounts', 'events')}
            paths['state'].write_text('{}')
            paths['effective'].write_text('http { server { server_name example.com; } }')
            paths['installs'].write_text('{"site":{"status":"installed"}}')
            paths['mounts'].write_text('[]')
            paths['events'].touch(mode=0o600)
            with patch.dict(os.environ, CROWDBASTION_HEALTH_EVENTS=str(paths['events'])):
                self.assertEqual(audit.status(paths['state'], 'site', paths['effective'], paths['installs'], paths['mounts']), 2)
            self.assertIn('web\tunknown', paths['events'].read_text())

    def test_uninstalled_web_bouncer_is_optional_for_readable_nginx_config(self):
        import crowdsec_request_audit as audit
        with tempfile.TemporaryDirectory() as tmp:
            paths = {name: Path(tmp)/name for name in ('state', 'effective', 'installs', 'mounts', 'events')}
            paths['state'].write_text('{}')
            paths['effective'].write_text('http { server { server_name example.com; } }')
            paths['installs'].write_text('{}')
            paths['mounts'].write_text('[]')
            paths['events'].touch(mode=0o600)
            with patch.dict(os.environ, CROWDBASTION_HEALTH_EVENTS=str(paths['events'])):
                audit.status(paths['state'], 'site', paths['effective'], paths['installs'], paths['mounts'])
            self.assertNotIn('web\tunknown', paths['events'].read_text())

    def test_event_writer_refuses_symlink_and_fifo(self):
        import crowdbastion_health as health
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)/'target'
            target.write_text('unchanged')
            event = Path(tmp)/'event'
            event.symlink_to(target)
            with patch.dict(os.environ, CROWDBASTION_HEALTH_EVENTS=str(event)):
                with self.assertRaises((OSError, ValueError)):
                    health.emit('core', 'ok')
                event.unlink()
                os.mkfifo(event)
                with self.assertRaises((OSError, ValueError)):
                    health.emit('core', 'ok')
            self.assertEqual(target.read_text(), 'unchanged')


if __name__ == '__main__':
    unittest.main()
