"""Purpose persistence, check dispatch and terminal navigation contracts."""
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stdout

import test_workflows

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import crowdsec_maintenance as maintenance


class Preferences(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'state/node-roles.json'

    def helper(self, action, *roles):
        return subprocess.run([sys.executable, str(ROOT/'lib/crowdbastion_node.py'),
                               action, str(self.path), *roles], capture_output=True, text=True)

    def test_combined_roles_survive_reload_without_credentials(self):
        result = self.helper('save', 'node', 'relay')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.helper('load').stdout.strip(), 'relay node')
        self.assertEqual(json.loads(self.path.read_text()), {'version': 1, 'roles': ['relay', 'node']})
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_conflicting_or_unknown_roles_do_not_replace_preferences(self):
        self.assertEqual(self.helper('save', 'remote', 'node').returncode, 0)
        before = self.path.read_bytes()
        for roles in [('remote', 'web'), ('remote', 'relay'), ('website',), ()]:
            with self.subTest(roles=roles):
                self.assertEqual(self.helper('save', *roles).returncode, 1)
                self.assertEqual(self.path.read_bytes(), before)

    def test_corrupt_and_unsafe_files_are_rejected(self):
        self.path.parent.mkdir()
        for content in ['{}', '{', '{"version":1,"roles":["web","remote"]}']:
            self.path.write_text(content)
            self.assertEqual(self.helper('load').returncode, 1)
        self.path.unlink()
        target = self.path.parent/'target'
        target.write_text('unchanged')
        self.path.symlink_to(target)
        self.assertEqual(self.helper('load').returncode, 1)
        self.assertEqual(self.helper('save', 'relay').returncode, 1)
        self.assertEqual(target.read_text(), 'unchanged')
        self.path.unlink()
        os.mkfifo(self.path)
        self.assertEqual(self.helper('load').returncode, 1)
        self.assertEqual(self.helper('save', 'relay').returncode, 1)

    def test_missing_preferences_are_read_only(self):
        self.assertEqual(self.helper('load').returncode, 3)
        self.assertFalse(self.path.parent.exists())

    def test_symlink_parent_and_writable_preference_are_rejected(self):
        self.path.parent.mkdir()
        self.path.write_text('{"version":1,"roles":["relay"]}')
        self.path.chmod(0o666)
        self.assertEqual(self.helper('load').returncode, 1)
        self.assertEqual(self.helper('save', 'web').returncode, 1)
        self.path.unlink()
        self.path.parent.rmdir()
        target = self.path.parent.parent/'outside'
        target.mkdir()
        self.path.parent.symlink_to(target, target_is_directory=True)
        self.assertEqual(self.helper('save', 'relay').returncode, 1)
        self.assertFalse((target/'node-roles.json').exists())


class Guidance(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def roles(self, *roles):
        path = self.base/'var/lib/crowdbastion/node-roles.json'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'version': 1, 'roles': list(roles)}))
        path.chmod(0o600)
        return path

    def test_select_cancel_and_eof_do_not_save_or_install(self):
        for value in ['0\n', '']:
            p = self.run_shell('select_node_roles', value)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertFalse((self.base/'var/lib/crowdbastion/node-roles.json').exists())
        self.assertEqual(self.commands(), '')

    def test_select_combination_only_saves_preference(self):
        p = self.run_shell('select_node_roles; load_node_roles; printf "roles=%s" "$NODE_ROLES"', '2 4\n')
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('roles=relay node', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_relay_status_skips_http_and_appsec_and_does_not_write(self):
        path = self.roles('relay')
        before = path.read_bytes()
        p = self.run_shell('main --status', overrides='check_relay_status() { return 2; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertNotIn('metrics show appsec', self.commands())
        self.assertNotIn('docker ', self.commands())
        self.assertIn('不适用', p.stdout)
        self.assertIn('--relay-path', p.stdout)
        self.assertEqual(path.read_bytes(), before)
        self.assertNotRegex(self.commands(), r'restart|reload|decisions add|machines add')

    def test_remote_status_does_not_require_or_query_local_core(self):
        self.roles('remote')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('main --status', overrides='remote_bouncer_status() { return 0; }; check_remote_firewall_status() { return 2; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertNotIn('cscli', self.commands())
        self.assertNotIn('crowdsec -t', self.commands())
        self.assertNotIn('systemctl is-active crowdsec\n', self.commands())
        self.assertIn('中心', p.stdout)

    def test_node_without_core_still_diagnoses_v2bx(self):
        self.roles('node')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('main --status', overrides='diagnose_v2bx() { printf "V2bX diagnosis\n"; return 2; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('V2bX diagnosis', p.stdout)
        self.assertNotIn('cscli', self.commands())
        self.assertIn('--install-relay', p.stdout)

    def test_combination_keeps_abnormal_precedence(self):
        self.roles('remote', 'node')
        p = self.run_shell('check_health_status', overrides='remote_bouncer_status() { return 1; }; check_remote_firewall_status() { return 2; }; diagnose_v2bx() { printf "node checked\n"; return 2; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('node checked', p.stdout)

    def test_invalid_profile_fails_without_legacy_check_or_mutation(self):
        path = self.roles('relay')
        path.write_text('{')
        p = self.run_shell('main --status')
        self.assertEqual(p.returncode, 1)
        self.assertEqual(self.commands(), '')
        self.assertEqual(path.read_text(), '{')

    def test_deployed_web_fault_is_not_hidden_by_relay_role(self):
        self.roles('relay')
        (self.config/'acquis.d').mkdir()
        (self.config/'acquis.d/crowdsec-1key-appsec.yaml').write_text('source: appsec\n')
        p = self.run_shell('check_health_status', overrides='check_web_health_status() { if [[ "${1:-web}" == web ]]; then printf "web inspected\n"; return 1; fi; return 2; }; check_relay_status() { return 2; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('web inspected', p.stdout)

    def test_managed_web_logs_in_active_custom_directory_are_not_hidden(self):
        self.roles('relay')
        active = self.base/'custom-acquisition'
        active.mkdir()
        (self.config/'config.yaml.local').write_text('crowdsec_service:\n  acquisition_dir: '+str(active)+'\n')
        (active/'crowdsec-1key-log-repair.yaml').write_text('filenames: [/custom/access.log]\nlabels: {type: nginx}\n')
        p = self.run_shell('check_health_status', overrides='check_web_health_status() { if [[ "${1:-web}" == web ]]; then printf "web inspected\n"; return 1; fi; return 2; }; check_relay_status() { return 2; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertIn('web inspected', p.stdout)

    def test_remote_v2bx_dispatches_bouncer_only_diagnostic(self):
        self.roles('remote', 'node')
        p = self.run_shell('diagnose_v2bx', overrides='''
python3() {
 if [[ "$1" == *crowdsec_v2bx.py ]]; then record diagnostic "$@"; return 2; fi
 command python3 "$@"
}
''')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('--bouncer-only', self.commands())

    def test_missing_relay_core_advises_relay_installation(self):
        self.roles('relay')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('main --status')
        self.assertEqual(p.returncode, 1)
        self.assertIn('--install-relay', p.stdout+p.stderr)
        self.assertNotIn('[1] → [1]', p.stdout+p.stderr)

    def test_malformed_system_metrics_are_abnormal_not_unverified(self):
        self.roles('relay')
        p = self.run_shell('check_health_status', overrides='''
cscli() { record cscli "$@"; if [[ "$*" == 'metrics show acquisition -o json' ]]; then printf '{invalid'; fi; }
check_relay_status() { return 2; }
''')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)

    def test_remote_deployed_web_is_inspected_without_local_lapi(self):
        self.roles('remote')
        (self.config/'acquis.d').mkdir()
        (self.config/'acquis.d/crowdsec-1key-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels: {type: appsec}\n')
        p = self.run_shell('main --status', overrides='remote_bouncer_status() { return 0; }; check_remote_firewall_status() { return 2; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('监听', p.stdout)
        self.assertNotIn('cscli', self.commands())
        self.assertNotIn('crowdsec -t', self.commands())

    def test_remote_deployed_web_listener_fault_is_abnormal(self):
        self.roles('remote')
        (self.config/'acquis.d').mkdir()
        (self.config/'acquis.d/crowdsec-1key-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels: {type: appsec}\n')
        p = self.run_shell('main --status', overrides='remote_bouncer_status() { return 0; }; check_remote_firewall_status() { return 2; }; ss() { :; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
        self.assertNotIn('cscli', self.commands())

    def test_remote_docker_web_read_failures_are_abnormal(self):
        self.roles('remote')
        (self.config/'crowdsec-1key-web-installs.json').write_text('{"site":{"status":"installed"}}')
        for failure in ('enumeration', 'effective', 'mounts', 'stopped'):
            with self.subTest(failure=failure):
                p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { return 0; }
check_remote_firewall_status() { return 2; }
docker() {
 record docker "$@"
 case "$*" in
  'ps '*) '''+('return 1' if failure == 'enumeration' else 'return 0' if failure == 'stopped' else 'printf "abc custom/site:latest site\\n"')+''' ;;
  'exec abc nginx -T') '''+('return 1' if failure == 'effective' else 'printf "http { }\\n"')+''' ;;
  'inspect '*) return 1 ;;
 esac
}
''')
                self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
                self.assertNotIn('cscli', self.commands())

    def test_remote_unmanaged_nonweb_container_does_not_cause_web_fault(self):
        self.roles('remote')
        (self.config/'crowdsec-1key-web-installs.json').write_text('{}')
        p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { return 0; }
check_remote_firewall_status() { return 2; }
docker() { record docker "$@"; if [[ "$1" == ps ]]; then printf 'abc redis:latest cache\n'; else return 1; fi; }
''')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertNotIn('exec abc', self.commands())

    def test_remote_offline_audit_checks_web_image_and_registered_custom_image(self):
        self.roles('remote')
        (self.config/'acquis.d').mkdir()
        (self.config/'acquis.d/crowdsec-1key-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels: {type: appsec}\n')
        for image in ('nginx:latest', 'custom/site:latest'):
            if image.startswith('custom'):
                (self.config/'crowdsec-1key-appsec-docker-links.yaml').write_text('"/config/bouncer.conf": {container: abc, name: site, target: /etc/bouncer.conf}\n')
            p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { return 0; }
check_remote_firewall_status() { return 2; }
docker() { record docker "$@"; if [[ "$1" == ps ]]; then printf 'abc '''+image+''' site\n'; else return 1; fi; }
''')
            self.assertEqual(p.returncode, 1, p.stdout+p.stderr)
            self.assertIn('exec abc nginx -T', self.commands())
            self.assertNotIn('cscli', self.commands())

    def test_remote_legacy_id_only_docker_link_matches_running_container(self):
        self.roles('remote')
        container_id = 'a'*64
        for selector in (container_id, container_id[:12]):
            (self.config/'crowdsec-1key-appsec-docker-links.yaml').write_text('"/config/bouncer.conf": {container: '+selector+', target: /etc/bouncer.conf}\n')
            p = self.run_shell('main --status', overrides='''
remote_bouncer_status() { return 0; }
check_remote_firewall_status() { return 2; }
docker() {
 record docker "$@"
 case "$*" in
  'ps '*) printf "'''+container_id+''' custom/site:latest site\n" ;;
  'exec '*) printf 'http { }\n' ;;
  'inspect '*) printf '[]\n' ;;
 esac
}
request_audit_tool() { return 2; }
''')
            self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
            self.assertIn('exec '+container_id+' nginx -T', self.commands())

    def run_terminal(self, action, inputs, overrides=''):
        output = []
        def terminal_run(args, **kwargs):
            master, slave = pty.openpty()
            process = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave, env=kwargs['env'])
            os.close(slave)
            if inputs:
                os.write(master, inputs.encode())
            deadline = time.monotonic() + 5
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], .1)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output.append(chunk.decode())
                    elif process.poll() is not None:
                        break
                if process.poll() is None:
                    process.kill()
                code = process.wait()
            finally:
                os.close(master)
            return subprocess.CompletedProcess(args, code, ''.join(output), '')
        from unittest.mock import patch
        with patch('test_workflows.subprocess.run', terminal_run):
            return self.run_shell(action, overrides=overrides)

    def test_tty_first_choice_and_return_have_no_extra_pause(self):
        # Pipe tests cannot observe pause's isatty branch.
        p = self.run_terminal('show_main_menu', '2\n4\n3\n0\n0\n0\n', 'locked_operation() { "$@"; }')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertNotIn('按回车', p.stdout)
        path = self.base/'var/lib/crowdbastion/node-roles.json'
        self.assertEqual(json.loads(path.read_text())['roles'], ['relay'])
        self.assertEqual(self.commands(), '')

    def test_v2bx_nested_returns_and_invalid_choices_have_no_pause(self):
        self.roles('node')
        p = self.run_terminal('show_main_menu', '4\n4\n3\ninvalid\n0\n4\n0\n0\n0\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertNotIn('按回车', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_next_action_uses_relay_installer_under_lock_and_pauses_once(self):
        self.roles('relay')
        (self.config/'config.yaml').unlink()
        p = self.run_terminal('interactive_health_check', '1\n\n', '''
check_relay_status() { return 2; }
install_crowdsec_core() { record install-profile "$@"; }
locked_operation() { record lock "$@"; "$@"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout)
        self.assertIn('lock install_crowdsec_core relay', self.commands())
        self.assertIn('install-profile relay', self.commands())
        self.assertEqual(p.stdout.count('按回车'), 1)

    def test_cli_status_on_terminal_never_prompts_or_saves_preferences(self):
        p = self.run_terminal('main --status', '')
        self.assertEqual(p.returncode, 2, p.stdout)
        self.assertNotIn('请选择', p.stdout)
        self.assertFalse((self.base/'var/lib/crowdbastion/node-roles.json').exists())

    def test_combined_web_and_node_cover_both_checks(self):
        self.roles('web', 'node')
        p = self.run_shell('check_health_status', overrides='''
check_web_health_status() { printf 'web checked\n'; return 2; }
check_relay_status() { return 2; }
diagnose_v2bx() { printf 'node checked\n'; return 2; }
''')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)
        self.assertIn('web checked', p.stdout)
        self.assertIn('node checked', p.stdout)

    def test_unknown_journal_source_is_unverified_not_system_normal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'metrics'
            path.write_text(json.dumps({'acquisition': {'journalctl:_SYSTEMD_UNIT=nginx.service': {'reads': 10, 'parsed': 10}}}))
            output = io.StringIO()
            with redirect_stdout(output):
                result = maintenance.system_health_metrics(path)
            self.assertEqual(result, 2)
            self.assertNotIn('[正常]', output.getvalue())


class RemoteAudit(unittest.TestCase):
    def test_remote_firewall_audit_checks_bouncer_only(self):
        from test_relay_mode import RelayAudit
        fixture = RelayAudit()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.file.write_text('mode: nftables\nnftables: {ipv4: {enabled: true}, ipv6: {enabled: true}}\n')
        fixture.tool('nft', '{"nftables": []}')
        result = subprocess.run([sys.executable, str(ROOT/'lib/crowdsec_relay.py'), 'audit-remote', str(fixture.config)],
                                capture_output=True, text=True, env={**os.environ, 'PATH': str(fixture.bin)+':'+os.environ['PATH']})
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        trace = fixture.trace.read_text()
        self.assertIn('systemctl is-active --quiet crowdsec-firewall-bouncer', trace)
        self.assertNotIn('systemctl is-active --quiet crowdsec\n', trace)
        self.assertNotIn('cscli', trace)


class SystemMetrics(unittest.TestCase):
    def test_reads_without_system_parsing_are_abnormal(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'metrics'
            path.write_text(json.dumps({'acquisition': {'file:/var/log/auth.log': {'reads': 96, 'parsed': 0, 'unparsed': 96}}}))
            output = io.StringIO()
            with redirect_stdout(output):
                result = maintenance.system_health_metrics(path)
            self.assertEqual(result, 1)
            self.assertNotIn('HTTP', output.getvalue())

    def test_parsed_system_logs_do_not_prove_attack_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'metrics'
            path.write_text(json.dumps({'acquisition': {'journalctl:_SYSTEMD_UNIT=ssh.service': {'reads': 96, 'parsed': 96, 'unparsed': 0}}}))
            output = io.StringIO()
            with redirect_stdout(output):
                result = maintenance.system_health_metrics(path)
            self.assertEqual(result, 2)
            self.assertIn('96', output.getvalue())
            self.assertIn('尚未验证', output.getvalue())
