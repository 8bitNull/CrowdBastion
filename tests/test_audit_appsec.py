"""Regression evidence for effective AppSec configuration and request verdicts."""
import importlib.util
import unittest
from pathlib import Path
import test_workflows

ROOT = Path(__file__).resolve().parents[1]

class AppSecAudit(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_override_refuses_host_link_before_mutation(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=\n')
        Path(str(file)+'.local').write_text(' APPSEC_URL = http://other:7422\n')
        result = self.run_shell('setup_appsec', '1\n', 'nginx() { return 0; }')
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(file.read_text(), 'APPSEC_URL=\n')
        self.assertIn('.local', result.stderr)

    def helper(self):
        path = ROOT/'lib/crowdsec_appsec.py'
        self.assertTrue(path.exists(), 'AppSec evidence helper is missing')
        spec = importlib.util.spec_from_file_location('appsec_audit', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_http200_unchanged_is_failed(self):
        helper = self.helper()
        self.assertEqual(helper.verdict('200', {'processed':0,'blocked':0,'rules':0}, {'processed':0,'blocked':0,'rules':0}), 'failed')

    def test_unrelated_403_is_inconclusive(self):
        helper = self.helper()
        self.assertEqual(helper.verdict('403', {'processed':0,'blocked':0,'rules':0}, {'processed':0,'blocked':0,'rules':0}), 'inconclusive')

    def test_metrics_and_rules_are_only_supporting_evidence(self):
        helper = self.helper()
        self.assertEqual(helper.verdict('403', {'processed':0,'blocked':0,'rules':0}, {'processed':1,'blocked':1,'rules':1}), 'passed')

    def test_counter_reset_is_inconclusive(self):
        helper = self.helper()
        self.assertEqual(helper.verdict('403', {'processed':9,'blocked':9,'rules':9}, {'processed':1,'blocked':1,'rules':1}), 'inconclusive')

    def test_policy_changes_only_explicit_choices(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text('API_KEY=secret\nAPPSEC_URL=http://127.0.0.1:7422\n')
        result = self.run_shell(f'configure_appsec_policy "{file}" true deny', 'y\n', 'openresty() { return 0; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('APPSEC_DROP_UNREADABLE_BODY=true', file.read_text())
        self.assertIn('APPSEC_FAILURE_ACTION=deny', file.read_text())
        self.assertIn('API_KEY=secret', file.read_text())

    def test_first_host_install_refuses_override_even_without_main_file(self):
        file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        file.parent.mkdir()
        Path(str(file)+'.local').write_text('APPSEC_URL=http://other:7422\n')
        result = self.run_shell('install_host_web_bouncer nginx', overrides='nginx() { return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('.local', result.stderr)
        self.assertNotIn('apt-get', self.commands())

    def test_container_unmapped_local_refuses_link(self):
        stub = test_workflows.Workflows.appsec_docker_stub(self, mounted=True)
        stub = stub.replace('exec) case "$4" in', 'exec) if [[ "$3" == test ]]; then return 1; fi; case "$4" in')
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        before = file.read_text()
        result = self.run_shell('link_docker_appsec', 'web123\ny\n', stub)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(file.read_text(), before)
        self.assertIn('.local', result.stderr)
        self.assertNotIn('nginx -s reload', self.commands())

    def test_policy_failed_reload_restores_original(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        original = 'API_KEY=secret\nAPPSEC_URL=http://127.0.0.1:7422\n'
        file.write_text(original)
        result = self.run_shell(f'configure_appsec_policy "{file}" true deny', 'y\n', 'openresty() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(file.read_text(), original)

    def test_official_prometheus_counters_are_read(self):
        helper = self.helper()
        self.assertEqual(helper.counters('cs_appsec_reqs_total{source="appsec"} 2\ncs_appsec_block_total{source="appsec"} 1\ncs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-env-access"} 1\n'), {'processed':2,'blocked':1,'rules':1})

    def test_http200_workflow_fails_instead_of_success(self):
        overrides = '''curl() {
 record curl "$@"
 if [[ "$*" == *http_code* ]]; then printf 200; else printf '# HELP cs_appsec_reqs_total requests\n'; fi
}'''
        # Enable readable metrics without making a live network request.
        text = (self.config/'config.yaml').read_text().replace('enabled: false', 'enabled: true')
        (self.config/'config.yaml').write_text(text)
        result = self.run_shell('verify_appsec', 'https://example.com\ny\n', overrides)
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('failed / 失败', result.stderr)
        self.assertIn('crowdsec_1key_probe=', self.commands())

    def test_403_and_expected_rule_increments_report_supporting_pass(self):
        (self.config/'config.yaml').write_text((self.config/'config.yaml').read_text().replace('enabled: false', 'enabled: true'))
        overrides = '''curl() {
 record curl "$@"
 if [[ "$*" == *http_code* ]]; then touch "$CS_DIR/probed"; printf 403
 elif [[ -f "$CS_DIR/probed" ]]; then
 printf 'cs_appsec_reqs_total{source="appsec"} 1\ncs_appsec_block_total{source="appsec"} 1\ncs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-env-access"} 1\n'
 else printf '# HELP cs_appsec_reqs_total requests\n'; fi
}'''
        result = self.run_shell('verify_appsec', 'https://example.com\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('passed / 通过（辅助证据）', result.stdout)
        self.assertIn('不能单独证明', result.stderr)

    def test_unrelated_rule_increment_does_not_pass(self):
        helper = self.helper()
        after = helper.counters('cs_appsec_reqs_total{source="appsec"} 1\ncs_appsec_block_total{source="appsec"} 1\ncs_appsec_rule_hits{rule_name="unrelated/rule"} 1\n')
        self.assertEqual(helper.verdict('403', {'processed':0,'blocked':0,'rules':0}, after), 'inconclusive')

    def test_duplicate_appsec_key_refuses_mutation(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=\nAPPSEC_URL=http://other:7422\n')
        result = self.run_shell(f'appsec_guard_config "{file}"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('重复', result.stderr)

    def test_commented_empty_local_is_preserved(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=\n')
        local = Path(str(file)+'.local')
        local.write_text('# administrator comments\n')
        result = self.run_shell(f'appsec_guard_config "{file}"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(local.read_text(), '# administrator comments\n')

    def test_nonroot_query_fragment_and_userinfo_rejected_before_probe(self):
        for target in ('https://example.com/?x=1', 'https://example.com/#part', 'https://user:secret@example.com', 'https://example.com/path'):
            with self.subTest(target=target):
                self.trace.write_text('')
                result = self.run_shell('verify_appsec', target+'\ny\n')
                self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
                self.assertNotIn('curl ', self.commands())

    def test_noncanonical_appsec_assignment_refused_before_link(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text(' APPSEC_URL = http://other:7422\n')
        result = self.run_shell(f'appsec_guard_config "{file}"')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('APPSEC_URL', result.stderr)

    def test_docker_policy_preserves_url_and_updates_explicit_choices(self):
        stub = test_workflows.Workflows.appsec_docker_stub(self, mounted=True)
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        result = self.run_shell('configure_appsec_policy docker true deny web123', 'y\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('APPSEC_URL=http://old.example:7422', file.read_text())
        self.assertIn('APPSEC_DROP_UNREADABLE_BODY=true', file.read_text())
        self.assertIn('APPSEC_FAILURE_ACTION=deny', file.read_text())
        self.assertIn('docker exec web123 nginx -s reload', self.commands())

    def test_docker_policy_reload_failure_restores_original(self):
        stub = test_workflows.Workflows.appsec_docker_stub(self, mounted=True, reload_succeeds=False)
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        original = file.read_text()
        result = self.run_shell('configure_appsec_policy docker true deny web123', 'y\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(file.read_text(), original)

    def test_policy_record_updates_only_config_digest(self):
        import hashlib
        import json
        file = self.config/'assets/bouncer.conf'
        file.parent.mkdir()
        file.write_text('APPSEC_URL=http://old:7422\nAPPSEC_FAILURE_ACTION=deny\n')
        state = self.config/'installs.json'
        original = {'web': {'host_assets':str(file.parent), 'resource_hashes':{'bouncer.conf':'old', 'access.lua':'unchanged'}, 'account':'keep'}}
        state.write_text(json.dumps(original))
        result = self.run_shell(f'appsec_audit_tool record-policy "{state}" web "{file}"')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        actual = json.loads(state.read_text())
        self.assertEqual(actual['web']['account'], 'keep')
        self.assertEqual(actual['web']['resource_hashes']['access.lua'], 'unchanged')
        self.assertEqual(actual['web']['resource_hashes']['bouncer.conf'], hashlib.sha256(file.read_text().replace('APPSEC_URL=http://old:7422', 'APPSEC_URL=').encode()).hexdigest())


class NativePolicyRecord(unittest.TestCase):
    def test_active_appsec_url_policy_remains_removable(self):
        import subprocess
        import test_web_install
        fixture = test_web_install.WebInstall()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        plan = fixture.plan()
        stage = fixture.stage(plan)
        state = fixture.root/'native.json'
        fixture.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        config = Path(plan['host_assets'])/'bouncer.conf'
        config.write_text(config.read_text().replace('APPSEC_URL=\n', 'APPSEC_URL=http://127.0.0.1:7422\n')+'APPSEC_FAILURE_ACTION=deny\n')
        result = subprocess.run(['python3', str(ROOT/'lib/crowdsec_appsec.py'), 'record-policy', str(state), 'openresty', str(config)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        try:
            entry = fixture.web.check_install(state, 'openresty', fixture.mounts)
        except ValueError as exc:
            self.fail('Policy mutation incorrectly breaks native ownership check: '+str(exc))
        self.assertEqual(entry['status'], 'installed')
