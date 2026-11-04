"""Regression cases established by independent reviews of the smart flow."""
import copy
import contextlib
import io
import json
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import test_user_flow
import workflow_fixture
import crowdbastion_flow as flow
import crowdbastion_flow_cli as cli


def web_facts():
    value = test_user_flow.snapshot()
    value['inventory']['appsec'] = True
    value['checks'].update(appsec='ok', web_rules='ok')
    value['component_fingerprints'] = {'core': 'a'*64, 'firewall': 'b'*64, 'appsec': 'c'*64, 'proxy': 'd'*64}
    value['targets'] = [dict(id='host:nginx', label='nginx', runtime='nginx', network='host',
                             owned=True, connected=True, transport=True, config_hash='e'*64,
                             integration_hash='2'*64, realip='verified', request_verification='pending', web_logs='ok',
                             server_names=['example.test'])]
    return value


class ReviewedTasks(unittest.TestCase):
    def state(self, online=True):
        state = flow.new_state(['web'], online_requests=online)
        state['selected_targets'] = ['host:nginx']
        return state

    def test_acceptance_summary_reuses_precomputed_fingerprint(self):
        import crowdbastion_ux as ux
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/'acceptance.json'
            record = dict(version=1, code=0, time=123.0, fingerprint='a'*64,
                          scope=dict(target='203.0.113.8', port=443, protocol='TCP', family='ip', hook='input'))
            path.write_text(json.dumps(record)); path.chmod(0o600)
            with patch.object(ux, 'tree_fingerprint', side_effect=AssertionError('unexpected second tree traversal')):
                summary = ux.acceptance_summary(path, root, now=124, fingerprint='a'*64)
                stale = ux.acceptance_summary(path, root, now=124, fingerprint='b'*64)
            self.assertIn('24 小时内的历史记录', summary)
            self.assertIn('检测到配置变化', stale)

    def test_ssh_logs_cannot_satisfy_selected_website_log_goal(self):
        facts = web_facts()
        facts['targets'][0]['web_logs'] = 'missing'
        result = flow.report(facts, self.state(False))
        self.assertEqual(result['recommended']['action'], 'configure_web_logs')
        self.assertNotIn('运行检查已完成', result['conclusion'])

    def test_missing_web_rules_require_connection_even_when_logs_parse(self):
        facts = web_facts()
        facts['checks']['web_rules'] = 'missing'
        self.assertEqual(flow.report(facts, self.state(False))['recommended']['action'], 'configure_web_logs')

    def test_log_only_website_requires_source_evidence_before_logs_and_acceptance(self):
        facts = web_facts()
        facts['targets'][0].update(owned=False, connected=False, realip='unknown')
        facts['acceptance'] = {'valid': True}
        result = flow.report(facts, self.state(False))
        self.assertEqual(result['recommended']['action'], 'diagnose_log_realip')
        self.assertEqual(result['recommended']['state'], 'needs_input')
        tasks = {t['id']: t for t in result['tasks']}
        self.assertNotEqual(tasks['web.logs:host:nginx']['state'], 'done')
        self.assertEqual(tasks['entry.verify']['state'], 'blocked')
        self.assertNotIn('运行检查已完成', result['conclusion'])
        self.assertFalse(any(t['action'] in ('configure_appsec', 'connect_website') for t in tasks.values()))

    def test_log_only_source_uncertainty_blocks_new_log_acquisition(self):
        facts = web_facts()
        facts['targets'][0].update(realip='unknown', web_logs='missing')
        task = next(t for t in flow.report(facts, self.state(False))['tasks'] if t['id'] == 'web.logs:host:nginx')
        self.assertEqual(task['state'], 'blocked')

    def test_online_mode_also_requires_source_before_new_log_acquisition(self):
        facts = web_facts()
        facts['targets'][0].update(owned=False, connected=False, realip='unknown', web_logs='missing')
        tasks = {t['id']: t for t in flow.report(facts, self.state(True))['tasks']}
        self.assertEqual(tasks['web.logs:host:nginx']['state'], 'blocked')
        self.assertEqual(tasks['web.connect:host:nginx']['state'], 'ready')

    def test_target_guard_rejects_changed_or_missing_integration_settings(self):
        state = self.state()
        facts = web_facts()
        facts['targets'][0]['realip'] = 'unknown'
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flow.save_state(root/'user-flow.json', state)
            facts['intent_token'] = flow.intent_fingerprint(state)
            path = root/'snapshot.json'
            path.write_text(json.dumps(facts))
            with patch.object(cli, 'discover', return_value=facts):
                self.assertEqual(cli.main(['guard', str(path), str(root/'etc/crowdsec'), str(root), 'host:nginx', 'verify_realip']), 0)
            for digest in ('3'*64, None):
                with self.subTest(integration=digest):
                    fresh = copy.deepcopy(facts)
                    fresh['targets'][0]['integration_hash'] = digest
                    with patch.object(cli, 'discover', return_value=fresh), self.assertRaises(ValueError):
                        cli.main(['guard', str(path), str(root/'etc/crowdsec'), str(root), 'host:nginx', 'verify_realip'])

    def test_remote_maintenance_never_schedules_local_web_mutations(self):
        facts = web_facts()
        facts['inventory']['remote'] = True
        facts['checks']['remote'] = 'ok'
        facts['checks']['appsec'] = 'missing'
        state = self.state()
        state['deployment_scope'] = {'choice': 'remote', 'fingerprint': facts['fingerprint']}
        tasks = flow.report(facts, state)['tasks']
        self.assertFalse(any(t['action'] in ('configure_appsec', 'connect_website', 'configure_web_logs') and t['state'] != 'blocked' for t in tasks))

    def test_empty_website_selection_does_not_block_independent_install(self):
        result = flow.report(test_user_flow.snapshot(False), flow.new_state(['web'], online_requests=True))
        self.assertEqual(result['recommended']['action'], 'install_core_web')

    def test_existing_proxy_services_are_diagnosed_regardless_saved_goal(self):
        for key, action in (('v2bx_service', 'v2bx_diagnose'), ('observer', 'observer_diagnose')):
            facts = test_user_flow.snapshot()
            facts['inventory']['v2bx' if key == 'v2bx_service' else 'observer'] = True
            facts['checks'][key] = 'fault'
            self.assertEqual(flow.report(facts, flow.new_state(['system']))['recommended']['action'], action)

    def test_unrelated_check_and_other_site_do_not_reopen_deferred_web_test(self):
        facts = web_facts()
        state = self.state()
        task = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'web.verify:host:nginx')
        state['deferred'][task['id']] = dict(fingerprint=task['evidence_fingerprint'], reason='later', at=123.0)
        facts['checks']['webui'] = 'ok'
        facts['fingerprint'] = 'f'*64
        facts['targets'].append(dict(facts['targets'][0], id='host:openresty', config_hash='0'*64))
        task = next(t for t in flow.build_tasks(facts, state) if t['id'] == task['id'])
        self.assertEqual(task['state'], 'deferred')
        facts['targets'][0]['config_hash'] = '1'*64
        task = next(t for t in flow.build_tasks(facts, state) if t['id'] == task['id'])
        self.assertNotEqual(task['state'], 'deferred')

    def test_auxiliary_test_completion_does_not_claim_actual_protection(self):
        facts = web_facts()
        state = self.state()
        task = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'web.verify:host:nginx')
        state['outcomes'][task['id']] = dict(fingerprint=task['evidence_fingerprint'], state='observed', at=123.0)
        result = flow.report(facts, state)
        self.assertEqual(next(t for t in result['tasks'] if t['id'] == task['id'])['state'], 'done')
        self.assertIn('待验证', result['conclusion'])

    def test_proxy_guidance_can_complete_without_claiming_runtime_checks_passed(self):
        facts = test_user_flow.snapshot(False)
        state = flow.new_state(['proxy'], program='other')
        task = flow.report(facts, state)['recommended']
        state['outcomes'][task['id']] = dict(fingerprint=task['evidence_fingerprint'], state='observed', at=123.0)
        result = flow.report(facts, state)
        self.assertEqual(next(t for t in result['tasks'] if t['id'] == task['id'])['state'], 'done')
        self.assertNotIn('运行检查已完成', result['conclusion'])

    def test_malformed_outcome_is_validation_error_and_home_keeps_working(self):
        state = flow.new_state(['system'])
        state['outcomes']['core.install'] = dict(state=[], fingerprint='a'*64, at=0)
        with self.assertRaises(ValueError):
            flow.validate_state(state)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'user-flow.json'
            path.write_text(json.dumps(state))
            path.chmod(0o600)
            with contextlib.redirect_stdout(io.StringIO()):
                result, loaded = cli.current(test_user_flow.snapshot(), path)
            self.assertIsNone(loaded)
            self.assertTrue(result['state_issue'])

    def test_huge_json_timestamp_is_rejected_without_crashing_home(self):
        state = flow.new_state(['system'])
        state['outcomes']['core.install'] = dict(state='failed', fingerprint='a'*64, at=10**400)
        with self.assertRaises(ValueError):
            flow.validate_state(state)

    def test_deferring_conflict_cannot_enable_implicit_remote_migration(self):
        facts = test_user_flow.snapshot()
        state = flow.new_state(['remote'])
        conflict = flow.report(facts, state)['recommended']
        state['deferred'][conflict['id']] = dict(fingerprint=conflict['evidence_fingerprint'], reason='later', at=0)
        remote = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'remote.connect')
        self.assertEqual(remote['state'], 'blocked')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state_path = root/'user-flow.json'
            flow.save_state(state_path, state)
            facts['intent_token'] = flow.intent_fingerprint(state)
            snapshot = root/'snapshot.json'
            snapshot.write_text(json.dumps(facts))
            with patch.object(cli, 'discover', return_value=facts), self.assertRaises(ValueError):
                cli.main(['guard', str(snapshot), str(root/'etc/crowdsec'), str(root), '-', 'connect_remote'])

    def test_pending_change_cannot_be_deferred_to_enable_new_install(self):
        facts = test_user_flow.snapshot(False)
        facts['pending'] = [dict(kind='network', state='staged', deadline=123)]
        state = flow.new_state(['system'])
        pending = flow.report(facts, state)['recommended']
        state['deferred'][pending['id']] = dict(fingerprint=pending['evidence_fingerprint'], reason='later', at=0)
        install = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'core.install')
        self.assertEqual(install['state'], 'blocked')

    def test_incomplete_transaction_scan_blocks_new_install_even_if_deferred(self):
        facts = test_user_flow.snapshot(False)
        facts['pending_scan_complete'] = False
        state = flow.new_state(['system'])
        result = flow.report(facts, state)
        self.assertEqual(result['recommended']['action'], 'inspect')
        pending = result['recommended']
        state['deferred'][pending['id']] = dict(fingerprint=pending['evidence_fingerprint'], reason='later', at=0)
        install = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'core.install')
        self.assertEqual(install['state'], 'blocked')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            flow.save_state(root/'user-flow.json', state)
            facts['intent_token'] = flow.intent_fingerprint(state)
            snapshot = root/'snapshot.json'
            snapshot.write_text(json.dumps(facts))
            with patch.object(cli, 'discover', return_value=facts), self.assertRaises(ValueError):
                cli.main(['guard', str(snapshot), str(root/'etc/crowdsec'), str(root), '-', 'install_core_system'])

    def test_unknown_existing_appsec_needs_diagnosis_before_engine_changes(self):
        facts = web_facts()
        facts['inventory']['appsec'] = None
        facts['checks']['appsec'] = 'unknown'
        result = flow.report(facts, self.state())
        self.assertEqual(result['recommended']['action'], 'inspect')
        self.assertEqual(next(t for t in result['tasks'] if t['id'] == 'web.engine')['state'], 'blocked')


class ReviewedShell(workflow_fixture.WorkflowFixtureMixin, unittest.TestCase):
    def setup_flow(self, facts, state):
        path = self.base/'var/lib/crowdbastion/user-flow.json'
        flow.save_state(path, state)
        facts['intent_token'] = flow.intent_fingerprint(state)
        snapshot = self.base/'flow-snapshot.json'
        snapshot.write_text(json.dumps(facts))
        work = self.base/'flow-session'
        work.mkdir(mode=0o700)
        return path, snapshot, work

    def test_explicit_local_verification_overrides_remote_marker(self):
        b = self.config/'bouncers'
        b.mkdir()
        (b/'crowdsec-firewall-bouncer.yaml.remote.json').write_text('{}')
        result = self.run_shell('verify_relay local', overrides='''
python3() { record verifier "$@"; }
load_node_roles() { NODE_ROLES=remote; }
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('--remote', self.commands())

    def test_flow_web_core_installs_only_system_base_before_site_selection(self):
        snapshot = self.base/'snapshot.json'
        snapshot.write_text('{}')
        result = self.run_shell('flow_install_core web '+shlex.quote(str(snapshot)), overrides='''
flow_tool() { record flow-guard "$@"; }
install_crowdsec_core() {
 case "$1" in web|relay) ;; *) return 23 ;; esac
 record core-install "$@"
 [[ "$3" != prepare ]] || printf 'prepared\\n' > "$2"
}
''')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        lines = self.commands().splitlines()
        installs = [line.split() for line in lines if line.startswith('core-install ')]
        self.assertEqual([(row[1], row[3]) for row in installs], [('relay', 'prepare'), ('relay', 'apply')])
        self.assertTrue(any(line.startswith('flow-guard guard ') and line.endswith(' - install_core_web') for line in lines))

    def test_log_source_diagnosis_stays_scoped_and_does_not_record_completion(self):
        facts = web_facts()
        facts['targets'][0].update(owned=False, connected=False, realip='unknown')
        state = flow.new_state(['web'], online_requests=False)
        state['selected_targets'] = ['host:nginx']
        path, snapshot, work = self.setup_flow(facts, state)
        before = path.read_bytes()
        (work/'snapshot').write_bytes(snapshot.read_bytes())
        result = self.run_shell('flow_next '+shlex.quote(str(work)), '1\n0\n', overrides='''
flow_collect() { cp SNAPSHOT "$1"; }
repair_cloudflare_real_ip() { record source-diagnosis "$CROWDBASTION_FLOW_TARGET" "$@"; }
'''.replace('SNAPSHOT', shlex.quote(str(snapshot))))
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('source-diagnosis host:nginx diagnose host', self.commands())
        self.assertEqual(path.read_bytes(), before)
        self.assertIn('待确认', result.stdout)

    def test_proxy_cancel_is_not_an_observation(self):
        output = self.base/'observed'
        result = self.run_shell('guided_protocol_status '+shlex.quote(str(output)), '0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(output.exists())

    def test_completed_proxy_guide_records_only_information(self):
        path, snapshot, work = self.setup_flow(test_user_flow.snapshot(False), flow.new_state(['proxy'], program='other'))
        result = self.run_shell('flow_dispatch inspect_proxy - '+shlex.quote(str(snapshot))+' '+shlex.quote(str(work)),
                                '1\n3\n1\n2\n1\n0\n')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(flow.load_state(path)['outcomes']['proxy.inspect']['state'], 'observed')
        self.assertNotIn('已验证实际运行', result.stdout)

    def test_successful_website_auxiliary_test_records_scoped_evidence(self):
        state = flow.new_state(['web'], online_requests=True)
        state['selected_targets'] = ['host:nginx']
        path, snapshot, work = self.setup_flow(web_facts(), state)
        overrides = '''
python3() {
 if [[ "$1" == *crowdsec_detection_diagnose.py && "$2" == metrics-url ]]; then
  printf 'http://127.0.0.1:6060/metrics'
 else command python3 "$@"; fi
}
curl() {
 if [[ "$*" == *http_code* ]]; then printf 403
 else
  local n=0; [[ ! -f "$TRACE.metrics" ]] || read -r n < "$TRACE.metrics"
  n=$((n+1)); printf '%s\\n' "$n" > "$TRACE.metrics"
  printf '# HELP cs_appsec_reqs_total total\\ncs_appsec_reqs_total %s\\ncs_appsec_block_total %s\\ncs_appsec_rule_hits{rule_name="crowdsecurity/vpatch-env-access"} %s\\n' "$n" "$n" "$n"
 fi
}
'''
        result = self.run_shell('flow_dispatch verify_website host:nginx '+shlex.quote(str(snapshot))+' '+shlex.quote(str(work)),
                                'https://example.test\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(flow.load_state(path)['outcomes']['web.verify:host:nginx']['state'], 'observed')
        self.assertIn('辅助证据', result.stdout+result.stderr)

    def test_website_auxiliary_request_cannot_use_another_instances_hostname(self):
        state = flow.new_state(['web'], online_requests=True)
        state['selected_targets'] = ['host:nginx']
        _, snapshot, work = self.setup_flow(web_facts(), state)
        result = self.run_shell('flow_dispatch verify_website host:nginx '+shlex.quote(str(snapshot))+' '+shlex.quote(str(work)),
                                'https://elsewhere.test\ny\n', 'curl() { record unexpected-request; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('unexpected-request', self.commands())

    def test_selected_host_log_repair_does_not_collect_other_runtime_or_presets(self):
        first = self.base/'site-a/access.log'
        other = self.base/'site-b/access.log'
        preset = self.base/'var/log/nginx/access.log'
        for path in (first, other, preset):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        overrides = '''
nginx() { printf 'http { access_log %s; }\\n' FIRST; }
openresty() { printf 'http { access_log %s; }\\n' OTHER; }
'''.replace('FIRST', shlex.quote(str(first))).replace('OTHER', shlex.quote(str(other)))
        result = self.run_shell('''
CROWDBASTION_FLOW_TARGET=host:nginx
prepare_log_repair || exit $?
cat "$LOG_REPAIR_STAGE/repaired.yaml"
cleanup_log_repair
''', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn(str(first), result.stdout)
        self.assertNotIn(str(other), result.stdout)
        self.assertNotIn(str(preset), result.stdout)

    def custom_docker(self, log, readable=True):
        mounts = json.dumps([dict(Type='bind', Source=str(log.parent), Destination='/var/log/nginx')])
        return '''
docker() {
 record docker "$@"
 case "$1" in
 ps) if [[ "$*" == *'.Names'* ]]; then
       printf 'abcdef123456 mycompany/edge:latest nginx-edge\\n987654321abc nginx:alpine other\\n'
     else printf 'abcdef123456 mycompany/edge:latest\\n987654321abc nginx:alpine\\n'; fi;;
 inspect) printf '%s\\n' MOUNTS;;
 exec) [[ "$2" == abcdef123456 && "$3 $4" == 'nginx -T' ]] || return 1
       READABLE
       printf 'http { access_log /var/log/nginx/chosen.log; }\\n';;
 esac
}
'''.replace('MOUNTS', shlex.quote(mounts)).replace('READABLE', ':' if readable else 'return 1')

    def test_selected_custom_image_log_repair_uses_effective_config(self):
        log = self.base/'custom-logs/chosen.log'
        log.parent.mkdir(); log.touch()
        result = self.run_shell('''
CROWDBASTION_FLOW_TARGET=docker:abcdef123456
prepare_log_repair || exit $?
cat "$LOG_REPAIR_STAGE/repaired.yaml"
cleanup_log_repair
''', overrides=self.custom_docker(log))
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn(str(log), result.stdout)
        self.assertNotIn('exec 987654321abc', self.commands())

    def test_selected_custom_image_is_only_appsec_candidate_after_runtime_check(self):
        log = self.base/'chosen.log'
        result = self.run_shell('CROWDBASTION_FLOW_TARGET=docker:abcdef123456 appsec_containers',
                                overrides=self.custom_docker(log))
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(result.stdout.strip(), 'abcdef123456 mycompany/edge:latest nginx-edge')
        self.assertIn('exec abcdef123456 nginx -T', self.commands())

    def test_selected_custom_image_with_unreadable_runtime_fails_explicitly(self):
        for action in ('prepare_log_repair', 'appsec_containers'):
            with self.subTest(action=action):
                result = self.run_shell('CROWDBASTION_FLOW_TARGET=docker:abcdef123456 '+action,
                                        overrides=self.custom_docker(self.base/'chosen.log', False))
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_guarded_realip_failure_is_not_swallowed_by_scope_selection(self):
        result = self.run_shell('MAINTENANCE_LOCK_HELD=true flow_guarded_legacy ignored verify_realip host:nginx verify', overrides='''
flow_tool() { return 0; }
verify_real_ip_request() { return 23; }
''')
        self.assertEqual(result.returncode, 23, result.stdout+result.stderr)

    def test_cancelled_auxiliary_test_does_not_leave_running_state(self):
        state = flow.new_state(['web'], online_requests=True)
        state['selected_targets'] = ['host:nginx']
        facts = web_facts()
        entry = next(t for t in flow.build_tasks(facts, state) if t['id'] == 'entry.verify')
        state['deferred'][entry['id']] = dict(fingerprint=entry['evidence_fingerprint'], reason='later', at=0)
        path, snapshot, work = self.setup_flow(facts, state)
        (work/'snapshot').write_bytes(snapshot.read_bytes())
        result = self.run_shell('flow_next '+shlex.quote(str(work)), '1\n\n0\n',
                                'flow_collect() { cp '+shlex.quote(str(snapshot))+' "$1"; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(flow.load_state(path)['outcomes']['web.verify:host:nginx']['state'], 'cancelled')

    def test_selected_docker_logs_do_not_expand_shared_mount_presets(self):
        import crowdsec_config as config
        import yaml
        logs = self.base/'shared-logs'
        logs.mkdir()
        chosen, other = logs/'site-a.log', logs/'access.log'
        chosen.touch(); other.touch()
        presets, mounts, discovered, output = [self.base/n for n in ('presets.yaml','mounts.tsv','discovered.jsonl','planned.yaml')]
        presets.write_text('')
        mounts.write_text('nginx\t'+json.dumps([dict(Type='bind', Source=str(logs), Destination='/var/log/nginx')])+'\n')
        discovered.write_text(json.dumps(dict(path=str(chosen),kind='nginx'))+'\n')
        with contextlib.redirect_stdout(io.StringIO()):
            config.stage_log_repair(self.config,presets,mounts,output,discovered,'selected')
        documents=list(yaml.safe_load_all(output.read_text()))
        paths=[p for doc in documents for p in doc.get('filenames',[])]
        self.assertIn(str(chosen),paths)
        self.assertNotIn(str(other),paths)

    def test_new_flow_service_start_cannot_bypass_unconfirmed_scope(self):
        facts = test_user_flow.snapshot()
        facts['inventory']['remote'] = True
        facts['checks']['core'] = 'fault'
        state = flow.new_state(['system'])
        conflict = flow.report(facts,state)['recommended']
        state['deferred'][conflict['id']] = dict(fingerprint=conflict['evidence_fingerprint'],reason='later',at=0)
        _, snapshot, _ = self.setup_flow(facts,state)
        b=self.config/'bouncers'; b.mkdir()
        (b/'crowdsec-firewall-bouncer.yaml.remote.json').write_text('{}')
        result=self.run_shell('flow_diagnose core '+shlex.quote(str(snapshot)),'y\n',
                              'health_service_state() { printf inactive; }')
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('systemctl start',self.commands())

    def test_failed_collection_retains_previous_snapshot(self):
        snapshot=self.base/'snapshot'
        before='{"version":1,"previous":true}\n'
        snapshot.write_text(before)
        result=self.run_shell('flow_collect '+shlex.quote(str(snapshot)),
                              overrides='flow_tool() { printf partial; return 1; }')
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(snapshot.read_text(),before)

    def test_selected_docker_reuse_does_not_ask_for_a_different_container(self):
        result=self.run_shell('CROWDBASTION_FLOW_TARGET=docker:abcdef123456abcdef123456abcdef123456abcdef123456abcdef123456abcdef link_docker_appsec',overrides='''
appsec_containers() { printf 'abcdef123456 nginx:alpine chosen\\n'; }
docker() { record docker "$@"; return 1; }
''')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('docker inspect --format {{.HostConfig.NetworkMode}} abcdef123456',self.commands())

    def test_dual_deployment_pending_checks_cannot_erase_an_earlier_failure(self):
        facts=test_user_flow.snapshot()
        facts['inventory']['remote']=True
        state=flow.new_state(['system'])
        state['deployment_scope']={'choice':'local','fingerprint':facts['fingerprint']}
        _, snapshot, work=self.setup_flow(facts,state)
        b=self.config/'bouncers'; b.mkdir()
        (b/'crowdsec-firewall-bouncer.yaml.remote.json').write_text('{}')
        overrides='flow_collect() { cp '+shlex.quote(str(snapshot))+' "$1"; }\n'+'''
check_health_status_raw() { health_expect core; health_event core ok; return 1; }
remote_bouncer_status() { return 2; }
check_remote_firewall_status() { return 2; }
'''
        result=self.run_shell('flow_full_check '+shlex.quote(str(snapshot))+' '+shlex.quote(str(work)),overrides=overrides)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(json.loads(snapshot.read_text())['checks'].get('check'),'unknown')


if __name__ == '__main__':
    unittest.main()
