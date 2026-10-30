"""Cross-feature and transaction regressions from the 2026-10-30 review."""
import json
from pathlib import Path
import unittest

import test_native_workflows
import test_notify
import test_workflows


class NotificationTransactions(unittest.TestCase):
    setUp = test_notify.NotificationInstallation.setUp
    run_shell = test_notify.NotificationInstallation.run_shell
    commands = test_notify.NotificationInstallation.commands
    setup_telegram = test_notify.NotificationInstallation.setup_telegram
    enable = test_notify.NotificationInstallation.enable
    OVERRIDES = test_notify.NotificationInstallation.OVERRIDES

    def test_failed_validation_stops_and_disables_new_worker_before_unit_removal(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        overrides = '''
systemctl() {
 record systemctl "$@"
 case "$*" in
  show*) echo 'LoadState=not-found';;
  'enable crowdbastion-notify.service') ln -s "$NOTIFY_UNIT" "$NOTIFY_UNIT.enabled";;
  'restart crowdbastion-notify.service') touch "$NOTIFY_UNIT.active";;
  'stop crowdbastion-notify.service') [[ -f "$NOTIFY_UNIT" ]] || return 1; rm -f "$NOTIFY_UNIT.active";;
  'disable crowdbastion-notify.service') [[ -f "$NOTIFY_UNIT" ]] || return 1; rm -f "$NOTIFY_UNIT.enabled";;
 esac
 return 0
}
crowdsec() { return 1; }
'''
        result = self.enable(overrides)
        self.assertNotEqual(result.returncode, 0)
        unit = self.base/'etc/systemd/system/crowdbastion-notify.service'
        self.assertFalse(unit.exists())
        self.assertFalse(Path(str(unit)+'.active').exists())
        self.assertFalse(Path(str(unit)+'.enabled').is_symlink())
        self.assertEqual(notification.read_bytes(), original)
        self.assertNotIn('回滚不完整', result.stderr)

    def test_unstoppable_worker_keeps_unit_and_code_for_manual_recovery(self):
        self.setup_telegram()
        overrides = self.OVERRIDES+'''
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() {
 if [[ "$*" == 'stop crowdbastion-notify.service' ]]; then return 1; fi
 systemctl_base "$@"
}
crowdsec() { return 1; }
'''
        result = self.enable(overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.base/'etc/systemd/system/crowdbastion-notify.service').exists())
        self.assertTrue((self.base/'usr/local/lib/crowdbastion-notify/crowdsec_notify.py').exists())
        self.assertIn('无法停止', result.stderr)
        self.assertTrue(list((self.base/'var/backups/crowdsec-1key').glob('change.*')))

    def test_failed_disable_keeps_unit_for_enablement_recovery(self):
        self.setup_telegram()
        overrides = self.OVERRIDES+'''
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() {
 if [[ "$*" == 'disable crowdbastion-notify.service' ]]; then return 1; fi
 systemctl_base "$@"
}
crowdsec() { return 1; }
'''
        result = self.enable(overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.base/'etc/systemd/system/crowdbastion-notify.service').exists())
        self.assertTrue((self.config/'crowdbastion-notify.json').exists())
        self.assertIn('无法取消启用', result.stderr)

    def test_term_after_prepare_restores_direct_route(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        overrides = self.OVERRIDES+'''
notify_tool() {
 python3 "$SCRIPT_DIR/lib/crowdsec_notify_setup.py" "$@" || return $?
 if [[ "$1" == prepare ]]; then kill -TERM "$BASHPID"; fi
}
'''
        result = self.run_shell('locked_operation enable_smart_notifications', overrides=overrides)
        self.assertEqual(result.returncode, 143, result.stdout+result.stderr)
        self.assertEqual(notification.read_bytes(), original)
        self.assertFalse((self.config/'crowdbastion-notify.json').exists())

    def test_term_after_core_restart_restores_files_before_reloading_core(self):
        notification = self.setup_telegram()
        original = notification.read_bytes()
        overrides = self.OVERRIDES+'''
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() {
 systemctl_base "$@" || return $?
 if [[ "$*" == 'restart crowdsec' ]]; then
  if [[ ! -e "$TRACE.interrupted" ]]; then touch "$TRACE.interrupted"; kill -TERM "$BASHPID";
  else record restored-route "$(python3 -c 'import sys,yaml;print(yaml.safe_load(open(sys.argv[1]))["url"])' "$TG_NOTIF_FILE")"; fi
 fi
}
'''
        result = self.run_shell('locked_operation enable_smart_notifications', overrides=overrides)
        self.assertEqual(result.returncode, 143, result.stdout+result.stderr)
        self.assertEqual(notification.read_bytes(), original)
        self.assertIn('restored-route https://api.telegram.org/', self.commands())
        self.assertFalse((self.base/'etc/systemd/system/crowdbastion-notify.service').exists())

    def test_term_during_disable_restarts_original_worker_and_preserves_queue(self):
        notification = self.setup_telegram()
        self.assertEqual(self.enable().returncode, 0)
        original = notification.read_bytes()
        self.trace.write_text('')
        state = self.base/'var/lib/crowdbastion-notify'
        state.mkdir(parents=True, exist_ok=True)
        (state/'queue-evidence').write_text('keep')
        overrides = self.OVERRIDES+'''
notify_tool() {
 python3 "$SCRIPT_DIR/lib/crowdsec_notify_setup.py" "$@" || return $?
 if [[ "$1" == restore ]]; then kill -TERM "$BASHPID"; fi
}
'''
        result = self.run_shell('locked_operation disable_smart_notifications', overrides=overrides)
        self.assertEqual(result.returncode, 143, result.stdout+result.stderr)
        self.assertEqual(notification.read_bytes(), original)
        self.assertTrue(json.loads((self.config/'crowdbastion-notify.json').read_text())['enabled'])
        self.assertIn('systemctl restart crowdbastion-notify.service', self.commands())
        self.assertEqual((state/'queue-evidence').read_text(), 'keep')


class NativeReloadTransactions(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_native_workflows.NativeWorkflows.fixture

    def reject(self, overrides):
        return overrides.replace("'exec '*' nginx -s reload') nginx_test_reload;;",
            "'exec '*' nginx -s reload') record silent_reload_rejection;;")+'\nsleep() { command sleep "$@"; }\n'

    def test_install_and_failed_recovery_preserve_live_dependencies(self):
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', self.reject(self.fixture()), timeout=30)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('bouncers delete', self.commands())
        self.assertTrue((self.base/'web/data/crowdsec-1key').is_dir())
        self.assertEqual(json.loads(self.state.read_text())['openresty']['status'], 'recovery-required')

    def test_remove_and_pending_retry_require_accepted_reload_before_cleanup(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        before = self.waf.read_bytes()
        self.trace.write_text('')
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', self.reject(overrides), timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('bouncers delete', self.commands())
        self.assertEqual(self.waf.read_bytes(), before)
        self.assertTrue((self.base/'web/data/crowdsec-1key').is_dir())
        # Persist pending cleanup as if the process died before reload acceptance.
        failing = overrides+'''
eval "$(declare -f web_tool | sed '1s/web_tool/web_tool_base/')"
web_tool() { [[ "$1" != forget ]] || return 1; web_tool_base "$@"; }
'''
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', failing)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(self.state.read_text())['openresty']['status'], 'cleanup-pending')
        self.trace.write_text('')
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', self.reject(overrides), timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('bouncers delete', self.commands())
        self.assertTrue((self.base/'web/data/crowdsec-1key').is_dir())


class V2bxPurge(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def service_state(self, active='active', enabled='enabled', loaded='loaded'):
        return '''
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() {
 if [[ "$1" == show && "$*" == *crowdsec-v2bx-* ]]; then
  record systemctl "$@"
  printf 'LoadState=%s\\nActiveState=%s\\nUnitFileState=%s\\n' '''+loaded+' '+active+' '+enabled+'''
  return 0
 fi
 systemctl_base "$@"
}
'''

    def test_purge_refuses_active_or_enabled_observers_before_mutations(self):
        for active, enabled in [('active','enabled'), ('inactive','enabled'), ('active','disabled'), ('activating','disabled')]:
            with self.subTest(active=active, enabled=enabled):
                self.trace.write_text('')
                result = self.run_shell('deep_purge_residuals', 'y\n', self.service_state(active, enabled))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(self.config.exists())
                self.assertNotIn('systemctl stop', self.commands())
                self.assertNotIn('apt-get', self.commands())

    def test_unreadable_service_state_refuses_purge(self):
        result = self.run_shell('deep_purge_residuals', 'y\n', 'systemctl() { return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.config.exists())

    def test_disabled_observers_preserve_evidence_and_remain_visible_in_audit(self):
        evidence = self.base/'var/lib/crowdsec-v2bx-observer'
        evidence.mkdir(parents=True)
        (evidence/'observations.db').write_bytes(b'evidence')
        overrides = self.service_state('inactive', 'disabled')
        result = self.run_shell('deep_purge_residuals', 'y\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.config.exists())
        self.assertEqual((evidence/'observations.db').read_bytes(), b'evidence')
        result = self.run_shell('audit_crowdsec_residuals', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(evidence), result.stdout)


class AdditionalTransactionReview(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    appsec_docker_stub = test_workflows.Workflows.appsec_docker_stub

    def test_silent_host_rollback_rejection_keeps_package_account(self):
        snapshot = self.base/'accounts-before.json'
        snapshot.write_text('[]')
        overrides = '''
nginx() { return 0; }
restore_config_change() { return 0; }
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() { if [[ "$1" == reload ]]; then record silent_reload_rejection; return 0; fi; systemctl_base "$@"; }
cscli() { record cscli "$@"; echo '[{"name":"crowdsec-nginx-bouncer-123"}]'; }
sleep() { command sleep "$@"; }
'''
        result = self.run_shell(f'host_web_rollback_package nginx {snapshot} crowdsec-nginx-bouncer', overrides=overrides, timeout=15)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('silent_reload_rejection', self.commands())
        self.assertNotIn('bouncers delete', self.commands())

    def test_term_during_docker_link_restores_route_and_registry(self):
        overrides = self.appsec_docker_stub(mounted=True)
        target = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        original = target.read_bytes()
        overrides += '''
eval "$(declare -f yaml_tool | sed '1s/yaml_tool/yaml_tool_base/')"
yaml_tool() {
 yaml_tool_base "$@" || return $?
 if [[ "$1" == link-docker-bouncer ]]; then kill -TERM "$BASHPID"; fi
}
'''
        result = self.run_shell('locked_operation link_docker_appsec', 'web123\ny\n', overrides)
        self.assertEqual(result.returncode, 143, result.stdout+result.stderr)
        self.assertEqual(target.read_bytes(), original)
        self.assertFalse((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())
        self.assertIn('nginx -s reload', self.commands())

    def test_term_after_disabling_core_restores_engine_and_web_route(self):
        overrides = self.appsec_docker_stub(mounted=True)
        result = self.run_shell('setup_appsec', '3\nweb123\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        target = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        original = target.read_bytes()
        overrides += '''
eval "$(declare -f systemctl | sed '1s/systemctl/systemctl_base/')"
systemctl() {
 systemctl_base "$@" || return $?
 if [[ "$*" == 'restart crowdsec' && ! -f "$TRACE.term" ]]; then
  touch "$TRACE.term"; kill -TERM "$BASHPID"
 fi
}
'''
        self.trace.write_text('')
        result = self.run_shell('locked_operation disable_appsec', 'y\n', overrides)
        self.assertEqual(result.returncode, 143, result.stdout+result.stderr)
        self.assertEqual(target.read_bytes(), original)
        self.assertTrue((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())
        self.assertTrue((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())
        self.assertEqual(self.commands().count('systemctl restart crowdsec\n'), 2)

    def test_unconfirmed_web_reload_cannot_disable_appsec_engine(self):
        overrides = self.appsec_docker_stub(mounted=True)
        result = self.run_shell('setup_appsec', '3\nweb123\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        target = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        original = target.read_bytes()
        overrides += '\nnginx_reload_verified() { record rejected_reload; return 1; }\n'
        self.trace.write_text('')
        result = self.run_shell('disable_appsec', 'y\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), original)
        self.assertTrue((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())
        self.assertNotIn('systemctl restart crowdsec', self.commands())
