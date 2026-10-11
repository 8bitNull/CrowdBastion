"""Hub transactions use real temporary files and isolated command stubs."""
from test_workflows import Workflows
import shlex
import subprocess

class HubMaintenance(Workflows):
    def test_collection_install_respects_maintenance_lock(self):
        lock=self.base/'run/lock/crowdsec-1key-hub.lock'; lock.parent.mkdir(parents=True)
        proc=subprocess.Popen(['flock',str(lock),'cat'],stdin=subprocess.PIPE)
        self.addCleanup(lambda: proc.communicate())
        import time
        time.sleep(.05)
        p=self.run_shell('install_collections crowdsecurity/nginx')
        self.assertNotEqual(p.returncode,0)
        self.assertNotIn('cscli hub',self.commands())

    def test_validation_failure_restores_changed_files(self):
        hub=self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        untouched=self.config/'config.yaml'; original=untouched.read_text()
        stub='cscli() { record cscli "$@"; echo new > '+shlex.quote(str(hub/'rule.yaml'))+'; }; crowdsec() { record crowdsec "$@"; return 1; }'
        p=self.run_shell('hub_maintenance update', overrides=stub)
        self.assertNotEqual(p.returncode,0)
        self.assertIn("cscli hub update", self.commands())
        self.assertEqual((hub/'rule.yaml').read_text(),'old')
        self.assertEqual(untouched.read_text(),original)
        self.assertNotIn('systemctl reload', self.commands())

    def test_reload_failure_restores_changed_files(self):
        rules=self.config/'hub'; rules.mkdir(); (rules/'rule.yaml').write_text('old')
        stub='cscli() { echo new > '+shlex.quote(str(rules/'rule.yaml'))+'; }; systemctl() { record systemctl "$@"; return 1; }'
        p=self.run_shell('hub_maintenance update', overrides=stub)
        self.assertNotEqual(p.returncode,0)
        self.assertEqual((rules/'rule.yaml').read_text(),'old')
        self.assertIn('rollback', (self.base/'var/log/crowdsec-1key-hub.log').read_text())

    def test_failed_update_restores_added_file(self):
        hub=self.config/'hub'; hub.mkdir()
        p=self.run_shell('hub_maintenance update', overrides='cscli() { echo new > '+shlex.quote(str(hub/'new.yaml'))+'; return 1; }')
        self.assertNotEqual(p.returncode,0)
        self.assertFalse((hub/'new.yaml').exists())

    def test_unmanaged_custom_rule_change_survives_rollback(self):
        rules=self.config/'scenarios'; rules.mkdir(); custom=rules/'custom.yaml'; custom.write_text('before')
        p=self.run_shell('hub_maintenance update', overrides='cscli() { record cscli "$@"; echo unrelated > '+shlex.quote(str(custom))+'; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(custom.read_text().strip(), 'unrelated')

    def test_symlinked_hub_root_aborts_before_mutation(self):
        target=self.base/'relocated-hub'; target.mkdir(); (target/'rule.yaml').write_text('old')
        (self.config/'hub').symlink_to(target, target_is_directory=True)
        p=self.run_shell('hub_maintenance update', overrides='cscli() { record cscli "$@"; echo new > '+shlex.quote(str(target/'rule.yaml'))+'; return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual((target/'rule.yaml').read_text(), 'old')
        self.assertNotIn('cscli hub', self.commands())
        self.assertIn('snapshot-failed', (self.base/'var/log/crowdsec-1key-hub.log').read_text())

    def test_restore_validation_failure_retains_snapshot(self):
        hub=self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        p=self.run_shell('hub_maintenance update', overrides='cscli() { record cscli "$@"; echo new > '+shlex.quote(str(hub/'rule.yaml'))+'; }; crowdsec() { return 1; }')
        self.assertNotEqual(p.returncode, 0)
        import re
        from pathlib import Path
        match=re.search(r'Hub snapshot retained: (.+)', p.stderr)
        self.assertIsNotNone(match, p.stdout+p.stderr)
        snapshot=Path(match.group(1)); self.addCleanup(lambda: snapshot.unlink(missing_ok=True))
        self.assertTrue(snapshot.exists())

    def test_busy_lock_does_not_modify_hub(self):
        lock=self.base/'run/lock/crowdsec-1key-hub.lock'; lock.parent.mkdir(parents=True)
        proc=subprocess.Popen(['flock',str(lock),'cat'],stdin=subprocess.PIPE)
        self.addCleanup(lambda: proc.communicate())
        import time
        time.sleep(.05)
        p=self.run_shell('hub_maintenance update')
        self.assertNotEqual(p.returncode,0)
        self.assertNotIn('cscli hub',self.commands())

    def test_cron_installs_independent_owned_runner(self):
        p=self.run_shell('enable_auto_update')
        self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        runner=self.base/'opt/crowdsec-1key-maintenance/hub_maintenance.sh'
        self.assertTrue(runner.exists())
        cron=(self.base/'etc/cron.d/crowdsec-autoupdate').read_text()
        self.assertIn(str(runner),cron)
        self.assertNotIn(str(self.source),cron)

for name in list(vars(Workflows)):
    if name.startswith('test_') and name not in HubMaintenance.__dict__:
        setattr(HubMaintenance,name,None)
del Workflows
