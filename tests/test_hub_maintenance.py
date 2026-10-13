"""Hub transactions use real temporary files and isolated command stubs."""
from test_workflows import Workflows
import shlex
import subprocess

class HubMaintenance(Workflows):
    def complete_inventory_stub(self):
        import json
        names = ['linux', 'sshd', 'nginx', 'nginx-proxy-manager', 'http-cve',
                 'base-http-scenarios', 'whitelist-good-actors',
                 'appsec-virtual-patching', 'appsec-generic-rules']
        inventory = json.dumps([{'name': 'crowdsecurity/'+name, 'status': 'enabled'} for name in names])
        return '''detect_os() { OS_ID=debian; }
cscli() {
 record cscli "$@"
 case "$*" in 'collections list -o json') printf '%s\\n' '''+shlex.quote(inventory)+''' ;; esac
 return 0
}'''

    def test_removal_entrypoints_preserve_hub_busy_status(self):
        import fcntl
        lock = self.base/'run/lock/crowdsec-1key-hub.lock'; lock.parent.mkdir(parents=True)
        for action, answers in [('main --uninstall-waf', 'y\n'),
                                ('locked_operation uninstall_specific_waf_collection', 'crowdsecurity/nginx\ny\n')]:
            with self.subTest(action=action), lock.open('w') as stream:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.trace.write_text('')
                p = self.run_shell(action, answers, self.complete_inventory_stub())
                self.assertEqual(p.returncode, 75, p.stdout+p.stderr)
                self.assertNotIn('collections remove', self.commands())

    def test_core_signal_with_existing_collections_restores_config_and_cleans_stage(self):
        before = (self.config/'config.yaml').read_bytes()
        stub = self.complete_inventory_stub()+'''
enable_prometheus_metrics() {
 yaml_tool metrics "$CS_DIR/config.yaml" || return 1
 record staged "$LOG_REPAIR_STAGE"
 kill -TERM "$BASHPID"
}'''
        p = self.run_shell('''main --install-core
status=$?
flock -n "$MAINTENANCE_LOCK" true || exit 91
flock -n "$HUB_LOCK_FILE" true || exit 92
exit "$status"''', '203.0.113.2\n', stub)
        self.assertEqual(p.returncode, 143, p.stdout+p.stderr)
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)
        self.assertFalse((self.config/'parsers/s02-enrich/99-admin-whitelist.yaml').exists())
        stages = [line.removeprefix('staged ') for line in self.commands().splitlines() if line.startswith('staged ')]
        self.assertEqual(len(stages), 1)
        from pathlib import Path
        self.assertFalse(Path(stages[0]).exists())
        self.assertNotIn('systemctl restart', self.commands())

    def test_signal_during_config_load_without_hub_changes_loads_restored_state(self):
        before = (self.config/'config.yaml').read_bytes()
        for action, answers in [('main --install-core', '203.0.113.2\n'),
                                ('main --install-appsec', '')]:
            with self.subTest(action=action):
                (self.config/'config.yaml').write_bytes(before)
                appsec = self.config/'acquis.d/crowdsec-1key-appsec.yaml'
                appsec.unlink(missing_ok=True)
                self.trace.write_text('')
                interrupted = self.base/'config-interrupted'; interrupted.unlink(missing_ok=True)
                stub = self.complete_inventory_stub()+'''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == restart ]]; then
  record loaded "$(sha256sum "$CS_DIR/config.yaml")" appsec="$([[ -f "$APPSEC_FILE" ]] && echo present || echo absent)"
  if [[ ! -f '''+shlex.quote(str(interrupted))+''' ]]; then
   touch '''+shlex.quote(str(interrupted))+'''; kill -TERM "$BASHPID"
  fi
 fi
 return 0
}'''
                p = self.run_shell(action, answers, stub)
                self.assertEqual(p.returncode, 143, p.stdout+p.stderr)
                self.assertEqual((self.config/'config.yaml').read_bytes(), before)
                self.assertFalse(appsec.exists())
                loads = [line for line in self.commands().splitlines() if line.startswith('loaded ')]
                self.assertEqual(len(loads), 2, p.stdout+p.stderr)
                import hashlib
                self.assertIn(hashlib.sha256(before).hexdigest(), loads[-1])
                self.assertTrue(loads[-1].endswith('appsec=absent'))

    def test_successful_config_load_without_hub_changes_keeps_new_config(self):
        import yaml
        p = self.run_shell('main --install-core', '203.0.113.2\n', self.complete_inventory_stub())
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue(yaml.safe_load((self.config/'config.yaml').read_text())['prometheus']['enabled'])
        self.assertNotIn('collections install', self.commands())
        p = self.run_shell('main --install-appsec', '0\n', self.complete_inventory_stub())
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((self.config/'acquis.d/crowdsec-1key-appsec.yaml').exists())
        self.assertNotIn('已恢复本次修改前的配置', p.stdout+p.stderr)

    def test_signal_after_hub_commit_preserves_loaded_config(self):
        import yaml
        before = (self.config/'config.yaml').read_bytes()
        for action, answers in [('main --install-core', '203.0.113.2\n'),
                                ('main --optimize', 'y\nn\ny\ny\n')]:
            with self.subTest(action=action):
                (self.config/'config.yaml').write_bytes(before)
                p = self.run_shell(action, answers, '''detect_os() { OS_ID=debian; }
maintenance_tool() {
 if [[ "$1" == prune-snapshots ]]; then kill -TERM "$BASHPID"; fi
 python3 "$SCRIPT_DIR/lib/crowdsec_maintenance.py" "$@"
}''')
                self.assertEqual(p.returncode, 143, p.stdout+p.stderr)
                self.assertTrue(yaml.safe_load((self.config/'config.yaml').read_text())['prometheus']['enabled'])
                self.assertTrue((self.config/'hub/test-installed').exists())
                self.assertNotIn('已恢复本次修改前的配置', p.stdout+p.stderr)

    def install_stub(self, hub, failure=''):
        return '''cscli() {
 record cscli "$@"
 case "$*" in
  'collections list -o json') echo '[]' ;;
  'collections install '*) echo new > '''+shlex.quote(str(hub/'rule.yaml'))+'''; '''+failure+''' ;;
 esac
 return 0
}'''

    def test_partial_collection_install_rolls_back(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        p = self.run_shell('install_collections crowdsecurity/nginx', overrides=self.install_stub(hub, 'return 1'))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text(), 'old')

    def test_collection_validation_failure_rolls_back_before_loading(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        stub = self.install_stub(hub, ':')+'\ncrowdsec() { record crowdsec "$@"; [[ "$(cat '+shlex.quote(str(hub/'rule.yaml'))+')" != new ]]; }'
        p = self.run_shell('install_collections crowdsecurity/nginx && reload_core_rules', overrides=stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text(), 'old')

    def test_collection_reload_failure_rolls_back(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        stub = self.install_stub(hub, ':')+'''\nreload_count=0
systemctl() { record systemctl "$@"; if [[ "$*" == 'reload crowdsec' ]]; then ((reload_count+=1)); ((reload_count>1)); else return 0; fi; }'''
        p = self.run_shell('install_collections crowdsecurity/nginx && reload_core_rules', overrides=stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text(), 'old')
        self.assertEqual(self.commands().count('systemctl reload crowdsec'), 2)

    def test_collection_holds_hub_lock_until_core_load(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        lock = self.base/'run/lock/crowdsec-1key-hub.lock'
        action = 'install_collections crowdsecurity/nginx && { flock -n '+shlex.quote(str(lock))+' true; probe=$?; reload_core_rules; exit "$probe"; }'
        p = self.run_shell(action, overrides=self.install_stub(hub, ':'))
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text().strip(), 'new')

    def test_collection_signal_rolls_back_and_preserves_signal_status(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        stub = self.install_stub(hub, 'kill -TERM "$BASHPID"')
        p = self.run_shell('main --install-waf', overrides=stub)
        self.assertEqual(p.returncode, 143, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text(), 'old')

    def test_signal_during_load_restores_hub_before_loading_old_state(self):
        for action, answers, load in [('main --install-waf', '', 'reload'),
                                       ('main --optimize', 'y\nn\ny\ny\n', 'restart')]:
            with self.subTest(action=action):
                hub = self.config/'hub'; hub.mkdir(exist_ok=True); (hub/'rule.yaml').write_text('old')
                self.trace.write_text('')
                self.base.joinpath('load-interrupted').unlink(missing_ok=True)
                stub = self.install_stub(hub, ':')+'''\nsystemctl() {
 record systemctl "$@"
 if [[ "$1" == '''+shlex.quote(load)+''' ]]; then
  record loaded "$(cat '''+shlex.quote(str(hub/'rule.yaml'))+''')"
  if [[ ! -f '''+shlex.quote(str(self.base/'load-interrupted'))+''' ]]; then
   touch '''+shlex.quote(str(self.base/'load-interrupted'))+'''; kill -TERM "$BASHPID"
  fi
 fi
 return 0
}'''
                p = self.run_shell(action, answers, stub)
                self.assertEqual(p.returncode, 143, p.stdout+p.stderr)
                self.assertEqual((hub/'rule.yaml').read_text(), 'old')
                self.assertEqual([line for line in self.commands().splitlines() if line.startswith('loaded ')],
                                 ['loaded new', 'loaded old'])

    def test_public_install_propagates_hub_lock_conflict(self):
        import fcntl
        lock = self.base/'run/lock/crowdsec-1key-hub.lock'; lock.parent.mkdir(parents=True)
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            p = self.run_shell('main --install-waf')
        self.assertEqual(p.returncode, 75, p.stdout+p.stderr)
        self.assertNotIn('collections install', self.commands())

    def test_optimize_final_validation_failure_rolls_back_rules_and_config(self):
        hub = self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        before = (self.config/'config.yaml').read_bytes()
        stub = self.install_stub(hub, ':')+'\ncrowdsec() { record crowdsec "$@"; [[ "$(cat '+shlex.quote(str(hub/'rule.yaml'))+')" != new ]]; }'
        p = self.run_shell('main --optimize', 'y\nn\ny\ny\n', overrides=stub)
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((hub/'rule.yaml').read_text(), 'old')
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)
        self.assertNotIn('systemctl restart', self.commands())

    def test_remove_restores_downloads_without_touching_database(self):
        import yaml
        data = self.base/'data'; data.mkdir()
        download = data/'geo.mmdb'; download.write_text('old')
        database = data/'live-storage'; database.write_text('live')
        document = yaml.safe_load((self.config/'config.yaml').read_text())
        document['config_paths'] = {'data_dir': str(data)}
        document['db_config'] = {'db_path': str(database)}
        (self.config/'config.yaml').write_text(yaml.safe_dump(document))
        stub = 'cscli() { printf new > '+shlex.quote(str(download))+'; printf decisions > '+shlex.quote(str(database))+'; return 1; }'
        p = self.run_shell('hub_maintenance remove crowdsecurity/nginx', overrides=stub)
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(download.read_text(), 'old')
        self.assertEqual(database.read_text(), 'decisions')

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
        stub='cscli() { record cscli "$@"; echo new > '+shlex.quote(str(hub/'rule.yaml'))+'; }; crowdsec() { record crowdsec "$@"; [[ "$(cat '+shlex.quote(str(hub/'rule.yaml'))+')" != new ]]; }'
        p=self.run_shell('hub_maintenance update', overrides=stub)
        self.assertNotEqual(p.returncode,0)
        self.assertIn("cscli hub update", self.commands())
        self.assertEqual((hub/'rule.yaml').read_text(),'old')
        self.assertEqual(untouched.read_text(),original)
        self.assertNotIn('systemctl reload', self.commands())

    def test_reload_failure_restores_changed_files(self):
        rules=self.config/'hub'; rules.mkdir(); (rules/'rule.yaml').write_text('old')
        stub='cscli() { echo new > '+shlex.quote(str(rules/'rule.yaml'))+'; }; systemctl() { record systemctl "$@"; [[ "$1" != reload ]]; }'
        p=self.run_shell('hub_maintenance update', overrides=stub)
        self.assertNotEqual(p.returncode,0)
        self.assertEqual((rules/'rule.yaml').read_text(),'old')
        self.assertIn('rollback', (self.base/'var/log/crowdsec-1key-update.log').read_text())

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
        self.assertIn('snapshot-failed', (self.base/'var/log/crowdsec-1key-update.log').read_text())

    def test_restore_validation_failure_retains_snapshot(self):
        hub=self.config/'hub'; hub.mkdir(); (hub/'rule.yaml').write_text('old')
        p=self.run_shell('hub_maintenance update', overrides='cscli() { record cscli "$@"; echo new > '+shlex.quote(str(hub/'rule.yaml'))+'; }; validation=0; crowdsec() { ((validation+=1)); ((validation==1)); }')
        self.assertNotEqual(p.returncode, 0)
        snapshots=list((self.base/'var/backups/crowdsec-1key').glob('hub.*/transaction.json'))
        self.assertEqual(len(snapshots), 1, p.stdout+p.stderr)
        self.assertIn('rollback=failed', (self.base/'var/log/crowdsec-1key-update.log').read_text())

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
        runner=self.base/'usr/local/lib/crowdsec-1key/current/manager.sh'
        self.assertTrue(runner.exists())
        cron=(self.base/'etc/cron.d/crowdsec-autoupdate').read_text()
        self.assertIn('/usr/local/lib/crowdsec-1key/current/manager.sh --update-hub',cron)
        self.assertNotIn(str(self.source),cron)
        self.assertTrue((runner.parent/'lib/hub_maintenance.sh').exists())
        self.assertTrue((runner.parent/'lib/crowdsec_hub_snapshot.py').exists())

for name in list(vars(Workflows)):
    if name.startswith('test_') and name not in HubMaintenance.__dict__:
        setattr(HubMaintenance,name,None)
del Workflows
