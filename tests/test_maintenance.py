"""Maintenance failure recovery, readiness and read-only audit coverage."""
from contextlib import redirect_stdout
import fcntl
import importlib
import io
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest

import yaml
import test_workflows

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
maintenance = importlib.import_module('crowdsec_maintenance')
config = importlib.import_module('crowdsec_config')


class Maintenance(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    make_webui = test_workflows.Workflows.make_webui
    webui_docker = test_workflows.Workflows.webui_docker

    def rules(self):
        directory = self.base/'owned-hub/parsers/s01-parse'
        directory.mkdir(parents=True)
        rule = directory/'original.yaml'
        rule.write_text('name: original\n')
        data = self.base/'var/lib/crowdsec/data'
        data.mkdir(parents=True)
        database = data/'custom.db'
        database.write_text('live database')
        document = yaml.safe_load((self.config/'config.yaml').read_text())
        (self.config/'parsers/s01-parse').mkdir(parents=True)
        document['config_paths'] = {'config_dir': str(self.config), 'hub_dir': str(self.base/'owned-hub'), 'data_dir': str(data)}
        document['db_config'] = {'db_path': str(database)}
        (self.config/'config.yaml').write_text(yaml.safe_dump(document))
        return rule, data, database

    def test_snapshot_restores_rules_links_and_downloads_but_not_database(self):
        rule, data, database = self.rules()
        (data/'geo.mmdb').write_text('old download')
        link = self.config/'parsers/s01-parse/link.yaml'
        link.symlink_to(rule)
        snapshot = self.base/'snapshot'
        maintenance.snapshot(self.config/'config.yaml', snapshot)
        rule.write_text('changed')
        link.unlink()
        (data/'geo.mmdb').write_text('new download')
        (data/'new.txt').write_text('new download')
        database.write_text('new decisions')
        (data/'custom.db-wal').write_text('new WAL')
        maintenance.record_after(snapshot)
        self.assertTrue(maintenance.changed(snapshot))
        maintenance.restore(snapshot)
        self.assertEqual(rule.read_text(), 'name: original\n')
        self.assertTrue(link.is_symlink())
        self.assertEqual((data/'geo.mmdb').read_text(), 'old download')
        self.assertFalse((data/'new.txt').exists())
        self.assertEqual(database.read_text(), 'new decisions')
        self.assertEqual((data/'custom.db-wal').read_text(), 'new WAL')
        self.assertFalse(maintenance.changed(snapshot))

    def test_corrupted_snapshot_is_rejected_before_changing_rules(self):
        rule, _, _ = self.rules()
        snapshot = self.base/'snapshot'
        maintenance.snapshot(self.config/'config.yaml', snapshot)
        document = json.loads((snapshot/'transaction.json').read_text())
        document['before'][str(rule)]['data'] = 'corrupt'
        (snapshot/'transaction.json').write_text(json.dumps(document))
        rule.write_text('current rules')
        with self.assertRaises(ValueError):
            maintenance.restore(snapshot)
        self.assertEqual(rule.read_text(), 'current rules')

    def test_snapshot_restore_refuses_later_changes_without_touching_other_files(self):
        rule, data, _ = self.rules()
        download = data/'geo.mmdb'; download.write_text('old')
        snapshot = self.base/'snapshot'
        maintenance.snapshot(self.config/'config.yaml', snapshot)
        rule.write_text('transaction'); download.write_text('transaction')
        maintenance.record_after(snapshot)
        rule.write_text('external change')
        with self.assertRaisesRegex(ValueError, 'concurrent modifications'):
            maintenance.restore(snapshot)
        self.assertEqual(rule.read_text(), 'external change')
        self.assertEqual(download.read_text(), 'transaction')

    def test_snapshot_refuses_external_children_before_any_rollback_mutation(self):
        rule, _, _ = self.rules()
        snapshot = self.base/'snapshot'
        maintenance.snapshot(self.config/'config.yaml', snapshot)
        rule.write_text('transaction')
        added = rule.parent/'added'; added.mkdir()
        transaction_file = added/'rule.yaml'; transaction_file.write_text('transaction')
        maintenance.record_after(snapshot)
        external = added/'external.yaml'; external.write_text('external')
        with self.assertRaisesRegex(ValueError, 'concurrent modifications'):
            maintenance.restore(snapshot)
        self.assertEqual(rule.read_text(), 'transaction')
        self.assertEqual(transaction_file.read_text(), 'transaction')
        self.assertEqual(external.read_text(), 'external')

    def test_update_rejects_symlinked_hub_before_mutation(self):
        self.rules()
        target = self.base/'external-hub'
        target.mkdir()
        rule = target/'rule.yaml'
        rule.write_text('original')
        (self.config/'hub').symlink_to(target, target_is_directory=True)
        result = self.run_shell('run_hub_update', overrides='cscli() { record cscli "$@"; printf changed > '+shlex.quote(str(rule))+'; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(rule.read_text(), 'original')
        self.assertNotIn('cscli hub', self.commands())

    def test_snapshot_rejects_hub_with_symlink_ancestor(self):
        self.rules()
        target = self.base/'external'
        (target/'hub').mkdir(parents=True)
        alias = self.base/'alias'
        alias.symlink_to(target, target_is_directory=True)
        document = config.read(self.config/'config.yaml')
        document['config_paths']['hub_dir'] = str(alias/'hub')
        config.write(self.config/'config.yaml', document)
        with self.assertRaises(ValueError):
            maintenance.snapshot(self.config/'config.yaml', self.base/'snapshot')

    def test_update_rejects_external_link_inside_hub(self):
        self.rules()
        hub = self.config/'hub'
        hub.mkdir()
        external = self.base/'external-rule.yaml'
        external.write_text('original')
        (hub/'rule.yaml').symlink_to(external)
        result = self.run_shell('run_hub_update', overrides='cscli() { record cscli "$@"; printf changed > '+shlex.quote(str(hub/'rule.yaml'))+'; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(external.read_text(), 'original')
        self.assertNotIn('cscli hub', self.commands())

    def test_snapshot_checks_configured_paths_inside_existing_root(self):
        self.rules()
        external = self.base/'external-hub'
        external.mkdir()
        for key in ('hub_dir', 'index_path'):
            with self.subTest(key=key):
                link = self.config/'parsers'/key
                link.symlink_to(external, target_is_directory=True)
                document = config.read(self.config/'config.yaml')
                document['config_paths'][key] = str(link)
                config.write(self.config/'config.yaml', document)
                with self.assertRaises(ValueError):
                    maintenance.snapshot(self.config/'config.yaml', self.base/('snapshot-'+key))
                link.unlink()
                del document['config_paths'][key]
                config.write(self.config/'config.yaml', document)

    def test_runtime_refuses_unmanaged_or_writable_directory(self):
        runtime = self.base/'usr/local/lib/crowdsec-1key'
        runtime.mkdir(parents=True)
        sentinel = runtime/'user-file'
        sentinel.write_text('keep')
        for managed in (False, True):
            with self.subTest(managed=managed):
                if managed:
                    (runtime/'.crowdsec-1key-managed').touch()
                    runtime.chmod(0o777)
                result = self.run_shell('install_maintenance_runtime')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(sentinel.read_text(), 'keep')
                self.assertFalse((runtime/'current').exists())

    def test_runtime_refuses_symlink_ancestor(self):
        target = self.base/'external-runtime'
        target.mkdir()
        parent = self.base/'usr/local'
        parent.mkdir(parents=True)
        (parent/'lib').symlink_to(target, target_is_directory=True)
        result = self.run_shell('install_maintenance_runtime')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_new_update_respects_existing_hub_lock(self):
        self.rules()
        lock = self.base/'run/lock/crowdsec-1key-hub.lock'
        lock.parent.mkdir(parents=True)
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_shell('run_hub_update')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('cscli hub', self.commands())

    def test_failed_hub_upgrade_rolls_back_and_returns_failure(self):
        rule, _, _ = self.rules()
        overrides = 'cscli() { record cscli "$@"; if [[ "$*" == "hub upgrade" ]]; then printf changed > '+shlex.quote(str(rule))+'; return 1; fi; }'
        result = self.run_shell('main --update-hub', overrides=overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(rule.read_text(), 'name: original\n')
        self.assertIn('systemctl reload crowdsec', self.commands())
        self.assertIn('原规则', result.stdout)
        self.assertIn('rollback=restored', (self.base/'var/log/crowdsec-1key-update.log').read_text())

    def test_hub_validation_failure_rolls_back(self):
        rule, _, _ = self.rules()
        overrides = ('cscli() { record cscli "$@"; [[ "$*" != "hub upgrade" ]] || printf changed > '+shlex.quote(str(rule))+'; }; '
                     'crowdsec() { record crowdsec "$@"; [[ "$(cat '+shlex.quote(str(rule))+')" != changed ]]; }')
        result = self.run_shell('run_hub_update', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(rule.read_text(), 'name: original\n')

    def test_unchanged_hub_does_not_reload(self):
        self.rules()
        result = self.run_shell('run_hub_update')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('systemctl reload crowdsec', self.commands())

    def test_failed_hub_reload_restores_original_rules_and_reloads_again(self):
        rule, _, _ = self.rules()
        overrides = ('cscli() { record cscli "$@"; [[ "$*" != "hub upgrade" ]] || printf changed > '+shlex.quote(str(rule))+'; }; '
                     'reload_count=0; systemctl() { record systemctl "$@"; if [[ "$*" == "reload crowdsec" ]]; then ((reload_count+=1)); ((reload_count>1)); else return 0; fi; }')
        result = self.run_shell('run_hub_update', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(rule.read_text(), 'name: original\n')
        self.assertEqual(self.commands().count('systemctl reload crowdsec'), 2)

    def test_snapshot_preserves_database_created_after_snapshot_without_extension(self):
        _, data, database = self.rules()
        database.unlink()
        database = data/'live-storage'
        document = config.read(self.config/'config.yaml')
        document['db_config']['db_path'] = str(database)
        config.write(self.config/'config.yaml', document)
        snapshot = self.base/'snapshot'
        maintenance.snapshot(self.config/'config.yaml', snapshot)
        database.write_text('new live database')
        self.assertFalse(maintenance.changed(snapshot))
        maintenance.restore(snapshot)
        self.assertEqual(database.read_text(), 'new live database')

    def test_snapshot_retention_keeps_failed_and_unmanaged_directories(self):
        backups = self.base/'backups'
        backups.mkdir()
        for index in range(17):
            directory = backups/('hub.'+str(index))
            directory.mkdir()
            (directory/'manifest.yaml').write_text('{}')
            (directory/'.successful').touch()
        failed = backups/'hub.failed'
        failed.mkdir()
        (failed/'manifest.yaml').write_text('{}')
        other = backups/'change.user'
        other.mkdir()
        maintenance.main(['prune-snapshots', str(backups)])
        self.assertEqual(len(list(backups.glob('hub.*/.successful'))), 14)
        self.assertTrue(failed.exists())
        self.assertTrue(other.exists())

    def test_concurrent_update_is_rejected_before_commands(self):
        lock = self.base/'run/lock/crowdsec-1key.lock'
        lock.parent.mkdir(parents=True)
        with lock.open('w') as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = self.run_shell('main --update-hub')
        self.assertEqual(result.returncode, 75, result.stdout+result.stderr)
        self.assertNotIn('cscli hub', self.commands())
        self.assertIn('已有管理操作', (self.base/'var/log/crowdsec-1key-update.log').read_text())

    def test_cron_uses_stable_runtime_not_repository_and_has_log_rotation(self):
        rotation = self.base/'etc/logrotate.d'
        rotation.mkdir()
        result = self.run_shell('main --enable-cron')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        cron = (self.base/'etc/cron.d/crowdsec-autoupdate').read_text()
        self.assertIn('/usr/local/lib/crowdsec-1key/current/manager.sh --update-hub', cron)
        self.assertNotIn(str(self.source), cron)
        self.assertTrue((self.base/'usr/local/lib/crowdsec-1key/current/lib/crowdsec_maintenance.py').is_file())
        self.assertIn('rotate 8', (rotation/'crowdsec-1key').read_text())

    def test_installed_packages_are_not_upgraded_or_reinstalled(self):
        result = self.run_shell('install_packages crowdsec curl', overrides="dpkg-query() { echo 'install ok installed'; }")
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('apt-get', self.commands())

    def test_unchanged_config_keeps_comments_inode_and_skips_restart(self):
        path = self.config/'config.yaml'
        original = path.read_text()+'# keep this comment\n'
        path.write_text(original)
        before = path.stat()
        config.write(path, config.read(path))
        self.assertEqual(path.read_text(), original)
        self.assertEqual(path.stat().st_ino, before.st_ino)
        result = self.run_shell('begin_config_change '+shlex.quote(str(path))+' && apply_core_config')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('systemctl restart crowdsec', self.commands())

    def test_metrics_keeps_custom_port_and_rejects_other_listener(self):
        local = self.config/'config.yaml.local'
        local.write_text('prometheus: {listen_port: 6067}\n')
        result = self.run_shell('enable_prometheus_metrics')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(config.read(local)['prometheus']['listen_port'], 6067)
        before = local.read_text()
        result = self.run_shell('enable_prometheus_metrics', overrides="ss() { echo 'LISTEN 0 128 127.0.0.1:6067 *:* users:((\"other\",pid=123,fd=1))'; }")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(local.read_text(), before)

    def test_enabled_collections_do_not_trigger_hub_or_install(self):
        overrides = "cscli() { record cscli \"$@\"; echo '[{\"name\":\"crowdsecurity/nginx\",\"status\":\"enabled\"}]'; }"
        result = self.run_shell('install_collections crowdsecurity/nginx && reload_core_rules', overrides=overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('cscli hub update', self.commands())
        self.assertNotIn('collections install', self.commands())
        self.assertNotIn('systemctl reload', self.commands())

    def test_webui_only_change_does_not_restart_core(self):
        ui = self.make_webui()
        compose = shlex.quote(str(ui/'docker-compose.yml'))
        core = shlex.quote(str(self.config/'config.yaml'))
        result = self.run_shell('begin_config_change '+compose+' '+core+' && printf changed > '+compose+' && apply_core_config')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('systemctl restart crowdsec', self.commands())

    def test_new_logs_are_reported_without_modifying_configuration(self):
        path = self.base/'opt/1panel/1panel/www/sites/new/log/access.log'
        path.parent.mkdir(parents=True)
        path.touch()
        before = {str(item): item.read_bytes() for item in self.config.rglob('*') if item.is_file()}
        result = self.run_shell('main --check-logs')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn(str(path), result.stdout+result.stderr)
        self.assertEqual(before, {str(item): item.read_bytes() for item in self.config.rglob('*') if item.is_file()})
        self.assertNotIn('systemctl restart', self.commands())

    def test_effective_nginx_log_directives_find_custom_bind_paths(self):
        log = self.base/'custom/requests.log'
        log.parent.mkdir()
        log.touch()
        mounts, effective, discovered = [self.base/name for name in ('mounts', 'effective', 'discovered')]
        mounts.write_text(json.dumps([{'Type': 'bind', 'RW': False, 'Source': str(log.parent), 'Destination': '/custom'}]))
        effective.write_text('http { server { access_log /custom/requests.log; } } stream { access_log /custom/tcp.log; }')
        maintenance.main(['runtime-logs', 'nginx', str(mounts), str(effective), str(discovered)])
        self.assertEqual(json.loads(discovered.read_text()), {'path': str(log), 'kind': 'nginx'})

    def test_running_webui_with_failed_http_health_rolls_back(self):
        ui = self.make_webui()
        original = (ui/'docker-compose.yml').read_text()
        result = self.run_shell('deploy_web_ui', '3000\ny\n', self.webui_docker()+"\ncurl() { echo '{\"status\":\"error\"}'; }", timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((ui/'docker-compose.yml').read_text(), original)
        self.assertNotIn('SUCCESS', result.stdout)

    def test_successful_webui_pins_digest_and_health_port(self):
        ui = self.make_webui()
        result = self.run_shell('deploy_web_ui', '3017\ny\n', self.webui_docker())
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        service = config.read(ui/'docker-compose.yml')['services']['crowdsec-web-ui']
        self.assertIn('@sha256:', service['image'])
        self.assertNotIn(':latest', service['image'])
        self.assertIn('3017/api/health', str(service['healthcheck']['test']))
        self.assertIn('http://127.0.0.1:3017/api/health', self.commands())

    def test_webui_occupied_port_must_belong_to_container_process(self):
        self.make_webui()
        stub = self.webui_docker()+"\nss() { echo 'LISTEN 0 128 127.0.0.1:3000 *:* users:((\"other\",pid=123,fd=1))'; }"
        result = self.run_shell('deploy_web_ui', '3000\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('docker pull', self.commands())

    def test_http_reads_without_parsing_are_abnormal_but_syslog_is_not(self):
        acquisition, appsec = self.base/'acquisition', self.base/'appsec'
        acquisition.write_text(json.dumps({'acquisition': {'file:/var/log/auth.log': {'reads': 1}}}))
        appsec.write_text('{}')
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(maintenance.health_metrics(acquisition, appsec), 0)
        self.assertIn('尚未验证', output.getvalue())
        acquisition.write_text(json.dumps({'acquisition': {'file:/www/access.log': {'reads': 1}}}))
        with redirect_stdout(io.StringIO()):
            self.assertEqual(maintenance.health_metrics(acquisition, appsec), 1)


if __name__ == '__main__':
    unittest.main()
