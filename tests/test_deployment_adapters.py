"""Host, NPM regeneration and private bridge compatibility contracts."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
import shlex
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml
import test_workflows
import test_native_workflows

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
import crowdsec_host as host
import crowdsec_request_audit as audit
import crowdsec_transport as transport
import crowdsec_web as web


class AdapterContracts(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.identity = 'a'*64
        self.inspection = {'HostConfig': {'NetworkMode': 'web'}, 'NetworkSettings': {'Networks': {
            'web': {'NetworkID': self.identity, 'Gateway': '172.18.0.1'}}}}
        self.networks = [{'Name': 'web', 'Id': self.identity, 'Driver': 'bridge',
                          'IPAM': {'Config': [{'Gateway': '172.18.0.1', 'Subnet': '172.18.0.0/24'}]}}]

    def private_plan(self, **changes):
        arguments = dict(inspection=self.inspection, networks=self.networks,
                         api_url='http://172.18.0.1:18080', appsec_url='http://172.18.0.1:17422')
        arguments.update(changes)
        return transport.plan(**arguments)

    def test_private_endpoints_require_connected_bridge_gateway(self):
        self.assertEqual(self.private_plan()['network_id'], self.identity)
        for invalid in ('http://127.0.0.1:8080', 'http://8.8.8.8:8080', 'http://172.18.0.2:8080',
                        'http://user:secret@172.18.0.1:8080', 'http://172.18.0.1:8080/v1',
                        'http://[fd00::1]:8080', 'http://private.example:8080', 'https://172.18.0.1:8080'):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.private_plan(api_url=invalid)

    def test_other_network_driver_or_changed_network_id_is_rejected(self):
        for driver in ('overlay', 'macvlan', 'host'):
            networks = copy.deepcopy(self.networks)
            networks[0]['Driver'] = driver
            with self.assertRaises(ValueError):
                self.private_plan(networks=networks)
        networks = copy.deepcopy(self.networks)
        networks[0]['Id'] = 'b'*64
        with self.assertRaises(ValueError):
            self.private_plan(networks=networks)

    def test_internal_bridge_without_default_gateway_uses_verified_ipam_and_container_address(self):
        inspection = copy.deepcopy(self.inspection)
        inspection['NetworkSettings']['Networks']['web'].update(Gateway='', IPAddress='172.18.0.2')
        networks = copy.deepcopy(self.networks)
        networks[0]['Internal'] = True
        self.assertEqual(self.private_plan(inspection=inspection, networks=networks)['network_id'], self.identity)

    def test_empty_gateway_does_not_bypass_internal_bridge_address_checks(self):
        for internal, address in ((False, '172.18.0.2'), (True, ''), (True, '172.19.0.2')):
            with self.subTest(internal=internal, address=address):
                inspection = copy.deepcopy(self.inspection)
                inspection['NetworkSettings']['Networks']['web'].update(Gateway='', IPAddress=address)
                networks = copy.deepcopy(self.networks)
                networks[0]['Internal'] = internal
                with self.assertRaises(ValueError):
                    self.private_plan(inspection=inspection, networks=networks)

    def test_wildcard_listener_is_not_used_as_private_listener(self):
        planned, listeners = self.root/'plan', self.root/'listeners'
        web.save_state(planned, self.private_plan())
        listeners.write_text('LISTEN 0 128 0.0.0.0:18080 *:*\nLISTEN 0 128 172.18.0.1:17422 *:*\n')
        with self.assertRaises(ValueError):
            transport.main(['listeners', str(planned), str(listeners)])
        listeners.write_text('LISTEN 0 128 172.18.0.1:18080 *:*\nLISTEN 0 128 172.18.0.1:17422 *:*\n')
        transport.main(['listeners', str(planned), str(listeners)])

    def test_host_path_discovery_uses_effective_http_logs_and_skips_symlinks(self):
        directory = self.root/'custom'
        directory.mkdir()
        linked = self.root/'linked'
        linked.symlink_to(directory)
        effective = f'http {{ access_log {directory}/access.log; error_log {linked}/error.log; include {directory}/*.conf; }}'
        mounts = host.identity_mounts(effective)
        self.assertEqual(len(mounts), 1)
        self.assertEqual(mounts[0]['Source'], str(directory))
        self.assertEqual(web.mount_path(str(directory/'access.log'), mounts)[0], str(directory/'access.log'))

    def host_fixture(self, buffer=''):
        config = self.root/'crowdsec-nginx-bouncer.conf'
        config.write_text('API_KEY=fixture-only-secret\nAPPSEC_URL=http://127.0.0.1:7422\n')
        links = self.root/'links.yaml'
        links.write_text(yaml.safe_dump({str(config): ''}))
        snippet = self.root/'crowdsec_nginx.conf'
        snippet.write_text(f'init_by_lua_block {{ local cs = require "crowdsec"; cs.init("{config}", "test") }}\naccess_by_lua_block {{ local cs = require "crowdsec"; cs.Allow(ngx.var.remote_addr) }}\n')
        effective = self.root/'effective'
        effective.write_text(f'# configuration file {self.root}/nginx.conf:\nhttp {{ include {snippet}; server {{ server_name example.com; access_log {self.root}/access.log {buffer}; error_log {self.root}/error.log; }} }}\n# configuration file {snippet}:\n'+snippet.read_text())
        for name in ('access.log', 'error.log'):
            (self.root/name).touch()
        mounts = self.root/'mounts'
        web.save_state(mounts, host.identity_mounts(effective.read_text()))
        planned = self.root/'planned'
        return config, links, snippet, effective, mounts, planned

    def test_host_inline_hook_can_be_instrumented_and_uses_both_logs(self):
        config, links, snippet, effective, mounts, planned = self.host_fixture()
        before = snippet.stat().st_ino
        audit.plan(effective, mounts, links, 'nginx', 'https://example.com', '8.8.8.8', 'a'*24, planned, str(config))
        data = web.read_state(planned)
        self.assertEqual({entry['kind'] for entry in data['logs']}, {'access_log', 'error_log'})
        self.assertIsNotNone(data['settings_sha'])
        audit.stage(planned)
        self.assertIn('cs.Allow(crowdsec_checked_ip)', snippet.read_text())
        self.assertEqual(snippet.stat().st_ino, before)

    def test_host_child_hook_or_local_override_cannot_pass_request_proof(self):
        config, links, snippet, effective, mounts, planned = self.host_fixture()
        original = effective.read_text()
        for extension in ('\nserver { access_by_lua_block { return } }', '\nsatisfy any;'):
            effective.write_text(original+extension)
            with self.assertRaises(ValueError):
                audit.plan(effective, mounts, links, 'nginx', 'https://example.com', '8.8.8.8', 'a'*24, planned, str(config))
        effective.write_text(original)
        Path(str(config)+'.local').write_text('APPSEC_URL=http://other.example:7422\n')
        with self.assertRaises(ValueError):
            audit.plan(effective, mounts, links, 'nginx', 'https://example.com', '8.8.8.8', 'a'*24, planned, str(config))

    def test_realip_atomic_update_keeps_existing_file_ownership(self):
        from crowdsec_realip import atomic_text
        import os
        target = self.root/'trusted-proxy.conf'
        target.write_text('original')
        if os.geteuid() == 0:
            os.chown(target, 65534, 65534)
        before = target.stat()
        atomic_text(target, 'managed', 0o640)
        self.assertEqual((target.stat().st_uid, target.stat().st_gid), (before.st_uid, before.st_gid))
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_foreign_bouncer_rejects_readonly_mount_local_override_and_linked_parent(self):
        from crowdsec_config import docker_bouncer_path
        settings = self.root/'bouncer.conf'
        original = 'API_KEY=fixture-only-secret\nAPPSEC_URL=\n'
        settings.write_text(original)
        mounted = {'Type': 'bind', 'RW': True, 'Source': str(self.root), 'Destination': '/config'}
        with patch.object(sys, 'stdin', io.StringIO(json.dumps([mounted]))), redirect_stdout(io.StringIO()):
            docker_bouncer_path('/config/bouncer.conf')
        linked = self.root/'linked'
        linked.symlink_to(self.root)
        for override in ('readonly', 'local', 'linked'):
            mount = dict(mounted)
            if override == 'readonly':
                mount['RW'] = False
            if override == 'local':
                (self.root/'bouncer.conf.local').write_text('APPSEC_URL=http://other.example:7422\n')
            if override == 'linked':
                mount['Source'] = str(linked)
            with self.subTest(override=override), patch.object(sys, 'stdin', io.StringIO(json.dumps([mount]))), self.assertRaises(ValueError):
                docker_bouncer_path('/config/bouncer.conf')
            if (self.root/'bouncer.conf.local').exists():
                (self.root/'bouncer.conf.local').unlink()
        self.assertEqual(settings.read_text(), original)

    def test_bounded_buffer_flush_is_waited_for_and_unknown_flush_is_rejected(self):
        config, links, snippet, effective, mounts, planned = self.host_fixture('buffer=32k flush=40s')
        audit.plan(effective, mounts, links, 'nginx', 'https://example.com', '8.8.8.8', 'a'*24, planned, str(config))
        self.assertEqual(web.read_state(planned)['wait_seconds'], 45)
        for invalid in ('buffer=32k', 'buffer=32k flush=3m'):
            effective.write_text(effective.read_text().replace('buffer=32k flush=40s', invalid))
            with self.assertRaises(ValueError):
                audit.plan(effective, mounts, links, 'nginx', 'https://example.com', '8.8.8.8', 'a'*24, planned, str(config))
            effective.write_text(effective.read_text().replace(invalid, 'buffer=32k flush=40s'))


class AdapterWorkflows(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_host_custom_log_path_is_discovered_without_changing_configuration(self):
        directory = self.base/'custom-http'
        directory.mkdir()
        access = directory/'visitors.log'
        access.touch()
        before = (self.config/'config.yaml').read_bytes()
        stub = 'nginx() { printf "%s\\n" '+shlex.quote(f'http {{ server {{ access_log {access}; }} }}')+'; }'
        result = self.run_shell('check_log_inventory', overrides=stub)
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertEqual((self.config/'config.yaml').read_bytes(), before)
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())
        result = self.run_shell('repair_log_acquis', 'y\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn(str(access), (self.config/'acquis.d/crowdsec-1key-log-repair.yaml').read_text())

    def host_realip(self):
        directory = self.base/'etc/nginx/conf.d'
        directory.mkdir(parents=True)
        self.target = directory/'crowdsec-1key-cloudflare-real-ip.conf'
        helper = self.base/'lib/crowdsec_realip.py'
        helper.write_text(helper.read_text().replace('/etc/nginx/', str(self.base)+'/etc/nginx/'))
        return ('nginx() { record nginx "$@"; case "$1" in -V) echo --with-http_realip_module;; '
                '-T) printf "%s\\n" '+shlex.quote(f'# configuration file {directory.parent}/nginx.conf:')+' '+shlex.quote(f'http {{ include {directory}/*.conf; }}')+'; '
                'if [[ -f '+shlex.quote(str(self.target))+' ]]; then printf "%s\\n" '+shlex.quote(f'# configuration file {self.target}:')+'; cat '+shlex.quote(str(self.target))+'; fi;; esac; }')

    def test_host_realip_apply_repeat_restore_does_not_restart_core(self):
        stub = self.host_realip()
        result = self.run_shell('repair_cloudflare_real_ip apply host', 'nginx\n2\nX-Forwarded-For\n192.0.2.0/24\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        before = self.target.stat().st_ino
        reloads = self.commands().count('systemctl reload nginx')
        result = self.run_shell('repair_cloudflare_real_ip apply host', 'nginx\n2\nX-Forwarded-For\n192.0.2.0/24\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.target.stat().st_ino, before)
        self.assertEqual(self.commands().count('systemctl reload nginx'), reloads)
        result = self.run_shell('repair_cloudflare_real_ip remove host', 'nginx\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertNotIn('restart crowdsec', self.commands())

    def test_host_failed_reload_restores_original_config_and_record(self):
        stub = self.host_realip()+'\nsystemctl() { record systemctl "$@"; [[ "$*" != "reload nginx" ]]; }'
        result = self.run_shell('repair_cloudflare_real_ip apply host', 'nginx\n2\nX-Forwarded-For\n192.0.2.0/24\ny\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse((self.config/'crowdsec-1key-real-ip.json').exists())


class NpmPersistence(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_native_workflows.NativeWorkflows.fixture

    def test_npm_generated_site_rebuild_keeps_custom_entry_and_account(self):
        stub = self.fixture()
        directory = self.base/'npm'
        custom = directory/'nginx/custom'
        custom.mkdir(parents=True)
        target = custom/'http_top.conf'
        original = 'add_header X-Custom retained;\n'
        target.write_text(original)
        (self.base/'mounts').write_text(json.dumps([{'Type': 'bind', 'RW': True, 'Source': str(directory), 'Destination': '/data'}]))
        effective = self.base/'effective'
        main = '# configuration file /etc/nginx/nginx.conf:\nhttp { include /data/nginx/custom/http_top[.]conf; }\n'
        effective.write_text(main)
        self.assertEqual(self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', stub).returncode, 0)
        self.assertTrue(target.read_text().startswith(original))
        before = self.commands().count('bouncers add ')
        installed = target.read_bytes()
        effective.write_text(main+'# configuration file /data/nginx/custom/http_top.conf:\n'+target.read_text()+
                             '# configuration file /data/nginx/proxy_host/99.conf:\nserver { server_name added.example.com; location / { proxy_pass http://backend; } }\n')
        result = self.run_shell('install_docker_web_bouncer', 'openresty\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(target.read_bytes(), installed)
        self.assertEqual(self.commands().count('bouncers add '), before)
        effective.write_text(effective.read_text()+'server { access_by_lua_block { return } }\n')
        result = self.run_shell('install_docker_web_bouncer', 'openresty\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(target.read_bytes(), installed)
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(target.read_text(), original)


class PrivateBridgeWorkflows(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_native_workflows.NativeWorkflows.fixture

    def bridge_fixture(self):
        stub = self.fixture()
        identity = 'a'*64
        inspection = {'HostConfig': {'NetworkMode': 'web'}, 'NetworkSettings': {'Networks': {
            'web': {'NetworkID': identity, 'Gateway': '172.18.0.1'}}}}
        networks = [{'Name': 'web', 'Id': identity, 'Driver': 'bridge',
                     'IPAM': {'Config': [{'Gateway': '172.18.0.1', 'Subnet': '172.18.0.0/24'}]}}]
        (self.base/'inspection').write_text(json.dumps([inspection]))
        (self.base/'networks').write_text(json.dumps(networks))
        self.private = transport.plan(inspection, networks, 'http://172.18.0.1:18080', 'http://172.18.0.1:17422')
        (self.config/'crowdsec-1key-docker-endpoints.json').write_text(json.dumps({'openresty': self.private}))
        stub += '\neval "$(declare -f docker | sed \'1s/docker/docker_base/\')"\n'
        stub += ('docker() { case "$*" in "inspect --format {{.HostConfig.NetworkMode}} "*) echo web;; '
                 '"inspect cid"|"inspect openresty") cat '+shlex.quote(str(self.base/'inspection'))+';; '
                 '"network inspect "*) cat '+shlex.quote(str(self.base/'networks'))+';; '
                 '"exec -i "*) record docker "$@"; echo null;; *) docker_base "$@";; esac; }\n'
                 'ss() { printf "%s\\n" "LISTEN 0 128 127.0.0.1:7422 *:*" "LISTEN 0 128 172.18.0.1:18080 *:*" "LISTEN 0 128 172.18.0.1:17422 *:*"; }')
        return stub

    def test_bridge_install_repeat_disable_and_remove_keep_private_addresses(self):
        stub = self.bridge_fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        settings = self.base/'web/data/crowdsec-1key/bouncer.conf'
        self.assertIn('API_URL=http://172.18.0.1:18080/', settings.read_text())
        self.assertIn('APPSEC_URL=http://172.18.0.1:17422', settings.read_text())
        (self.base/'effective').write_text('# configuration file /usr/local/openresty/1pwaf/data/conf/waf.conf:\n'+self.waf.read_text())
        accounts = self.commands().count('bouncers add ')
        result = self.run_shell('install_docker_web_bouncer', 'openresty\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.commands().count('bouncers add '), accounts)
        result = self.run_shell('yaml_tool appsec "$APPSEC_FILE" && disable_appsec', 'y\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('APPSEC_URL=\n', settings.read_text())
        self.assertIn('API_URL=http://172.18.0.1:18080/', settings.read_text())
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(settings.exists())
        self.assertNotIn('network connect', self.commands())

    def test_private_authentication_failure_revokes_new_key_without_website_changes(self):
        stub = self.bridge_fixture()+'\neval "$(declare -f docker | sed \'1s/docker/docker_private/\')"\ndocker() { if [[ "$*" == "exec -i "* ]]; then return 1; fi; docker_private "$@"; }'
        original = self.waf.read_bytes()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.waf.read_bytes(), original)
        self.assertNotIn('nginx -s reload', self.commands())
        self.assertRegex(self.commands(), 'bouncers delete cs-web-1key-')

    def test_endpoint_change_after_install_does_not_silently_reuse_old_url(self):
        stub = self.bridge_fixture()
        self.assertEqual(self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', stub).returncode, 0)
        changed = {**self.private, 'api_url': 'http://172.18.0.1:18081'}
        (self.config/'crowdsec-1key-docker-endpoints.json').write_text(json.dumps({'openresty': changed}))
        result = self.run_shell('install_docker_web_bouncer', 'openresty\n', stub.replace('172.18.0.1:18080', '172.18.0.1:18081'))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('原安装不一致', result.stdout+result.stderr)

    def test_default_ldnmp_without_lua_keeps_log_and_firewall_path(self):
        stub = self.bridge_fixture()+'\neval "$(declare -f docker | sed \'1s/docker/docker_private/\')"\ndocker() { if [[ "$*" == "exec "*" nginx -V" ]]; then echo "nginx version: nginx/1.26"; return 0; fi; docker_private "$@"; }'
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', stub)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Lua', result.stdout+result.stderr)
        self.assertNotIn('bouncers add ', self.commands())
        self.assertNotIn('nginx -s reload', self.commands())


class PrivateBridgeDiagnostics(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_native_workflows.NativeWorkflows.fixture
    bridge_fixture = PrivateBridgeWorkflows.bridge_fixture

    def diagnose(self, stub, action='diagnose_appsec_containers'):
        before = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                  for directory in (self.config, self.base/'web')
                  for path in directory.rglob('*') if path.is_file()}
        result = self.run_shell(action, overrides=stub)
        after = {path: (path.read_bytes(), path.stat().st_ino, path.stat().st_mtime_ns)
                 for directory in (self.config, self.base/'web')
                 for path in directory.rglob('*') if path.is_file()}
        self.assertEqual(after, before)
        self.assertNotRegex(self.commands(), r'bouncers (add|delete)|nginx -s reload|systemctl (restart|reload)|network (connect|create)|curl')
        return result

    def test_registered_bridge_reports_valid_network_and_listeners_without_claiming_protection(self):
        result = self.diagnose(self.bridge_fixture())
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('网络与宿主机精确监听匹配', result.stdout)
        self.assertIn('http://172.18.0.1:17422', result.stdout)
        self.assertIn('容器连通性和实际防护仍需请求验证', result.stdout)
        self.assertNotIn('请配置私有网络可达', result.stderr)
        self.assertIn('缺少 CrowdSec Web Bouncer', result.stderr)

    def test_unregistered_bridge_keeps_setup_guidance_without_failing(self):
        stub = self.bridge_fixture()
        (self.config/'crowdsec-1key-docker-endpoints.json').unlink()
        result = self.diagnose(stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('未登记私有端点', result.stderr)
        self.assertIn('--configure-docker-endpoints', result.stderr)

    def test_record_for_another_container_does_not_count_as_registered(self):
        stub = self.bridge_fixture()
        (self.config/'crowdsec-1key-docker-endpoints.json').write_text(json.dumps({'other': self.private}))
        result = self.diagnose(stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('未登记私有端点', result.stderr)
        self.assertNotIn('精确监听匹配', result.stdout)

    def test_recreated_bridge_network_is_reported_as_invalid_and_hook_checks_continue(self):
        stub = self.bridge_fixture()
        for filename in ('inspection', 'networks'):
            path = self.base/filename
            path.write_text(path.read_text().replace('a'*64, 'b'*64))
        result = self.diagnose(stub)
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('Docker 网络已变化', result.stderr)
        self.assertIn('已登记私有端点核验失败', result.stderr)
        self.assertIn('缺少 CrowdSec Web Bouncer', result.stderr)

    def test_missing_or_wildcard_listener_does_not_report_registered_bridge_as_valid(self):
        stub = self.bridge_fixture()
        for listener in ('127.0.0.1:7422', '0.0.0.0:17422'):
            with self.subTest(listener=listener):
                result = self.diagnose(stub+'\nss() { echo '+shlex.quote('LISTEN 0 128 '+listener+' *:*')+'; }')
                self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
                self.assertIn('精确监听', result.stderr)
                self.assertNotIn('精确监听匹配', result.stdout)

    def test_corrupt_registration_is_not_misreported_as_unregistered(self):
        stub = self.bridge_fixture()
        for content in ('invalid json', '[]', '{"openresty": null}'):
            with self.subTest(content=content):
                (self.config/'crowdsec-1key-docker-endpoints.json').write_text(content)
                result = self.diagnose(stub)
                self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
                self.assertNotIn('未登记私有端点', result.stderr)
                self.assertNotIn('精确监听匹配', result.stdout)

    def test_host_network_does_not_read_irrelevant_bridge_registration(self):
        stub = self.fixture()
        (self.config/'crowdsec-1key-docker-endpoints.json').write_text('invalid json')
        result = self.diagnose(stub)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('host 网络', result.stdout)
        self.assertNotIn('私有端点', result.stdout+result.stderr)

    def test_appsec_status_propagates_registered_bridge_failure(self):
        stub = self.bridge_fixture()+'\nss() { echo "LISTEN 0 128 127.0.0.1:7422 *:*"; }'
        (self.config/'acquis.d').mkdir()
        (self.config/'acquis.d/crowdsec-1key-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nappsec_configs:\n  - crowdsecurity/appsec-default\nlabels:\n  type: appsec\n')
        result = self.diagnose(stub, 'check_appsec_status')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('已登记私有端点核验失败', result.stderr)
        self.assertIn('AppSec 配置地址存在监听', result.stdout)


if __name__ == '__main__':
    unittest.main()
