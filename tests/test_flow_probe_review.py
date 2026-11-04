"""Regression evidence for safe flow guards and instance-specific web discovery."""
import json
from contextlib import redirect_stdout
import io
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import crowdbastion_flow_probe as probe


class ProbeReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cs = self.root/'etc/crowdsec'
        self.cs.mkdir(parents=True)
        (self.cs/'config.yaml').write_text('api: {}\n')
        self.state = self.root/'var/lib/crowdbastion'
        self.answers = {}

    def discover(self, real_audit=False):
        def runner(args, timeout):
            if real_audit and args[0] == 'env':
                return probe.run_command(args, timeout)
            code, output = self.answers.get(tuple(args), (127, ''))
            return subprocess.CompletedProcess(args, code, output, '')
        return probe.discover(self.cs, self.state, runner=runner)

    def metrics(self, sources):
        self.answers[('cscli', 'metrics', 'show', 'acquisition', '-o', 'json')] = (0, json.dumps({'acquisition': sources}))

    def host(self, effective):
        self.answers[('nginx', '-T')] = (0, effective)

    def acquisitions(self, directory=None, single=None):
        directory = directory or self.cs/'acquis.d'
        directory.mkdir(parents=True, exist_ok=True)
        service = {'acquisition_dir': str(directory)}
        if single is not None:
            service['acquisition_path'] = str(single)
        (self.cs/'config.yaml').write_text(json.dumps({'crowdsec_service': service}))
        return directory

    def listening(self, *addresses):
        self.answers[('ss', '-H', '-lnt')] = (0, ''.join('LISTEN 0 128 '+address+' 0.0.0.0:*\n' for address in addresses))

    def transaction(self, ident='b'*32, state='staged'):
        directory = self.state/'changes'/ident
        directory.mkdir(parents=True)
        (directory/'manifest.json').write_text(json.dumps({'kind': 'network'}))
        (directory/'journal.json').write_text(json.dumps({'state': state, 'deadline': 2_000_000_000}))
        return directory

    def container(self, identity, name='edge', image='registry.example/acme/web:1'):
        item = {'Id': identity, 'Name': '/'+name, 'HostConfig': {'NetworkMode': 'host'}, 'Mounts': []}
        self.answers[('docker', 'inspect', identity)] = (0, json.dumps([item]))
        self.answers[('docker', 'exec', identity, 'nginx', '-T')] = (0, 'http { server { server_name edge.test; } }')
        return {'ID': identity, 'Names': name, 'Image': image}

    def managed_container(self, port=8442, bridge=False):
        import crowdsec_request_audit as audit
        import crowdsec_web as web
        directory = self.acquisitions()
        address = '172.18.0.1' if bridge else '127.0.0.1'
        endpoint = 'http://'+address+':'+str(port)
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: '+address+':'+str(port)+'\n')
        data = self.root/'docker-data'
        data.mkdir()
        mounts = [{'Type': 'bind', 'RW': True, 'Source': str(data), 'Destination': '/data'}]
        effective = 'http { include /data/nginx/custom/http_top.conf; server { server_name edge.test; access_log /data/requests.log; error_log /data/errors.log; } }'
        transport = {'api_url': 'http://172.18.0.1:18080', 'appsec_url': endpoint,
                     'network_id': 'c'*64, 'gateway': '172.18.0.1'} if bridge else None
        plan = web.plan_install(effective, mounts, 'registry.example/acme/web:1',
                                'bridge' if bridge else 'host', 'openresty/1.25', transport)
        stage = self.root/'web-stage'
        stage.mkdir()
        rendered = web.render_hooks(plan)
        for name, text in rendered.items():
            (stage/('target.conf' if name == 'target' else name)).write_text(text)
        api_url = transport['api_url'] if bridge else 'http://127.0.0.1:8080'
        (stage/'bouncer.conf').write_text('API_URL='+api_url+'/\nAPI_KEY=PRIVATE_TEST_KEY\nAPPSEC_URL='+endpoint+'\nAPPSEC_FAILURE_ACTION=deny\nLAPI_FAILURE_ACTION=deny\n')
        installs = self.cs/'crowdsec-1key-web-installs.json'
        web.apply_install(plan, stage, installs, 'edge', 'test-bouncer')
        dumped = '# configuration file /etc/nginx/nginx.conf:\n'+effective+'\n# configuration file '+plan['container_target']+':\n'+rendered['target']
        work = self.root/'request-fixture'
        work.mkdir()
        (work/'effective').write_text(dumped)
        (work/'mounts').write_text(json.dumps(mounts))
        for name in ('requests.log', 'errors.log'):
            (data/name).touch()
        token = 'a'*24
        audit.plan(work/'effective', work/'mounts', installs, 'edge', 'https://edge.test', '8.8.8.8', token, work/'plan')
        hook = Path(plan['host_assets'])/'access.lua'
        original = hook.read_text()
        audit.stage(work/'plan')
        (data/'requests.log').write_text('8.8.8.8 - - [11/Oct/2026:10:00:00 +0000] "GET /?crowdsec_ip_check='+token+' HTTP/1.1" 200 2\n')
        (data/'errors.log').write_text('crowdsec-1key-ip|'+token+'|'+json.dumps({'client': '8.8.8.8', 'bouncer': '8.8.8.8', 'host': 'edge.test'})+'\n')
        with redirect_stdout(io.StringIO()):
            audit.verify(work/'plan', work/'result')
        hook.write_text(original)
        audit.main(['record', str(self.cs/'crowdsec-1key-ip-verifications.json'), 'edge', str(work/'result')])
        identity = 'a'*64
        row = {'ID': identity, 'Names': 'edge', 'Image': 'registry.example/acme/web:1'}
        item = {'Id': identity, 'Name': '/edge', 'HostConfig': {'NetworkMode': 'bridge' if bridge else 'host'}, 'Mounts': mounts}
        self.listening(address+':'+str(port), *([address+':18080'] if bridge else []))
        if bridge:
            item['NetworkSettings'] = {'Networks': {'crowdnet': {'NetworkID': 'c'*64, 'Gateway': address, 'IPAddress': '172.18.0.2'}}}
            (self.cs/'crowdsec-1key-docker-endpoints.json').write_text(json.dumps({'edge': transport}))
            self.answers[('docker', 'network', 'inspect', 'c'*64)] = (0, json.dumps([{'Id': 'c'*64, 'Name': 'crowdnet', 'Driver': 'bridge',
                'IPAM': {'Config': [{'Subnet': '172.18.0.0/16', 'Gateway': address}]}}]))
            for url, suffix, status in ((api_url, '/v1/decisions', '403'), (endpoint, '/', '200')):
                self.answers[('docker', 'exec', identity, 'curl', '-sS', '--noproxy', '*', '--connect-timeout', '1', '--max-time', '2', '-o', '/dev/null', '-w', '%{http_code}', url+suffix)] = (0, status)
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps(row))
        self.answers[('docker', 'inspect', identity)] = (0, json.dumps([item]))
        self.answers[('docker', 'exec', identity, 'nginx', '-T')] = (0, dumped)
        return Path(plan['host_assets'])/'bouncer.conf', item

    def test_normal_hub_index_does_not_make_guard_permanently_incomplete(self):
        hub = self.cs/'hub'
        hub.mkdir()
        (hub/'.index.json').write_bytes(b' ' * 3_976_187)
        self.assertTrue(probe.config_fingerprint(self.cs)[1])
        with self.assertRaises(ValueError):
            probe.read_file(hub/'.index.json')

    def test_large_active_configuration_is_streamed_and_changes_guard(self):
        config = self.cs/'large.yaml'
        config.write_bytes(b'x' * 1_300_000)
        before, complete = probe.config_fingerprint(self.cs)
        self.assertTrue(complete)
        config.write_bytes(b'y' * 1_300_000)
        self.assertNotEqual(probe.config_fingerprint(self.cs)[0], before)

    def test_active_link_into_hub_is_hashed_even_when_cache_is_excluded(self):
        hub = self.cs/'hub/parsers'
        hub.mkdir(parents=True)
        source = hub/'nginx.yaml'
        source.write_text('name: first\n')
        active = self.cs/'parsers'
        active.mkdir()
        (active/'nginx.yaml').symlink_to(source)
        before, complete = probe.config_fingerprint(self.cs)
        self.assertTrue(complete)
        source.write_text('name: second\n')
        after, complete = probe.config_fingerprint(self.cs)
        self.assertTrue(complete)
        self.assertNotEqual(before, after)

    def test_external_links_and_total_budget_remain_incomplete(self):
        outside = self.root/'outside.yaml'
        outside.write_text('untrusted\n')
        (self.cs/'external.yaml').symlink_to(outside)
        self.assertFalse(probe.config_fingerprint(self.cs)[1])
        (self.cs/'external.yaml').unlink()
        (self.cs/'huge.yaml').write_bytes(b'x' * (9 * 1024 * 1024))
        self.assertFalse(probe.config_fingerprint(self.cs)[1])
        self.assertFalse(probe.config_fingerprint(self.cs, deadline=time.monotonic()-1)[1])

    def test_distribution_nginx_module_link_is_hashed_and_rejects_unsafe_permissions(self):
        enabled = self.root/'etc/nginx/modules-enabled'
        available = self.root/'usr/share/nginx/modules-available'
        enabled.mkdir(parents=True)
        available.mkdir(parents=True)
        module = available/'mod-http-geoip2.conf'
        module.write_text('load_module modules/ngx_http_geoip2_module.so;\n')
        (enabled/'50-mod-http-geoip2.conf').symlink_to(module)
        before, complete = probe.config_fingerprint(self.cs)
        self.assertTrue(complete)
        module.write_text('load_module modules/ngx_http_geoip_module.so;\n')
        after, complete = probe.config_fingerprint(self.cs)
        self.assertTrue(complete)
        self.assertNotEqual(before, after)
        module.chmod(0o666)
        self.assertFalse(probe.config_fingerprint(self.cs)[1])
        module.chmod(0o644)
        available.chmod(0o777)
        self.assertFalse(probe.config_fingerprint(self.cs)[1])

    def test_cyclic_active_link_is_incomplete_instead_of_crashing_discovery(self):
        (self.cs/'cycle.yaml').symlink_to('cycle.yaml')
        self.assertFalse(self.discover()['fingerprint_complete'])

    def test_ssh_metrics_cannot_complete_website_log_evidence(self):
        self.host('http { server { server_name example.com; access_log /var/log/nginx/access.log; } }')
        self.metrics({'file:/var/log/auth.log': {'reads': 8, 'parsed': 8}})
        report = self.discover()
        self.assertEqual(report['checks']['logs'], 'ok')
        self.assertEqual(report['targets'][0].get('web_logs'), 'missing')
        self.assertEqual(report['targets'][0].get('server_names'), ['example.com'])

    def test_matching_log_sources_classify_busy_idle_and_unparsed_instances(self):
        self.host('http { server { server_name one.test two.test; access_log /var/log/nginx/access.log; } }')
        for counters, expected in (({'reads': 0, 'parsed': 0}, 'pending'),
                                   ({'reads': 4, 'parsed': 0}, 'fault'),
                                   ({'reads': 4, 'parsed': 4}, 'ok')):
            with self.subTest(expected=expected):
                self.metrics({'file:/var/log/nginx/access.log': counters})
                self.assertEqual(self.discover()['targets'][0].get('web_logs'), expected)

    def test_all_configured_access_logs_need_precise_evidence(self):
        self.host('http { access_log /logs/access.log; server { access_log /logs/other.log; } }')
        self.metrics({'file:/logs/access.log': {'reads': 5, 'parsed': 5},
                      'file:/logs/other.log.old': {'reads': 5, 'parsed': 5}})
        self.assertEqual(self.discover()['targets'][0].get('web_logs'), 'missing')

    def test_dynamic_or_unavailable_log_evidence_stays_unknown(self):
        self.metrics({'file:/logs/access.log': {'reads': 5, 'parsed': 5}})
        self.host('http { access_log /logs/$host.log; }')
        self.assertEqual(self.discover()['targets'][0].get('web_logs'), 'unknown')
        self.host('http { access_log /logs/access.log; }')
        self.answers[('cscli', 'metrics', 'show', 'acquisition', '-o', 'json')] = (0, '{')
        self.assertEqual(self.discover()['targets'][0].get('web_logs'), 'unknown')

    def test_stream_log_and_names_do_not_prove_http_site_evidence(self):
        self.host('stream { server { server_name bogus.test; access_log /logs/tcp.log; } } http { server { server_name actual.test; } }')
        self.metrics({'file:/logs/tcp.log': {'reads': 5, 'parsed': 5}})
        target = self.discover()['targets'][0]
        self.assertEqual(target.get('server_names'), ['actual.test'])
        self.assertNotEqual(target.get('web_logs'), 'ok')

    def test_docker_logs_require_persistent_host_path_mapping(self):
        identity = 'a' * 64
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps({'ID': identity, 'Names': 'edge', 'Image': 'nginx:alpine'}))
        item = {'Id': identity, 'Name': '/edge', 'HostConfig': {'NetworkMode': 'host'},
                'Mounts': [{'Type': 'bind', 'Source': '/srv/edge/logs', 'Destination': '/var/log/nginx', 'RW': False}]}
        self.answers[('docker', 'inspect', identity)] = (0, json.dumps([item]))
        self.answers[('docker', 'exec', identity, 'nginx', '-T')] = (0, 'http { server { server_name edge.test; access_log /var/log/nginx/access.log; } }')
        self.metrics({'file:/srv/edge/logs/access.log': {'reads': 5, 'parsed': 5}})
        self.assertEqual(self.discover()['targets'][0].get('web_logs'), 'ok')
        item['Mounts'] = []
        self.answers[('docker', 'inspect', identity)] = (0, json.dumps([item]))
        self.assertEqual(self.discover()['targets'][0].get('web_logs'), 'unknown')

    def test_custom_container_without_name_or_image_hints_is_identified_by_nginx(self):
        row = self.container('a'*64)
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps(row))
        report = self.discover()
        self.assertEqual([target['id'] for target in report['targets']], ['docker:'+'a'*64])
        self.assertEqual(report['targets'][0]['server_names'], ['edge.test'])

    def test_known_web_containers_are_prioritized_before_the_candidate_limit(self):
        identity = 'f'*64
        unknown = [{'ID': '%064x' % index, 'Names': 'worker'+str(index), 'Image': 'registry.example/acme/worker:1'}
                   for index in range(1, 34)]
        for registered in (True, False):
            with self.subTest(registered=registered):
                registry = self.cs/'crowdsec-1key-web-installs.json'
                if registered:
                    registry.write_text('{"edge":{}}')
                elif registry.exists():
                    registry.unlink()
                row = self.container(identity, image='registry.example/acme/web:1' if registered else 'nginx:alpine')
                self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, '\n'.join(json.dumps(item) for item in unknown+[row]))
                report = self.discover()
                self.assertEqual([target['id'] for target in report['targets']], ['docker:'+identity])
                self.assertTrue(any('网站容器扫描' in message for message in report['limitations']))

    def test_failed_unknown_container_probe_does_not_become_a_website_target(self):
        row = self.container('a'*64)
        self.answers[('docker', 'exec', 'a'*64, 'nginx', '-T')] = (127, '')
        self.answers[('docker', 'ps', '--no-trunc', '--format', '{{json .}}')] = (0, json.dumps(row))
        self.assertEqual(self.discover()['targets'], [])

    def test_container_budget_cutoff_reports_an_incomplete_scan(self):
        row = self.container('a'*64)
        actual_monotonic = time.monotonic
        shift = [0]
        def runner(args, timeout):
            if args == ['docker', 'ps', '--no-trunc', '--format', '{{json .}}']:
                shift[0] = 20
                return subprocess.CompletedProcess(args, 0, json.dumps(row), '')
            return subprocess.CompletedProcess(args, 127, '', '')
        with patch.object(probe.time, 'monotonic', side_effect=lambda: actual_monotonic()+shift[0]):
            report = probe.discover(self.cs, self.state, runner=runner)
        self.assertEqual(report['targets'], [])
        self.assertTrue(any('网站容器扫描' in message for message in report['limitations']))

    def test_web_rules_require_enabled_nginx_and_basic_http_collections(self):
        command = ('cscli', 'collections', 'list', '-o', 'json')
        cases = [([], 'missing'),
                 ([{'name': 'crowdsecurity/linux', 'status': 'enabled'}], 'missing'),
                 ([{'name': 'crowdsecurity/nginx', 'status': 'enabled'}, {'name': 'crowdsecurity/base-http-scenarios', 'status': 'disabled'}], 'missing'),
                 ([{'name': 'crowdsecurity/nginx', 'status': 'enabled,tainted'}, {'name': 'crowdsecurity/base-http-scenarios', 'status': 'enabled'}], 'missing'),
                 ([{'name': 'crowdsecurity/nginx', 'status': 'enabled'}, {'name': 'crowdsecurity/base-http-scenarios', 'status': 'enabled'}], 'ok')]
        for items, expected in cases:
            with self.subTest(expected=expected, items=items):
                self.answers[command] = (0, json.dumps({'collections': items}))
                self.assertEqual(self.discover()['checks'].get('web_rules'), expected)
        self.answers[command] = (0, '{')
        self.assertEqual(self.discover()['checks'].get('web_rules'), 'unknown')

    def test_component_fingerprints_ignore_unrelated_websites_notifications_and_checks(self):
        before = self.discover().get('component_fingerprints')
        self.assertIsInstance(before, dict)
        self.assertEqual(set(before), {'core', 'firewall', 'appsec', 'proxy'})
        (self.cs/'crowdsec-1key-web-installs.json').write_text('{"other":{"secret":"PRIVATE"}}')
        (self.cs/'notifications').mkdir()
        (self.cs/'notifications/mail.yaml').write_text('changed: true\n')
        self.metrics({'file:/var/log/auth.log': {'reads': 8, 'parsed': 8}})
        self.assertEqual(self.discover()['component_fingerprints'], before)
        (self.cs/'config.yaml').write_text('api: {changed: true}\n')
        after = self.discover()['component_fingerprints']
        self.assertNotEqual(after['core'], before['core'])
        self.assertEqual(after['firewall'], before['firewall'])
        self.assertEqual(after['proxy'], before['proxy'])

    def test_core_component_tracks_actual_acquisition_configuration(self):
        before = self.discover()['component_fingerprints']['core']
        (self.cs/'acquis.yaml').write_text('filenames: [/var/log/auth.log]\n')
        first = self.discover()['component_fingerprints']['core']
        self.assertNotEqual(first, before)
        directory = self.cs/'acquis.d'
        directory.mkdir()
        (directory/'custom.yaml').write_text('filenames: [/srv/audit.log]\n')
        self.assertNotEqual(self.discover()['component_fingerprints']['core'], first)

    def test_firewall_and_proxy_changes_affect_only_their_components(self):
        before = self.discover().get('component_fingerprints', {})
        bouncers = self.cs/'bouncers'
        bouncers.mkdir()
        (bouncers/'crowdsec-firewall-bouncer.yaml').write_text('api_key: PRIVATE\n')
        after = self.discover().get('component_fingerprints', {})
        self.assertNotEqual(after.get('firewall'), before.get('firewall'))
        self.assertEqual(after.get('core'), before.get('core'))
        v2bx = self.root/'etc/V2bX'
        v2bx.mkdir()
        (v2bx/'config.json').write_text('{}')
        final = self.discover().get('component_fingerprints', {})
        self.assertNotEqual(final.get('proxy'), after.get('proxy'))
        self.assertEqual(final.get('firewall'), after.get('firewall'))

    def test_proxy_fingerprint_hashes_configuration_instead_of_observer_runtime_files(self):
        directory = self.root/'usr/local/lib/crowdsec-v2bx-observer'
        directory.mkdir(parents=True)
        (directory/'config.json').write_text('{"enabled":true}')
        initial = self.discover()
        before = initial['component_fingerprints']['proxy']
        (directory/'runtime.log').write_text('new event\n')
        self.assertEqual(self.discover()['component_fingerprints']['proxy'], before)
        self.assertEqual(self.discover()['fingerprint'], initial['fingerprint'])
        (directory/'config.json').write_text('{"enabled":false}')
        self.assertNotEqual(self.discover()['component_fingerprints']['proxy'], before)

    def test_target_integration_hash_tracks_own_bouncer_without_raw_secrets(self):
        self.host('http { server { server_name one.test; } }')
        before = self.discover()['targets'][0].get('integration_hash')
        bouncers = self.cs/'bouncers'
        bouncers.mkdir()
        config = bouncers/'crowdsec-nginx-bouncer.conf'
        config.write_text('API_KEY=VERY_PRIVATE_SECRET\n')
        after = self.discover()
        self.assertNotEqual(after['targets'][0].get('integration_hash'), before)
        self.assertNotIn('VERY_PRIVATE_SECRET', json.dumps(after))
        (bouncers/'crowdsec-openresty-bouncer.conf').write_text('API_KEY=OTHER\n')
        self.assertEqual(self.discover()['targets'][0].get('integration_hash'), after['targets'][0]['integration_hash'])

    def test_malformed_appsec_registration_keeps_integration_unknown(self):
        self.host('http { server { server_name one.test; } }')
        (self.cs/'crowdsec-1key-appsec-links.yaml').write_text('broken: [\n')
        self.assertIsNone(self.discover()['targets'][0]['integration_hash'])

    def test_unsafe_component_configuration_cannot_produce_a_reliable_hash(self):
        bouncers = self.cs/'bouncers'
        bouncers.mkdir()
        config = bouncers/'crowdsec-firewall-bouncer.yaml'
        config.write_text('api_key: SECRET\n')
        config.chmod(0o666)
        self.assertIsNone(self.discover()['component_fingerprints']['firewall'])
        self.assertFalse(self.discover()['fingerprint_complete'])

    def test_external_appsec_source_is_detected_without_tool_owned_filename(self):
        directory = self.acquisitions()
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        self.listening('127.0.0.1:8442')
        report = self.discover()
        self.assertIs(report['inventory']['appsec'], True)
        self.assertEqual(report['checks']['appsec'], 'ok')

    def test_appsec_follows_effective_custom_directory_and_single_file(self):
        directory = self.cs/'acquis.d'
        directory.mkdir()
        (directory/'ignored.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n')
        custom = self.root/'custom-acquis'
        custom.mkdir()
        single = self.root/'standalone-acquis.yaml'
        single.write_text('source: appsec\nlisten_addr: "[::1]:9442"\n')
        self.acquisitions()
        (self.cs/'config.yaml.local').write_text(json.dumps({'crowdsec_service': {
            'acquisition_dir': str(custom), 'acquisition_path': str(single)}}))
        (custom/'edge.yml').write_text('source: appsec\nlisten_addr: 127.0.0.2:8442\n')
        self.listening('[::1]:9442', '127.0.0.2:8442')
        report = self.discover()
        self.assertIs(report['inventory']['appsec'], True)
        self.assertEqual(report['checks']['appsec'], 'ok')

    def test_all_effective_appsec_listeners_need_current_socket_evidence(self):
        directory = self.acquisitions()
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n---\nsource: appsec\nlisten_addr: "[::1]:8442"\n')
        self.listening('127.0.0.1:7422')
        self.assertNotEqual(self.discover()['checks']['appsec'], 'ok')
        self.listening('127.0.0.1:7422', '[::1]:8442')
        self.assertEqual(self.discover()['checks']['appsec'], 'ok')
        self.listening()
        self.assertNotEqual(self.discover()['checks']['appsec'], 'ok')

    def test_malformed_acquisition_never_claims_appsec_is_missing_or_healthy(self):
        directory = self.acquisitions()
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: [\n')
        report = self.discover()
        self.assertIsNone(report['inventory']['appsec'])
        self.assertEqual(report['checks']['appsec'], 'unknown')
        self.assertIsNone(report['component_fingerprints']['appsec'])
        self.assertTrue(report['limitations'])

    def test_appsec_custom_acquisition_changes_invalidate_global_and_component_guard(self):
        directory = self.acquisitions(self.root/'custom-acquis')
        config = directory/'appsec.yaml'
        config.write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        before = self.discover()
        self.assertTrue(before['fingerprint_complete'])
        config.write_text('source: appsec\nlisten_addr: 127.0.0.1:9442\n')
        after = self.discover()
        self.assertTrue(after['fingerprint_complete'])
        self.assertNotEqual(after['fingerprint'], before['fingerprint'])
        self.assertNotEqual(after['component_fingerprints']['appsec'], before['component_fingerprints']['appsec'])
        self.assertNotEqual(after['component_fingerprints']['core'], before['component_fingerprints']['core'])
        self.assertNotEqual(probe.config_fingerprint(self.cs)[0], before['fingerprint'])

    def test_explicit_active_acquisition_inside_hub_is_not_treated_as_unused_cache(self):
        directory = self.acquisitions(self.cs/'hub/active-acquis')
        config = directory/'appsec.yaml'
        config.write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        before = self.discover()
        config.write_text('source: appsec\nlisten_addr: 127.0.0.1:9442\n')
        self.assertNotEqual(self.discover()['fingerprint'], before['fingerprint'])

    def test_acquisition_parent_traversal_cannot_escape_the_guard_roots(self):
        directory = self.acquisitions(self.cs/'../external-acquis')
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        report = self.discover()
        self.assertIsNone(report['inventory']['appsec'])
        self.assertFalse(report['fingerprint_complete'])

    def test_appsec_confirmed_absence_uses_effective_configuration(self):
        self.acquisitions()
        report = self.discover()
        self.assertIs(report['inventory']['appsec'], False)
        self.assertEqual(report['checks']['appsec'], 'missing')

    def test_appsec_component_tracks_effective_locations_without_unrelated_acquisition_content(self):
        first = self.acquisitions(self.root/'first-acquis')
        (first/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        before = self.discover()['component_fingerprints']['appsec']
        (first/'other-site.yaml').write_text('filenames: [/var/log/other.log]\nlabels: {type: nginx}\n')
        self.assertEqual(self.discover()['component_fingerprints']['appsec'], before)
        old_managed = self.cs/'acquis.d'
        old_managed.mkdir()
        (old_managed/'crowdsec-1key-appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:1111\n')
        self.assertEqual(self.discover()['component_fingerprints']['appsec'], before)
        self.acquisitions(self.root/'second-acquis')
        empty_first = self.discover()['component_fingerprints']['appsec']
        self.acquisitions(self.root/'third-acquis')
        self.assertNotEqual(self.discover()['component_fingerprints']['appsec'], empty_first)

    def test_invalid_acquisition_document_structure_is_unknown(self):
        directory = self.acquisitions()
        (directory/'appsec.yaml').write_text('- source: appsec\n  listen_addr: 127.0.0.1:7422\n')
        self.assertIsNone(self.discover()['inventory']['appsec'])
        self.assertEqual(self.discover()['checks']['appsec'], 'unknown')

    def test_stdlib_only_fresh_entry_and_existing_yaml_dependency_failure_are_distinct(self):
        script = '''import json, pathlib, subprocess, sys
sys.path.insert(0, sys.argv[1])
import crowdbastion_flow_probe as probe
root = pathlib.Path(sys.argv[2])
def runner(args, timeout):
    if args == ['nginx', '-T'] and (root/'crowdsec-1key-appsec-links.yaml').exists():
        return subprocess.CompletedProcess(args, 0, 'http { server { server_name one.test; } }', '')
    return subprocess.CompletedProcess(args, 127, '', '')
print(json.dumps(probe.discover(root, root/'state', runner=runner)))
'''
        lib = str(Path(__file__).resolve().parents[1]/'lib')
        fresh = self.root/'fresh/etc/crowdsec'
        result = subprocess.run([sys.executable, '-S', '-c', script, lib, str(fresh)], capture_output=True, text=True, check=True)
        fresh_report = json.loads(result.stdout)
        self.assertIs(fresh_report['inventory']['appsec'], False)
        result = subprocess.run([sys.executable, '-S', '-c', script, lib, str(self.cs)], capture_output=True, text=True, check=True)
        existing = json.loads(result.stdout)
        self.assertIsNone(existing['inventory']['appsec'])
        self.assertEqual(existing['checks']['appsec'], 'unknown')
        self.assertTrue(existing['limitations'])
        (self.cs/'crowdsec-1key-appsec-links.yaml').write_text('{}')
        result = subprocess.run([sys.executable, '-S', '-c', script, lib, str(self.cs)], capture_output=True, text=True, check=True)
        self.assertIsNone(json.loads(result.stdout)['targets'][0]['integration_hash'])

    def test_existing_yaml_parsing_cannot_overrun_the_shared_probe_budget(self):
        self.acquisitions()
        # A large mapping makes YAML parsing itself consume the time budget.
        (self.cs/'config.yaml').write_text('crowdsec_service:\n  acquisition_dir: '+str(self.cs/'acquis.d')+'\n'+
                                         ''.join('key_%05d: value\n' % index for index in range(45000)))
        started = time.monotonic()
        report = probe.discover(self.cs, self.state, budget=0.03,
                                runner=lambda args, timeout: subprocess.CompletedProcess(args, 127, '', ''))
        self.assertLess(time.monotonic()-started, 0.5)
        self.assertEqual(report['checks']['appsec'], 'unknown')

    def test_missing_changes_is_complete_and_valid_transactions_are_observed(self):
        report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), True)
        self.transaction()
        report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), True)
        self.assertEqual(report['pending'][0]['state'], 'staged')

    def test_corrupt_or_ambiguous_transaction_records_block_guard(self):
        directory = self.transaction()
        manifest = directory/'manifest.json'
        journal = directory/'journal.json'
        cases = [('bad-json', '{', '{"state":"committed","deadline":2000000000}'),
                 ('manifest-list', '[]', '{"state":"committed","deadline":2000000000}'),
                 ('journal-list', '{"kind":"network"}', '[]'),
                 ('unknown-kind', '{"kind":"other"}', '{"state":"committed","deadline":2000000000}'),
                 ('unknown-state', '{"kind":"network"}', '{"state":"other","deadline":2000000000}'),
                 ('no-deadline', '{"kind":"network"}', '{"state":"committed"}'),
                 ('boolean-deadline', '{"kind":"network"}', '{"state":"committed","deadline":true}'),
                 ('oversized-deadline', '{"kind":"network"}', json.dumps({'state': 'committed', 'deadline': 10**400})),
                 ('nonfinite-deadline', '{"kind":"network"}', '{"state":"committed","deadline":NaN}'),
                 ('bad-effects', '{"kind":"network","effects":"broken"}', '{"state":"committed","deadline":2000000000}'),
                 ('bad-items', '{"kind":"network"}', '{"state":"committed","deadline":2000000000,"items":{}}'),
                 ('duplicate-state', '{"kind":"network"}', '{"state":"staged","state":"committed","deadline":2000000000}')]
        for name, manifest_text, journal_text in cases:
            with self.subTest(name=name):
                manifest.write_text(manifest_text)
                journal.write_text(journal_text)
                report = self.discover()
                self.assertIs(report.get('pending_scan_complete'), False)
                self.assertFalse(report['fingerprint_complete'])
                self.assertTrue(report['limitations'])

    def test_changes_root_file_or_symlink_is_unknown(self):
        self.state.mkdir(parents=True)
        root = self.state/'changes'
        root.write_text('not a directory')
        self.assertIs(self.discover().get('pending_scan_complete'), False)
        root.unlink()
        outside = self.root/'outside-changes'
        outside.mkdir()
        root.symlink_to(outside, target_is_directory=True)
        report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), False)
        self.assertFalse(report['fingerprint_complete'])

    def test_transaction_symlink_and_writable_record_are_unknown(self):
        directory = self.transaction()
        journal = directory/'journal.json'
        journal.chmod(0o666)
        report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), False)
        self.assertFalse(report['fingerprint_complete'])
        journal.chmod(0o644)
        directory.rename(self.state/'original-transaction')
        directory.symlink_to(self.state/'original-transaction', target_is_directory=True)
        self.assertIs(self.discover().get('pending_scan_complete'), False)

    def test_changes_listing_failure_is_unknown(self):
        self.transaction()
        original = probe.os.scandir
        def broken(path):
            if Path(path) == self.state/'changes':
                raise PermissionError('fixture listing denied')
            return original(path)
        with patch.object(probe.os, 'scandir', side_effect=broken):
            report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), False)
        self.assertFalse(report['fingerprint_complete'])

    def test_129th_pending_transaction_cannot_be_silently_ignored(self):
        for index in range(128):
            self.transaction('%032x' % index, 'committed')
        self.transaction('f'*32)
        report = self.discover()
        self.assertIs(report.get('pending_scan_complete'), False)
        self.assertFalse(report['fingerprint_complete'])

    def test_transaction_scan_budget_exhaustion_blocks_guard(self):
        self.transaction()
        report = probe.discover(self.cs, self.state, budget=0,
                                runner=lambda args, timeout: subprocess.CompletedProcess(args, 127, '', ''))
        self.assertIs(report.get('pending_scan_complete'), False)
        self.assertFalse(report['fingerprint_complete'])

    def test_optional_container_budget_exhaustion_preserves_recovery_inventory(self):
        directory = self.transaction(state='committed')
        row = self.container('a'*64)
        actual_monotonic = time.monotonic
        for state in ('committed', 'staged'):
            with self.subTest(state=state):
                (directory/'journal.json').write_text(json.dumps({'state': state, 'deadline': 2_000_000_000}))
                shift = [0]
                def runner(args, timeout):
                    if args == ['docker', 'ps', '--no-trunc', '--format', '{{json .}}']:
                        return subprocess.CompletedProcess(args, 0, json.dumps(row), '')
                    if args == ['docker', 'inspect', 'a'*64]:
                        shift[0] = 20
                    return subprocess.CompletedProcess(args, 127, '', '')
                with patch.object(probe.time, 'monotonic', side_effect=lambda: actual_monotonic()+shift[0]):
                    report = probe.discover(self.cs, self.state, runner=runner)
                self.assertIs(report['pending_scan_complete'], True)
                self.assertTrue(report['fingerprint_complete'])
                expected = [] if state == 'committed' else [{'kind': 'network', 'state': 'staged', 'deadline': 2_000_000_000}]
                self.assertEqual(report['pending'], expected)

    def test_optional_container_budget_exhaustion_preserves_appsec_listener_evidence(self):
        directory = self.acquisitions()
        (directory/'appsec.yaml').write_text('source: appsec\nlisten_addr: 127.0.0.1:8442\n')
        row = self.container('a'*64)
        actual_monotonic = time.monotonic
        shift = [0]
        def runner(args, timeout):
            if args == ['ss', '-H', '-lnt']:
                return subprocess.CompletedProcess(args, 0, 'LISTEN 0 128 127.0.0.1:8442 0.0.0.0:*\n', '')
            if args == ['docker', 'ps', '--no-trunc', '--format', '{{json .}}']:
                return subprocess.CompletedProcess(args, 0, json.dumps(row), '')
            if args == ['docker', 'inspect', 'a'*64]:
                shift[0] = 20
            return subprocess.CompletedProcess(args, 127, '', '')
        with patch.object(probe.time, 'monotonic', side_effect=lambda: actual_monotonic()+shift[0]):
            report = probe.discover(self.cs, self.state, runner=runner)
        self.assertEqual(report['checks']['appsec'], 'ok')

    def test_real_docker_ip_proof_cannot_hide_an_invalid_appsec_endpoint(self):
        config, _ = self.managed_container(port=9442)
        before = self.discover(real_audit=True)['targets'][0]
        self.assertTrue(before['connected'])
        self.assertEqual(before['realip'], 'verified')
        config.write_text(config.read_text().replace('APPSEC_URL=http://127.0.0.1:9442', 'APPSEC_URL=http://127.0.0.1:1'))
        after = self.discover(real_audit=True)['targets'][0]
        self.assertFalse(after['connected'])
        self.assertEqual(after['realip'], 'verified')

    def test_real_host_hook_requires_its_actual_appsec_listener(self):
        directory = self.acquisitions()
        source = directory/'appsec.yaml'
        source.write_text('source: appsec\nlisten_addr: 127.0.0.1:17422\n')
        self.listening('127.0.0.1:17422')
        config = self.cs/'bouncers/crowdsec-nginx-bouncer.conf'
        config.parent.mkdir()
        config.write_text('API_KEY=PRIVATE_TEST_KEY\nAPPSEC_URL=http://127.0.0.1:7422\n')
        (self.cs/'crowdsec-1key-appsec-links.yaml').write_text(json.dumps({str(config): ''}))
        snippet = self.root/'etc/nginx/conf.d/crowdsec_nginx.conf'
        snippet.parent.mkdir(parents=True)
        snippet.write_text('init_by_lua_block { local cs = require "crowdsec"; cs.init("'+str(config)+'", "test") }\n'
                           'access_by_lua_block { local cs = require "crowdsec"; cs.Allow(ngx.var.remote_addr) }\n')
        self.host('# configuration file '+str(self.root/'etc/nginx/nginx.conf')+':\n'
                  'http { include '+str(snippet)+'; server { server_name example.com; } }\n'
                  '# configuration file '+str(snippet)+':\n'+snippet.read_text())
        report = self.discover(real_audit=True)
        self.assertEqual(report['checks']['appsec'], 'ok')
        self.assertFalse(report['targets'][0]['connected'])
        source.write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\n')
        self.listening('127.0.0.1:7422')
        self.assertTrue(self.discover(real_audit=True)['targets'][0]['connected'])
        source.write_text('source: appsec\nlisten_addr: 0.0.0.0:7422\n')
        self.listening('0.0.0.0:7422')
        self.assertTrue(self.discover(real_audit=True)['targets'][0]['connected'])
        self.answers[('ss', '-H', '-lnt')] = (127, '')
        self.assertFalse(self.discover(real_audit=True)['targets'][0]['connected'])

    def test_real_docker_ip_proof_cannot_hide_a_shadow_mounted_local_override(self):
        config, item = self.managed_container()
        override = self.root/'actual-local.conf'
        override.write_text('APPSEC_URL=http://127.0.0.1:1\n')
        item['Mounts'].append({'Type': 'bind', 'RW': True, 'Source': str(override),
                               'Destination': '/data/crowdsec-1key/bouncer.conf.local'})
        self.answers[('docker', 'inspect', item['Id'])] = (0, json.dumps([item]))
        report = self.discover(real_audit=True)
        self.assertFalse(report['targets'][0]['connected'])
        self.assertEqual(report['targets'][0]['realip'], 'verified')
        self.assertNotIn('PRIVATE_TEST_KEY', json.dumps(report))

    def test_real_docker_bridge_connection_requires_its_verified_registered_endpoint(self):
        config, _ = self.managed_container(port=17422, bridge=True)
        before = self.discover(real_audit=True)['targets'][0]
        self.assertTrue(before['transport'])
        self.assertTrue(before['connected'])
        config.write_text(config.read_text().replace('APPSEC_URL=http://172.18.0.1:17422', 'APPSEC_URL=http://172.18.0.1:1'))
        after = self.discover(real_audit=True)['targets'][0]
        self.assertTrue(after['transport'])
        self.assertFalse(after['connected'])
        self.assertEqual(after['realip'], 'verified')
        # A second healthy engine listener cannot replace the endpoint that
        # was verified for this bridge's private transport registration.
        with (self.cs/'acquis.d/appsec.yaml').open('a') as stream:
            stream.write('---\nsource: appsec\nlisten_addr: 172.18.0.1:17423\n')
        self.listening('172.18.0.1:17422', '172.18.0.1:17423', '172.18.0.1:18080')
        config.write_text(config.read_text().replace('APPSEC_URL=http://172.18.0.1:1\n', 'APPSEC_URL=http://172.18.0.1:17423\n'))
        report = self.discover(real_audit=True)
        self.assertEqual(report['checks']['appsec'], 'ok')
        self.assertTrue(report['targets'][0]['transport'])
        self.assertFalse(report['targets'][0]['connected'])

    def test_real_completed_engine_root_is_a_complete_nonpending_inventory(self):
        from crowdbastion_change import Engine
        class Adapter:
            def verify(self, metadata):
                return True
        class Timer:
            def arm(self, root, ident, runtime, deadline):
                pass
            def disarm(self, ident):
                pass
        engine = Engine(self.state/'changes', Adapter(), scheduler=Timer(),
                        guard=lambda: None, lock_path=self.state/'maintenance.lock')
        transaction = engine.apply('network', [], timeout=60)
        self.assertEqual(engine.commit(transaction['id'])['state'], 'committed')
        report = self.discover()
        self.assertIs(report['pending_scan_complete'], True)
        self.assertTrue(report['fingerprint_complete'])
        self.assertEqual(report['pending'], [])

    def test_invalid_managed_marker_is_an_incomplete_inventory(self):
        self.transaction(state='committed')
        marker = self.state/'changes/.crowdbastion-managed'
        for text in ('{"version":true}', '{"version":1,"extra":1}', '[]', '{'):
            with self.subTest(text=text):
                marker.write_text(text)
                report = self.discover()
                self.assertIs(report['pending_scan_complete'], False)
                self.assertFalse(report['fingerprint_complete'])

    def test_missing_journal_preparation_remains_unknown(self):
        directory = self.transaction()
        (directory/'journal.json').unlink()
        self.assertIs(self.discover()['pending_scan_complete'], False)

    def test_firewall_migration_requires_safe_directory_and_terminal_marker(self):
        self.state.mkdir(parents=True)
        migration = self.state/'firewall-migration'
        migration.write_text('not a directory')
        self.assertIs(self.discover()['pending_scan_complete'], False)
        migration.unlink()
        migration.mkdir()
        report = self.discover()
        self.assertIs(report['pending_scan_complete'], True)
        self.assertEqual(report['pending'], [{'kind': 'firewall', 'state': 'migration_pending'}])
        outside = self.root/'outside-committed'
        outside.touch()
        (migration/'committed').symlink_to(outside)
        self.assertIs(self.discover()['pending_scan_complete'], False)
        (migration/'committed').unlink()
        (migration/'committed').touch()
        report = self.discover()
        self.assertIs(report['pending_scan_complete'], True)
        self.assertEqual(report['pending'], [])

    def test_invalid_acceptance_timestamps_are_read_only_unavailable_history(self):
        from crowdbastion_ux import save_acceptance
        path = self.state/'relay-acceptance.json'
        save_acceptance(path, self.cs, {'target': '203.0.113.8', 'port': 443,
                                       'protocol': 'TCP', 'family': 'ip', 'hook': 'input'}, 0)
        record = json.loads(path.read_text())
        for timestamp in (10**400, True, '0', float('nan'), float('inf'), None, []):
            with self.subTest(timestamp=repr(timestamp)):
                record['time'] = timestamp
                path.write_text(json.dumps(record))
                before = path.read_bytes()
                report = self.discover()
                self.assertFalse(report['acceptance']['valid'])
                self.assertIn('无法完整核验', report['acceptance']['summary'])
                self.assertEqual(path.read_bytes(), before)

    def test_valid_acceptance_is_not_verified_when_the_probe_budget_is_zero(self):
        from crowdbastion_ux import save_acceptance
        hub = self.cs/'hub'
        hub.mkdir()
        for index in range(600):
            (hub/('%04d.yaml' % index)).write_text('name: cached\n')
        path = self.state/'relay-acceptance.json'
        save_acceptance(path, self.cs, {'target': '203.0.113.8', 'port': 443,
                                      'protocol': 'TCP', 'family': 'ip', 'hook': 'input'}, 0)
        before = path.read_bytes()
        report = probe.discover(self.cs, self.state, budget=0,
                                runner=lambda args, timeout: subprocess.CompletedProcess(args, 127, '', ''))
        self.assertFalse(report['acceptance']['valid'])
        self.assertIn('尚未核验', report['acceptance']['summary'])
        self.assertEqual(path.read_bytes(), before)

    def test_acceptance_worker_timeout_is_bounded_and_keeps_history_unchanged(self):
        from crowdbastion_ux import save_acceptance
        path = self.state/'relay-acceptance.json'
        save_acceptance(path, self.cs, {'target': '203.0.113.8', 'port': 443,
                                      'protocol': 'TCP', 'family': 'ip', 'hook': 'input'}, 0)
        before = path.read_bytes()
        actual_run = probe.run_command
        def slow_history_worker(args, timeout):
            if any('_parse_acceptance_history' in str(argument) for argument in args):
                # Exercise the actual subprocess timeout and termination path.
                return actual_run([sys.executable, '-c', 'import time; time.sleep(2)'], timeout)
            return actual_run(args, timeout)
        started = time.monotonic()
        with patch.object(probe, 'run_command', side_effect=slow_history_worker):
            report = probe.discover(self.cs, self.state, budget=0.2,
                                    runner=lambda args, timeout: subprocess.CompletedProcess(args, 127, '', ''))
        self.assertLess(time.monotonic()-started, 0.8)
        self.assertFalse(report['acceptance']['valid'])
        self.assertEqual(path.read_bytes(), before)

    def test_normal_acceptance_history_is_verified_within_the_shared_budget(self):
        from crowdbastion_ux import save_acceptance
        path = self.state/'relay-acceptance.json'
        save_acceptance(path, self.cs, {'target': '203.0.113.8', 'port': 443,
                                      'protocol': 'TCP', 'family': 'ip', 'hook': 'input'}, 0)
        before = path.read_bytes()
        report = self.discover()
        self.assertTrue(report['acceptance']['valid'])
        self.assertIn('TCP', report['acceptance']['summary'])
        self.assertEqual(path.read_bytes(), before)


if __name__ == '__main__':
    unittest.main()
