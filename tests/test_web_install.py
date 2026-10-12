"""Native Web Bouncer plans and persisted configuration, without system changes."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import os

ROOT = Path(__file__).resolve().parents[1]
WAF = '''lua_shared_dict waf_req_count 10m;
lua_shared_dict waf 200m;
lua_shared_dict waf_block_ip 20m;
lua_shared_dict waf_limit 10m;
lua_shared_dict waf_sql 300m;
lua_shared_dict waf_locks 1m;
lua_code_cache on;
lua_package_path "/usr/local/openresty/1pwaf/?.lua;/usr/local/openresty/1pwaf/lib/?.lua;;";
init_by_lua_file /usr/local/openresty/1pwaf/init.lua;
access_by_lua_file /usr/local/openresty/1pwaf/waf.lua;
log_by_lua_file /usr/local/openresty/1pwaf/log_and_traffic.lua;
init_worker_by_lua_file /usr/local/openresty/1pwaf/worker.lua;
'''
REMOTE_WAF = '/usr/local/openresty/1pwaf/data/conf/waf.conf'


class WebInstall(unittest.TestCase):
    def setUp(self):
        path = ROOT/'lib/crowdsec_web.py'
        self.assertTrue(path.exists(), 'native Web Bouncer installer is missing')
        spec = importlib.util.spec_from_file_location('web_install_helper', path)
        self.web = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.web)
        self.tmp = tempfile.TemporaryDirectory(prefix='crowdsec-native-web-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root/'data/conf').mkdir(parents=True)
        self.waf = self.root/'data/conf/waf.conf'
        self.waf.write_text(WAF)
        self.mounts = [{'Type': 'bind', 'RW': True, 'Source': str(self.root/'data'),
                        'Destination': '/usr/local/openresty/1pwaf/data'}]
        self.effective = '# configuration file '+REMOTE_WAF+':\n'+WAF

    def plan(self, **changes):
        args = dict(effective=self.effective, mounts=self.mounts, image='1panel/openresty:1',
                    network='host', version='nginx version: openresty/1.31')
        args.update(changes)
        return self.web.plan_install(**args)

    def test_1panel_plan_uses_real_mount_and_keeps_log_hook(self):
        plan = self.plan()
        self.assertEqual(plan['host_target'], str(self.waf))
        files = self.web.render_hooks(plan)
        text = files['target']
        self.assertIn('log_by_lua_file /usr/local/openresty/1pwaf/log_and_traffic.lua;', text)
        self.assertIn('lua_shared_dict waf_sql 300m;', text)
        self.assertIn('/usr/local/openresty/1pwaf/lib/?.lua', text)
        self.assertIn('crowdsec_cache', text)
        self.assertLess(files['access.lua'].index('loadfile('), files['access.lua'].index('.Allow('))
        self.assertNotIn('dofile(', files['access.lua'])
        self.assertIn('/usr/local/openresty/1pwaf/init.lua', files['init.lua'])
        self.assertIn('/usr/local/openresty/1pwaf/worker.lua', files['worker.lua'])

    def test_no_lua_ldnmp_is_rejected_before_mutation(self):
        with self.assertRaisesRegex(ValueError, 'Lua'):
            self.plan(image='nginx:alpine', version='nginx version: nginx/1.29')
        self.assertEqual(self.waf.read_text(), WAF)

    def test_bridge_without_verified_endpoints_is_rejected_before_mutation(self):
        with self.assertRaisesRegex(ValueError, 'configure-docker-endpoints'):
            self.plan(network='bridge')

    def test_readonly_and_shadowed_mounts_are_rejected(self):
        for mounts in [[{**self.mounts[0], 'RW': False}], [*self.mounts,
                {'Type': 'tmpfs', 'Destination': '/usr/local/openresty/1pwaf/data/conf'}]]:
            with self.subTest(mounts=mounts), self.assertRaises(ValueError):
                self.plan(mounts=mounts)

    def test_unrecognized_waf_hook_is_preserved(self):
        changed = WAF.replace('access_by_lua_file /usr/local/openresty/1pwaf/waf.lua;',
                              'access_by_lua_file /custom/security.lua;')
        self.waf.write_text(changed)
        with self.assertRaisesRegex(ValueError, '钩子'):
            self.plan(effective='# configuration file '+REMOTE_WAF+':\n'+changed)
        self.assertEqual(self.waf.read_text(), changed)

    def test_satisfy_any_and_child_hook_are_rejected(self):
        for extra in ['server { satisfy any; allow all; }',
                      'server { location / { access_by_lua_file /custom.lua; } }']:
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                self.plan(effective=self.effective+'\n'+extra)

    def test_npm_uses_persistent_http_include(self):
        (self.root/'npm').mkdir()
        mounts = [{'Type': 'bind', 'RW': True, 'Source': str(self.root/'npm'), 'Destination': '/data'}]
        effective = '# configuration file /etc/nginx/nginx.conf:\nhttp {\ninclude /data/nginx/custom/http_top[.]conf;\n}\n'
        plan = self.plan(effective=effective, mounts=mounts, image='jc21/nginx-proxy-manager:2')
        self.assertEqual(plan['host_target'], str(self.root/'npm/nginx/custom/http_top.conf'))
        self.assertIn('init_by_lua_file', self.web.render_hooks(plan)['target'])

    def test_lua_enabled_ldnmp_uses_enabled_conf_d_include(self):
        (self.root/'conf.d').mkdir()
        mounts = [{'Type': 'bind', 'RW': True, 'Source': str(self.root/'conf.d'), 'Destination': '/etc/nginx/conf.d'}]
        effective = '# configuration file /etc/nginx/nginx.conf:\nhttp {\ninclude /etc/nginx/conf.d/*.conf;\n}\n'
        plan = self.plan(effective=effective, mounts=mounts, image='custom/nginx:lua')
        self.assertEqual(plan['host_target'], str(self.root/'conf.d/crowdsec-1key.conf'))

    def test_conf_d_inside_server_is_not_used_as_http_context(self):
        (self.root/'conf.d').mkdir()
        mounts = [{'Type': 'bind', 'RW': True, 'Source': str(self.root/'conf.d'), 'Destination': '/etc/nginx/conf.d'}]
        with self.assertRaisesRegex(ValueError, 'HTTP'):
            self.plan(effective='http { server { include /etc/nginx/conf.d/*.conf; } }', mounts=mounts)

    def test_only_owned_resource_paths_are_generated(self):
        plan = self.plan()
        assets = self.web.render_hooks(plan)
        self.assertEqual(set(assets), {'target', 'init.lua', 'access.lua', 'worker.lua'})
        self.assertEqual(plan['host_assets'], str(self.root/'data/crowdsec-1key'))

    def test_archives_require_exact_digest(self):
        archive = self.root/'bad.tgz'
        archive.write_bytes(b'not an official release')
        with self.assertRaisesRegex(ValueError, 'SHA256'):
            self.web.verify_archive(archive, '0'*64)

    def stage(self, plan):
        bouncer = Path('/tmp/crowdsec-official-openresty.tgz')
        http = Path('/tmp/crowdsec-http')
        if not bouncer.exists() or not http.exists():
            self.skipTest('official pinned archives are required for archive integration')
        stage = self.root/'stage'
        self.web.stage_assets(plan, bouncer, http, stage,
                              '0123456789abcdef0123456789abcdef', 'http://127.0.0.1:8080/')
        return stage

    def test_vendor_dependencies_are_isolated_and_secret_is_private(self):
        stage = self.stage(self.plan())
        lua = (stage/'lib/crowdsec_1key/crowdsec.lua').read_text()
        self.assertIn('require "crowdsec_1key.resty.http"', lua)
        self.assertIn('require "crowdsec_1key.plugins.crowdsec.config"', lua)
        self.assertEqual((stage/'bouncer.conf').stat().st_mode & 0o777, 0o600)
        self.assertNotIn('${API_KEY}', (stage/'bouncer.conf').read_text())
        self.assertIn('APPSEC_URL=\n', (stage/'bouncer.conf').read_text())
        self.assertFalse((stage/'lib/resty').exists())

    def test_install_owns_only_new_resources_and_prevents_reinstall(self):
        plan = self.plan()
        stage = self.stage(plan)
        state = self.root/'native.json'
        self.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        self.assertIn('crowdsec_cache', self.waf.read_text())
        self.assertEqual(self.web.read_state(state)['openresty']['original'], WAF)
        self.assertEqual(state.stat().st_mode & 0o777, 0o600)
        self.assertEqual(Path(plan['host_assets']).stat().st_mode & 0o777, 0o755)
        with self.assertRaises(ValueError):
            self.web.apply_install(plan, stage, state, 'openresty', 'other')

    def test_changed_mount_or_target_prevents_removal(self):
        plan = self.plan()
        stage = self.stage(plan)
        state = self.root/'native.json'
        self.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        with self.assertRaises(ValueError):
            self.web.check_install(state, 'openresty', [{**self.mounts[0], 'Source': '/other'}])
        self.waf.write_text(self.waf.read_text()+'# manual edit\n')
        with self.assertRaises(ValueError):
            self.web.check_install(state, 'openresty', self.mounts)

    def test_changed_owned_resource_is_preserved_on_removal(self):
        plan = self.plan()
        stage = self.stage(plan)
        state = self.root/'native.json'
        self.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        (Path(plan['host_assets'])/'access.lua').write_text('-- customized\n')
        with self.assertRaisesRegex(ValueError, '资源'):
            self.web.check_install(state, 'openresty', self.mounts)

    def test_removal_restores_original_hooks_and_requires_cleanup_commit(self):
        plan = self.plan()
        stage = self.stage(plan)
        state = self.root/'native.json'
        self.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        entry = self.web.check_install(state, 'openresty', self.mounts)
        with self.assertRaises(ValueError):
            self.web.main(['forget', str(state), 'openresty'])
        self.web.restore_install(entry)
        self.assertEqual(self.waf.read_text(), WAF)
        self.web.main(['pending', str(state), 'openresty'])
        self.web.main(['forget', str(state), 'openresty'])
        self.assertEqual(self.web.read_state(state), {})
        self.assertFalse(Path(plan['host_assets']).exists())

    def test_cleanup_can_finish_when_resources_were_already_deleted(self):
        plan = self.plan()
        stage = self.stage(plan)
        state = self.root/'native.json'
        self.web.apply_install(plan, stage, state, 'openresty', 'cs-native-test')
        self.web.main(['pending', str(state), 'openresty'])
        import shutil
        shutil.rmtree(plan['host_assets'])
        self.web.main(['forget', str(state), 'openresty'])
        self.assertEqual(self.web.read_state(state), {})


if __name__ == '__main__':
    unittest.main()
