"""Real IP planning must preserve configs and trust only validated Cloudflare ranges."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
RANGES = ['104.16.0.0/13', '162.158.0.0/15', '172.64.0.0/13', '2606:4700::/32']


class RealIP(unittest.TestCase):
    def setUp(self):
        path = ROOT/'lib/crowdsec_realip.py'
        self.assertTrue(path.exists(), 'real IP repair planner is missing')
        spec = importlib.util.spec_from_file_location('realip_helper', path)
        self.helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.helper)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mounts = [{'Type':'bind', 'RW':True, 'Source':str(self.root),
                        'Destination':'/usr/local/openresty/nginx/conf/http.d'}]
        self.effective = '# configuration file /usr/local/openresty/nginx/conf/nginx.conf:\nhttp { include /usr/local/openresty/nginx/conf/http.d/*.conf; }\n'

    def plan(self, **changes):
        args = dict(effective=self.effective, mounts=self.mounts, ranges=RANGES, owned=None)
        args.update(changes)
        return self.helper.plan_real_ip(**args)

    def test_real_mount_http_include_and_cloudflare_header(self):
        plan = self.plan()
        self.assertEqual(plan['host_target'], str(self.root/'crowdsec-1key-cloudflare-real-ip.conf'))
        text = plan['text']
        self.assertIn('real_ip_header CF-Connecting-IP;', text)
        self.assertIn('set_real_ip_from 104.16.0.0/13;', text)
        self.assertIn('set_real_ip_from 2606:4700::/32;', text)
        self.assertNotIn('127.0.0.1', text)
        self.assertFalse(Path(plan['host_target']).exists())

    def test_invalid_unbounded_or_private_ranges_are_refused(self):
        for value in ['0.0.0.0/0', '::/0', '127.0.0.1/32', '10.0.0.0/8', 'garbage', '104.16.0.1/13']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(ranges=[*RANGES, value])

    def test_existing_real_ip_rules_or_target_are_not_overwritten(self):
        with self.assertRaisesRegex(ValueError, '已有'):
            self.plan(effective=self.effective+'real_ip_header X-Forwarded-For;')
        target = self.root/'crowdsec-1key-cloudflare-real-ip.conf'
        target.write_text('# custom\n')
        with self.assertRaises(ValueError):
            self.plan()
        self.assertEqual(target.read_text(), '# custom\n')

    def test_child_include_and_shadow_mount_are_refused(self):
        with self.assertRaises(ValueError):
            self.plan(effective='http { server { include /usr/local/openresty/nginx/conf/http.d/*.conf; } }')
        with self.assertRaises(ValueError):
            self.plan(mounts=[{**self.mounts[0], 'RW':False}])
        target = '/usr/local/openresty/nginx/conf/http.d/crowdsec-1key-cloudflare-real-ip.conf'
        source = self.root/'single-file.conf'
        source.write_text('# file mount\n')
        with self.assertRaises(ValueError):
            self.plan(mounts=[*self.mounts, {'Type':'bind','RW':True,'Source':str(source),'Destination':target}])

    def test_owned_update_and_manual_change_protection(self):
        plan = self.plan()
        Path(plan['host_target']).write_text(plan['text'])
        import hashlib
        owned = dict(host_target=plan['host_target'], container_target=plan['container_target'],
                     sha=hashlib.sha256(plan['text'].encode()).hexdigest())
        effective = self.effective+'# configuration file '+plan['container_target']+':\n'+plan['text']
        updated = self.plan(effective=effective, owned=owned)
        self.assertEqual(updated['text'], plan['text'])
        Path(plan['host_target']).write_text(plan['text']+'# manual\n')
        with self.assertRaises(ValueError):
            self.plan(effective=effective, owned=owned)

    def npm_fixture(self):
        mounts = [{'Type': 'bind', 'RW': True, 'Source': str(self.root), 'Destination': '/data'}]
        effective = '''# configuration file /etc/nginx/nginx.conf:
http {
set_real_ip_from 10.0.0.0/8;
real_ip_header X-Real-IP;
real_ip_recursive on;
include /data/nginx/custom/http_top[.]conf;
}
# configuration file /etc/nginx/conf.d/include/ip_ranges.conf:
set_real_ip_from 104.16.0.0/13;
# configuration file /data/nginx/proxy_host/10.conf:
server { include /data/nginx/custom/server_proxy[.]conf; }
'''
        return effective, mounts

    def test_npm_merge_update_and_remove_preserve_custom_file(self):
        import json
        effective, mounts = self.npm_fixture()
        target = self.root/'nginx/custom/server_proxy.conf'
        target.parent.mkdir(parents=True)
        original = '# user setting\nadd_header X-Test preserved;\n'
        target.write_text(original)
        target.chmod(0o640)
        plan = self.plan(effective=effective, mounts=mounts)
        self.assertEqual(plan['scope'], 'npm-proxy-hosts')
        self.assertTrue(plan['text'].startswith(original))
        self.assertIn('real_ip_header CF-Connecting-IP;', plan['text'])
        self.assertNotIn('set_real_ip_from 10.0.0.0/8;', plan['text'])
        staged, state = self.root/'plan.json', self.root/'state.json'
        staged.write_text(json.dumps(plan))
        self.helper.main(['apply', str(staged), str(state), 'npm'])
        owned = json.loads(state.read_text())['npm']
        updated = self.plan(effective=effective+'# configuration file /data/nginx/custom/server_proxy.conf:\n'+plan['text'], mounts=mounts, owned=owned)
        self.assertEqual(updated['text'], plan['text'])
        self.helper.main(['remove', str(state), 'npm'])
        self.assertEqual(target.read_text(), original)
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)

    def test_npm_refuses_per_host_header_override(self):
        effective, mounts = self.npm_fixture()
        with self.assertRaises(ValueError):
            self.plan(effective=effective+'server { real_ip_header X-Forwarded-For; }', mounts=mounts)

    def test_custom_policy_has_one_explicit_header_and_trust_list(self):
        plan = self.plan(provider='custom', header='x-forwarded-for', ranges=['192.0.2.0/24'])
        self.assertIn('real_ip_header X-Forwarded-For;', plan['text'])
        self.assertNotIn('CF-Connecting-IP', plan['text'])
        for value in ['Forwarded', 'unknown-header', 'X-Real-IP; include /tmp/x']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(provider='custom', header=value, ranges=['192.0.2.0/24'])
        for value in ['0.0.0.0/0', '::/0', '10.0.0.0/8', '127.0.0.0/8']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.plan(provider='custom', header='X-Real-IP', ranges=[value])

    def test_custom_loopback_trust_requires_exact_address(self):
        plan = self.plan(provider='custom', header='X-Real-IP', ranges=['127.0.0.1/32'])
        self.assertIn('set_real_ip_from 127.0.0.1/32;', plan['text'])


if __name__ == '__main__':
    unittest.main()
