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


if __name__ == '__main__':
    unittest.main()
