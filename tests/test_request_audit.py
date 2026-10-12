"""A request proof must agree with both the log client and Lua Bouncer input."""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
import crowdsec_request_audit as audit


class RequestAudit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.effective, self.mounts, self.plan, self.result = [self.root/name for name in ('effective', 'mounts', 'plan', 'result')]
        self.hook = self.root/'access.lua'
        self.hook.write_text('assert(loadfile("/original/waf.lua"))()\nlocal cs = require "crowdsec_1key.crowdsec"\ncs.Allow(ngx.var.remote_addr)\n')
        self.original = self.hook.read_text()
        self.entry = {'status': 'installed', 'container_assets': '/data', 'host_assets': str(self.root)}
        self.effective.write_text('http { access_by_lua_file /data/access.lua; server { server_name example.com; access_log /data/requests.log; error_log /data/errors.log; } }')
        self.mounts.write_text(json.dumps([{'Type': 'bind', 'RW': True, 'Source': str(self.root), 'Destination': '/data'}]))
        (self.root/'requests.log').touch()
        (self.root/'errors.log').touch()
        self.token = 'a'*24

    def make_plan(self, url='https://example.com'):
        with patch.object(audit, 'check_install', return_value=self.entry):
            audit.plan(self.effective, self.mounts, 'state', 'openresty', url, '8.8.8.8', self.token, self.plan)

    def log_request(self, client='8.8.8.8', bouncer='8.8.8.8'):
        (self.root/'requests.log').write_text(client+' - - [11/Oct/2026:10:00:00 +0000] "GET /?crowdsec_ip_check='+self.token+' HTTP/1.1" 200 2\n')
        trace = {'client': client, 'bouncer': bouncer, 'peer': '172.70.1.1', 'xff': '8.8.8.8', 'host': 'example.com'}
        (self.root/'errors.log').write_text('[error] crowdsec-1key-ip|'+self.token+'|'+json.dumps(trace)+', client: '+client+'\n')

    def test_original_waf_runs_before_instrumentation_and_file_inode_is_kept(self):
        self.make_plan()
        inode = self.hook.stat().st_ino
        audit.stage(self.plan)
        text = self.hook.read_text()
        self.assertLess(text.index('/original/waf.lua'), text.index('crowdsec_checked_ip'))
        self.assertIn('cs.Allow(crowdsec_checked_ip)', text)
        self.assertEqual(inode, self.hook.stat().st_ino)

    def test_unknown_site_and_non_root_or_credential_urls_are_rejected(self):
        for url in ('https://unknown.com', 'https://example.com/path', 'https://user:pass@example.com', 'https://example.com/?query=yes'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.make_plan(url)
        self.assertEqual(self.hook.read_text(), self.original)

    def test_preflight_race_does_not_overwrite_changed_lua(self):
        self.make_plan()
        self.hook.write_text('changed by administrator')
        with self.assertRaises(ValueError):
            audit.stage(self.plan)
        self.assertEqual(self.hook.read_text(), 'changed by administrator')

    def test_agreeing_request_records_proof_without_sensitive_headers(self):
        self.make_plan()
        self.log_request()
        with redirect_stdout(io.StringIO()):
            audit.verify(self.plan, self.result)
        result = json.loads(self.result.read_text())
        self.assertEqual(result['client'], '8.8.8.8')
        self.assertEqual(result['site'], 'example.com')
        self.assertNotIn('xff', result)
        self.assertNotIn('token', result)

    def test_proxy_address_or_different_bouncer_input_cannot_pass(self):
        self.make_plan()
        for client, bouncer in [('172.70.1.1', '172.70.1.1'), ('8.8.8.8', '172.70.1.1')]:
            self.log_request(client, bouncer)
            with self.subTest(client=client, bouncer=bouncer), redirect_stdout(io.StringIO()), self.assertRaises(ValueError):
                audit.verify(self.plan, self.result)
        self.assertFalse(self.result.exists())

    def test_access_log_without_bouncer_trace_is_unverified(self):
        self.make_plan()
        self.log_request()
        (self.root/'errors.log').write_text('')
        with self.assertRaises(ValueError):
            audit.verify(self.plan, self.result)

    def test_changed_configuration_or_expired_proof_is_unverified(self):
        state = self.root/'proofs'
        proof = {'verified_at': datetime.now(timezone.utc).isoformat(), 'config_sha': audit.config_digest(self.effective.read_text()),
                 'bouncer_sha': hashlib.sha256(self.hook.read_bytes()).hexdigest()}
        with patch.object(audit, 'check_install', return_value=self.entry), redirect_stdout(io.StringIO()):
            for change in ('none', 'expired', 'config', 'hook'):
                current = dict(proof)
                if change == 'expired':
                    current['verified_at'] = (datetime.now(timezone.utc)-timedelta(days=2)).isoformat()
                if change == 'config':
                    current['config_sha'] = 'changed'
                if change == 'hook':
                    current['bouncer_sha'] = 'changed'
                state.write_text(json.dumps({'openresty': {'example.com': current}}))
                self.assertEqual(audit.status(state, 'openresty', self.effective, 'installs', self.mounts), 0 if change == 'none' else 2)


if __name__ == '__main__':
    unittest.main()
