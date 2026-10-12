"""Read-only upstream evidence uses actual mounted logs, never infers trust."""
import importlib
import io
from contextlib import redirect_stdout
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))


class RealIPDiagnosis(unittest.TestCase):
    def setUp(self):
        self.helper = importlib.import_module('crowdsec_realip_diagnose')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mounts = [{'Type':'bind', 'RW':False, 'Source':str(self.root), 'Destination':'/data'}]

    def test_request_lookup_uses_available_search_command(self):
        (self.root/'access.log').write_text('8.8.8.8 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 2\n')
        for available, command in [('/usr/bin/rg', 'rg'), (None, 'grep')]:
            output = io.StringIO()
            with patch.object(self.helper.shutil, 'which', return_value=available), redirect_stdout(output):
                self.helper.report_evidence('access_log /data/access.log;', self.mounts)
            self.assertIn('关联请求：'+command+' -F -- ', output.getvalue())

    def test_standard_and_npm_logs_include_timestamp_and_client_field(self):
        (self.root/'standard.log').write_text('198.51.100.17 - - [11/Oct/2026:10:00:00 +0000] "GET /?secret=private HTTP/1.1" 200 2\n')
        (self.root/'npm.log').write_text('[11/Oct/2026:10:01:00 +0000] - 200 200 - GET https host "/" [Client 2001:db8::17] [Length 2] [Gzip -] [Sent-to backend] "agent" "-"\n')
        text = 'http { access_log /data/standard.log main; access_log /data/npm.log proxy; }'
        reports = self.helper.log_evidence(text, self.mounts)
        self.assertEqual(reports[0]['ips'], [('198.51.100.17', 1)])
        self.assertEqual(reports[1]['ips'], [('2001:db8::17', 1)])
        self.assertEqual(reports[1]['latest'], '11/Oct/2026:10:01:00 +0000')
        self.assertNotIn('secret', str(reports))

    def test_unmounted_symlink_stream_and_dynamic_logs_are_skipped(self):
        outside = self.root.parent/(self.root.name+'-outside.log')
        outside.write_text('8.8.8.8 secret\n')
        self.addCleanup(outside.unlink)
        (self.root/'alias.log').symlink_to(outside)
        (self.root/'stream-access.log').write_text('8.8.8.8 secret\n')
        text = 'http { access_log /data/alias.log; access_log /data/stream-access.log; access_log /outside.log; access_log /data/$host.log; }'
        self.assertEqual(self.helper.log_evidence(text, self.mounts), [])

    def test_custom_and_empty_formats_are_explicitly_unresolved(self):
        (self.root/'custom.log').write_text('custom layout client=8.8.8.8\n')
        (self.root/'empty.log').write_text('')
        reports = self.helper.log_evidence('access_log /data/custom.log; access_log /data/empty.log;', self.mounts)
        self.assertEqual(len(reports), 2)
        self.assertEqual(reports[0]['ips'], [])
        self.assertIsNone(reports[1]['latest'])

    def test_recent_evidence_is_bounded_and_deduplicated(self):
        (self.root/'large.log').write_text('old data\n'*20000+'8.8.8.8 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 2\n'*30)
        reports = self.helper.log_evidence('access_log /data/large.log; access_log /data/large.log;', self.mounts)
        self.assertEqual(len(reports), 1)
        self.assertEqual(reports[0]['sampled'], 20)
        self.assertEqual(reports[0]['ips'], [('8.8.8.8', 20)])

    def test_request_controlled_client_text_does_not_override_real_client(self):
        (self.root/'standard.log').write_text('9.9.9.9 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 2 "-" "malicious [Client 1.1.1.1]"\n')
        (self.root/'npm.log').write_text('[11/Oct/2026:10:01:00 +0000] - 200 200 - GET https host "/[Client 1.1.1.1]" [Client 8.8.8.8] [Length 2] [Gzip -] [Sent-to backend] "malicious [Client 4.4.4.4]" "-"\n')
        reports = self.helper.log_evidence('access_log /data/standard.log; access_log /data/npm.log;', self.mounts)
        self.assertEqual(reports[0]['ips'], [('9.9.9.9', 1)])
        self.assertEqual(reports[1]['ips'], [('8.8.8.8', 1)])

    def test_included_stream_configuration_is_not_http_evidence(self):
        (self.root/'tcp.log').write_text('8.8.8.8 connection data\n')
        effective = '''# configuration file /etc/nginx/nginx.conf:
stream { include /etc/nginx/tcp.conf; }
# configuration file /etc/nginx/tcp.conf:
server { listen 1234; access_log /data/tcp.log tcp; }
'''
        self.assertEqual(self.helper.log_evidence(effective, self.mounts), [])

    def test_relative_nested_and_shared_includes_remain_conservative(self):
        for name in ['http', 'tcp', 'shared']:
            (self.root/(name+'.log')).write_text('8.8.8.8 - - [11/Oct/2026:10:00:00 +0000] "GET / HTTP/1.1" 200 2\n')
        effective = '''# configuration file /etc/nginx/nginx.conf:
http { include conf.d/http[.]conf; include conf.d/shared.conf; }
stream { include conf.d/tcp.conf; }
# configuration file /etc/nginx/conf.d/http.conf:
server { access_log /data/http.log; }
# configuration file /etc/nginx/conf.d/tcp.conf:
include conf.d/shared.conf;
server { access_log /data/tcp.log; }
# configuration file /etc/nginx/conf.d/shared.conf:
access_log /data/shared.log;
'''
        reports = self.helper.log_evidence(effective, self.mounts)
        self.assertEqual([item['path'] for item in reports], [str(self.root/'http.log')])


if __name__ == '__main__':
    unittest.main()
