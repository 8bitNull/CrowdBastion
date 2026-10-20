"""Real file input: refuse forged/mismatched receipts and bound reads."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def receipt(**changes):
    data = dict(v=1, ip='192.0.2.10', status=403, cause='lapi_ban', time=1000,
                upstream='', request_id='a'*32)
    data.update(changes)
    return ('2026/10/19 21:08:08 [error] 12#12: *2 [lua] execution.lua:22: emit(): CB_EXEC_V1 '+
            json.dumps(data)+' while logging request, client: 192.0.2.10, server: example\n')


class ExecutionEvidence(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT/'lib/crowdsec_execution.py').is_file(), 'execution evidence reader is missing')
        spec = importlib.util.spec_from_file_location('execution', ROOT/'lib/crowdsec_execution.py')
        self.reader = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.reader)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.log = self.dir/'proxy-host-1_error.log'

    def query(self, **kwargs):
        return self.reader.query([str(self.dir)], '192.0.2.10', 950, now=1100, **kwargs)

    def test_real_receipts_deduplicate_and_filter_ip_and_time(self):
        self.log.write_text(receipt()+receipt()+receipt(request_id='b'*32, cause='appsec_rule')+
                            receipt(ip='192.0.2.11')+receipt(time=949)+receipt(time=1101))
        result = self.query()
        self.assertEqual(result['state'], 'observed')
        self.assertEqual(result['count'], 2)
        self.assertEqual(set(result['causes']), {'lapi_ban', 'appsec_rule'})

    def test_business_status_and_embedded_forgery_are_not_evidence(self):
        self.log.write_text('request: "'+receipt()+'"\n'+receipt(upstream='127.0.0.1:8000')+
                            receipt(status=200)+receipt(request_id='client-forged')+receipt(v=True)+
                            receipt(cause='unknown')+receipt(status=True))
        self.assertEqual(self.query()['state'], 'empty')

    def test_missing_or_symlink_logs_are_unavailable_not_empty(self):
        self.assertEqual(self.query()['state'], 'unavailable')
        target = self.dir/'secret.txt'; target.write_text(receipt())
        self.log.symlink_to(target)
        self.assertEqual(self.query()['state'], 'unavailable')

    def test_tail_read_is_bounded_and_reports_sampling(self):
        self.log.write_text(receipt(time=960)+'x'*90000+'\n'+receipt(time=1010, request_id='b'*32))
        result = self.query()
        self.assertEqual(result['count'], 1)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(result['bytes_read'], 65536)

    def test_rotation_and_unterminated_partial_lines(self):
        (self.dir/'proxy-host-1_error.log.1').write_text(receipt())
        self.log.write_text(receipt(request_id='b'*32).rstrip('\n'))
        self.assertEqual(self.query()['count'], 1)

    def test_generic_nginx_error_log_name_is_read(self):
        (self.dir/'error.log').write_text(receipt())
        self.assertEqual(self.query()['state'], 'observed')

    def test_window_is_clamped_to_24_hours(self):
        self.log.write_text(receipt(time=1000))
        result = self.reader.query([str(self.dir)], '192.0.2.10', 0, now=90000)
        self.assertEqual(result['state'], 'empty')
        self.assertEqual(result['since'], 3600)


if __name__ == '__main__':
    unittest.main()
