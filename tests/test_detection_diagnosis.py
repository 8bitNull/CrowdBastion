"""Shared bounded diagnostics and effective metrics endpoint regression checks."""
import importlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))


class DetectionDiagnosis(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_host_npm_logs_use_client_and_ignore_stream_include(self):
        h = importlib.import_module('crowdsec_realip_diagnose')
        log = self.root/'npm.log'
        log.write_text('[11/Oct/2026:10:01:00 +0000] - 200 200 - GET https host "/" [Client 8.8.8.8] [Length 2] [Gzip -] [Sent-to backend] "agent" "-"\n')
        stream = self.root/'tcp.log'
        stream.write_text('9.9.9.9 stream\n')
        text = f'''# configuration file /etc/nginx/nginx.conf:
http {{ access_log {log}; }}
stream {{ include /etc/nginx/tcp.conf; }}
# configuration file /etc/nginx/tcp.conf:
access_log {stream};
'''
        reports = h.log_evidence(text, [], host=True)
        self.assertEqual([r['path'] for r in reports], [str(log)])
        self.assertEqual(reports[0]['ips'], [('8.8.8.8', 1)])

    def test_effective_metrics_ipv6_override_and_wildcard(self):
        h = importlib.import_module('crowdsec_detection_diagnose')
        config = self.root/'config.yaml'
        config.write_text('prometheus:\n  enabled: true\n  listen_addr: 127.0.0.1\n  listen_port: 6060\n')
        Path(str(config)+'.local').write_text('prometheus:\n  listen_addr: "::1"\n  listen_port: 9600\n')
        self.assertEqual(h.metrics_url(config), 'http://[::1]:9600/metrics')
        Path(str(config)+'.local').write_text('prometheus:\n  listen_addr: 0.0.0.0\n')
        self.assertEqual(h.metrics_url(config), 'http://127.0.0.1:6060/metrics')

    def test_disabled_or_invalid_metrics_are_unresolved(self):
        h = importlib.import_module('crowdsec_detection_diagnose')
        config = self.root/'config.yaml'
        for data in ['prometheus: {enabled: false}', 'prometheus: {enabled: true, listen_port: 70000}', 'prometheus: {enabled: true, listen_addr: "bad/host", listen_port: 6060}']:
            config.write_text(data)
            with self.assertRaises(ValueError):
                h.metrics_url(config)

    def test_range_changes_support_old_registry_and_explicit_diff(self):
        h = importlib.import_module('crowdsec_detection_diagnose')
        self.assertEqual(h.range_changes({}, ['8.8.8.0/24']), (['8.8.8.0/24'], []))
        self.assertEqual(h.range_changes({'ranges': ['8.8.8.0/24','9.9.9.0/24']}, ['8.8.8.0/24','1.1.1.0/24']), (['1.1.1.0/24'], ['9.9.9.0/24']))

    def test_window_deltas_only_compare_counter_series(self):
        h = importlib.import_module('crowdsec_detection_diagnose')
        before = '# TYPE cs_lines_total counter\ncs_lines_total{source="a"} 5\n# TYPE cs_active gauge\ncs_active 4\n'
        after = '# TYPE cs_lines_total counter\ncs_lines_total{source="a"} 8\n# TYPE cs_active gauge\ncs_active 1\n'
        self.assertEqual(h.counter_deltas(before, after), [('cs_lines_total{source="a"}', 3.0)])

    def test_window_reset_or_missing_series_is_unknown(self):
        h = importlib.import_module('crowdsec_detection_diagnose')
        before = '# TYPE cs_total counter\ncs_total{source="a"} 5\ncs_total{source="b"} 2\n'
        after = '# TYPE cs_total counter\ncs_total{source="a"} 1\ncs_total{source="c"} 3\n'
        self.assertEqual(h.counter_deltas(before, after), [('cs_total{source="a"}', None), ('cs_total{source="b"}', None), ('cs_total{source="c"}', None)])

    def test_legacy_tool_uses_effective_endpoint_and_shared_npm_format(self):
        if os.geteuid() != 0:
            self.skipTest('diagnostic entrypoint requires root')
        config = self.root/'config.yaml'
        config.write_text('prometheus: {enabled: true, listen_addr: 127.0.0.1, listen_port: 9600}\n')
        log = self.root/'npm.log'
        log.write_text('[11/Oct/2026:10:01:00 +0000] - 200 200 - GET https host "/" [Client 8.8.8.8] [Length 2] [Gzip -] [Sent-to backend] "secret-agent" "-"\n')
        effective = self.root/'nginx.txt'
        effective.write_text('http { access_log /data/npm.log proxy; }\n')
        mounts = self.root/'mounts.json'
        mounts.write_text(json.dumps([{'Type':'bind','Source':str(self.root),'Destination':'/data','RW':False}]))
        trace = self.root/'curl-trace'
        fake = self.root/'bin'
        fake.mkdir()
        stubs = {
            'cscli': '#!/bin/bash\nexit 0\n',
            'curl': '#!/bin/bash\nprintf "%s\\n" "$*" >> "$AUDIT_TRACE"\nprintf "# TYPE cs_node_wl_hits_ok_total counter\\ncs_node_wl_hits_ok_total{type=\\"appsec\\"} 1\\n"\n',
            'docker': '#!/bin/bash\ncase "$1" in ps) echo "qa jc21/nginx-proxy-manager:latest npm";; exec) cat "$AUDIT_EFFECTIVE";; inspect) cat "$AUDIT_MOUNTS";; esac\n',
            'journalctl': '#!/bin/bash\nexit 0\n',
        }
        for name, script in stubs.items():
            path = fake/name
            path.write_text(script)
            path.chmod(0o755)
        env = {**os.environ, 'PATH':str(fake)+':/usr/bin:/bin', 'CROWDSEC_CONFIG':str(config), 'AUDIT_TRACE':str(trace), 'AUDIT_EFFECTIVE':str(effective), 'AUDIT_MOUNTS':str(mounts)}
        script = Path(__file__).resolve().parents[1]/'tools/diagnose-detection.sh'
        result = subprocess.run(['bash', str(script)], env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('127.0.0.1:9600/metrics', trace.read_text())
        self.assertIn('日志客户端 IP 8.8.8.8', result.stdout)
        self.assertNotIn('secret-agent', result.stdout)
        self.assertEqual(config.read_text(), 'prometheus: {enabled: true, listen_addr: 127.0.0.1, listen_port: 9600}\n')
        result = subprocess.run(['bash', str(script), '--window', '1'], env=env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('窗口内没有变化', result.stdout)
        self.assertEqual(len(trace.read_text().splitlines()), 3)

    def test_invalid_window_rejected_before_collection(self):
        script = Path(__file__).resolve().parents[1]/'tools/diagnose-detection.sh'
        for value in ('0', '61', '-1', '1.5', '01'):
            result = subprocess.run(['bash', str(script), '--window', value], text=True, capture_output=True, timeout=5)
            self.assertEqual(result.returncode, 1)
            self.assertIn('用法', result.stderr)


if __name__ == '__main__':
    unittest.main()
