import importlib.util
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
LINE = '+0000 2026-10-13 12:00:00 ERROR inbound/anytls[node]: process connection from 198.51.100.8:123: unknown user password: fallback disabled\n'


class StreamLifecycle(unittest.TestCase):
    def setUp(self):
        helper = ROOT/'lib/crowdsec_v2bx_stream.py'
        self.assertTrue(helper.exists(), 'incremental publisher is missing')
        sys.path.insert(0, str(ROOT/'lib'));self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        spec = importlib.util.spec_from_file_location('stream_test', helper)
        self.mod = importlib.util.module_from_spec(spec);spec.loader.exec_module(self.mod)
        from crowdsec_v2bx_observe import Observer
        self.tmp = tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name);self.state = self.base/'stream';self.state.mkdir(mode=0o700)
        self.log = self.base/'sing.log';self.log.write_text(LINE)
        self.db = self.base/'sing.sqlite'
        self.observer = Observer(self.log, self.db, 'sing');self.addCleanup(self.observer.close)
        self.observer.poll()

    def publisher(self, **kwargs):
        obj = self.mod.Publisher(self.state, {'sing': self.db}, **kwargs)
        self.addCleanup(obj.close);return obj

    def lines(self, pub):
        return [json.loads(line) for line in pub.output.read_text().splitlines()]

    def test_incremental_backlog_restart_and_stable_ids(self):
        pub = self.publisher();pub.bind_consumer('generation-one')
        self.assertEqual(pub.publish(), 1);self.assertEqual(pub.publish(), 0)
        first = self.lines(pub);pub.close()
        with self.log.open('a') as stream:stream.write(LINE)
        self.observer.poll()
        pub = self.publisher();pub.bind_consumer('generation-one')
        self.assertEqual(pub.publish(), 1)
        self.assertEqual(len(self.lines(pub)), 2)
        self.assertEqual(self.lines(pub)[0]['observation_id'], first[0]['observation_id'])
        self.assertNotEqual(self.lines(pub)[0]['observation_id'], self.lines(pub)[1]['observation_id'])

    def test_fully_written_pending_batch_is_not_republished(self):
        pub = self.publisher();pub.bind_consumer('one')
        pub.before_commit = lambda: (_ for _ in ()).throw(RuntimeError('simulated crash'))
        with self.assertRaises(RuntimeError):pub.publish()
        self.assertEqual(len(self.lines(pub)), 1);pub.close()
        pub = self.publisher();pub.bind_consumer('one')
        self.assertEqual(pub.publish(), 0);self.assertEqual(len(self.lines(pub)), 1)

    def test_partial_append_stops_without_rewriting(self):
        pub = self.publisher();pub.bind_consumer('one')
        def partial(data):
            with pub.output.open('ab') as stream:stream.write(data[:12])
            raise OSError('simulated partial write')
        pub.append = partial
        with self.assertRaises(OSError):pub.publish()
        original = pub.output.read_bytes();pub.close()
        with self.assertRaises(ValueError):self.publisher()
        self.assertEqual((self.state/'events.ndjson').read_bytes(), original)

    def test_consumer_restart_and_output_replacement_stop(self):
        pub = self.publisher();pub.bind_consumer('one');pub.publish()
        with self.assertRaises(ValueError):pub.bind_consumer('two')
        pub.output.rename(self.state/'saved.ndjson');pub.output.touch();pub.output.chmod(0o600)
        with self.assertRaises(ValueError):pub.publish()

    def test_capacity_never_commits_cursor(self):
        pub = self.publisher(max_bytes=8);pub.bind_consumer('one')
        with self.assertRaises(ValueError):pub.publish()
        self.assertEqual(pub.output.stat().st_size, 0)

    def test_source_replacement_stops(self):
        pub = self.publisher();pub.bind_consumer('one');pub.publish();pub.close()
        self.observer.close();old = self.db.read_bytes();self.db.rename(self.base/'previous.sqlite');self.db.write_bytes(old);self.db.chmod(0o600)
        with self.assertRaises(ValueError):self.publisher()

    def test_single_instance_and_noneligible_probe(self):
        pub = self.publisher();pub.bind_consumer('one')
        with self.assertRaises((ValueError, BlockingIOError)):self.publisher()
        pub.probe();self.assertEqual(self.lines(pub), [{}]);self.assertEqual(pub.publish(), 1)

    def test_rotated_source_and_collector_restart_do_not_reexport(self):
        pub = self.publisher();pub.bind_consumer('one');pub.publish()
        self.log.rename(self.base/'sing.log.1');self.log.write_text(LINE)
        self.observer.poll();self.assertEqual(pub.publish(), 1)
        self.observer.close()
        from crowdsec_v2bx_observe import Observer
        self.observer = Observer(self.log, self.db, 'sing');self.addCleanup(self.observer.close)
        self.observer.poll();self.assertEqual(pub.publish(), 0)
        self.assertEqual(len(self.lines(pub)), 2)

    def test_recovered_full_batch_is_fsynced_before_cursor_commit(self):
        from unittest.mock import patch
        pub = self.publisher();pub.bind_consumer('one')
        pub.before_commit = lambda: (_ for _ in ()).throw(RuntimeError('crash'))
        with self.assertRaises(RuntimeError):pub.publish()
        pub.close()
        with patch.object(self.mod.os, 'fsync', wraps=os.fsync) as synced:
            pub = self.publisher()
            self.assertGreaterEqual(synced.call_count, 1)

    def test_zero_byte_intent_waits_for_same_consumer_before_retry(self):
        pub = self.publisher();pub.bind_consumer('one')
        pub.append = lambda data: (_ for _ in ()).throw(OSError('before append'))
        with self.assertRaises(OSError):pub.publish()
        pub.close()
        pub = self.publisher()
        self.assertEqual(pub.output.stat().st_size, 0)
        with self.assertRaises(ValueError):pub.bind_consumer('two')
        self.assertEqual(pub.output.stat().st_size, 0)
        pub.bind_consumer('one');self.assertEqual(len(self.lines(pub)), 1)
        self.assertEqual(pub.publish(), 0)

    def test_copytruncate_rewrite_reports_risk_and_publishes_new_event(self):
        pub = self.publisher();pub.bind_consumer('one');pub.publish()
        self.log.write_text(LINE.replace('198.51.100.8', '198.51.100.9'))
        metrics = self.observer.poll()
        self.assertEqual(metrics['truncations'], 1)
        self.assertEqual(metrics['continuity_risks'], 1)
        self.assertEqual(pub.publish(), 1)
        self.assertEqual({e['source_ip'] for e in self.lines(pub)}, {'198.51.100.8', '198.51.100.9'})
