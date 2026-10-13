"""Observe real file lifecycle; projections and cursors commit together."""
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


class ObservationLifecycle(unittest.TestCase):
    def setUp(self):
        helper = ROOT/'lib/crowdsec_v2bx_observe.py'
        self.assertTrue(helper.exists(), 'persistent observer is missing')
        sys.path.insert(0, str(ROOT/'lib'))
        self.addCleanup(sys.path.remove, str(ROOT/'lib'))
        spec = importlib.util.spec_from_file_location('observe_test', helper)
        self.mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.mod)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'sing.log'
        self.source.touch()
        self.db = self.base/'observe.sqlite'

    def observer(self, **kwargs):
        item = self.mod.Observer(self.source, self.db, 'sing', **kwargs)
        self.addCleanup(item.close)
        return item

    def records(self, observer):
        target = self.base/('snapshot-'+str(len(list(self.base.glob('snapshot-*'))))+'.ndjson')
        observer.export(target)
        return [json.loads(line) for line in target.read_text().splitlines()]

    def test_append_partial_restart_without_duplicate(self):
        self.source.write_text(LINE+LINE[:-1])
        o = self.observer();o.poll()
        self.assertEqual(len(self.records(o)), 1)
        o.close()
        with self.source.open('a') as out:out.write('\n')
        o = self.observer();o.poll();o.poll()
        self.assertEqual(len(self.records(o)), 2)
        self.assertEqual(o.status()['lines'], 2)

    def test_rename_drains_old_fd_and_reads_new(self):
        self.source.write_text(LINE);o = self.observer();o.poll()
        old = self.source.with_suffix('.log.1');self.source.rename(old)
        with old.open('a') as out:out.write(LINE)
        self.source.write_text(LINE)
        o.poll();o.poll()
        self.assertEqual(len(self.records(o)), 3)
        self.assertEqual(o.status()['rotations'], 1)

    def test_restart_recovers_available_rotated_inode(self):
        self.source.write_text(LINE);o = self.observer();o.poll();o.close()
        old = self.source.with_suffix('.log.1');self.source.rename(old)
        with old.open('a') as out:out.write(LINE)
        self.source.write_text(LINE)
        o = self.observer();o.poll();o.poll()
        self.assertEqual(len(self.records(o)), 3)

    def test_copytruncate_and_rewrite_larger_than_offset_are_detected(self):
        self.source.write_text(LINE*2);o = self.observer();o.poll()
        self.source.write_text(LINE.replace('198.51.100.8','198.51.100.9'))
        o.poll()
        self.source.write_text(LINE.replace('198.51.100.8','198.51.100.7')*4)
        o.poll()
        self.assertEqual(len(self.records(o)), 7)
        self.assertEqual(o.status()['truncations'], 2)
        self.assertEqual(o.status()['continuity_risks'], 2)

    def test_restart_reads_old_file_while_new_path_is_missing(self):
        self.source.write_text(LINE);o = self.observer();o.poll();o.close()
        old=self.source.with_suffix('.log.1');self.source.rename(old)
        with old.open('a') as out:out.write(LINE)
        o = self.observer();o.poll()
        self.assertEqual(len(self.records(o)),2)

    def test_rotated_partial_never_blocks_new_file_or_forms_injected_line(self):
        self.source.write_text('ACCOUNT_SECRET'+LINE[:-1]);o = self.observer();o.poll()
        self.source.rename(self.source.with_suffix('.log.1'))
        self.source.write_text(LINE)
        o.poll();o.poll()
        self.assertEqual(len(self.records(o)), 1)
        self.assertEqual(o.status()['ignored']['incomplete_rotated_line'], 1)

    def test_capacity_stops_without_advancing_or_duplicate_replay(self):
        o = self.observer(max_events=1)
        self.source.write_text(LINE);o.poll()
        with self.source.open('a') as out:out.write(LINE)
        with self.assertRaises(self.mod.InputError):o.poll()
        self.assertEqual(len(self.records(o)),1)
        o.close();o = self.observer(max_events=2);o.poll()
        self.assertEqual(len(self.records(o)),2)

    def test_missing_source_then_creation_is_observed(self):
        self.source.unlink();o = self.observer();o.poll()
        self.assertEqual(o.status()['missing_polls'],1)
        self.source.write_text(LINE);o.poll()
        self.assertEqual(len(self.records(o)),1)

    def test_missing_old_inode_marks_continuity_risk(self):
        self.source.write_text(LINE);o = self.observer();o.poll();o.close()
        held = self.source.open('rb');self.addCleanup(held.close)
        self.source.unlink();self.source.write_text(LINE*2)
        o = self.observer();o.poll()
        self.assertGreaterEqual(o.status()['continuity_risks'], 1)

    def test_atomic_failure_does_not_advance_cursor(self):
        o = self.observer()
        with sqlite3.connect(self.db) as db:
            db.execute("CREATE TRIGGER fail_insert BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'test-only'); END")
        self.source.write_text(LINE)
        with self.assertRaises(self.mod.InputError):o.poll()
        with sqlite3.connect(self.db) as db:db.execute('DROP TRIGGER fail_insert')
        o.close();o = self.observer();o.poll()
        self.assertEqual(len(self.records(o)), 1)
        self.assertEqual(o.status()['lines'], 1)

    def test_oversize_and_invalid_utf8_do_not_split_or_leak(self):
        o = self.observer()
        self.source.write_bytes(b'ACCOUNT_SECRET'+b'x'*9000);o.poll()
        with self.source.open('ab') as out:out.write(b'\n\xff\n'+LINE.encode())
        o.poll()
        self.assertEqual(len(self.records(o)), 1)
        self.assertEqual(o.status()['oversized_lines'], 1)
        self.assertNotIn('ACCOUNT_SECRET', self.db.read_bytes().decode(errors='ignore'))

    def test_relay_exclusion_and_no_raw_account_database(self):
        self.source.write_text(LINE.replace('[node]','[[http://PANEL_SECRET]-anytls:10]'))
        o = self.observer(relay_cidrs='198.51.100.0/24');o.poll()
        self.assertEqual(self.records(o)[0]['source_status'], 'relay_address')
        self.assertEqual(o.status()['failure_observations'], 0)
        self.assertNotIn('PANEL_SECRET', self.db.read_bytes().decode(errors='ignore'))
        self.assertEqual(os.stat(self.db).st_mode & 0o777, 0o600)

    def test_different_database_cannot_duplicate_same_source_concurrently(self):
        self.source.write_text(LINE);o = self.observer();o.poll()
        other = self.mod.Observer(self.source,self.base/'other.sqlite','sing')
        self.addCleanup(other.close)
        with self.assertRaises(self.mod.InputError):other.poll()
        self.assertEqual(other.status()['events'],0)

    def test_duplicate_instance_and_changed_config_rejected(self):
        o = self.observer()
        with self.assertRaises(self.mod.InputError):self.observer()
        o.close()
        with self.assertRaises(self.mod.InputError):self.observer(relay_cidrs='198.51.100.0/24')

    def test_fifo_symlink_source_and_output_are_rejected(self):
        self.source.unlink();os.mkfifo(self.source);o = self.observer()
        with self.assertRaises(self.mod.InputError):o.poll()
        o.close();self.source.unlink();self.source.symlink_to(self.base/'no-file')
        o = self.observer()
        with self.assertRaises(self.mod.InputError):o.poll()
        target=self.base/'output';target.symlink_to(self.base/'no-file')
        with self.assertRaises(self.mod.InputError):o.export(target)

    def test_database_alias_cannot_create_missing_source(self):
        self.source.unlink()
        alias=self.base/'alias';alias.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(self.mod.InputError):
            self.mod.Observer(self.source,alias/self.source.name,'sing')
        self.assertFalse(self.source.exists())

    def test_export_cannot_create_missing_source_or_directory_alias(self):
        self.source.unlink();o = self.observer();o.poll()
        with self.assertRaises(self.mod.InputError):o.export(self.source)
        alias=self.base/'alias';alias.symlink_to(self.base,target_is_directory=True)
        with self.assertRaises(self.mod.InputError):o.export(alias/self.source.name)
        self.assertFalse(self.source.exists())

    def test_late_old_inode_write_after_handoff_is_reported_as_risk(self):
        self.source.write_text(LINE);o = self.observer();o.poll()
        old=self.source.with_suffix('.log.1');self.source.rename(old)
        self.source.write_text(LINE);o.poll()
        with old.open('a') as out:out.write(LINE)
        o.poll()
        self.assertGreaterEqual(o.status()['continuity_risks'],1)

    def test_export_refuses_overwrite_and_source_mutation(self):
        self.source.write_text(LINE);before=self.source.read_bytes();o = self.observer();o.poll()
        out = self.base/'snapshot.ndjson';o.export(out)
        with self.assertRaises(self.mod.InputError):o.export(out)
        self.assertEqual(self.source.read_bytes(),before)
        self.assertEqual(os.stat(out).st_mode & 0o777,0o600)
