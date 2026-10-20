"""Confirmation and private audit regressions; no commands or Telegram calls."""
import importlib
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import patch


class ActionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.state = self.base / 'state'
        try:
            self.module = importlib.import_module('crowdsec_bot_actions')
        except ModuleNotFoundError:
            self.fail('The ActionStore implementation is missing')
        self.store = self.module.ActionStore(self.state, '123456:private-bot-token')

    def ticket(self, action='ban', params=None, user=42, chat=-100):
        if params is None:
            params = ['203.0.113.20', '4h'] if action == 'ban' else []
        nonce = self.store.offer(action, params, user, chat, now=100)
        return self.store.take(nonce, user, chat, now=101)

    def test_confirmation_binds_actor_chat_and_parameters_without_mutable_aliases(self):
        params = ['203.0.113.20', '4h']
        nonce = self.store.offer('ban', params, 42, -100, now=100)
        params[0] = '198.51.100.2'
        self.assertIsNone(self.store.take(nonce, 99, -100, now=101))
        self.assertIsNone(self.store.take(nonce, 42, -999, now=101))
        ticket = self.store.take(nonce, 42, -100, now=102)
        self.assertEqual(set(ticket), {'id', 'action', 'params', 'user', 'chat'})
        self.assertEqual((ticket['action'], ticket['params'], ticket['user'], ticket['chat']),
                         ('ban', ['203.0.113.20', '4h'], 42, -100))
        self.assertIsNone(self.store.take(nonce, 42, -100, now=103))

    def test_confirmation_expires_at_sixty_seconds(self):
        before = self.store.offer('reload', [], 42, -100, now=100)
        boundary = self.store.offer('reload', [], 42, -100, now=100)
        self.assertIsNotNone(self.store.take(before, 42, -100, now=159.999))
        self.assertIsNone(self.store.take(boundary, 42, -100, now=160))

    def test_confirmation_uses_monotonic_clock_by_default(self):
        with patch.object(self.module.time, 'monotonic', side_effect=[100, 160]):
            nonce = self.store.offer('reload', [], 42, -100)
            self.assertIsNone(self.store.take(nonce, 42, -100))

    def test_cancellation_requires_actor_and_chat_and_consumes_once(self):
        nonce = self.store.offer('drop_caches', [], 42, -100, now=100)
        self.assertFalse(self.store.cancel(nonce, 99, -100, now=101))
        self.assertFalse(self.store.cancel(nonce, 42, -999, now=101))
        self.assertTrue(self.store.cancel(nonce, 42, -100, now=101))
        self.assertFalse(self.store.cancel(nonce, 42, -100, now=102))
        self.assertIsNone(self.store.take(nonce, 42, -100, now=102))

    def test_new_store_cannot_accept_old_confirmation(self):
        nonce = self.store.offer('reload', [], 42, -100, now=100)
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertIsNone(restarted.take(nonce, 42, -100, now=101))
        self.assertIsNotNone(self.store.take(nonce, 42, -100, now=101))

    def test_invalid_actions_parameters_and_actor_ids_are_rejected(self):
        invalid = [
            ('shell', ['cat', '/etc/config']), ('reload', ['private-config']),
            ('drop_caches', ['3']), ('unban', []), ('white', ['203.0.113.1', 'secret']),
            ('ban', ['203.0.113.20; reboot', '4h']), ('ban', ['203.0.113.20', '4h; reboot']),
            ('ban', ['203.0.113.20', '4d']),
            ('ban', ['203.0.113.20', '9' * 100 + 'h']), ('white', ['config-secret']),
            ('ban', '203.0.113.20'), ('ban', [1234]),
        ]
        for action, params in invalid:
            with self.subTest(action=action, params=params), self.assertRaises(ValueError):
                self.store.offer(action, params, 42, -100, now=100)
        for user, chat in [(True, -100), (0, -100), (-42, -100), (42, False), (42, 0), ('42', -100)]:
            with self.subTest(user=user, chat=chat), self.assertRaises(ValueError):
                self.store.offer('reload', [], user, chat, now=100)

    def test_all_supported_parameter_shapes_and_ipv6_are_accepted(self):
        for action, params in [('ban', ['2001:db8::20']), ('ban', ['203.0.113.20', '30m']),
                               ('ban', ['203.0.113.20', '1h30m']),
                               ('unban', ['203.0.113.20']), ('white', ['2001:db8::1']),
                               ('reload', []), ('drop_caches', [])]:
            with self.subTest(action=action, params=params):
                self.assertEqual(self.ticket(action, params)['params'], params)

    def test_memory_only_operations_and_status_do_not_create_state_directory(self):
        self.ticket('reload')
        self.assertEqual(self.store.unfinished(), [])
        self.assertFalse(self.state.exists())

    @property
    def audit(self):
        digest = hashlib.sha256(b'123456:private-bot-token').hexdigest()[:24]
        return self.state / ('bot-actions-' + digest + '.jsonl')

    def records(self):
        return [json.loads(line) for line in self.audit.read_text().splitlines()]

    def test_started_record_is_durable_and_survives_restart(self):
        ticket = self.ticket()
        self.store.begin(ticket)
        record = self.records()[0]
        self.assertEqual(record['event'], 'started')
        self.assertEqual({key: record[key] for key in ticket}, ticket)
        timestamp = datetime.fromisoformat(record['timestamp'].replace('Z', '+00:00'))
        self.assertEqual(timestamp.utcoffset().total_seconds(), 0)
        self.assertLess(abs((datetime.now(timezone.utc) - timestamp).total_seconds()), 10)
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertEqual(restarted.unfinished()[0]['id'], ticket['id'])
        self.assertEqual(restarted.unfinished()[0]['timestamp'], record['timestamp'])

    def test_final_record_resolves_started_ticket_after_restart(self):
        ticket = self.ticket()
        self.store.begin(ticket)
        self.store.finish(ticket, 'success', 'Operation completed')
        self.assertEqual([entry['event'] for entry in self.records()], ['started', 'finished'])
        self.assertEqual(self.records()[-1]['outcome'], 'success')
        self.assertEqual(self.records()[-1]['message'], 'Operation completed')
        self.assertEqual(self.module.ActionStore(self.state, '123456:private-bot-token').unfinished(), [])
        with self.assertRaises(ValueError):
            self.store.finish(ticket, 'success', 'Duplicate')

    def test_status_lists_recent_five_unfinished_tickets_and_keeps_older_pending(self):
        tickets = [self.ticket('reload') for _ in range(7)]
        for ticket in tickets:
            self.store.begin(ticket)
        self.assertEqual([entry['id'] for entry in self.store.unfinished()],
                         [ticket['id'] for ticket in reversed(tickets[2:])])
        self.store.finish(tickets[-1], 'failed', 'Operation failed')
        self.assertEqual([entry['id'] for entry in self.store.unfinished()],
                         [ticket['id'] for ticket in reversed(tickets[1:-1])])

    def test_audits_are_token_isolated_and_never_write_token(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        other = self.module.ActionStore(self.state, 'other-private-token')
        self.assertEqual(other.unfinished(), [])
        other_ticket = other.take(other.offer('reload', [], 42, -100), 42, -100)
        other.begin(other_ticket)
        self.assertEqual([item['id'] for item in self.store.unfinished()], [ticket['id']])
        for path in self.state.iterdir():
            self.assertNotIn('123456:private-bot-token', path.read_text())
            self.assertNotIn('other-private-token', path.read_text())
            self.assertNotIn('private-token', path.name)

    def test_final_summary_is_bounded_single_line_and_token_redacted(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        self.store.finish(ticket, 'unknown', '123456:private-bot-token\nhello\x00\x1b\t' + 'x' * 1000)
        message = self.records()[-1]['message']
        self.assertNotIn('123456:private-bot-token', message)
        self.assertIn('hello', message)
        self.assertLessEqual(len(message), 256)
        self.assertTrue(all(character.isprintable() for character in message))
        self.assertEqual([entry['id'] for entry in self.store.unfinished()], [ticket['id']])

    def test_tampered_tickets_cannot_log_arbitrary_configuration(self):
        original = self.ticket()
        for update in [{'action': 'shell'}, {'params': ['private-config']},
                       {'id': '../private-config'}, {'user': True}, {'config': 'private-config'}]:
            with self.subTest(update=update), self.assertRaises(ValueError):
                self.store.begin(dict(original, **update))
        self.assertFalse(self.state.exists())

    def test_invalid_outcome_and_changed_ticket_leave_action_unfinished(self):
        ticket = self.ticket()
        self.store.begin(ticket)
        for changed, outcome in [(ticket, 'raw command output'),
                                 (dict(ticket, params=['203.0.113.99', '4h']), 'success')]:
            with self.subTest(outcome=outcome), self.assertRaises(ValueError):
                self.store.finish(changed, outcome, 'Operation completed')
        self.assertEqual(len(self.records()), 1)
        self.assertEqual(self.store.unfinished()[0]['id'], ticket['id'])
        with self.assertRaises(ValueError):
            self.store.begin(ticket)

    def test_files_and_directory_are_private_even_with_permissive_umask(self):
        self.state.mkdir(mode=0o755)
        previous = os.umask(0)
        try:
            self.store.begin(self.ticket('reload'))
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o700)
        for path in self.state.iterdir():
            self.assertTrue(stat.S_ISREG(path.lstat().st_mode))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_constructor_and_status_leave_existing_files_and_modes_unchanged(self):
        self.store.begin(self.ticket('reload'))
        paths = [self.state] + list(self.state.iterdir())
        before = {path: (path.stat().st_mtime_ns, path.stat().st_ctime_ns, path.stat().st_mode) for path in paths}
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertEqual(len(restarted.unfinished()), 1)
        after = {path: (path.stat().st_mtime_ns, path.stat().st_ctime_ns, path.stat().st_mode) for path in paths}
        self.assertEqual(before, after)

    def test_begin_rejects_symlink_state_directory_and_symlink_parent(self):
        target = self.base / 'target'
        target.mkdir()
        link = self.base / 'link'
        link.symlink_to(target, target_is_directory=True)
        for path in [link, link / 'nested']:
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                self.module.ActionStore(path, '123456:private-bot-token').begin(self.ticket('reload'))
        self.assertEqual(list(target.iterdir()), [])

    def test_begin_rejects_non_directory_state_path(self):
        self.state.write_text('preserve')
        with self.assertRaises((OSError, ValueError)):
            self.store.begin(self.ticket('reload'))
        self.assertEqual(self.state.read_text(), 'preserve')

    def test_audit_and_pending_symlinks_are_rejected_without_touching_target(self):
        self.store.begin(self.ticket('reload'))
        target = self.base / 'private-config'
        target.write_text('preserve')
        for path in list(self.state.iterdir()):
            with self.subTest(path=path):
                prior = path.read_bytes()
                path.unlink()
                path.symlink_to(target)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.store.begin(self.ticket('reload'))
                    self.assertEqual(target.read_text(), 'preserve')
                finally:
                    path.unlink()
                    path.write_bytes(prior)
                    path.chmod(0o600)

    def test_audit_directory_and_fifo_are_rejected_without_hanging(self):
        self.state.mkdir()
        for kind in ['directory', 'fifo']:
            with self.subTest(kind=kind):
                if kind == 'directory':
                    self.audit.mkdir()
                else:
                    os.mkfifo(self.audit)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.store.begin(self.ticket('reload'))
                finally:
                    self.audit.rmdir() if kind == 'directory' else self.audit.unlink()

    def test_fsync_failure_prevents_successful_begin(self):
        real_fsync = os.fsync

        def fail_audit_sync(descriptor):
            if self.audit.exists() and os.fstat(descriptor).st_ino == self.audit.stat().st_ino:
                raise OSError('disk failure')
            return real_fsync(descriptor)

        ticket = self.ticket('reload')
        with patch.object(self.module.os, 'fsync', side_effect=fail_audit_sync):
            with self.assertRaises(OSError):
                self.store.begin(ticket)
        self.assertEqual(self.store.unfinished()[0]['id'], ticket['id'])

    def test_failed_final_fsync_preserves_unfinished_state(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        real_fsync = os.fsync
        audit_inode = self.audit.stat().st_ino

        def fail_audit_sync(descriptor):
            if os.fstat(descriptor).st_ino == audit_inode:
                raise OSError('disk failure')
            return real_fsync(descriptor)

        with patch.object(self.module.os, 'fsync', side_effect=fail_audit_sync):
            with self.assertRaises(OSError):
                self.store.finish(ticket, 'success', 'Operation completed')
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertEqual(restarted.unfinished()[0]['id'], ticket['id'])

    def test_failed_final_write_preserves_unfinished_state_after_restart(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        self.audit.unlink()
        self.audit.mkdir()
        with self.assertRaises((OSError, ValueError)):
            self.store.finish(ticket, 'success', 'Operation completed')
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertEqual(restarted.unfinished()[0]['id'], ticket['id'])

    def test_rotation_keeps_three_private_backups_and_old_unfinished_action(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        filler = json.dumps({'event': 'finished', 'message': 'x' * 200}) + '\n'
        limit = 1024 * 1024
        content = filler.encode() * ((limit - 1) // len(filler))
        content += b' ' * (limit - 1 - len(content))
        for _ in range(5):
            self.audit.write_bytes(content)
            completed = self.ticket('reload')
            self.store.begin(completed)
            self.store.finish(completed, 'success', 'Operation completed')
        audit_files = sorted(self.state.glob(self.audit.name + '*'))
        self.assertEqual(len(audit_files), 4)
        self.assertEqual({path.name for path in audit_files},
                         {self.audit.name, self.audit.name + '.1', self.audit.name + '.2', self.audit.name + '.3'})
        self.assertTrue(all(path.stat().st_size <= limit for path in audit_files))
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in audit_files))
        restarted = self.module.ActionStore(self.state, '123456:private-bot-token')
        self.assertEqual([entry['id'] for entry in restarted.unfinished()], [ticket['id']])
        restarted.finish(ticket, 'unknown', 'Result could not be verified')
        self.assertEqual([entry['id'] for entry in restarted.unfinished()], [ticket['id']])
        restarted.finish(ticket, 'success', 'Result verified')
        self.assertEqual(restarted.unfinished(), [])

    def test_status_rejects_insecure_audit_permissions_without_changing_them(self):
        ticket = self.ticket('reload')
        self.store.begin(ticket)
        pending = next(self.state.glob('*.pending.json'))
        pending.chmod(0o644)
        with self.assertRaises((OSError, ValueError)):
            self.store.unfinished()
        self.assertEqual(stat.S_IMODE(pending.stat().st_mode), 0o644)
        pending.chmod(0o600)
        self.state.chmod(0o755)
        with self.assertRaises((OSError, ValueError)):
            self.store.unfinished()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o755)

    @unittest.skipUnless(os.geteuid() == 0, 'Ownership regression needs chown privileges')
    def test_foreign_owned_state_is_rejected_without_changing_its_owner(self):
        self.store.begin(self.ticket('reload'))
        pending = next(self.state.glob('*.pending.json'))
        for path in [pending, self.state]:
            with self.subTest(path=path):
                os.chown(path, 12345, -1)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        self.store.unfinished()
                    with self.assertRaises((OSError, ValueError)):
                        self.store.begin(self.ticket('reload'))
                    self.assertEqual(path.stat().st_uid, 12345)
                finally:
                    os.chown(path, 0, -1)

    def test_corrupt_pending_state_fails_closed_and_is_preserved(self):
        self.store.begin(self.ticket('reload'))
        pending = next(self.state.glob('*.pending.json'))
        pending.write_text('{invalid-private-config')
        with self.assertRaises(ValueError):
            self.store.unfinished()
        with self.assertRaises(ValueError):
            self.store.begin(self.ticket('reload'))
        self.assertEqual(pending.read_text(), '{invalid-private-config')


if __name__ == '__main__':
    unittest.main()
