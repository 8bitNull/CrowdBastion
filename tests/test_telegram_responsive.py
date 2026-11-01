"""Health cards remain honest, fresh when requested, and responsive under slow probes."""
import importlib.util
from pathlib import Path
import sys
import threading
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))


def load_bot():
    spec = importlib.util.spec_from_file_location('responsive_bot', ROOT / 'lib/crowdsec_bot.py')
    bot = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bot)
    return bot


class HealthCards(unittest.TestCase):
    def setUp(self):
        self.bot = load_bot()
        from crowdbastion_health import summarize
        self.report = {'checked_at': 1750000000.0, 'scope': '网站、本地中转',
                       'checks': {'core': 'ok', 'bouncer': 'ok', 'traffic': 'pending'}}
        self.report['summary'] = summarize([('core', 'required'), *self.report['checks'].items()], 2, 'overall', 'relay')
        report = self.report

        class Collector:
            _cached = None
            _cached_at = None
            calls = 0

            def collect(self):
                if self._cached is None:
                    self.calls += 1
                    self._cached = dict(report)
                    self._cached_at = time.monotonic()
                return self._cached

        self.collector = Collector()
        health = self.bot.sibling('crowdsec_bot_health')
        self.factory = patch.object(health, 'HealthCollector', return_value=self.collector)
        self.factory.start()
        self.addCleanup(self.factory.stop)

    def test_pending_is_neutral_and_verdict_visible_in_both_sizes(self):
        for details in (False, True):
            with self.subTest(details=details):
                text = self.bot.module_health_status(details)
                self.assertIn('检查结论：运行检查通过，实际拦截待验证', text)
                self.assertIn('实际拦截验证：待验证', text)
                self.assertNotIn('实际拦截验证通过', text)

    def test_cache_source_and_sample_time_are_visible(self):
        first = self.bot.module_health_status()
        second = self.bot.module_health_status()
        self.assertIn('采样：本次采样', first)
        self.assertIn('采样：复用 30 秒内缓存', second)
        self.assertIn('采样时间：', second)
        self.assertEqual(self.collector.calls, 1)

    def test_refresh_samples_again_but_detail_navigation_reuses(self):
        self.bot.render_view('status')
        self.bot.render_view('status', details=True)
        self.assertEqual(self.collector.calls, 1)
        self.bot.render_view('status', force_refresh=True)
        self.assertEqual(self.collector.calls, 2)
        _, markup = self.bot.render_view('status', details=True)
        buttons = [button for row in markup['inline_keyboard'] for button in row]
        self.assertIn('fresh:more:nav:status', [b['callback_data'] for b in buttons])

    def test_refresh_can_share_sample_completed_after_request(self):
        self.bot.render_view('status')
        self.bot.render_view('status', force_refresh=True, requested_at=self.collector._cached_at - 1)
        self.assertEqual(self.collector.calls, 1)

    def test_confirmation_store_initialized_once_across_threads(self):
        bot = load_bot()
        actions = bot.sibling('crowdsec_bot_actions')
        actual = actions.ActionStore
        entered, release, second_started = threading.Event(), threading.Event(), threading.Event()
        instances, results = [], []
        def constructor(*args):
            instance = actual(*args)
            instances.append(instance)
            entered.set()
            release.wait(2)
            return instance
        def second():
            second_started.set()
            results.append(bot.get_action_store())
        with patch.object(actions, 'ActionStore', side_effect=constructor):
            first = threading.Thread(target=lambda: results.append(bot.get_action_store()))
            other = threading.Thread(target=second)
            first.start()
            self.assertTrue(entered.wait(1))
            other.start()
            self.assertTrue(second_started.wait(1))
            release.set()
            first.join(2)
            other.join(2)
        self.assertEqual(len(instances), 1, 'duplicate stores can lose process-local confirmations')
        self.assertIs(results[0], results[1])

    def test_failed_complete_check_is_never_replaced_with_success(self):
        from crowdbastion_health import summarize
        self.report['checks'] = {'check': 'unknown', 'traffic': 'pending'}
        self.report['summary'] = summarize(list(self.report['checks'].items()), 2, 'overall', '')
        text = self.bot.module_health_status()
        self.assertIn('检查未完成', text)
        self.assertNotIn('运行检查通过', text)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.bot = load_bot()
        self.entered, self.release = threading.Event(), threading.Event()
        self.worker = None

    def tearDown(self):
        self.release.set()
        if self.worker:
            self.worker.close()

    def make_worker(self):
        self.assertTrue(hasattr(self.bot, 'HealthViewWorker'), 'bounded health worker missing')
        self.worker = self.bot.HealthViewWorker()
        return self.worker

    def slow(self):
        self.entered.set()
        if not self.release.wait(3):
            raise AssertionError('test did not release probe')
        return 'old'

    def test_slow_query_does_not_block_main_menu_and_navigation_supersedes_result(self):
        worker = self.make_worker()
        self.bot._HEALTH_WORKER = worker
        self.bot.ADMIN_USER_ID, self.bot.ADMIN_CHAT_ID = 12, -34
        sent, done = [], threading.Event()
        def telegram(method, payload=None):
            sent.append((method, payload))
            return {'ok': True, 'result': {'message_id': 90}}
        callback = lambda data: {'callback_query': {'id': 'q', 'from': {'id': 12}, 'data': data,
                    'message': {'message_id': 90, 'chat': {'id': -34}}}}
        with patch.object(self.bot, 'tg_request', side_effect=telegram), \
             patch.object(self.bot, 'module_health_status', side_effect=lambda **kw: self.slow()):
            self.bot.handle_update(callback('nav:status'))
            self.assertTrue(self.entered.wait(1))
            self.bot.handle_update(callback('nav:home'))
            self.assertTrue(any(p and '主菜单' in p.get('text', '') for _, p in sent))
            self.release.set()
            worker.submit('barrier', lambda: 'done', lambda result: done.set())
            self.assertTrue(done.wait(1))
        self.assertFalse(any(p and p.get('text', '').startswith('old') for _, p in sent))

    def test_pending_cards_are_bounded_and_same_card_keeps_latest(self):
        worker = self.make_worker()
        results, done = [], threading.Event()
        self.assertTrue(worker.submit('a', self.slow, results.append))
        self.assertTrue(self.entered.wait(1))
        self.assertTrue(worker.submit('a', lambda: 'new', results.append))
        for i in range(7):
            self.assertTrue(worker.submit(i, lambda: 'queued', results.append))
        self.assertFalse(worker.submit('overflow', lambda: 'bad', results.append))
        self.release.set()
        # Clear pending keys and confirm a fresh task can run after invalidation.
        worker.invalidate()
        self.assertTrue(worker.submit('done', lambda: 'done', lambda result: done.set()))
        self.assertTrue(done.wait(1))
        self.assertNotIn('old', results)
        self.assertNotIn('bad', results)

    def test_exception_does_not_kill_worker_or_disclose_diagnostic(self):
        worker = self.make_worker()
        delivered, done = [], threading.Event()
        def failure():
            raise ValueError('SECRET-PRIVATE')
        worker.submit('a', failure, delivered.append)
        worker.submit('b', lambda: 'ok', lambda result: done.set())
        self.assertTrue(done.wait(1))
        self.assertEqual(len(delivered), 1)
        self.assertNotIn('SECRET', str(delivered))
        self.assertIn('查询未完成', str(delivered))

    def test_invalidate_all_discards_inflight_result(self):
        worker = self.make_worker()
        delivered, done = [], threading.Event()
        worker.submit('a', self.slow, delivered.append)
        self.assertTrue(self.entered.wait(1))
        worker.invalidate()
        self.release.set()
        worker.submit('b', lambda: 'ok', lambda result: done.set())
        self.assertTrue(done.wait(1))
        self.assertEqual(delivered, [])


class ConfirmationsDuringHealth(unittest.TestCase):
    def setUp(self):
        from test_custom_bot_flow import ConfirmedFlows
        ConfirmedFlows.setUp(self)
        self.bot._HEALTH_WORKER = self.bot.HealthViewWorker()
        self.worker = self.bot._HEALTH_WORKER
        self.release, self.entered = threading.Event(), threading.Event()
        self.addCleanup(self.worker.close)
        self.addCleanup(self.release.set)

    from test_custom_bot_flow import ConfirmedFlows as _Flows
    telegram = _Flows.telegram
    message = _Flows.message
    callback = _Flows.callback
    request = _Flows.request

    def test_cancel_and_confirm_stay_serial_during_probe_and_success_discards_old_result(self):
        old_results, done = [], threading.Event()
        def slow():
            self.entered.set()
            self.release.wait(3)
            return 'old'
        self.worker.submit(42, slow, old_results.append)
        self.assertTrue(self.entered.wait(1))
        yes, no = self.request(self.message('/unban 203.0.113.8'))
        self.bot.handle_update(self.callback(no))
        with patch.object(self.bot, 'run_cmd') as command:
            self.bot.handle_update(self.callback(yes))
            command.assert_not_called()
        yes, _ = self.request(self.message('/unban 203.0.113.8'))
        calls = []
        with patch.object(self.bot, 'run_cmd', side_effect=lambda *a, **kw: calls.append(threading.get_ident()) or ''):
            self.bot.handle_update(self.callback(yes))
            self.bot.handle_update(self.callback(yes))
        self.assertEqual(calls, [threading.get_ident()])
        self.release.set()
        self.worker.submit('done', lambda: '', lambda result: done.set())
        self.assertTrue(done.wait(1))
        self.assertEqual(old_results, [])


if __name__ == '__main__':
    unittest.main()
