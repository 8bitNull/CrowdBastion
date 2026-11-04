"""Real cscli counter-only rows must not create an idle-source verdict."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from crowdbastion_health import acquisition_state, parse_acquisition_metrics


class AcquisitionCounterRows(unittest.TestCase):
    def classify(self, sources):
        return acquisition_state(parse_acquisition_metrics(json.dumps({'acquisition': sources})))

    def test_real_vps167_sources_and_counter_row_are_not_idle(self):
        self.assertEqual(self.classify({':': {'whitelisted': 9},
                                       'file:/www/sites/site/log/access.log': {'reads': 100, 'parsed': 100},
                                       'journalctl:ssh.service': {'reads': 20, 'parsed': 9}}), 'ok')

    def test_positive_counter_only_row_is_not_tied_to_a_source_name(self):
        self.assertEqual(self.classify({'aggregate': {'whitelisted': 1},
                                       'file:/var/log/auth.log': {'reads': 3, 'parsed': 1}}), 'ok')

    def test_counter_alone_or_no_sources_never_proves_collection(self):
        for sources in ({}, {':': {'whitelisted': 9}}, {':': {'whitelisted': 0}}):
            with self.subTest(sources=sources):
                self.assertEqual(self.classify(sources), 'pending')

    def test_real_idle_or_empty_source_still_requires_evidence(self):
        for idle in ({}, {'reads': 0}, {'reads': 0, 'parsed': 0, 'whitelisted': 9}, {'whitelisted': 0}):
            with self.subTest(idle=idle):
                self.assertEqual(self.classify({':': {'whitelisted': 9},
                                               'busy': {'reads': 2, 'parsed': 2}, 'idle': idle}), 'pending')

    def test_busy_unparsed_source_wins_even_with_aggregate_and_idle_rows(self):
        self.assertEqual(self.classify({':': {'whitelisted': 9}, 'idle': {},
                                       'unparsed': {'reads': 10, 'parsed': 0, 'unparsed': 10}}), 'fault')

    def test_invalid_whitelist_counts_are_rejected(self):
        for value in (-1, True, '9', None, float('nan'), float('inf')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.classify({':': {'whitelisted': value}, 'busy': {'reads': 2, 'parsed': 2}})

    def test_unknown_fields_do_not_turn_an_unobserved_source_into_an_aggregate(self):
        self.assertEqual(self.classify({'busy': {'reads': 2, 'parsed': 1},
                                       'idle': {'whitelisted': 3, 'unknown': 2}}), 'pending')


if __name__ == '__main__':
    unittest.main()
