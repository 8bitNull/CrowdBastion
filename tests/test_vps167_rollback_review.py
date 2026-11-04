"""Exercise node rollback against real temporary trees, never production paths."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
from crowdsec_maintenance import fingerprint

TEMPLATE = Path(os.environ.get('VPS167_ROLLBACK_TEMPLATE', str(ROOT/'docs/audit/2026-11-02-vps167-optimize-review/scripts/rollback-manager-v2.py')))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@unittest.skipUnless(os.geteuid() == 0, 'node rollback requires root-owned fixtures')
class ManagerRollbackReview(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.backup = self.base/'backup'
        self.runtime = self.base/'runtime'
        self.result = self.base/'results'
        for p in [self.backup, self.runtime, self.result]:
            p.mkdir(mode=0o700)
        self.root = self.base/'source'
        self.saved = self.backup/'source-directory.before'
        self.parked = self.backup/'source-directory.deployed'
        for p, content in [(self.root, 'new source'), (self.saved, 'original source')]:
            p.mkdir(mode=0o700)
            (p/'manager.sh').write_text(content)
            (p/'manager.sh').chmod(0o600)
        self.cron = self.base/'hub.cron'
        self.cron.write_text('30 3 * * * root new-maintenance\n')
        self.cron.chmod(0o644)
        original = self.backup/'hub.cron.before'
        original.write_text('# disabled original updater\n')
        original.chmod(0o600)
        self.entry = self.base/'daily'
        self.entry.write_text('exec new-manager\n')
        self.entry.chmod(0o755)
        self.maintenance = self.runtime/'release-new'
        self.maintenance.mkdir(mode=0o700)
        (self.runtime/'current').symlink_to(self.maintenance.name)
        self.stage = {'backup': str(self.backup), 'root': str(self.root),
                      'runtime': str(self.runtime), 'maintenance': str(self.maintenance),
                      'entry': str(self.entry), 'cron': str(self.cron), 'cron_mode': 0o644,
                      'cron_before_sha256': sha(original), 'cron_after_sha256': sha(self.cron),
                      'entry_after_sha256': sha(self.entry),
                      'original_source_fingerprint': fingerprint(self.saved),
                      'prepared_source_fingerprint': fingerprint(self.root)}
        self.module = runpy.run_path(str(TEMPLATE), init_globals={'RESULT_DIRECTORY': str(self.result)})

    def restore(self, check=False):
        return self.module['restore'](self.stage, check_only=check)

    def assert_restored(self):
        self.assertEqual(fingerprint(self.root), self.stage['original_source_fingerprint'])
        self.assertEqual(sha(self.cron), self.stage['cron_before_sha256'])
        self.assertFalse(os.path.lexists(self.entry))
        self.assertFalse(os.path.lexists(self.runtime/'current'))

    def reject_unchanged(self, check=True):
        before = fingerprint(self.base)
        with self.assertRaises((AssertionError, ValueError, OSError)):
            self.restore(check)
        self.assertEqual(fingerprint(self.base), before)

    def test_complete_rollback_and_repeated_invocation(self):
        self.restore()
        self.assert_restored()
        self.restore()
        self.assert_restored()

    def test_check_only_performs_no_writes(self):
        before = fingerprint(self.base)
        self.assertTrue(self.restore(True)['check_only'])
        self.assertEqual(fingerprint(self.base), before)

    def test_retry_after_deployed_source_was_parked(self):
        os.rename(self.root, self.parked)
        self.restore()
        self.assert_restored()

    def test_retry_after_second_rename_fails(self):
        real_rename = os.rename
        def rename(source, destination):
            if Path(source) == self.saved:
                raise OSError('injected failure before restoring original directory')
            return real_rename(source, destination)
        with mock.patch('os.rename', side_effect=rename), self.assertRaises(OSError):
            self.restore()
        self.assertFalse(self.root.exists())
        self.assertTrue(self.saved.is_dir())
        self.assertTrue(self.parked.is_dir())
        self.restore()
        self.assert_restored()

    def test_dangling_parked_destination_is_not_overwritten(self):
        self.parked.symlink_to(self.base/'missing-foreign-target')
        self.reject_unchanged(False)

    def test_dry_run_rejects_corrupt_original_cron_backup(self):
        (self.backup/'hub.cron.before').write_text('corrupt backup\n')
        self.reject_unchanged()

    def test_dry_run_rejects_missing_original_cron_backup(self):
        (self.backup/'hub.cron.before').unlink()
        self.reject_unchanged()

    def test_cron_symlink_with_identical_bytes_is_rejected(self):
        other = self.base/'foreign.cron'
        self.cron.rename(other)
        self.cron.symlink_to(other)
        self.reject_unchanged()

    def test_changed_cron_mode_is_rejected(self):
        self.cron.chmod(0o600)
        self.reject_unchanged()

    def test_foreign_parked_source_is_rejected_on_resume(self):
        os.rename(self.root, self.parked)
        (self.parked/'manager.sh').write_text('changed by another operation')
        self.reject_unchanged(False)

    def test_foreign_root_is_rejected(self):
        (self.root/'manager.sh').write_text('changed by another operation')
        self.reject_unchanged(False)

    def test_cron_replace_failure_leaves_live_targets_unchanged(self):
        before = fingerprint(self.base)
        real_replace = os.replace
        def replace(source, destination):
            if Path(destination) == self.cron:
                raise OSError('injected atomic cron replacement failure')
            return real_replace(source, destination)
        with mock.patch('os.replace', side_effect=replace), self.assertRaises(OSError):
            self.restore()
        self.assertEqual(fingerprint(self.base), before)

    def test_retry_after_result_record_failure(self):
        real_replace = os.replace
        def replace(source, destination):
            if Path(destination).parent == self.result:
                raise OSError('injected result record failure')
            return real_replace(source, destination)
        with mock.patch('os.replace', side_effect=replace), self.assertRaises(OSError):
            self.restore()
        self.assert_restored()
        self.restore()
        self.assert_restored()

    def test_directory_ancestor_symlink_is_rejected_before_writes(self):
        real_runtime = self.base/'runtime-real'
        self.runtime.rename(real_runtime)
        self.runtime.symlink_to(real_runtime, target_is_directory=True)
        self.reject_unchanged(False)

    def test_foreign_parked_dangling_link_is_rejected_on_resume(self):
        import shutil
        shutil.rmtree(self.root)
        self.parked.symlink_to(self.base/'missing-foreign-target')
        self.reject_unchanged(False)

    def test_changed_source_ownership_is_rejected(self):
        os.chown(self.saved/'manager.sh', 12345, -1)
        self.reject_unchanged(False)

    def test_missing_root_before_new_directory_install_is_recoverable(self):
        # Failure between the two initial deployment renames is recoverable too.
        import shutil
        shutil.rmtree(self.root)
        self.restore()
        self.assert_restored()

    def test_foreign_current_is_rejected(self):
        (self.runtime/'current').unlink()
        (self.runtime/'current').symlink_to('another-release')
        self.reject_unchanged(False)


if __name__ == '__main__':
    unittest.main()
