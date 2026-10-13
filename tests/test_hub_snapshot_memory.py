"""Checksum compatibility and bounded memory for large Hub download snapshots."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import crowdsec_hub_snapshot as snapshot


class SnapshotChecksumMemory(unittest.TestCase):
    def test_checksum_matches_existing_format_and_ignores_checksum_field(self):
        document = {'before': {'/资料': {'kind': 'file', 'data': 'a\\b\n"é'}},
                    'format': 2, 'checksum': 'old'}
        expected = hashlib.sha256(json.dumps(
            {key: value for key, value in document.items() if key != 'checksum'},
            sort_keys=True).encode()).hexdigest()
        self.assertEqual(snapshot.digest(document), expected)

    @unittest.skipUnless(sys.platform == 'linux', 'requires Linux address-space limit')
    def test_checksum_large_download_records_fit_bounded_address_space(self):
        helper_directory = str(Path(__file__).resolve().parents[1] / 'lib')
        program = '''
import resource, sys
sys.path.insert(0, sys.argv[1])
import crowdsec_hub_snapshot as snapshot
resource.setrlimit(resource.RLIMIT_AS, (220*1024*1024, 220*1024*1024))
document = {'before': {str(i): {'kind': 'file', 'data': chr(65+i)*(16*1024*1024)} for i in range(6)}}
print(snapshot.digest(document))
'''
        result = subprocess.run([sys.executable, '-c', program, helper_directory],
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex(result.stdout.strip(), r'^[0-9a-f]{64}$')

    @unittest.skipUnless(sys.platform == 'linux', 'requires Linux address-space limit')
    def test_full_download_snapshot_lifecycle_fits_low_memory(self):
        helper_directory = str(Path(__file__).resolve().parents[1] / 'lib')
        program = r"""
import resource, sys, tempfile, hashlib, json
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import crowdsec_maintenance as maintenance
resource.setrlimit(resource.RLIMIT_AS, (160*1024*1024, 160*1024*1024))
def checksum(path):
    h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    return h.hexdigest()
with tempfile.TemporaryDirectory() as folder:
    root=Path(folder);data=root/'data';data.mkdir()
    for name, size in [('City.mmdb',61),('ASN.mmdb',11)]:
        with (data/name).open('wb') as stream:stream.truncate(size*1024*1024)
    config=root/'config.yaml';config.write_text('config_paths:\n  config_dir: '+str(root)+'\n  data_dir: '+str(data)+'\n')
    original=checksum(data/'City.mmdb')
    destination=root/'snapshot'
    maintenance.snapshot(config,destination)
    with (data/'City.mmdb').open('r+b') as stream:stream.write(b'changed')
    (data/'new.txt').write_text('added')
    maintenance.record_after(destination)
    assert maintenance.changed(destination)
    maintenance.restore(destination)
    assert checksum(data/'City.mmdb')==original
    assert not (data/'new.txt').exists()
    assert not maintenance.changed(destination)
print(json.dumps({'peak_rss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss}))
"""
        result=subprocess.run([sys.executable,'-c',program,helper_directory],capture_output=True,text=True,timeout=30)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertLess(json.loads(result.stdout)['peak_rss_kib'],128*1024)

class SnapshotContentIntegrity(unittest.TestCase):
    def setUp(self):
        import tempfile
        import crowdsec_maintenance
        self.maintenance = crowdsec_maintenance
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.hub = self.root/'hub'
        self.hub.mkdir()
        self.rule = self.hub/'rule.yaml'
        self.rule.write_bytes(b'original rule')
        self.data = self.root/'data'
        self.data.mkdir()
        self.download = self.data/'City.mmdb'
        self.download.write_bytes(b'original download')
        self.config = self.root/'config.yaml'
        self.config.write_text('config_paths:\n  config_dir: '+str(self.root)+'\n  data_dir: '+str(self.data)+'\n')
        self.destination = self.root/'snapshot'

    def make_changed_snapshot(self):
        self.maintenance.snapshot(self.config, self.destination)
        self.rule.write_bytes(b'changed rule')
        self.download.write_bytes(b'changed download')
        self.maintenance.record_after(self.destination)
        metadata = self.destination/'transaction.json'
        document = json.loads(metadata.read_text())
        blob = self.destination/'files'/document['before'][str(self.download)]['data']['sha256']
        return metadata, document, blob

    def test_corrupted_or_symlinked_content_refuses_restore_before_any_mutation(self):
        _, _, blob = self.make_changed_snapshot()
        for attack in ('corrupt', 'symlink'):
            with self.subTest(attack=attack):
                blob.unlink()
                if attack == 'corrupt':
                    blob.write_bytes(b'corrupted')
                else:
                    external = self.root/'external'
                    external.write_bytes(b'original download')
                    blob.symlink_to(external)
                with self.assertRaises((ValueError, OSError)):
                    self.maintenance.restore(self.destination)
                self.assertEqual(self.rule.read_bytes(), b'changed rule')
                self.assertEqual(self.download.read_bytes(), b'changed download')

    @unittest.skipUnless(sys.platform == 'linux', 'requires FIFO and O_NONBLOCK')
    def test_fifo_content_refuses_restore_without_blocking_or_mutation(self):
        import os
        _, _, blob = self.make_changed_snapshot()
        blob.unlink()
        os.mkfifo(blob)
        program = """
import sys
sys.path.insert(0, sys.argv[1])
import crowdsec_maintenance as maintenance
try:
    maintenance.restore(sys.argv[2])
except (ValueError, OSError):
    print('refused')
else:
    raise SystemExit(1)
"""
        try:
            result=subprocess.run([sys.executable,'-c',program,str(Path(__file__).resolve().parents[1]/'lib'),str(self.destination)],capture_output=True,text=True,timeout=2)
        except subprocess.TimeoutExpired:
            self.fail('Non-regular content blocked restoration instead of being refused')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout.strip(),'refused')
        self.assertEqual(self.rule.read_bytes(),b'changed rule')
        self.assertEqual(self.download.read_bytes(),b'changed download')

    def test_missing_content_store_is_refused_without_creating_it(self):
        import shutil
        metadata, _, _ = self.make_changed_snapshot()
        files = self.destination/'files'
        shutil.rmtree(files)
        with self.assertRaises((ValueError,OSError)):
            snapshot.read_document(metadata)
        self.assertFalse(files.exists())

    def test_empty_snapshot_still_requires_private_content_store(self):
        self.rule.unlink()
        self.download.unlink()
        self.maintenance.snapshot(self.config,self.destination)
        (self.destination/'files').chmod(0o755)
        with self.assertRaises(ValueError):
            snapshot.read_document(self.destination/'transaction.json')

    def test_invalid_content_reference_cannot_escape_snapshot_directory(self):
        metadata, document, _ = self.make_changed_snapshot()
        document['before'][str(self.download)]['data']['sha256'] = '../../external'
        document['checksum'] = snapshot.digest(document)
        metadata.write_text(json.dumps(document))
        with self.assertRaises(ValueError):
            self.maintenance.restore(self.destination)
        self.assertEqual(self.rule.read_bytes(), b'changed rule')

    def test_content_directory_and_files_are_private(self):
        import stat
        self.maintenance.snapshot(self.config, self.destination)
        files = self.destination/'files'
        self.assertEqual(stat.S_IMODE(files.stat().st_mode), 0o700)
        for path in files.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        files.chmod(0o755)
        with self.assertRaises(ValueError):
            self.maintenance.record_after(self.destination)

    def test_legacy_embedded_snapshot_remains_recoverable(self):
        self.destination.mkdir(mode=0o700)
        metadata = self.destination/'transaction.json'
        snapshot.save(metadata, snapshot.before(self.config))
        (self.destination/'manifest.yaml').write_text('format: 2\n')
        self.rule.write_bytes(b'changed rule')
        self.download.write_bytes(b'changed download')
        self.maintenance.record_after(self.destination)
        self.maintenance.restore(self.destination)
        self.assertEqual(self.rule.read_bytes(), b'original rule')
        self.assertEqual(self.download.read_bytes(), b'original download')
