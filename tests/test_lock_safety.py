"""Shared shell/Python lock safety using temporary paths, never host locks."""
import fcntl
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

import crowdbastion_change as change

ROOT = Path(__file__).resolve().parents[1]

class SharedLockSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name); self.base.chmod(0o700)
        self.path = self.base/'maintenance.lock'; self.hub = self.base/'hub.lock'
        self.protected = self.base/'protected'; self.protected.write_text('protected fixture\n')
        self.trace = self.base/'trace'
    def shell(self, action, prefix=''):
        script = 'source '+shlex.quote(str(ROOT/'crowdbastion.sh'))+'\n'
        script += 'MAINTENANCE_LOCK='+shlex.quote(str(self.path))+'\nHUB_LOCK_FILE='+shlex.quote(str(self.hub))+'\n'
        script += 'fixture_trace='+shlex.quote(str(self.trace))+'\n'+r'''
firewall_migration_pending() { return 1; }
hub_workflow_exit() { :; }
require_core() { return 0; }
require_yaml() { return 0; }
require_commands() { return 0; }
systemctl() { printf 'business\n' >> "$fixture_trace"; return 1; }
crowdsec() { printf 'business\n' >> "$fixture_trace"; return 1; }
fixture_action() { printf 'business\n' >> "$fixture_trace"; }
'''+prefix+'\n'+action
        return subprocess.run(['bash', '-c', script], text=True, capture_output=True, timeout=5)
    def assert_refused_untouched(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.protected.read_text(), 'protected fixture\n')
        self.assertFalse(self.trace.exists(), result.stdout+result.stderr)
    def test_symlink_never_truncates_before_engine_validation_in_all_shell_paths(self):
        for action, path in (('locked_operation fixture_action',self.path), ('hub_maintenance update',self.path), ('hub_begin update',self.hub)):
            with self.subTest(action=action):
                path.unlink(missing_ok=True); self.trace.unlink(missing_ok=True)
                self.protected.write_text('protected fixture\n')
                path.symlink_to(self.protected)
                result = self.shell(action)
                try: self.assert_refused_untouched(result)
                finally: path.unlink()
    def test_hardlinks_and_unsafe_owner_refuse_before_shell_mutation(self):
        os.link(self.protected,self.path)
        self.assert_refused_untouched(self.shell('locked_operation fixture_action'))
        self.path.unlink()
        if os.geteuid() != 0: return
        self.path.write_text('lock content\n'); os.chown(self.path,65534,65534)
        self.assert_refused_untouched(self.shell('locked_operation fixture_action'))
        self.assertEqual(self.path.read_text(),'lock content\n')
    def test_nonsticky_writable_ancestor_refuses_without_creating_lock(self):
        writable = self.base/'writable'; writable.mkdir(); writable.chmod(0o777)
        child = writable/'private'; child.mkdir(); child.chmod(0o700)
        self.path = child/'lock'
        self.assert_refused_untouched(self.shell('locked_operation fixture_action'))
        self.assertFalse(self.path.exists())
    def test_lock_contents_and_inode_preserved_and_real_contention_returns_75(self):
        self.path.write_text('existing lock content\n'); self.path.chmod(0o600)
        inode = self.path.stat().st_ino
        result = self.shell('locked_operation fixture_action')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.path.read_text(),'existing lock content\n'); self.assertEqual(self.path.stat().st_ino,inode)
        self.trace.unlink()
        with self.path.open('r+') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.assertEqual(self.shell('locked_operation fixture_action').returncode,75)
        self.assertFalse(self.trace.exists())
    def test_inherited_fd9_reused_without_releasing_parent_lock_and_forged_flag_refused(self):
        code = 'from pathlib import Path; import sys; from crowdbastion_change import maintenance_lock; c=maintenance_lock(Path(sys.argv[1])); c.__enter__(); c.__exit__(None,None,None); print("inner")'
        inner = 'PYTHONDONTWRITEBYTECODE=1 PYTHONPATH='+shlex.quote(str(ROOT/'lib'))+' python3 -c '+shlex.quote(code)+' "$1" || exit 92; flock -n "$1" true && exit 91; exit 0'
        script = 'locked_operation bash -c '+shlex.quote(inner)+' fixture '+shlex.quote(str(self.path))
        result = self.shell(script)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr); self.assertIn('inner',result.stdout)
        self.assert_refused_untouched(self.shell('locked_operation fixture_action', 'MAINTENANCE_LOCK_HELD=true'))
    def test_python_lock_rejects_hardlink_even_with_matching_inherited_fd9(self):
        os.link(self.protected,self.path)
        with self.assertRaises((ValueError,OSError)):
            with change.maintenance_lock(self.path): self.fail('unsafe linked lock accepted')
        result = self.shell('PYTHONPATH='+shlex.quote(str(ROOT/'lib'))+' MAINTENANCE_LOCK_HELD=true python3 -c '+
            shlex.quote('from crowdbastion_change import maintenance_lock; import sys; from pathlib import Path; c=maintenance_lock(Path(sys.argv[1])); c.__enter__()')+' '+shlex.quote(str(self.path)),
            'exec 9<> "$MAINTENANCE_LOCK"\nflock -n 9')
        self.assertNotEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(self.protected.read_text(),'protected fixture\n')
    def test_sticky_shared_parent_supports_safe_owned_lock_and_descriptor_replacement_refuses(self):
        sticky = self.base/'shared'; sticky.mkdir(); sticky.chmod(0o1777)
        self.path = sticky/'lock'
        result = self.shell('locked_operation fixture_action')
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.trace.unlink()
        replace = '''change_lock_tool() {
 PYTHONDONTWRITEBYTECODE=1 python3 "$SCRIPT_DIR/lib/crowdbastion_change.py" "$@" || return $?
 if [[ "$1" == lock-prepare ]]; then
  rm -- "$MAINTENANCE_LOCK"
  ln -s -- '''+shlex.quote(str(self.protected))+''' "$MAINTENANCE_LOCK"
 fi
}'''
        self.assert_refused_untouched(self.shell('locked_operation fixture_action',replace))
    def test_hub_lock_content_preserved_and_busy_status_matches_shared_flock(self):
        self.hub.write_text('existing Hub lock\n'); self.hub.chmod(0o600)
        with self.hub.open('r+') as stream:
            fcntl.flock(stream,fcntl.LOCK_EX|fcntl.LOCK_NB)
            result = self.shell('hub_begin update', 'hub_event() { :; }')
            self.assertEqual(result.returncode,75,result.stdout+result.stderr)
        self.assertEqual(self.hub.read_text(),'existing Hub lock\n'); self.assertFalse(self.trace.exists())
    def test_missing_python_refuses_before_preflight_or_any_lock_write(self):
        unavailable = '''require_commands() { [[ "$1" != python3 ]]; }
python3() { printf 'unexpected helper\n' >> "$fixture_trace"; return 99; }'''
        result = self.shell('locked_operation fixture_action',unavailable)
        self.assert_refused_untouched(result); self.assertFalse(self.path.exists())
        self.assertIn('Python3',result.stdout+result.stderr)
