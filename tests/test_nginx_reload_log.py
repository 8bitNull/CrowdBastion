"""A master accepting a configuration is distinct from respawning old workers."""
import importlib.util
from pathlib import Path
import tempfile
import unittest


class ReloadLog(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('reload_log', Path(__file__).resolve().parents[1]/'lib/crowdsec_nginx_reload.py')
        self.tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.tool)
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.proc = self.base/'proc'
        for host, namespace in [('42', '1'), ('101', '7'), ('102', '8')]:
            directory = self.proc/host; directory.mkdir(parents=True)
            (directory/'status').write_text('NSpid:\t'+host+'\t'+namespace+'\n')
        self.log = self.base/'nginx error.log'; self.log.write_text(self.line('reconfiguring')+self.line('start worker processes'))
        self.cursor = self.tool.capture('42', self.log, self.proc)

    @staticmethod
    def line(message, pid=1, level='notice'):
        return f'2026/10/20 00:00:00 [{level}] {pid}#{pid}: {message}\n'

    def append(self, *messages):
        with self.log.open('a') as stream:
            stream.write(''.join(self.line(message) for message in messages))

    def accepted(self):
        return self.tool.accepted(self.cursor, self.log, ['101', '102'], self.proc)

    def test_old_or_respawn_records_do_not_prove_acceptance(self):
        self.assertFalse(self.accepted())
        self.append('reconfiguring', 'start worker process 7', 'start worker process 8')
        self.assertFalse(self.accepted())

    def test_fresh_complete_master_cohort_matches_namespaced_workers(self):
        self.append('reconfiguring', 'start worker processes', 'start worker process 7', 'start worker process 8')
        self.assertTrue(self.accepted())

    def test_wrong_master_partial_line_and_missing_worker_are_not_accepted(self):
        self.append('reconfiguring', 'start worker processes', 'start worker process 7')
        with self.log.open('a') as stream:
            stream.write(self.line('start worker process 8', pid=2))
            stream.write(self.line('start worker process 8').rstrip('\n'))
        self.assertFalse(self.accepted())
        with self.log.open('a') as stream: stream.write('\n')
        self.assertTrue(self.accepted())

    def test_later_rejection_and_conflicting_lifecycle_invalidate_previous_cohort(self):
        for event in ['reconfiguring', 'init_by_lua_file error: missing cert',
                      'changing binary', 'reopening logs', 'exiting',
                      'signal 12 (SIGUSR2) received from 99']:
            with self.subTest(event=event):
                self.log.write_text('')
                cursor = self.tool.capture('42', self.log, self.proc)
                self.append('reconfiguring', 'start worker processes', 'start worker process 7', 'start worker process 8', event)
                self.assertFalse(self.tool.accepted(cursor, self.log, ['101', '102'], self.proc))

    def test_replaced_truncated_or_overwritten_log_is_rejected(self):
        for action in ('replace', 'truncate', 'overwrite'):
            with self.subTest(action=action):
                self.log.write_text('baseline\n')
                cursor = self.tool.capture('42', self.log, self.proc)
                if action == 'replace':
                    replacement = self.base/'replacement'; replacement.write_text('baseline\n'); replacement.replace(self.log)
                elif action == 'truncate': self.log.write_text('')
                else: self.log.write_text('different\n')
                self.append('reconfiguring', 'start worker processes', 'start worker process 7', 'start worker process 8')
                with self.assertRaises(ValueError):
                    self.tool.accepted(cursor, self.log, ['101', '102'], self.proc)

    def test_locate_only_main_notice_error_log_matching_open_inode(self):
        master = self.proc/'42'; (master/'fd').mkdir()
        (master/'root').symlink_to('/')
        (master/'fd/5').symlink_to(self.log)
        dump = '# configuration file /nginx.conf:\nerror_log "'+str(self.log)+'" notice;\nhttp {}\n'
        self.assertEqual(self.tool.locate('42', dump, self.proc), master/'fd/5')
        for invalid in [dump.replace(' notice;', ' error;'),
                        '# configuration file /nginx.conf:\nhttp { include /http.conf; }\n# configuration file /http.conf:\nerror_log "'+str(self.log)+'" notice;\n',
                        dump.replace(str(self.log), '/missing'),
                        dump.replace('error_log', 'access_log')]:
            with self.subTest(dump=invalid), self.assertRaises(ValueError):
                self.tool.locate('42', invalid, self.proc)

    def test_bound_log_read_and_missing_namespace_metadata_fail_closed(self):
        self.append('x' * (self.tool.MAX_LOG_BYTES+1))
        with self.assertRaises(ValueError): self.accepted()
        with self.assertRaises((OSError, ValueError)):
            self.tool.capture('missing', self.log, self.proc)

    def test_shared_log_with_colliding_container_master_pid_is_rejected(self):
        other = self.proc/'43'; (other/'fd').mkdir(parents=True)
        (other/'status').write_text('NSpid:\t43\t1\n')
        (other/'fd/5').symlink_to(self.log)
        # Another container's successful cycle must not bless target workers
        # respawned from a rejected cycle, even if all records say master 1.
        self.append('reconfiguring', 'init_by_lua_file error: missing cert',
                    'reconfiguring', 'start worker processes', 'start worker process 19',
                    'start worker process 7', 'start worker process 8')
        with self.assertRaises(ValueError): self.accepted()
        with self.assertRaises(ValueError): self.tool.capture('42', self.log, self.proc)
        master = self.proc/'42'; (master/'fd').mkdir()
        (master/'root').symlink_to('/')
        (master/'fd/5').symlink_to(self.log)
        dump = '# configuration file /nginx.conf:\nerror_log "'+str(self.log)+'" notice;\n'
        with self.assertRaises(ValueError): self.tool.locate('42', dump, self.proc)

    def test_distinct_logged_master_pid_does_not_make_log_ambiguous(self):
        other = self.proc/'43'; (other/'fd').mkdir(parents=True)
        (other/'status').write_text('NSpid:\t43\t2\n')
        (other/'fd/5').symlink_to(self.log)
        self.append('reconfiguring', 'start worker processes', 'start worker process 7', 'start worker process 8')
        self.assertTrue(self.accepted())


if __name__ == '__main__':
    unittest.main()
