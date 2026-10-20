"""Live master/worker acceptance, including vendor init failure after a successful -t."""
import contextlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import unittest
import urllib.request

import test_workflows
import test_web_bouncer_runtime as runtime_tests
NGINX = runtime_tests.NGINX


@unittest.skipUnless(NGINX and Path(NGINX).is_file(), 'Lua-enabled Nginx required')
class LiveReload(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp

    @contextlib.contextmanager
    def runtime(self):
        runtime_tests.WebBouncerRuntime.setUpClass()
        assets = self.base/'assets'
        runtime_tests.WebBouncerRuntime.web.stage_assets({'mode': 'npm', 'original': None, 'container_assets': str(assets)},
            runtime_tests.WebBouncerRuntime.bouncer_archive, runtime_tests.WebBouncerRuntime.http_archive, assets,
            '0123456789abcdef0123456789abcdef', 'http://127.0.0.1:9/')
        cert, key = self.base/'client.crt', self.base/'client.key'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                        '-subj', '/CN=reload-test', '-keyout', str(key), '-out', str(cert)],
                       check=True, capture_output=True)
        config = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        config.parent.mkdir()
        (assets/'bouncer.conf').rename(config)
        (assets/'bouncer.conf').symlink_to(config)
        with config.open('a') as f:
            f.write(f'\nUSE_TLS_AUTH=true\nTLS_CLIENT_CERT={cert}\nTLS_CLIENT_KEY={key}\n')
        prefix = Path(os.environ['CROWDBASTION_TEST_LUA_PREFIX'])
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = f'{prefix}/usr/lib/x86_64-linux-gnu:{prefix}/lib/x86_64-linux-gnu'
        nginx_conf = self.base/'nginx.conf'
        port = runtime_tests.unused_port()
        nginx_conf.write_text(f'''
load_module {prefix}/usr/lib/nginx/modules/ndk_http_module.so;
load_module {prefix}/usr/lib/nginx/modules/ngx_http_lua_module.so;
daemon off;
master_process on;
worker_processes 2;
pid {self.base}/nginx.pid;
error_log {self.base}/nginx-error.log notice;
events {{ worker_connections 128; }}
http {{
 access_log off;
 client_body_temp_path {self.base}/body;
 proxy_temp_path {self.base}/proxy;
 fastcgi_temp_path {self.base}/fastcgi;
 uwsgi_temp_path {self.base}/uwsgi;
 scgi_temp_path {self.base}/scgi;
 lua_package_path "{assets}/lib/?.lua;{prefix}/usr/share/lua/5.1/?.lua;{prefix}/usr/share/lua/5.1/?/init.lua;;";
 lua_package_cpath "{prefix}/usr/lib/x86_64-linux-gnu/lua/5.1/?.so;;";
 lua_shared_dict crowdsec_cache 2m;
 init_by_lua_file {assets}/init.lua;
 server {{ listen 127.0.0.1:{port}; location / {{ return 200 "alive"; }} }}
}}
''')
        cmd = [NGINX, '-p', str(self.base)+'/', '-c', str(nginx_conf)]
        process = subprocess.Popen(cmd, env=env, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if self.workers(process.pid):
                    break
                if process.poll() is not None:
                    self.fail(process.stderr.read().decode()+((self.base/'nginx-error.log').read_text() if (self.base/'nginx-error.log').exists() else ''))
                time.sleep(.05)
            self.assertTrue(self.workers(process.pid))
            bindir = self.base/'bin'; bindir.mkdir()
            nginx_cmd = shlex.join(cmd)
            scripts = {
                'openresty': f'exec {nginx_cmd} "$@"',
                'systemctl': f'case "$1" in show) echo {process.pid};; reload) exec {nginx_cmd} -s reload;; *) exit 1;; esac',
                'docker': f'''case "$1" in
 top) exec ps -p {process.pid} --ppid {process.pid} -o pid,ppid,stat,args;;
 exec) shift 2; [ "$1" = nginx ] || exit 1; shift; exec {nginx_cmd} "$@";;
 *) exit 1;; esac''',
            }
            for name, text in scripts.items():
                path = bindir/name; path.write_text('#!/bin/bash\n'+text+'\n'); path.chmod(0o755)
            env['PATH'] = str(bindir)+':'+env['PATH']
            yield config, cert, process, env
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill(); process.wait(timeout=5)
            process.stderr.close()

    @staticmethod
    def workers(master):
        result = subprocess.run(['ps', '--ppid', str(master), '-o', 'pid=,args='], capture_output=True, text=True)
        return {line.split()[0] for line in result.stdout.splitlines() if 'nginx: worker process' in line and 'shutting down' not in line}

    def shell(self, action, env):
        return subprocess.run(['bash', '-c', f'source {shlex.quote(str(self.source))}\n'
            'require_core() { :; }; require_yaml() { :; }; require_commands() { :; }; confirm() { :; }\n'+action],
            env=env, capture_output=True, text=True, timeout=26)

    def test_host_policy_commits_only_after_live_worker_replacement(self):
        with self.runtime() as (config, cert, process, env):
            old_workers = self.workers(process.pid)
            result = self.shell(f'configure_appsec_policy {shlex.quote(str(config))} true passthrough', env)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertTrue(self.workers(process.pid)-old_workers)
            self.assertIn('APPSEC_FAILURE_ACTION=passthrough', config.read_text())

    def test_vendor_init_rejection_rolls_back_policy_and_reports_incomplete_recovery(self):
        with self.runtime() as (config, cert, process, env):
            original = config.read_bytes(); old_workers = self.workers(process.pid)
            cert.unlink()
            # Nginx's command processes succeed even though the live master rejects init_by_lua.
            for option in [['-t'], ['-s', 'reload'], ['-T']]:
                probe = subprocess.run(['openresty']+option, env=env, capture_output=True)
                self.assertEqual(probe.returncode, 0, probe.stderr.decode())
            started = time.monotonic()
            result = self.shell(f'configure_appsec_policy {shlex.quote(str(config))} true passthrough', env)
            self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(config.read_bytes(), original)
            self.assertEqual(self.workers(process.pid), old_workers)
            self.assertIn('恢复不完整', result.stderr)
            self.assertTrue(list((self.base/'var/backups/crowdsec-1key').glob('change.*')))
            self.assertLess(time.monotonic()-started, 23)

    def test_docker_verification_observes_live_master_and_workers(self):
        with self.runtime() as (config, cert, process, env):
            old_workers = self.workers(process.pid)
            result = self.shell('nginx_reload_verified docker web', env)
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertTrue(self.workers(process.pid)-old_workers)

    def test_rejected_reload_with_old_cycle_respawns_does_not_commit_policy(self):
        from crowdsec_appsec import set_policy
        with self.runtime() as (config, cert, process, env):
            conf = self.base/'nginx.conf'
            # Read the configuration held in each serving worker's Lua state.
            lua = ('content_by_lua_block { local _, runtime = debug.getupvalue('
                   'require("crowdsec_1key.crowdsec").get_mode, 1); '
                   'ngx.say(runtime.conf["APPSEC_FAILURE_ACTION"]); }')
            conf.write_text(conf.read_text().replace('return 200 "alive";', lua))
            set_policy(config, 'false', 'passthrough', 'passthrough')
            old = self.workers(process.pid)
            subprocess.run(['openresty', '-s', 'reload'], env=env, check=True, capture_output=True)
            for _ in range(100):
                current = self.workers(process.pid)
                if len(current) == 2 and not current & old:
                    break
                time.sleep(.05)
            self.assertEqual(len(current), 2)
            self.assertFalse(current & old)
            port = re.search(r'listen 127.0.0.1:(\d+)', conf.read_text())[1]
            def live_policy():
                with urllib.request.urlopen('http://127.0.0.1:'+port+'/', timeout=2) as response:
                    return response.read().decode().strip()
            self.assertEqual(live_policy(), 'passthrough')
            original = config.read_bytes()
            cert.unlink()
            systemctl = self.base/'bin/systemctl'
            script = systemctl.read_text().replace('reload) exec ', 'reload) ')
            # Only the first reload kills these exact fixture PIDs. Wait for
            # the master to reject init, then respawn using its old cycle.
            script = script.replace('-s reload;;', '-s reload; sleep .4; '
                'if [ ! -f '+shlex.quote(str(self.base/'respawned'))+' ]; then '
                'kill -KILL '+' '.join(sorted(current))+'; touch '+
                shlex.quote(str(self.base/'respawned'))+'; sleep .4; fi;;')
            systemctl.write_text(script)
            result = self.shell('configure_appsec_policy '+shlex.quote(str(config))+' true deny', env)
            self.assertEqual(live_policy(), 'passthrough')
            self.assertFalse(self.workers(process.pid) & current)
            self.assertIn('init_by_lua_file error', (self.base/'nginx-error.log').read_text())
            self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertEqual(config.read_bytes(), original)
            self.assertNotIn('正文及 AppSec/LAPI 故障策略已按选择配置', result.stdout)
            self.assertIn('恢复不完整', result.stderr)

    def test_unobservable_master_log_refuses_policy_and_preserves_config(self):
        with self.runtime() as (config, cert, process, env):
            conf = self.base/'nginx.conf'
            conf.write_text(conf.read_text().replace('nginx-error.log notice;', 'nginx-error.log error;'))
            original = config.read_bytes()
            result = self.shell('configure_appsec_policy '+shlex.quote(str(config))+' true passthrough', env)
            self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
            self.assertIn('notice', result.stderr)
            self.assertEqual(config.read_bytes(), original)


class ReloadProcessEvidence(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell

    def test_log_namespace_query_is_bounded_when_metadata_read_hangs(self):
        proc = Path(str(self.trace)+'.proc/42'); proc.mkdir(parents=True)
        os.mkfifo(proc/'status')
        log = self.base/'error.log'; log.write_text('')
        started = time.monotonic()
        result = self.run_shell('nginx_reload_tool 0.2 capture 42 '+shlex.quote(str(log)),
                                overrides='unset -f timeout', timeout=2)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertLess(time.monotonic()-started, 1)

    def test_worker_that_dies_before_second_sample_is_not_accepted(self):
        overrides = r'''
docker() {
 case "$1" in
 top)
  local n=0; [[ ! -f "$TRACE.samples" ]] || read -r n < "$TRACE.samples"
  echo "$((n+1))" > "$TRACE.samples"
  echo 'PID PPID STAT COMMAND'
  echo '42 1 Ss nginx: master process nginx'
  case "$n" in 0) echo '100 42 S nginx: worker process';; 1) echo '101 42 S nginx: worker process';; esac;;
 esac
}
'''
        result = self.run_shell('nginx_reload_verified docker web', overrides=overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_master_replacement_is_not_accepted_as_reload(self):
        overrides = r'''
docker() {
 case "$1" in
 top)
  echo 'PID PPID STAT COMMAND'
  if [[ -f "$TRACE.reloaded" ]]; then
   echo '43 1 Ss nginx: master process nginx'; echo '101 43 S nginx: worker process'
  else
   echo '42 1 Ss nginx: master process nginx'; echo '100 42 S nginx: worker process'
  fi;;
 exec) [[ "$*" != *'nginx -s reload' ]] || touch "$TRACE.reloaded";;
 esac
 return 0
}
'''
        result = self.run_shell('nginx_reload_verified docker web', overrides=overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_host_process_queries_share_one_ten_second_deadline(self):
        bindir = self.base/'bin'; bindir.mkdir()
        scripts = {
            'openresty': 'exit 0',
            'systemctl': '''case "$1" in
 show) [[ ! -f "$TRACE.reloaded" ]] || sleep 3; echo 42;;
 reload) touch "$TRACE.reloaded";; esac''',
            'ps': '''if [[ -f "$TRACE.reloaded" ]]; then exec sleep 30; fi
printf 'PID PPID STAT COMMAND\n42 1 Ss nginx: master process nginx\n100 42 S nginx: worker process\n'
''',
        }
        for name, content in scripts.items():
            path = bindir/name; path.write_text('#!/bin/bash\n'+content+'\n'); path.chmod(0o755)
        overrides = 'unset EPOCHREALTIME; unset -f systemctl ps timeout sleep; export PATH='+shlex.quote(str(bindir))+':"$PATH"'
        started = time.monotonic()
        try:
            result = self.run_shell('nginx_reload_verified openresty', overrides=overrides, timeout=12)
        except subprocess.TimeoutExpired:
            self.fail('Host sampling exceeded the shared ten-second verification deadline')
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertLess(time.monotonic()-started, 11.5)

    def test_term_ignoring_query_and_child_are_killed_within_remaining_budget(self):
        bindir = self.base/'bin'; bindir.mkdir()
        docker = bindir/'docker'
        docker.write_text('''#!/bin/bash
trap '' TERM
(sleep 0.8; touch "$TRACE.child-survived") &
wait
printf 'PID PPID STAT COMMAND\n42 1 Ss nginx: master process nginx\n100 42 S nginx: worker process\n'
''')
        docker.chmod(0o755)
        overrides = 'unset -f docker timeout sleep; export PATH='+shlex.quote(str(bindir))+':"$PATH"'
        started = time.monotonic()
        result = self.run_shell('deadline=$(nginx_monotonic_us); nginx_process_snapshot docker web "$((deadline+200000))"',
                                overrides=overrides, timeout=2)
        elapsed = time.monotonic()-started
        # Wait beyond the child marker time to verify the whole owned group died.
        time.sleep(max(0, 1-elapsed))
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertLess(elapsed, 0.65)
        self.assertFalse(Path(str(self.trace)+'.child-survived').exists())

    def test_hung_process_query_cannot_extend_ten_second_verification(self):
        bindir = self.base/'bin'; bindir.mkdir()
        docker = bindir/'docker'
        docker.write_text('''#!/bin/bash
case "$1" in
 top)
  if [[ -f "$TRACE.reloaded" ]]; then exec sleep 30; fi
  printf 'PID PPID STAT COMMAND\n42 1 Ss nginx: master process nginx\n100 42 S nginx: worker process\n';;
 exec) [[ "$*" != *'nginx -s reload' ]] || touch "$TRACE.reloaded";;
esac
exit 0
''')
        docker.chmod(0o755)
        overrides = 'unset -f docker timeout sleep; export PATH='+shlex.quote(str(bindir))+':"$PATH"'
        started = time.monotonic()
        result = self.run_shell('nginx_reload_verified docker web', overrides=overrides, timeout=13)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertLess(time.monotonic()-started, 11.5)


if __name__ == '__main__':
    unittest.main()
