"""Simulated user workflows for dedicated Cloudflare real IP changes."""
import json
import shlex
import unittest
import test_workflows


class RealIPWorkflows(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def fixture(self, npm=False):
        directory = self.base/('data' if npm else 'http.d')
        directory.mkdir()
        remote = '/data/nginx/custom/server_proxy.conf' if npm else '/usr/local/openresty/nginx/conf/http.d/crowdsec-1key-cloudflare-real-ip.conf'
        self.target = directory/('nginx/custom/server_proxy.conf' if npm else 'crowdsec-1key-cloudflare-real-ip.conf')
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.state = self.config/'crowdsec-1key-real-ip.json'
        effective = self.base/'effective'
        effective.write_text('# configuration file /usr/local/openresty/nginx/conf/nginx.conf:\nhttp { include /usr/local/openresty/nginx/conf/http.d/*.conf; }\n')
        if npm:
            effective.write_text('''# configuration file /etc/nginx/nginx.conf:
http { set_real_ip_from 10.0.0.0/8; real_ip_header X-Real-IP; real_ip_recursive on; include /data/nginx/custom/http_top[.]conf; }
# configuration file /data/nginx/proxy_host/10.conf:
server { include /data/nginx/custom/server_proxy[.]conf; }
''')
        mounts = self.base/'mounts'
        mounts.write_text(json.dumps([{'Type':'bind','RW':True,'Source':str(directory),
                                     'Destination':'/data' if npm else '/usr/local/openresty/nginx/conf/http.d'}]))
        return '''docker() {
record docker "$@"
case "$*" in
 'top '*) nginx_test_processes;;
 'exec '*' nginx -s reload') nginx_test_reload;;
 'ps --format '*) echo 'cid 1panel/openresty:1 openresty';;
 'inspect --format {{json .Mounts}} '*) cat '''+shlex.quote(str(mounts))+''';;
 'exec '*' nginx -T') cat '''+shlex.quote(str(effective))+'''
 if [[ -f '''+shlex.quote(str(self.target))+''' ]]; then
  echo '# configuration file '''+remote+''':'
  cat '''+shlex.quote(str(self.target))+'''
 fi;;
 'exec '*' nginx -V') echo 'nginx version: openresty/1.31 --with-http_realip_module';;
esac
return 0
}
curl() {
local url='' out=''
while (($#)); do case "$1" in -o) out="$2"; shift;; http*) url="$1";; esac; shift; done
if [[ "$url" == *ips-v4 ]]; then
cat > "$out" <<'RANGES'
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
RANGES
else
printf '%s\\n' '2400:cb00::/32' '2606:4700::/32' '2803:f800::/32' > "$out"
fi
}
'''

    def test_apply_repeat_and_restore_preserve_other_configuration(self):
        overrides = self.fixture()
        config_before = (self.config/'config.yaml').read_text()
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('real_ip_header CF-Connecting-IP;', self.target.read_text())
        self.assertNotIn('127.0.0.1', self.target.read_text())
        original = self.target.read_text()
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.target.read_text(), original)
        result = self.run_shell('repair_cloudflare_real_ip remove', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertEqual((self.config/'config.yaml').read_text(), config_before)
        self.assertNotIn('bouncers add', self.commands())

    def test_cancel_does_not_write_configuration(self):
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\nn\n', self.fixture())
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())

    def test_reload_failure_restores_configuration_and_state(self):
        overrides = self.fixture()+'''\neval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec '*' nginx -s reload' && ! -f "$TRACE.failed" ]]; then touch "$TRACE.failed"; return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn('SUCCESS', result.stdout)

    def test_bad_range_response_stops_before_changes(self):
        overrides = self.fixture()+'''\ncurl() { while (($#)); do if [[ "$1" == -o ]]; then echo '<html>error</html>' > "$2"; return 0; fi; shift; done; }
'''
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_purge_preserves_active_real_ip_ownership(self):
        self.fixture()
        self.state.write_text(json.dumps({'openresty': {'host_target': str(self.target)}}))
        result = self.run_shell('deep_purge_residuals', 'y\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.state.exists())
        self.assertIn('--restore-real-ip', result.stdout+result.stderr)
        self.assertNotIn('systemctl stop', self.commands())

    def test_custom_proxy_does_not_fetch_or_guess_cdn_ranges(self):
        overrides = self.fixture()
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n2\nX-Forwarded-For\n192.0.2.0/24\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('real_ip_header X-Forwarded-For;', self.target.read_text())
        self.assertNotIn('CF-Connecting-IP', self.target.read_text())
        self.assertNotIn('curl ', self.commands())

    def test_npm_preserves_custom_settings_on_apply_and_restore(self):
        overrides = self.fixture(npm=True)
        original = '# existing settings\nadd_header X-Test intact;\n'
        self.target.write_text(original)
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n1\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertTrue(self.target.read_text().startswith(original))
        self.assertIn('real_ip_header CF-Connecting-IP;', self.target.read_text())
        result = self.run_shell('repair_cloudflare_real_ip remove', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.target.read_text(), original)

    def test_unknown_upstream_is_read_only_and_does_not_require_module(self):
        overrides = self.fixture()+'''\neval "$(declare -f docker | sed '1s/docker/docker_base/')"
require_core() { return 1; }
docker() { if [[ "$*" == 'exec '*' nginx -V' ]]; then return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n3\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('上游仍未确认', result.stdout+result.stderr)
        self.assertIn('crowdsec_ip_check=', result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn('curl ', self.commands())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_confirmed_direct_keeps_existing_trust_untouched(self):
        overrides = self.fixture()
        original = '# existing configuration\n'
        self.target.write_text(original)
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n4\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('无需新增真实 IP 配置', result.stdout+result.stderr)
        self.assertEqual(self.target.read_text(), original)
        self.assertFalse(self.state.exists())
        self.assertNotIn('curl ', self.commands())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_diagnosis_needs_neither_core_nor_curl_nor_module(self):
        overrides = self.fixture()+'''\nrequire_core() { return 1; }
require_commands() { [[ "$*" != *curl* ]]; }
eval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec '*' nginx -V' ]]; then return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('main --diagnose-real-ip', 'openresty\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('上游仍未确认', result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn('curl ', self.commands())
        self.assertNotIn('nginx -s reload', self.commands())

    def test_unknown_keeps_existing_managed_files_and_registry(self):
        overrides = self.fixture()
        original = '# managed real IP\nreal_ip_header CF-Connecting-IP;\n'
        state = '{"openresty": {"header": "CF-Connecting-IP"}}\n'
        self.target.write_text(original)
        self.state.write_text(state)
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\n3\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.target.read_text(), original)
        self.assertEqual(self.state.read_text(), state)
        self.assertIn('--restore-real-ip', result.stdout+result.stderr)
        self.assertNotIn('curl ', self.commands())
        self.assertNotIn('nginx -s reload', self.commands())


if __name__ == '__main__':
    unittest.main()
