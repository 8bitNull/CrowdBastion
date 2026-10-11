"""Simulated user workflows for dedicated Cloudflare real IP changes."""
import json
import shlex
import unittest
import test_workflows


class RealIPWorkflows(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def fixture(self):
        directory = self.base/'http.d'
        directory.mkdir()
        self.target = directory/'crowdsec-1key-cloudflare-real-ip.conf'
        self.state = self.config/'crowdsec-1key-real-ip.json'
        effective = self.base/'effective'
        effective.write_text('# configuration file /usr/local/openresty/nginx/conf/nginx.conf:\nhttp { include /usr/local/openresty/nginx/conf/http.d/*.conf; }\n')
        mounts = self.base/'mounts'
        mounts.write_text(json.dumps([{'Type':'bind','RW':True,'Source':str(directory),
                                     'Destination':'/usr/local/openresty/nginx/conf/http.d'}]))
        return '''docker() {
record docker "$@"
case "$*" in
 'ps --format '*) echo 'cid 1panel/openresty:1 openresty';;
 'inspect --format {{json .Mounts}} '*) cat '''+shlex.quote(str(mounts))+''';;
 'exec '*' nginx -T') cat '''+shlex.quote(str(effective))+'''
 if [[ -f '''+shlex.quote(str(self.target))+''' ]]; then
  echo '# configuration file /usr/local/openresty/nginx/conf/http.d/crowdsec-1key-cloudflare-real-ip.conf:'
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
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('real_ip_header CF-Connecting-IP;', self.target.read_text())
        self.assertNotIn('127.0.0.1', self.target.read_text())
        original = self.target.read_text()
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.target.read_text(), original)
        result = self.run_shell('repair_cloudflare_real_ip remove', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertEqual((self.config/'config.yaml').read_text(), config_before)
        self.assertNotIn('bouncers add', self.commands())

    def test_cancel_does_not_write_configuration(self):
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\nn\n', self.fixture())
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())

    def test_reload_failure_restores_configuration_and_state(self):
        overrides = self.fixture()+'''\neval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec '*' nginx -s reload' && ! -f "$TRACE.failed" ]]; then touch "$TRACE.failed"; return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.target.exists())
        self.assertFalse(self.state.exists())
        self.assertNotIn('SUCCESS', result.stdout)

    def test_bad_range_response_stops_before_changes(self):
        overrides = self.fixture()+'''\ncurl() { while (($#)); do if [[ "$1" == -o ]]; then echo '<html>error</html>' > "$2"; return 0; fi; shift; done; }
'''
        result = self.run_shell('repair_cloudflare_real_ip', 'openresty\ny\n', overrides)
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


if __name__ == '__main__':
    unittest.main()
