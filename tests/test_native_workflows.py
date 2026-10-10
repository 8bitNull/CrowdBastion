"""Native install/remove transaction tests with simulated Docker and official assets."""
import json
from pathlib import Path
import shlex
import unittest

import test_workflows
from test_web_install import WAF, REMOTE_WAF


class NativeWorkflows(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def fixture(self, extra=''):
        if not Path('/tmp/crowdsec-official-openresty.tgz').exists():
            self.skipTest('pinned official archives required')
        data = self.base/'web/data'
        (data/'conf').mkdir(parents=True)
        self.waf = data/'conf/waf.conf'
        self.waf.write_text(WAF)
        (self.base/'effective').write_text('# configuration file '+REMOTE_WAF+':\n'+WAF)
        (self.base/'mounts').write_text(json.dumps([{'Type': 'bind', 'RW': True,
            'Source': str(data), 'Destination': '/usr/local/openresty/1pwaf/data'}]))
        self.state = self.config/'crowdsec-1key-web-installs.json'
        return '''docker() {
record docker "$@"
case "$*" in
 'ps --format '*) echo 'cid 1panel/openresty:1 openresty';;
 'inspect --format {{.HostConfig.NetworkMode}} '*) echo host;;
 'inspect --format {{.State.Running}} '*) echo true;;
 'inspect --format {{json .Mounts}} '*) cat '''+shlex.quote(str(self.base/'mounts'))+''';;
 'exec '*' nginx -T') cat '''+shlex.quote(str(self.base/'effective'))+''';;
 'exec '*' nginx -V') echo 'nginx version: openresty/1.31';;
esac
return 0
}
curl() {
record curl "$@"
local url='' out=''
while (($#)); do
 case "$1" in -o) out="$2"; shift;; http*) url="$1";; esac
 shift
done
if [[ "$url" == *lua-resty-http* ]]; then cp /tmp/crowdsec-http "$out";
else cp /tmp/crowdsec-official-openresty.tgz "$out"; fi
}
'''+extra

    def test_install_and_repeat_keep_original_waf_without_second_account(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('crowdsec_cache', self.waf.read_text())
        before = self.commands().count('bouncers add ')
        result = self.run_shell('install_docker_web_bouncer', 'openresty\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(before, self.commands().count('bouncers add '))
        self.assertNotIn('0123456789abcdef', result.stdout+result.stderr)

    def test_cancel_before_account_or_file_changes(self):
        result = self.run_shell('install_docker_web_bouncer', 'openresty\nn\n', self.fixture())
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertNotIn('bouncers add', self.commands())

    def test_reload_failure_restores_waf_and_deletes_only_new_account(self):
        overrides = self.fixture()+'''\neval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec '*' nginx -s reload' && ! -e "$TRACE.reload" ]]; then touch "$TRACE.reload"; record reload_failed; return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertFalse((self.base/'web/data/crowdsec-1key').exists())
        self.assertNotIn('SUCCESS', result.stdout)
        self.assertRegex(self.commands(), 'bouncers delete cs-web-1key-')

    def test_remove_restores_original_and_drops_appsec_registry_entry(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertEqual(json.loads(self.state.read_text()), {})
        self.assertFalse((self.config/'crowdsec-1key-appsec-docker-links.yaml').exists())

    def test_failed_rollback_reload_keeps_dependencies_and_account(self):
        overrides = self.fixture()+'''\neval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec '*' nginx -s reload' ]]; then return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.base/'web/data/crowdsec-1key').exists())
        self.assertNotIn('bouncers delete', self.commands())
        self.assertEqual(json.loads(self.state.read_text())['openresty']['status'], 'recovery-required')
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', overrides+'\ndocker() { docker_base "$@"; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertFalse((self.base/'web/data/crowdsec-1key').exists())

    def test_bad_download_is_rejected_before_account_registration(self):
        overrides = self.fixture()+'''\ncurl() { local dest=''; while (($#)); do if [[ "$1" == -o ]]; then dest="$2"; shift; fi; shift; done; printf corrupted > "$dest"; }
'''
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('SHA256', result.stderr)
        self.assertNotIn('bouncers add', self.commands())
        self.assertEqual(self.waf.read_text(), WAF)

    def test_failed_registration_leaves_website_intact(self):
        overrides = self.fixture()+'''\ncscli() { record cscli "$@"; return 1; }
'''
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertFalse((self.base/'web/data/crowdsec-1key').exists())
        self.assertNotIn('bouncers delete', self.commands())

    def test_cleanup_failure_leaves_retryable_state_without_reactivating_revoked_key(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        failing = overrides+'''\ncscli() { record cscli "$@"; if [[ "$*" == bouncers\\ delete* ]]; then return 1; fi; }
'''
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', failing)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.waf.read_text(), WAF)
        self.assertEqual(json.loads(self.state.read_text())['openresty']['status'], 'cleanup-pending')
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_cleanup_retry_handles_already_revoked_account(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        failing = overrides+'''\neval "$(declare -f web_tool | sed '1s/web_tool/web_tool_base/')"
web_tool() { if [[ "$1" == forget ]]; then return 1; fi; web_tool_base "$@"; }
'''
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', failing)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.waf.read_text(), WAF)
        absent = overrides+'''\ncscli() { record cscli "$@"; case "$*" in 'bouncers delete '*) return 1;; 'bouncers list -o json') echo '[]';; esac; }
'''
        result = self.run_shell('remove_docker_web_bouncer', 'openresty\ny\n', absent)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_native_file_hook_is_diagnosed_and_can_be_relinked_after_disable(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        (self.base/'effective').write_text('# configuration file '+REMOTE_WAF+':\n'+self.waf.read_text())
        config = self.base/'web/data/crowdsec-1key/bouncer.conf'
        text = config.read_text().replace('APPSEC_URL=http://127.0.0.1:7422', 'APPSEC_URL=')
        config.write_text(text)
        (self.config/'crowdsec-1key-appsec-docker-links.yaml').unlink()
        result = self.run_shell('diagnose_appsec_containers', '', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertNotIn('缺少 CrowdSec Web Bouncer', result.stdout+result.stderr)
        result = self.run_shell('link_docker_appsec', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', config.read_text())


if __name__ == '__main__':
    unittest.main()
