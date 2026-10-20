"""Regression cases derived from the three real VPS acceptance reports."""
import json
from pathlib import Path
import shlex
import unittest

import test_workflows
import test_native_workflows
from test_web_install import REMOTE_WAF


class FirewallBackendSafety(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def test_fresh_install_avoids_nftables_renewal_backend(self):
        result = self.run_shell('install_bouncer_package')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('iptables ipset crowdsec-firewall-bouncer-iptables', self.commands())
        self.assertNotIn('crowdsec-firewall-bouncer-nftables', self.commands())

    def installed(self, mode, version):
        config = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        config.parent.mkdir(exist_ok=True)
        config.write_text('mode: '+mode+'\napi_key: keep-private\n')
        binary = self.base/'bin/crowdsec-firewall-bouncer'
        binary.parent.mkdir(exist_ok=True)
        binary.write_text('#!/bin/sh\nprintf "%s\\n" '+shlex.quote('version: '+version)+'\n')
        binary.chmod(0o755)
        return config, 'export PATH='+shlex.quote(str(binary.parent))+':"$PATH"'

    def test_known_nftables_renewal_defect_stops_reinstall_before_package_changes(self):
        for version in ['v0.0.36', 'v0.0.38-debian-pragmatic-amd64']:
            with self.subTest(version=version):
                config, overrides = self.installed('nftables', version)
                before = config.read_bytes()
                self.trace.write_text('')
                result = self.run_shell('install_bouncer_package', overrides=overrides)
                self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
                self.assertIn('续封', result.stderr)
                self.assertEqual(config.read_bytes(), before)
                self.assertNotIn('apt-get', self.commands())
                self.assertNotIn('systemctl', self.commands())
                self.assertNotIn('keep-private', result.stdout+result.stderr)

    def test_effective_local_backend_is_checked(self):
        config, overrides = self.installed('iptables', 'v0.0.36')
        local = Path(str(config)+'.local')
        local.write_text('mode: nftables\n')
        result = self.run_shell('install_bouncer_package', overrides=overrides)
        self.assertNotEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(local.read_text(), 'mode: nftables\n')
        self.assertNotIn('apt-get', self.commands())

    def test_known_defect_stops_core_install_before_dependency_installation(self):
        _, overrides = self.installed('nftables', 'v0.0.36')
        result = self.run_shell('install_crowdsec_core', '203.0.113.2\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('apt-get', self.commands())
        self.assertNotIn('collections install', self.commands())

    def test_known_defect_stops_connection_repair_before_creating_account(self):
        config, overrides = self.installed('nftables', 'v0.0.38')
        result = self.run_shell('repair_firewall_bouncer', overrides=overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(Path(str(config)+'.local').exists())
        self.assertNotIn('bouncers add', self.commands())
        self.assertNotIn('restart', self.commands())

    def test_active_service_version_takes_precedence_over_path_binary(self):
        import importlib
        import subprocess
        from unittest.mock import patch
        helper = importlib.import_module('crowdsec_firewall')
        config, _ = self.installed('nftables', 'v9.9.9')
        calls = []

        def process(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, '42\n' if argv[0] == 'systemctl'
                                               else 'version: v0.0.36\n', '')

        with patch.object(helper.subprocess, 'run', side_effect=process):
            state, _ = helper.assess(config)
        self.assertEqual(state, 'fault')
        self.assertEqual(calls[-1], ['/proc/42/exe', '-version'])

    def test_unknown_nftables_version_is_not_reported_as_validated(self):
        _, overrides = self.installed('nftables', 'development-build')
        result = self.run_shell('check_firewall_backend', overrides=overrides)
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('尚未验证', result.stdout+result.stderr)

    def test_malformed_backend_yaml_never_discloses_credentials(self):
        config, _ = self.installed('iptables', 'v0.0.36')
        for target in [config, Path(str(config)+'.local')]:
            with self.subTest(target=target.name):
                config.write_text('mode: iptables\n')
                target.write_text('mode: nftables\napi_key: [private-secret-canary\n')
                result = self.run_shell('check_firewall_backend')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('private-secret-canary', result.stdout+result.stderr)
                self.assertNotIn('Traceback', result.stdout+result.stderr)
                target.unlink()


class UnifiedFailurePolicy(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    fixture = test_native_workflows.NativeWorkflows.fixture

    def native_install(self):
        overrides = self.fixture()
        result = self.run_shell('install_docker_web_bouncer', 'openresty\ny\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        entry = json.loads(self.state.read_text())['openresty']
        (self.base/'effective').write_text('# configuration file '+REMOTE_WAF+':\n'+self.waf.read_text())
        return overrides, Path(entry['host_assets'])/'bouncer.conf'

    def test_policy_refuses_inactive_or_overridden_request_hooks(self):
        overrides, config = self.native_install()
        before, state_before = config.read_bytes(), self.state.read_bytes()
        effective = self.base/'effective'
        effective.write_text(effective.read_text()+'\nserver { location / { access_by_lua_block { return } } }\n')
        self.trace.write_text('')
        result = self.run_shell('configure_appsec_policy docker false deny openresty deny', 'y\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(self.state.read_bytes(), state_before)
        self.assertNotIn('reload', self.commands())

    def test_post_reload_hook_failure_rolls_back_policy_and_record(self):
        overrides, config = self.native_install()
        result = self.run_shell('configure_appsec_policy docker false passthrough openresty passthrough',
                                'y\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        before, state_before = config.read_bytes(), self.state.read_bytes()
        overrides += '''
eval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() {
 if [[ "$*" == 'exec cid nginx -s reload' ]]; then touch "$TRACE.loaded"; fi
 if [[ "$*" == 'exec cid nginx -T' && -e "$TRACE.loaded" ]]; then printf 'http { }\\n'; return 0; fi
 docker_base "$@"
}
'''
        result = self.run_shell('configure_appsec_policy docker false deny openresty deny', 'y\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(self.state.read_bytes(), state_before)

    def test_managed_policy_sets_both_failures_and_keeps_credentials_and_url(self):
        overrides, config = self.native_install()
        old_lines = [line for line in config.read_text().splitlines()
                     if line.startswith(('API_KEY=', 'APPSEC_URL='))]
        result = self.run_shell('configure_appsec_policy docker false passthrough openresty passthrough',
                                'y\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('LAPI_FAILURE_ACTION=passthrough', config.read_text())
        result = self.run_shell('configure_appsec_policy docker false deny openresty deny', 'y\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('APPSEC_FAILURE_ACTION=deny', config.read_text())
        self.assertIn('LAPI_FAILURE_ACTION=deny', config.read_text())
        self.assertEqual(old_lines, [line for line in config.read_text().splitlines()
                                    if line.startswith(('API_KEY=', 'APPSEC_URL='))])
        self.assertNotIn('0123456789abcdef', result.stdout+result.stderr)
        # Updated ownership must remain usable for subsequent upgrades/removal.
        self.assertEqual(self.run_shell('configure_appsec_policy docker false deny openresty deny',
                                       'y\n', overrides).returncode, 0)

    def test_duplicate_lapi_policy_is_rejected_without_changes(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text('LAPI_FAILURE_ACTION=deny\nLAPI_FAILURE_ACTION=passthrough\n')
        before = file.read_bytes()
        result = self.run_shell('appsec_guard_config '+shlex.quote(str(file)))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(file.read_bytes(), before)

    def test_unmanaged_lapi_request_is_refused_before_mutation(self):
        file = self.config/'bouncers/crowdsec-openresty-bouncer.conf'
        file.parent.mkdir()
        file.write_text('API_KEY=private\nAPPSEC_URL=http://127.0.0.1:7422\n')
        before = file.read_bytes()
        result = self.run_shell('configure_appsec_policy '+shlex.quote(str(file))+' false deny "" deny',
                                'y\n', 'openresty() { return 0; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(file.read_bytes(), before)
        self.assertNotIn('reload', self.commands())

    def test_policy_reload_failure_restores_both_choices_and_ownership(self):
        overrides, config = self.native_install()
        result = self.run_shell('configure_appsec_policy docker false passthrough openresty passthrough',
                                'y\n', overrides)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        before, state_before = config.read_bytes(), self.state.read_bytes()
        overrides += '''
eval "$(declare -f docker | sed '1s/docker/docker_base/')"
docker() { if [[ "$*" == 'exec cid nginx -s reload' ]]; then return 1; fi; docker_base "$@"; }
'''
        result = self.run_shell('configure_appsec_policy docker false deny openresty deny', 'y\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(self.state.read_bytes(), state_before)

    def test_invalid_lapi_choice_preserves_live_files(self):
        overrides, config = self.native_install()
        before, state_before = config.read_bytes(), self.state.read_bytes()
        self.trace.write_text('')
        result = self.run_shell('configure_appsec_policy docker false deny openresty invalid', 'y\n', overrides)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(config.read_bytes(), before)
        self.assertEqual(self.state.read_bytes(), state_before)
        self.assertNotIn('reload', self.commands())


if __name__ == '__main__':
    unittest.main()
