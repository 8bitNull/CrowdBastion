"""Relay installation and read-only firewall evidence, isolated from the host."""
import json
import os
from pathlib import Path
import shlex
import subprocess
import unittest

import yaml
import test_workflows


class RelayMode(unittest.TestCase):
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def setUp(self):
        test_workflows.Workflows.setUp(self)
        # main re-detects the OS, using the fixture's rewritten /etc path.
        (self.base/'etc/os-release').write_text('ID=debian\n')

    def auth_log(self):
        path = self.base/'var/log/auth.log'
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
        return path

    def relay_file(self):
        return self.config/'acquis.d/crowdsec-1key-relay.yaml'

    def install(self, overrides=''):
        return self.run_shell('main --install-relay', '203.0.113.2\n', overrides)

    def test_relay_installs_system_rules_and_only_auth_log(self):
        auth = self.auth_log()
        web = self.base/'var/log/nginx/access.log'
        web.parent.mkdir(parents=True)
        web.touch()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(self.relay_file().read_text()), {
            'filenames': [str(auth)], 'labels': {'type': 'syslog'}})
        self.assertIn('collections install crowdsecurity/linux crowdsecurity/sshd crowdsecurity/whitelist-good-actors', self.commands())
        self.assertNotRegex(self.commands(), r'crowdsecurity/(nginx|http|appsec)|docker |nginx |openresty ')
        self.assertIn('enable --now crowdsec-firewall-bouncer', self.commands())
        self.assertFalse((self.config/'acquis.d/crowdsec-1key-log-repair.yaml').exists())

    def test_relay_preserves_existing_web_and_appsec_sources(self):
        self.auth_log()
        directory = self.config/'acquis.d'
        directory.mkdir()
        web = directory/'web-sites.yaml'
        appsec = directory/'appsec.yaml'
        web.write_text('# owned by another installer\nfilenames: [/custom/access.log]\nlabels: {type: nginx}\n')
        appsec.write_text('source: appsec\nlisten_addr: 127.0.0.1:7422\nlabels: {type: appsec}\n')
        before = {p: p.read_bytes() for p in (web, appsec)}
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual({p: p.read_bytes() for p in before}, before)
        self.assertNotIn('collections remove', self.commands())

    def test_relay_fresh_install_creates_system_acquisition(self):
        auth = self.auth_log()
        seed = self.base/'seed-config.yaml'
        seed.write_bytes((self.config/'config.yaml').read_bytes())
        (self.config/'config.yaml').unlink()
        override = ('apt-get() { record apt-get "$@"; '
                    'if [[ "$*" == "install -y --no-upgrade crowdsec" ]]; then '
                    'cp '+shlex.quote(str(seed))+' "$CS_DIR/config.yaml"; fi; return 0; }')
        result = self.install(override)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('apt-get update', self.commands())
        self.assertIn('https://install.crowdsec.net', self.commands())
        self.assertEqual(yaml.safe_load(self.relay_file().read_text())['filenames'], [str(auth)])

    def test_relay_unrelated_journal_source_does_not_hide_missing_ssh(self):
        directory = self.config/'acquis.d'
        directory.mkdir()
        (directory/'other.yaml').write_text('source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=nginx.service]\nlabels: {type: syslog}\n')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(self.relay_file().read_text())['journalctl_filter'],
                         ['_SYSTEMD_UNIT=ssh.service', '_SYSTEMD_UNIT=sshd.service'])

    def test_relay_respects_active_paths_and_existing_globs(self):
        auth = self.auth_log()
        active = self.base/'active-acquis'
        active.mkdir()
        (active/'existing.yml').write_text(yaml.safe_dump({
            'filenames': [str(auth.parent/'auth.*')], 'labels': {'type': 'syslog'}}))
        (self.config/'config.yaml.local').write_text(yaml.safe_dump({
            'crowdsec_service': {'acquisition_dir': str(active)}}))
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse((active/'crowdsec-1key-relay.yaml').exists())
        self.assertFalse(self.relay_file().exists())

    def test_relay_uses_journald_when_auth_files_absent(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(yaml.safe_load(self.relay_file().read_text()), {
            'source': 'journalctl',
            'journalctl_filter': ['_SYSTEMD_UNIT=ssh.service', '_SYSTEMD_UNIT=sshd.service'],
            'labels': {'type': 'syslog'}})
        self.assertIn('cscli metrics', result.stdout)

    def test_relay_existing_journal_source_does_not_get_duplicate(self):
        directory = self.config/'acquis.d'
        directory.mkdir()
        existing = directory/'ssh.yaml'
        existing.write_text('source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service]\nlabels: {type: syslog}\n')
        before = existing.read_bytes()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(existing.read_bytes(), before)
        self.assertFalse(self.relay_file().exists())

    def test_relay_broad_journal_unit_filter_does_not_duplicate_ssh(self):
        self.auth_log()
        directory = self.config/'acquis.d'
        directory.mkdir()
        existing = directory/'system.yaml'
        existing.write_text('source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service, _SYSTEMD_UNIT=nginx.service]\nlabels: {type: syslog}\n')
        before = existing.read_bytes()
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(existing.read_bytes(), before)
        self.assertFalse(self.relay_file().exists())

    def test_relay_constrained_ssh_journal_avoids_duplicate_and_warns(self):
        directory = self.config/'acquis.d'
        directory.mkdir()
        (directory/'ssh.yaml').write_text('source: journalctl\njournalctl_filter: [_SYSTEMD_UNIT=ssh.service, PRIORITY=3]\nlabels: {type: syslog}\n')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse(self.relay_file().exists())
        self.assertIn('额外过滤条件', result.stderr)

    def test_relay_repeated_install_keeps_inode_and_skips_core_restart(self):
        self.auth_log()
        self.assertEqual(self.install().returncode, 0)
        inode = self.relay_file().stat().st_ino
        content = self.relay_file().read_bytes()
        self.trace.write_text('')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(self.relay_file().stat().st_ino, inode)
        self.assertEqual(self.relay_file().read_bytes(), content)
        self.assertNotIn('systemctl restart crowdsec', self.commands())

    def test_relay_validation_failure_removes_new_source_and_restores_whitelist(self):
        self.auth_log()
        whitelist = self.config/'parsers/s02-enrich/99-admin-whitelist.yaml'
        whitelist.parent.mkdir(parents=True)
        whitelist.write_text('name: custom/admin\nwhitelist: {ip: [203.0.113.9]}\n')
        before = whitelist.read_bytes()
        result = self.install('crowdsec() { record crowdsec "$@"; return 1; }')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.relay_file().exists())
        self.assertEqual(whitelist.read_bytes(), before)
        self.assertNotIn('systemctl restart crowdsec', self.commands())
        self.assertNotIn('SUCCESS', result.stdout)
        self.assertIn('crowdsec -t', self.commands())

    def test_relay_restart_failure_rolls_back_source(self):
        self.auth_log()
        result = self.install('''failed=false
systemctl() {
 record systemctl "$@"
 if [[ "$*" == 'restart crowdsec' && "$failed" == false ]]; then failed=true; return 1; fi
 return 0
}''')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.relay_file().exists())
        self.assertNotIn('SUCCESS', result.stdout)
        self.assertGreaterEqual(self.commands().count('systemctl restart crowdsec'), 2)

    def test_relay_symlink_destination_is_rejected(self):
        self.auth_log()
        self.relay_file().parent.mkdir()
        outside = self.base/'outside.yaml'
        outside.write_text('# unchanged\n')
        self.relay_file().symlink_to(outside)
        result = self.install()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(), '# unchanged\n')
        self.assertNotIn('systemctl restart crowdsec', self.commands())

    def test_installation_menu_exposes_relay_entry(self):
        result = self.run_shell('manage_installation', '5\n0\n',
                                'install_crowdsec_core() { record profile "$@"; }')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn('profile relay', self.commands())

    def test_relay_status_cli_does_not_take_management_lock(self):
        result = self.run_shell('main --relay-status', overrides='''
check_relay_status() { printf 'read-only relay\n'; return 2; }
locked_operation() { printf 'unexpected lock\n'; return 99; }
''')
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('read-only relay', result.stdout)


class RelayAudit(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base/'crowdsec'
        (self.config/'bouncers').mkdir(parents=True)
        self.file = self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        self.bin = self.base/'bin'
        self.bin.mkdir()
        self.trace = self.base/'trace'
        self.trace.touch()
        self.tool('systemctl', '', 0)

    def tool(self, name, output, status=0):
        script = self.bin/name
        script.write_text('#!/bin/sh\nprintf "%s\\n" "'+name+' $*" >> '+shlex.quote(str(self.trace))+
                          '\nprintf "%s\\n" '+shlex.quote(output)+'\nexit '+str(status)+'\n')
        script.chmod(0o755)

    def audit(self):
        return subprocess.run(['python3', str(test_workflows.ROOT/'lib/crowdsec_relay.py'),
                               'audit', str(self.config)], capture_output=True, text=True,
                              env={**os.environ, 'PATH': str(self.bin)+':'+os.environ['PATH']})

    def test_input_only_iptables_reports_forward_and_ipv6_unverified(self):
        self.file.write_text('mode: iptables\napi_key: secret-do-not-print\nblacklists_ipv4: [blocked4]\nblacklists_ipv6: [blocked6]\niptables_chains: [INPUT]\n')
        self.tool('iptables', '-P INPUT ACCEPT\n-A INPUT -m set --match-set blocked4 src -j DROP')
        self.tool('ip6tables', '-P INPUT ACCEPT')
        self.tool('ipset', 'blocked4\nblocked6')
        before = self.file.read_bytes()
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv4 INPUT: 已发现', result.stdout)
        self.assertIn('IPv4 FORWARD: 尚未发现', result.stdout)
        self.assertIn('IPv6 INPUT: 尚未发现', result.stdout)
        self.assertNotIn('secret-do-not-print', result.stdout+result.stderr)
        self.assertEqual(self.file.read_bytes(), before)
        self.assertEqual(self.trace.read_text().splitlines(), [
            'systemctl is-active --quiet crowdsec',
            'systemctl is-active --quiet crowdsec-firewall-bouncer',
            'ipset list -name', 'iptables -S', 'ip6tables -S'])

    def test_iptables_local_override_and_jump_chain_are_inspected(self):
        self.file.write_text('mode: nftables\n')
        Path(str(self.file)+'.local').write_text('mode: iptables\nblacklists_ipv4: [custom4]\nblacklists_ipv6: [custom6]\niptables_chains: [INPUT, FORWARD]\n')
        self.tool('ipset', 'custom4\ncustom6')
        self.tool('iptables', '-A INPUT -j CS\n-A FORWARD -j CS\n-A CS -m set --match-set custom4 src -j DROP')
        self.tool('ip6tables', '-A FORWARD -m set --match-set custom6 src -j DROP')
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv4 FORWARD: 已发现', result.stdout)
        self.assertIn('IPv6 FORWARD: 已发现', result.stdout)
        self.assertNotIn('nft ', self.trace.read_text())
        self.assertIn('实际业务阻断尚未验证', result.stdout)

    def test_ipset_only_has_no_automatic_firewall_coverage(self):
        self.file.write_text('mode: ipset\n')
        self.tool('ipset', 'crowdsec-blacklists\ncrowdsec6-blacklists')
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('仅管理集合', result.stdout)
        self.assertNotIn('已发现封禁', result.stdout)

    def nft_fixture(self, hook='input', table='custom', family='ip'):
        return {'nftables': [
            {'table': {'family': family, 'name': table}},
            {'set': {'family': family, 'table': table, 'name': 'deny4'}},
            {'chain': {'family': family, 'table': table, 'name': 'ban', 'hook': hook, 'prio': -10}},
            {'rule': {'family': family, 'table': table, 'chain': 'ban', 'expr': [
                {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': '@deny4'}},
                {'drop': None}]}}]}

    def test_nft_custom_table_set_and_hook_are_inspected(self):
        self.file.write_text('mode: nftables\nblacklists_ipv4: deny4\nnftables:\n  ipv4: {enabled: true, table: custom}\n  ipv6: {enabled: false}\n')
        self.tool('nft', json.dumps(self.nft_fixture(hook='forward')))
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv4 FORWARD: 已发现', result.stdout)
        self.assertIn('IPv4 INPUT: 尚未发现', result.stdout)
        self.assertIn('IPv6: 配置未启用', result.stdout)
        self.assertEqual(self.trace.read_text().splitlines()[-1], 'nft -j list ruleset')

    def test_nft_unrelated_table_is_not_counted_as_bouncer(self):
        self.file.write_text('mode: nftables\nblacklists_ipv4: deny4\nnftables:\n  ipv4: {enabled: true, table: custom}\n  ipv6: {enabled: false}\n')
        self.tool('nft', json.dumps(self.nft_fixture(table='other')))
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv4 INPUT: 尚未发现', result.stdout)

    def test_nft_unhooked_or_destination_ip_rule_is_not_source_blocking(self):
        self.file.write_text('mode: nftables\nblacklists_ipv4: deny4\nnftables:\n  ipv4: {enabled: true, table: custom}\n  ipv6: {enabled: false}\n')
        fixture = self.nft_fixture()
        fixture['nftables'][-1]['rule']['expr'][0]['match']['left']['payload']['field'] = 'daddr'
        self.tool('nft', json.dumps(fixture))
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv4 INPUT: 尚未发现', result.stdout)

    def test_nft_official_ipv6_table_and_global_blacklist_are_used(self):
        self.file.write_text('mode: nftables\nblacklists_ipv6: deny4\nnftables:\n  ipv4: {enabled: false}\n  ipv6: {enabled: true}\n')
        fixture = self.nft_fixture(table='crowdsec6', family='ip6')
        fixture['nftables'][-1]['rule']['expr'][0]['match']['left']['payload']['protocol'] = 'ip6'
        self.tool('nft', json.dumps(fixture))
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv6 INPUT: 已发现', result.stdout)

    def test_disabled_ipv6_is_reported_without_reading_stale_rules(self):
        self.file.write_text('mode: iptables\ndisable_ipv6: true\n')
        self.tool('ipset', 'crowdsec-blacklists')
        self.tool('iptables', '-A INPUT -m set --match-set crowdsec-blacklists src -j DROP')
        self.tool('ip6tables', '', 1)
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('IPv6: 配置未启用', result.stdout)
        self.assertNotIn('ip6tables', self.trace.read_text())

    def test_nft_set_only_reports_manual_filter_ownership(self):
        self.file.write_text('mode: nftables\nnftables:\n  ipv4: {enabled: true, set-only: true}\n  ipv6: {enabled: false}\n')
        self.tool('nft', json.dumps({'nftables': []}))
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('set-only', result.stdout)

    def test_malformed_config_never_echoes_api_key(self):
        self.file.write_text('mode: [nftables\napi_key: secret-do-not-print\n')
        result = self.audit()
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertNotIn('secret-do-not-print', result.stdout+result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_failed_firewall_read_is_an_error_without_raw_output(self):
        self.file.write_text('mode: nftables\n')
        self.tool('nft', 'permission denied', 1)
        result = self.audit()
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('读取失败', result.stdout+result.stderr)

    def test_missing_bouncer_is_unverified_not_success(self):
        result = self.audit()
        self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
        self.assertIn('未安装', result.stdout)

    def test_inactive_service_is_an_error(self):
        self.file.write_text('mode: ipset\n')
        self.tool('systemctl', '', 3)
        self.tool('ipset', '')
        result = self.audit()
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertIn('未运行', result.stdout)


if __name__ == '__main__':
    unittest.main()
