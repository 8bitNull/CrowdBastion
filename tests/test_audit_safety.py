"""Fail-closed destructive safety and explicitly requested administrator protection."""
from test_workflows import Workflows

class AuditSafety(Workflows):
    def run_shell(self, action, user_input='', overrides='', timeout=5):
        return super().run_shell(action, user_input, 'ip() { echo "[]"; };\n'+overrides, timeout)

    def test_firewall_failure_is_unknown(self):
        p = self.run_shell('firewall_status', overrides='nft() { return 1; }; iptables() { return 1; }; ip6tables() { return 1; }; ipset() { return 1; }')
        self.assertEqual(p.returncode, 2, p.stdout+p.stderr)

    def test_firewall_empty_success_is_absent(self):
        p = self.run_shell('firewall_status', overrides='nft() { return 0; }; iptables() { return 0; }; ip6tables() { return 0; }; ipset() { return 0; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)

    def test_default_hook_is_not_a_residual_chain(self):
        cfg=self.config/'bouncers/crowdsec-firewall-bouncer.yaml'
        cfg.parent.mkdir()
        cfg.write_text('mode: iptables\niptables_chains: [INPUT]\n')
        p=self.run_shell('firewall_status', overrides='nft() { return 0; }; iptables() { echo "-P INPUT ACCEPT"; }; ip6tables() { return 0; }; ipset() { return 0; }')
        self.assertEqual(p.returncode, 1, p.stdout+p.stderr)

    def test_purge_unknown_aborts_before_service_stop(self):
        p = self.run_shell('deep_purge_residuals', 'y\n', 'nft() { return 1; }; iptables() { return 1; }; ip6tables() { return 1; }; ipset() { return 1; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('systemctl stop', self.commands())
        self.assertTrue(self.config.exists())

    def test_purge_unsupported_os_aborts_before_service_stop(self):
        p = self.run_shell('deep_purge_residuals', 'y\n', 'OS_ID=unsupported')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('systemctl stop', self.commands())

    def test_package_query_failure_aborts_before_service_stop(self):
        p=self.run_shell('deep_purge_residuals', 'y\n', 'dpkg-query() { return 2; }; nft() { return 0; }; iptables() { return 0; }; ip6tables() { return 0; }; ipset() { return 0; }')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('systemctl stop', self.commands())

    def test_loopback_unspecified_refused(self):
        for ip in ('127.0.0.2', '::1', '0.0.0.0', '::', '::ffff:127.0.0.1', '::ffff:0.0.0.0'):
            with self.subTest(ip=ip):
                self.trace.write_text('')
                self.run_shell('manage_firewall_ops', f'4\n{ip}\n4h\ntest\n0\n')
                self.assertNotIn('decisions add', self.commands())

    def test_local_interface_refused(self):
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n0\n', 'ip() { echo \'[{"addr_info":[{"local":"203.0.113.5"}]}]\'; }')
        self.assertNotIn('decisions add', self.commands())

    def test_recorded_admin_refused(self):
        path=self.config/'parsers/s02-enrich/99-admin-whitelist.yaml'
        path.parent.mkdir(parents=True)
        path.write_text('whitelist:\n  ip: [203.0.113.5]\n')
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n0\n')
        self.assertNotIn('decisions add', self.commands())

    def test_allowlist_cancel_never_mutates(self):
        self.run_shell('manage_admin_allowlist', '2\n203.0.113.5\nn\n0\n')
        self.assertNotRegex(self.commands(), r'allowlists (create|add|remove|delete)')

    def test_public_target_is_not_guessed_as_local(self):
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n0\n')
        self.assertIn('decisions add --ip 203.0.113.5', self.commands())

    def test_allowlist_explicit_add_protects_same_address(self):
        self.run_shell('manage_admin_allowlist', '2\n203.0.113.5\ny\n0\n')
        self.assertIn('allowlists add crowdsec-1key-admin 203.0.113.5', self.commands())
        self.trace.write_text('')
        self.run_shell('manage_firewall_ops', '4\n203.0.113.5\n4h\ntest\n0\n')
        self.assertNotIn('decisions add', self.commands())

    def test_self_report_read_only(self):
        self.run_shell('diagnose_self_report')
        self.assertIn('cscli decisions list --ip 127.0.0.1', self.commands())
        self.assertNotIn('cscli capi status', self.commands())
        self.assertNotRegex(self.commands(), r'decisions (delete|add)|allowlists (add|create)|systemctl restart|curl')

# Do not inherit and duplicate the baseline workflow suite.
for name in list(vars(Workflows)):
    if name.startswith('test_') and name not in AuditSafety.__dict__:
        setattr(AuditSafety, name, None)
del Workflows
