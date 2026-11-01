"""Purpose-aware navigation with all host effects confined to workflow stubs."""
import unittest

import test_node_guidance
import test_workflows


class MenuConvergence(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    roles = test_node_guidance.Guidance.roles

    def test_remote_ip_menu_without_core_never_uses_local_cscli(self):
        self.roles('remote', 'node')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('manage_firewall_ops', '1\n2\n3\n4\n0\n', '''
remote_bouncer_status() { record remote-status; }
check_remote_firewall_status() { record remote-firewall; }
check_relay_path() { record relay-path "$@"; }
verify_relay() { record verify-relay "$@"; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('仅在检测中心执行', p.stdout)
        self.assertEqual(self.commands().splitlines(), [
            'remote-status', 'remote-firewall', 'relay-path remote', 'verify-relay remote'])

    def test_managed_remote_marker_routes_without_saved_roles(self):
        marker = self.config/'bouncers/crowdsec-firewall-bouncer.yaml.remote.json'
        marker.parent.mkdir()
        marker.write_text('{}')
        p = self.run_shell('manage_firewall_ops', '0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('远端执行', p.stdout)
        self.assertNotIn('cscli', self.commands())

    def test_remote_preference_preserves_existing_local_ip_management(self):
        self.roles('remote', 'node')
        p = self.run_shell('manage_firewall_ops', '1\n\n0\n', '''
manage_remote_firewall_ops() { record unexpected-remote-menu; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('cscli decisions list', self.commands())
        self.assertNotIn('unexpected-remote-menu', self.commands())

    def test_corrupt_roles_does_not_enter_local_ip_menu(self):
        path = self.roles('remote')
        path.write_text('{')
        p = self.run_shell('manage_firewall_ops', '4\n')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('cscli', self.commands())

    def test_remote_marker_path_check_keeps_remote_audit_context(self):
        marker = self.config/'bouncers/crowdsec-firewall-bouncer.yaml.remote.json'
        marker.parent.mkdir()
        marker.write_text('{}')
        p = self.run_shell('manage_firewall_ops', '3\n0\n', '''
python3() {
 case "$1" in
  */crowdsec_relay_paths.py) return 2 ;;
  */crowdsec_relay.py) record relay-audit "$2"; return 2 ;;
  *) command python3 "$@" ;;
 esac
}
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands(), 'relay-audit audit-remote\n')

    def test_existing_docker_bouncer_can_reconnect_from_website_guide(self):
        p = self.run_shell('guided_website_setup', '2\n3\n2\n0\n', '''
link_docker_appsec() { record link-existing-docker; }
install_web_bouncer() { record unexpected-install; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands(), 'link-existing-docker\n')

    def test_bridge_guide_orders_engine_endpoints_bouncer_and_verify(self):
        p = self.run_shell('guided_website_setup', '3\n1\n2\n3\n1\n4\n0\n', '''
setup_appsec() { record engine "$@"; }
configure_docker_endpoints() { record endpoints; }
install_web_bouncer() { record bouncer; }
verify_appsec() { record verify; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), [
            'engine engine-only', 'endpoints', 'bouncer', 'verify'])
        self.assertLess(p.stdout.index('配置网站请求检测引擎'), p.stdout.index('登记已准备好的私有连接地址'))

    def test_host_guide_and_cancel_do_not_offer_bridge_registration(self):
        p = self.run_shell('guided_website_setup', '1\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('2. 登记', p.stdout)
        self.assertEqual(self.commands(), '')
        for inputs in ('0\n', '', '3\n'):
            with self.subTest(inputs=inputs):
                p = self.run_shell('guided_website_setup', inputs)
                self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
                self.assertEqual(self.commands(), '')

    def test_engine_only_sets_up_listener_without_consuming_next_step(self):
        p = self.run_shell('setup_appsec engine-only; read -r next; printf "NEXT=%s" "$next"', 'next-step\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('NEXT=next-step', p.stdout)
        self.assertTrue(any((self.config/'acquis.d').glob('*appsec*')))
        self.assertNotIn('请选择可用接入项', p.stdout)

    def test_bridge_engine_failure_does_not_install_following_steps(self):
        p = self.run_shell('guided_website_setup', '3\n1\n0\n', '''
setup_appsec() { record engine; return 1; }
configure_docker_endpoints() { record unexpected-endpoints; }
install_web_bouncer() { record unexpected-bouncer; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('本步骤未完成', p.stdout)
        self.assertEqual(self.commands(), 'engine\n')

    def test_v2bx_guide_opens_full_workflow(self):
        self.roles('node')
        p = self.run_shell('guided_setup', '1\n0\n', '''
manage_v2bx_node() { record node-menu; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands(), 'node-menu\n')

    def test_v2bx_sample_and_template_are_explicit_and_read_only(self):
        p = self.run_shell('manage_v2bx_node', '3\n4\n0\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('分析已有日志样本', p.stdout)
        self.assertIn('"sources"', p.stdout)
        self.assertIn('0600', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_basic_repairs_exposes_locked_firewall_maintenance(self):
        p = self.run_shell('manage_basic_repairs', '5\n0\n', '''
locked_operation() { record lock "$@"; "$@"; }
manage_firewall_maintenance() { record maintenance; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), ['lock manage_firewall_maintenance', 'maintenance'])

    def test_pending_migration_can_reach_maintenance_under_real_lock(self):
        p = self.run_shell('manage_basic_repairs', '5\n0\n', '''
firewall_migration_pending() { return 0; }
manage_firewall_maintenance() { record maintenance; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands(), 'maintenance\n')

    def test_website_bouncer_cancel_does_not_install_or_reconnect(self):
        for inputs in ('0\n', ''):
            p = self.run_shell('guided_website_bouncer 3', inputs, '''
install_web_bouncer() { record unexpected-install; }
link_docker_appsec() { record unexpected-link; }
''')
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
            self.assertEqual(self.commands(), '')

    def test_relay_baseline_does_not_install_web_collections(self):
        self.roles('relay', 'node')
        p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
install_collections() { record collections "$@"; }
reload_core_rules() { record reload; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('crowdsecurity/sshd', self.commands())
        self.assertNotIn('crowdsecurity/nginx', self.commands())

    def test_remote_baseline_explains_center_without_mutation(self):
        self.roles('remote')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
install_collections() { record unexpected-install; }
reload_core_rules() { record unexpected-reload; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('检测中心', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_remote_rules_menu_explains_center_without_local_core(self):
        self.roles('remote')
        (self.config/'config.yaml').unlink()
        p = self.run_shell('manage_waf_rules', '4\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('检测中心', p.stdout)
        self.assertNotIn('请先通过', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_remote_marker_rules_menu_preserves_center_authority(self):
        marker = self.config/'bouncers/crowdsec-firewall-bouncer.yaml.remote.json'
        marker.parent.mkdir()
        marker.write_text('{}')
        p = self.run_shell('manage_waf_rules', '1\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('检测中心', p.stdout)
        self.assertEqual(self.commands(), '')

    def test_remote_preference_keeps_existing_local_baseline_repair(self):
        self.roles('remote', 'node')
        p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
install_baseline_collections() { record web-baseline; }
reload_core_rules() { record reload; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), ['web-baseline', 'reload'])

    def test_relay_preference_repairs_deployed_website_baseline(self):
        self.roles('relay', 'node')
        p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
node_web_deployed() { return 0; }
install_baseline_collections() { record web-baseline; }
install_collections() { record unexpected-relay-baseline; }
reload_core_rules() { record reload; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().splitlines(), ['web-baseline', 'reload'])

    def test_relay_baseline_detects_custom_website_acquisition(self):
        self.roles('relay')
        for name in ('acquis.yaml', 'acquis.d/custom.yaml'):
            with self.subTest(name=name):
                path = self.config/name
                path.parent.mkdir(exist_ok=True)
                path.write_text('filenames: [/var/log/nginx/access.log]\nlabels:\n  type: nginx\n')
                self.trace.write_text('')
                p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
install_baseline_collections() { record web-baseline; }
install_collections() { record unexpected-relay-baseline; }
reload_core_rules() { record reload; }
''')
                self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
                self.assertEqual(self.commands().splitlines(), ['web-baseline', 'reload'])
                path.unlink()

    def test_cli_baseline_keeps_web_collections_for_relay_purpose(self):
        self.roles('relay')
        p = self.run_shell('reset_waf_to_core_baseline', overrides='''
install_collections() { record collections "$@"; }
reload_core_rules() { record reload; }
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('crowdsecurity/nginx', self.commands())

    def test_relay_baseline_stops_when_acquisition_cannot_be_parsed(self):
        self.roles('relay')
        (self.config/'acquis.yaml').write_text('filenames: [\n')
        directory = self.config/'acquis.d'
        directory.mkdir()
        (directory/'custom.yaml').write_text('filenames: [/var/log/nginx/access.log]\nlabels:\n  type: nginx\n')
        p = self.run_shell('reset_waf_to_core_baseline purpose', overrides='''
install_collections() { record unexpected-install; }
reload_core_rules() { record unexpected-reload; }
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('无法确认', p.stdout+p.stderr)
        self.assertEqual(self.commands(), '')

    def test_website_withdrawal_help_does_not_change_services(self):
        p = self.run_shell('manage_website_protection', '9\n0\n')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('宿主机', p.stdout)
        self.assertIn('上游', p.stdout)
        self.assertIn('--restore-host-real-ip', p.stdout)
        self.assertEqual(self.commands(), '')


if __name__ == '__main__':
    unittest.main()