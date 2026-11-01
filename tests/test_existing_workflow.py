"""Existing-deployment navigation uses isolated system-command stubs."""
import unittest
import test_workflows


class ExistingWorkflow(unittest.TestCase):
    setUp = test_workflows.Workflows.setUp
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands

    def stubs(self):
        return '''
source "$SCRIPT_DIR/lib/firewall.sh"
existing_deployment_tool() {
 record existing "$@"
 case "$1" in
 plan) printf '{"backend":"iptables","cron_risks":[],"restore_services":[],"scope":[]}' ;;
 cron-list) printf '[]' ;;
 esac
}
repair_firewall_startup() { record repair-startup; }
check_firewall_runtime() { record check-runtime; return 0; }
'''

    def test_existing_repair_cancel_and_eof_do_not_modify(self):
        for inputs in ('n\n', ''):
            self.trace.write_text('')
            p = self.run_shell('repair_existing_deployment', inputs, self.stubs())
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
            self.assertNotIn('repair-startup', self.commands())
            self.assertNotIn('cron-disable', self.commands())

    def test_confirmed_repair_calls_existing_transaction(self):
        p = self.run_shell('repair_existing_deployment', 'y\n', self.stubs())
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('repair-startup', self.commands())
        self.assertNotIn('restart docker', self.commands())

    def test_failed_preflight_stops_before_confirmation_or_mutation(self):
        p = self.run_shell('repair_existing_deployment', 'y\n', self.stubs()+'''
existing_deployment_tool() { record existing "$@"; return 1; }
''')
        self.assertNotEqual(p.returncode, 0)
        self.assertNotIn('repair-startup', self.commands())

    def test_cli_repair_uses_management_lock_and_blocks_during_migration(self):
        p = self.run_shell('main --repair-existing', 'n\n', self.stubs())
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        p = self.run_shell('mkdir -p "$FIREWALL_MIGRATION_STATE"; main --repair-existing', 'y\n', self.stubs())
        self.assertEqual(p.returncode, 75)

    def test_each_cron_confirmation_reads_user_input(self):
        p = self.run_shell('repair_existing_deployment', 'y\ny\ny\n', self.stubs()+'''
maintenance_tool() { return 0; }
existing_deployment_tool() {
 record existing "$@"
 case "$1" in
 plan) printf '{"cron_risks":[],"restore_services":[]}' ;;
 cron-list) printf '[{"index":1,"family":"IPv4"},{"index":2,"family":"IPv6"}]' ;;
 esac
}
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().count('existing cron-disable'), 2)

    def test_partial_cron_failure_still_attempts_restore(self):
        p = self.run_shell('repair_existing_deployment', 'y\ny\n', self.stubs()+'''
maintenance_tool() { return 0; }
existing_deployment_tool() {
 record existing "$@"
 case "$1" in
 plan) printf '{"cron_risks":[],"restore_services":[]}' ;;
 cron-list) printf '[{"index":1,"family":"IPv4"}]' ;;
 cron-disable) return 1 ;;
 esac
}
''')
        self.assertNotEqual(p.returncode, 0)
        self.assertIn('existing cron-restore', self.commands())

    def test_backup_root_is_dedicated_and_can_be_reused(self):
        p = self.run_shell('repair_existing_deployment && repair_existing_deployment', 'y\ny\ny\ny\n', self.stubs()+'''
existing_deployment_tool() {
 record existing "$@"
 case "$1" in
 plan) printf '{"cron_risks":[],"restore_services":[]}' ;;
 cron-list) printf '[{"index":1,"family":"IPv4"}]' ;;
 esac
}
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.commands().count('existing cron-disable'), 2)
        self.assertIn('/existing-deployment/cron.', self.commands())