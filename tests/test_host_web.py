"""Host package installation boundaries, with real temporary configuration files."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class HostWeb(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='crowdsec-host-web-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.config = self.base / 'etc/crowdsec'
        self.config.mkdir(parents=True)
        self.nginx = self.base / 'etc/nginx/nginx.conf'
        self.nginx.parent.mkdir(parents=True)
        self.nginx.write_text('events {}\nhttp {\n include '+str(self.nginx.parent/'conf.d/*.conf')+';\n server { listen 80; }\n}\n')
        self.openresty = self.base / 'usr/local/openresty/nginx/conf/nginx.conf'
        self.openresty.parent.mkdir(parents=True)
        self.openresty.write_text('events {}\nhttp {\n server { listen 80; }\n}\n')
        self.trace = self.base/'trace'
        self.trace.touch()
        (self.base/'var/backups/crowdsec-1key').mkdir(parents=True)
        self.file = self.config/'bouncers/crowdsec-nginx-bouncer.conf'
        self.file.parent.mkdir()

    def run_install(self, runtime='nginx', overrides=''):
        source = ROOT/'lib/host_web_bouncer.sh'
        if not source.exists():
            self.fail('host Web Bouncer installer is missing')
        content = source.read_text()
        content = re.sub(r'(?<![\w./-])/(?:etc|usr/local|var)/',
                         lambda m: str(self.base)+m.group(), content)
        copied = self.base/'host.sh'
        copied.write_text(content)
        prelude = r'''
set -o pipefail
record() { printf '%s\n' "$*" >> "$TRACE"; }
log_info() { echo "[INFO] $*"; }
log_warn() { echo "[WARN] $*" >&2; }
log_err() { echo "[ERROR] $*" >&2; }
log_succ() { echo "[SUCCESS] $*"; }
require_core() { :; }
require_yaml() { :; }
require_commands() { for x in "$@"; do command -v "$x" >/dev/null || return 1; done; }
ss() { echo 'LISTEN 0 128 127.0.0.1:7422 0.0.0.0:*'; }
appsec_default_listener_ready() { record appsec-listener-check; return 0; }
confirm() { return 0; }
begin_config_change() {
 BACKUP_PATHS=("$@"); BACKUP_COPIES=(); local i=0 p
 mkdir -p "$BASE/backup"
 for p in "$@"; do
  BACKUP_COPIES+=("$BASE/backup/$i")
  if [[ -e "$p" ]]; then cp -a "$p" "$BASE/backup/$i"; else touch "$BASE/backup/$i.absent"; fi
  ((i+=1))
 done
}
restore_config_change() {
 local i
 for i in "${!BACKUP_PATHS[@]}"; do
  if [[ -f "${BACKUP_COPIES[$i]}.absent" ]]; then rm -f "${BACKUP_PATHS[$i]}";
  else cp -a "${BACKUP_COPIES[$i]}" "${BACKUP_PATHS[$i]}"; fi
 done
}
yaml_tool() { python3 "$HELPER" "$@"; }
nginx() {
 record nginx "$@"
 case "$1" in
  -V) echo "nginx version: nginx/1.26; configure arguments: --conf-path=$BASE/etc/nginx/nginx.conf" >&2;;
  -T) printf '# configuration file %s:\n' "$BASE/etc/nginx/nginx.conf"; cat "$BASE/etc/nginx/nginx.conf";
      [[ ! -f "$BASE/etc/nginx/conf.d/crowdsec_nginx.conf" ]] || { printf '# configuration file %s:\n' "$BASE/etc/nginx/conf.d/crowdsec_nginx.conf"; cat "$BASE/etc/nginx/conf.d/crowdsec_nginx.conf"; };;
 esac
 return 0
}
openresty() {
 record openresty "$@"
 case "$1" in
  -V) echo "nginx version: openresty/1.27; configure arguments: --conf-path=$BASE/usr/local/openresty/nginx/conf/nginx.conf" >&2;;
  -T) printf '# configuration file %s:\n' "$BASE/usr/local/openresty/nginx/conf/nginx.conf"; cat "$BASE/usr/local/openresty/nginx/conf/nginx.conf";
      [[ ! -f "$BASE/usr/local/openresty/nginx/conf/conf.d/crowdsec_openresty.conf" ]] || { printf '# configuration file %s:\n' "$BASE/usr/local/openresty/nginx/conf/conf.d/crowdsec_openresty.conf"; cat "$BASE/usr/local/openresty/nginx/conf/conf.d/crowdsec_openresty.conf"; };;
 esac
 return 0
}
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then echo "{ path=/usr/sbin/$RUNTIME ; argv[]=/usr/sbin/$RUNTIME ; }"; fi
 return 0
}
dpkg-query() {
 case "$*" in
  *crowdsec-*-bouncer*) return 1;;
  *) echo 'install ok installed';;
 esac
}
apt-cache() { echo '  Candidate: 1.1.3'; }
apt-get() {
 record apt-get "$@"
 if [[ "$*" == *--simulate* ]]; then echo "Inst crowdsec-$RUNTIME-bouncer (1.1.3 CrowdSec [all])"; return 0; fi
 mkdir -p "${SNIPPET%/*}"
 printf 'API_KEY=package-created-secret\nAPI_URL=http://127.0.0.1:8080\nAPPSEC_URL=\n' > "$CONF"
 printf 'init_by_lua_block { local cs = require "crowdsec" }\naccess_by_lua_block { cs.Allow(ngx.var.remote_addr) }\n' > "$SNIPPET"
 touch "$BASE/account-created"
 echo 'API Key : package-created-secret'
 return 0
}
cscli() {
 record cscli "$@"
 case "$*" in
  'bouncers list -o json')
   if [[ -f "$BASE/account-created" ]]; then printf '[{"name":"crowdsec-%s-bouncer-1234567890"},{"name":"existing-firewall"}]\n' "$RUNTIME";
   else echo '[{"name":"existing-firewall"}]'; fi;;
 esac
 return 0
}
'''
        conf = self.config/f'bouncers/crowdsec-{runtime}-bouncer.conf'
        snippet = (self.nginx.parent/'conf.d/crowdsec_nginx.conf' if runtime=='nginx'
                   else self.openresty.parent/'conf.d/crowdsec_openresty.conf')
        env = {**os.environ, 'BASE':str(self.base), 'TRACE':str(self.trace),
               'HELPER':str(ROOT/'lib/crowdsec_config.py'), 'CONF':str(conf),
               'SNIPPET':str(snippet), 'RUNTIME':runtime}
        command = (f'source {shlex.quote(str(copied))}\n'+prelude+
                   f'\nCS_DIR={shlex.quote(str(self.config))}\nAPPSEC_LINKS="$CS_DIR/links.yaml"\nOS_ID=debian\n'+overrides+
                   f'\ninstall_host_web_bouncer {runtime}')
        return subprocess.run(['bash','-c',command], env=env, capture_output=True, text=True, timeout=10)

    def commands(self):
        return self.trace.read_text()

    def test_missing_candidate_does_not_install_or_modify_config(self):
        before = self.nginx.read_text()
        p = self.run_install(overrides="apt-cache() { echo 'Candidate: (none)'; }")
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())
        self.assertEqual(self.nginx.read_text(), before)

    def test_existing_unknown_lua_hook_prevents_package_install(self):
        self.nginx.write_text(self.nginx.read_text().replace('server {', 'access_by_lua_file /custom/waf.lua;\n server {'))
        before = self.nginx.read_text()
        p = self.run_install()
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())
        self.assertEqual(self.nginx.read_text(), before)

    def test_dependency_upgrade_plan_stops_before_real_install(self):
        p = self.run_install(overrides='apt-get() { record apt-get "$@"; echo "Inst nginx [1.20] (1.26 Ubuntu [amd64])"; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(self.file.exists())

    def test_nginx_install_links_package_config_without_exposing_key(self):
        before = self.nginx.read_text()
        p = self.run_install()
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', self.file.read_text())
        self.assertEqual(self.nginx.read_text(), before)
        self.assertNotIn('package-created-secret', p.stdout+p.stderr)
        self.assertIn('systemctl reload nginx', self.commands())

    def test_openresty_adds_include_within_http(self):
        p = self.run_install('openresty')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        text = self.openresty.read_text()
        self.assertIn('include '+str(self.openresty.parent/'conf.d/crowdsec_openresty.conf')+';', text)
        self.assertLess(text.index('http {'), text.index('include '))
        self.assertLess(text.index('include '), text.index('server {'))

    def test_failed_reload_restores_new_configs_and_only_new_account(self):
        before = self.openresty.read_text()
        p = self.run_install('openresty', r'''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then echo "{ path=/usr/bin/openresty ; argv[]=/usr/bin/openresty ; }"; fi
 if [[ "$1" == reload && ! -f "$BASE/first-reload-failed" ]]; then touch "$BASE/first-reload-failed"; return 1; fi
 return 0
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.openresty.read_text(), before)
        self.assertFalse((self.config/'bouncers/crowdsec-openresty-bouncer.conf').exists())
        self.assertFalse((self.openresty.parent/'conf.d/crowdsec_openresty.conf').exists())
        self.assertFalse((self.config/'links.yaml').exists())
        self.assertIn('cscli bouncers delete crowdsec-openresty-bouncer-1234567890', self.commands())
        self.assertNotIn('cscli bouncers delete existing-firewall', self.commands())
        self.assertLess(self.commands().rindex('systemctl reload openresty'),
                        self.commands().index('cscli bouncers delete crowdsec-openresty-bouncer-1234567890'))

    def test_failed_rollback_reload_preserves_new_package_account(self):
        p = self.run_install('openresty', r'''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then echo "{ path=/usr/bin/openresty ; argv[]=/usr/bin/openresty ; }"; fi
 [[ "$1" != reload ]]
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((self.base/'account-created').exists())
        self.assertNotIn('cscli bouncers delete', self.commands())
        self.assertIn('保留', p.stderr)

    def test_failed_configuration_restore_preserves_new_package_account(self):
        p = self.run_install('openresty', r'''
restore_config_change() { record restore-config-failed; return 1; }
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then echo "{ path=/usr/bin/openresty ; argv[]=/usr/bin/openresty ; }"; fi
 [[ "$1" != reload ]]
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertTrue((self.config/'bouncers/crowdsec-openresty-bouncer.conf').exists())
        self.assertNotIn('cscli bouncers delete', self.commands())

    def test_missing_appsec_listener_prevents_host_installation(self):
        p = self.run_install(overrides='appsec_default_listener_ready() { return 1; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())
        self.assertFalse(self.file.exists())

    def test_missing_listener_checker_prevents_existing_bouncer_changes(self):
        before = 'API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n'
        self.file.write_text(before)
        p = self.run_install(overrides='unset -f appsec_default_listener_ready')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.file.read_text(), before)
        self.assertNotIn('systemctl reload', self.commands())

    def test_existing_bouncer_is_linked_without_reinstallation(self):
        self.file.write_text('API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n')
        p = self.run_install()
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())
        self.assertNotIn('cscli bouncers add', self.commands())
        self.assertIn('API_KEY=keep-secret', self.file.read_text())
        self.assertIn('APPSEC_URL=http://127.0.0.1:7422', self.file.read_text())

    def test_existing_bouncer_reload_failure_restores_previous_url(self):
        before = 'API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n'
        self.file.write_text(before)
        p = self.run_install(overrides='systemctl() { record systemctl "$@"; [[ "$1" != reload ]]; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.file.read_text(), before)
        self.assertFalse((self.config/'links.yaml').exists())

    def test_local_override_is_not_silently_bypassed(self):
        self.file.write_text('API_KEY=keep-secret\nAPPSEC_URL=\n')
        Path(str(self.file)+'.local').write_text('APPSEC_URL=http://other-waf:7422\n')
        p = self.run_install()
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('APPSEC_URL=http://127.0.0.1:7422', self.file.read_text())

    def test_openresty_default_prefix_is_supported_without_explicit_conf_path(self):
        p = self.run_install('openresty', r'''
old_openresty=$(declare -f openresty)
eval "${old_openresty/openresty ()/original_openresty ()}"
openresty() {
 if [[ "$1" == -V ]]; then echo "nginx version: openresty/1.27; configure arguments: --prefix=$BASE/usr/local/openresty/nginx"; return 0; fi
 original_openresty "$@"
}
''')
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertIn('systemctl reload openresty', self.commands())

    def test_package_failure_restores_modified_main_and_cleans_new_account(self):
        before = self.nginx.read_text()
        p = self.run_install(overrides=r'''
apt-get() {
 record apt-get "$@"
 if [[ "$*" == *--simulate* ]]; then echo 'Inst crowdsec-nginx-bouncer (1.1.3 CrowdSec [all])'; return 0; fi
 echo 'broken config' > "$BASE/etc/nginx/nginx.conf"
 mkdir -p "${SNIPPET%/*}"
 echo 'invalid' > "$SNIPPET"
 echo 'API_KEY=private-secret' > "$CONF"
 touch "$BASE/account-created"
 return 1
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.nginx.read_text(), before)
        self.assertFalse(self.file.exists())
        self.assertFalse((self.nginx.parent/'conf.d/crowdsec_nginx.conf').exists())
        self.assertIn('cscli bouncers delete crowdsec-nginx-bouncer-1234567890', self.commands())

    def test_installed_package_missing_conf_is_not_reinstalled(self):
        p = self.run_install(overrides="dpkg-query() { echo 'install ok installed'; }")
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())

    def test_unsupported_distro_does_not_install_packages(self):
        p = self.run_install(overrides='OS_ID=fedora')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())

    def test_custom_service_configuration_is_not_mistaken_for_default(self):
        p = self.run_install(overrides=r'''
systemctl() {
 record systemctl "$@"
 if [[ "$1" == show ]]; then echo '{ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -c /custom/nginx.conf ; }'; fi
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertNotIn('apt-get', self.commands())

    def test_pending_unrelated_package_configuration_stops_before_install(self):
        p = self.run_install(overrides=r'''
apt-get() {
 record apt-get "$@"
 echo 'Inst crowdsec-nginx-bouncer (1.1.3 CrowdSec [all])'
 echo 'Conf unrelated-package (2.0 Debian [amd64])'
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(self.file.exists())
        self.assertNotIn('cscli bouncers list', self.commands())

    def test_invalid_bouncer_snapshot_stops_before_mutation(self):
        p = self.run_install(overrides='cscli() { record cscli "$@"; echo "{}"; }')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(self.file.exists())
        self.assertNotIn('apt-get -y', self.commands())

    def test_syntax_failure_restores_link_and_configuration(self):
        p = self.run_install(overrides=r'''
old_nginx=$(declare -f nginx)
eval "${old_nginx/nginx ()/original_nginx ()}"
nginx() {
 if [[ "$1" == -t && -f "$BASE/account-created" ]]; then record nginx "$@"; return 1; fi
 original_nginx "$@"
}
''')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertFalse(self.file.exists())
        self.assertFalse((self.config/'links.yaml').exists())
        self.assertNotIn('systemctl reload nginx', self.commands())

    def test_container_owned_existing_config_is_not_relinked_as_host(self):
        before = 'API_KEY=keep-secret\nAPPSEC_URL=http://old.example:7422\n'
        self.file.write_text(before)
        state = self.config/'docker-links.yaml'
        state.write_text(str(self.file)+':\n  container: existing-proxy\n  target: /etc/crowdsec/bouncers/crowdsec-nginx-bouncer.conf\n')
        p = self.run_install(overrides=f'APPSEC_DOCKER_LINKS={shlex.quote(str(state))}')
        self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual(self.file.read_text(), before)
        self.assertNotIn('systemctl reload', self.commands())


if __name__ == '__main__':
    unittest.main()
