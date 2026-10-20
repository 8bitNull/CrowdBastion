"""Remote configuration boundaries; no host service or firewall effects."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT/'lib/crowdsec_remote_bouncer.py'

class RemoteConfig(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)/'crowdsec-firewall-bouncer.yaml'
        self.base.write_text('mode: iptables\napi_key: old\niptables_chains: [INPUT, FORWARD]\n')
        self.local = Path(str(self.base)+'.local')
        self.state = Path(str(self.base)+'.remote.json')
    def run_tool(self, action, data=None):
        return subprocess.run([sys.executable,str(HELPER),action,str(self.base)], input=json.dumps(data or {}), capture_output=True,text=True)
    def server(self, status=200, payload=b'{"new":[],"deleted":[]}'):
        owner=self
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                owner.request_path=self.path
                owner.request_key=self.headers.get('X-Api-Key')
                self.send_response(status); self.end_headers(); self.wfile.write(payload)
            def log_message(self,*args): pass
        server=HTTPServer(('127.0.0.1',0),Handler)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.server_close); self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}/'
    def test_rejects_unsafe_urls_and_header_injection_without_writes(self):
        for url in ['http://example.com/', 'http://100.64.0.1/', 'https://u:p@example.com/', 'https://example.com/?key=x', 'https://example.com/#x', 'https://example.com:bad/','ftp://127.0.0.1/']:
            r=self.run_tool('apply',{'url':url,'key':'secret'})
            self.assertNotEqual(r.returncode,0)
            self.assertFalse(self.local.exists())
        r=self.run_tool('apply',{'url':self.server(),'key':'secret\nInjected: yes'})
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('secret',r.stdout+r.stderr)
    def test_authenticated_apply_preserves_base_and_creates_private_overlay(self):
        before=self.base.read_bytes()
        url=self.server()
        r=self.run_tool('apply',{'url':url,'key':'do-not-print'})
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.request_key,'do-not-print')
        self.assertEqual(self.request_path,'/v1/decisions/stream?startup=true')
        self.assertEqual(self.base.read_bytes(),before)
        self.assertEqual(self.local.stat().st_mode & 0o777,0o600)
        self.assertNotIn('do-not-print',r.stdout+r.stderr+self.state.read_text())
    def test_authentication_failure_preserves_existing_files(self):
        self.local.write_text('api_key: another-owner\n')
        before=self.local.read_bytes()
        r=self.run_tool('apply',{'url':self.server(403),'key':'hidden-secret'})
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.local.read_bytes(),before)
        self.assertNotIn('hidden-secret',r.stdout+r.stderr)
    def test_bad_key_on_managed_overlay_preflight_preserves_all_files(self):
        url=self.server()
        self.assertEqual(self.run_tool('apply',{'url':url,'key':'old-key'}).returncode,0)
        before={p:p.read_bytes() for p in (self.base,self.local,self.state)}
        bad_url=self.server(403)
        r=self.run_tool('apply',{'url':bad_url,'key':'wrong-key-secret'})
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.request_key,'wrong-key-secret')
        self.assertEqual({p:p.read_bytes() for p in before},before)
        self.assertNotIn('wrong-key-secret',r.stdout+r.stderr)
    def test_refuses_unmanaged_and_modified_overlay_removal(self):
        self.local.write_text('api_key: other\n')
        self.assertNotEqual(self.run_tool('remove').returncode,0)
        self.assertTrue(self.local.exists())
        self.local.unlink()
        self.assertEqual(self.run_tool('apply',{'url':self.server(),'key':'secret'}).returncode,0)
        self.local.write_text('api_key: externally-modified\n')
        self.assertNotEqual(self.run_tool('remove').returncode,0)
        self.assertTrue(self.local.exists())
    def test_managed_remove_restores_original_base_without_touching_it(self):
        before=self.base.read_bytes()
        self.assertEqual(self.run_tool('apply',{'url':self.server(),'key':'secret'}).returncode,0)
        self.assertEqual(self.run_tool('remove').returncode,0)
        self.assertFalse(self.local.exists()); self.assertFalse(self.state.exists())
        self.assertEqual(self.base.read_bytes(),before)
    def test_http_200_html_is_not_authenticated_decision_stream(self):
        r=self.run_tool('apply',{'url':self.server(payload=b'<html>login</html>'),'key':'secret'})
        self.assertNotEqual(r.returncode,0)
        self.assertFalse(self.local.exists())
    def test_unmanaged_local_override_refused_even_with_good_credentials(self):
        self.local.write_text('mode: nftables\napi_key: other\n')
        r=self.run_tool('apply',{'url':self.server(),'key':'secret'})
        self.assertNotEqual(r.returncode,0)
        self.assertEqual(self.local.read_text(),'mode: nftables\napi_key: other\n')
    def test_symlink_is_not_followed(self):
        outside=Path(self.tmp.name)/'outside'; outside.write_text('keep')
        self.local.symlink_to(outside)
        self.assertNotEqual(self.run_tool('apply',{'url':self.server(),'key':'secret'}).returncode,0)
        self.assertEqual(outside.read_text(),'keep')


import test_workflows
class RemoteWorkflow(unittest.TestCase):
    run_shell = test_workflows.Workflows.run_shell
    commands = test_workflows.Workflows.commands
    def setUp(self):
        test_workflows.Workflows.setUp(self)
        (self.base/'etc/os-release').write_text('ID=debian\n')
        directory=self.config/'bouncers'; directory.mkdir()
        self.file=directory/'crowdsec-firewall-bouncer.yaml'
        self.file.write_text('mode: iptables\napi_key: old\n')
    def test_status_is_read_only_and_no_lock(self):
        r=self.run_shell('main --relay-bouncer-status',overrides='remote_bouncer_status() { echo status; }; locked_operation() { return 99; }')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertIn('status',r.stdout)
    def test_configuration_restart_failure_restores_overlay_and_no_core_calls(self):
        r=self.run_shell('main --configure-relay-bouncer','http://127.0.0.1:8080/\nsecret-never-log\n',overrides="""
remote_bouncer_input() { printf '%s\n' '{"url":"http://127.0.0.1:8080/","key":"secret-never-log"}' > "$1"; }
remote_bouncer_tool() {
 case "$1" in
 guard|preflight) return 0 ;;
 apply) printf 'api_key: secret-never-log\n' > "$REMOTE_CONFIG.local"; printf '{}\n' > "$REMOTE_CONFIG.remote.json" ;;
 esac
}
systemctl() { record systemctl "$@"; [[ "$1" != restart ]]; }
""")
        self.assertNotEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('systemctl restart crowdsec-firewall-bouncer', self.commands())
        self.assertFalse(Path(str(self.file)+'.local').exists())
        self.assertNotIn('secret-never-log',r.stdout+r.stderr+self.commands())
        self.assertNotIn('cscli',self.commands())
        self.assertNotRegex(self.commands(),r'(restart|stop|enable|disable) crowdsec(?:\n|$)')
    def test_removal_unmanaged_refuses_before_service_change(self):
        Path(str(self.file)+'.local').write_text('api_key: other\n')
        r=self.run_shell('main --remove-relay-bouncer')
        self.assertNotEqual(r.returncode,0)
        self.assertNotIn('systemctl',self.commands())

    def test_release_checksum_failure_never_writes_installed_artifacts(self):
        stage=self.base/'release-stage'; stage.mkdir()
        archive=self.base/'release.tgz'; archive.write_bytes(b'wrong-release')
        metadata=self.base/'release.json'
        metadata.write_text(json.dumps({'assets':[{'name':'crowdsec-firewall-bouncer-linux-amd64.tgz','digest':'sha256:'+'0'*64}]}))
        override=f"""
uname() {{ echo x86_64; }}
curl() {{
 local dest=${{!#}}
 if [[ "$*" == *api.github.com* ]]; then cp {metadata} "$dest"; else cp {archive} "$dest"; fi
}}
"""
        r=self.run_shell('remote_bouncer_release '+str(stage),overrides=override)
        self.assertNotEqual(r.returncode,0)
        self.assertFalse((self.base/'usr/local/bin/crowdsec-firewall-bouncer').exists())
        self.assertEqual(self.file.read_text(),'mode: iptables\napi_key: old\n')
    def test_fresh_install_failure_removes_new_files_and_no_core_actions(self):
        self.file.unlink()
        override="""
remote_bouncer_input() { printf '{}\n' > "$1"; }
remote_bouncer_tool() { return 0; }
remote_bouncer_release() {
 mkdir -p "$(dirname "$REMOTE_BINARY")" "$(dirname "$REMOTE_UNIT")"
 printf binary > "$REMOTE_BINARY"; printf unit > "$REMOTE_UNIT"
 printf 'mode: nftables\n' > "$REMOTE_CONFIG"
 return 1
}
systemctl() { record systemctl "$@"; [[ "$1" != cat && "$1" != is-active && "$1" != is-enabled ]]; }
install_packages() { record packages "$@"; }
"""
        r=self.run_shell('main --install-relay-bouncer',overrides=override)
        self.assertNotEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertFalse(self.file.exists())
        self.assertFalse((self.base/'usr/local/bin/crowdsec-firewall-bouncer').exists())
        self.assertNotIn('cscli',self.commands())
        self.assertNotIn('packages crowdsec',self.commands())

    def test_failed_remove_restores_runtime_enablement_only_after_change(self):
        overrides="""
remote_bouncer_tool() { [[ "$1" != remove ]]; }
systemctl() {
 record systemctl "$@"
 if [[ "$1" == is-enabled ]]; then echo enabled-runtime; fi
 return 0
}
"""
        r=self.run_shell('main --remove-relay-bouncer',overrides=overrides)
        self.assertNotEqual(r.returncode,0)
        self.assertIn('systemctl enable --runtime crowdsec-firewall-bouncer',self.commands())
        self.assertNotIn('systemctl enable crowdsec-firewall-bouncer',self.commands())

    def test_fresh_install_enables_new_unit_when_previous_unit_not_found(self):
        import hashlib
        import io
        import tarfile
        self.file.unlink()
        url=RemoteConfig.server(self)
        archive=self.base/'official-fixture.tgz'
        base_config=b'mode: ${BACKEND}\napi_key: ${API_KEY}\napi_url: http://127.0.0.1:8080/\nupdate_frequency: 10s\nnftables:\n  ipv4: {enabled: true, table: crowdsec, chain: crowdsec-chain, priority: -10}\n  ipv6: {enabled: true, table: crowdsec6, chain: crowdsec6-chain, priority: -10}\n'
        with tarfile.open(archive,'w:gz') as tar:
            for name,payload in [('crowdsec-firewall-bouncer',b'#!/bin/sh\nexit 0\n'),('config/crowdsec-firewall-bouncer.yaml',base_config)]:
                member=tarfile.TarInfo('crowdsec-firewall-bouncer-v0.0.36/'+name)
                member.size=len(payload); tar.addfile(member,io.BytesIO(payload))
        metadata=self.base/'official-fixture.json'
        metadata.write_text(json.dumps({'assets':[{'name':'crowdsec-firewall-bouncer-linux-amd64.tgz','digest':'sha256:'+hashlib.sha256(archive.read_bytes()).hexdigest()}]}))
        credentials=self.base/'input.json'
        credentials.write_text(json.dumps({'url':url,'key':'fresh-secret-no-print'}))
        override=f"""
uname() {{ echo x86_64; }}
curl() {{
 local dest=${{!#}}
 if [[ "$*" == *api.github.com* ]]; then cp {metadata} "$dest"; else cp {archive} "$dest"; fi
}}
remote_bouncer_input() {{ cp {credentials} "$1"; }}
install_packages() {{ record packages "$@"; }}
systemctl() {{
 record systemctl "$@"
 case "$1" in
  is-enabled) printf 'not-found\n'; return 4 ;;
  cat) return 1 ;;
  is-active) [[ -f "$REMOTE_UNIT" ]]; return $? ;;
  *) return 0 ;;
 esac
}}
"""
        r=self.run_shell('main --install-relay-bouncer',overrides=override)
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('systemctl enable crowdsec-firewall-bouncer',self.commands())
        self.assertTrue((self.base/'usr/local/bin/crowdsec-firewall-bouncer').exists())
        self.assertTrue((self.base/'etc/systemd/system/crowdsec-firewall-bouncer.service').exists())
        self.assertIn('mode: iptables',self.file.read_text())
        self.assertIn('packages iptables ipset',self.commands())
        import yaml
        local=yaml.safe_load(Path(str(self.file)+'.local').read_text())
        self.assertEqual(local['nftables_hooks'],['input','forward'])
        self.assertEqual(local['iptables_chains'],['INPUT','FORWARD'])
        self.assertEqual(local['api_url'],url)
        self.assertNotIn('fresh-secret-no-print',r.stdout+r.stderr+self.commands())
        self.assertNotIn('cscli',self.commands())
        self.assertNotIn('packages crowdsec',self.commands())

    def test_local_core_profiles_refuse_managed_remote_overlay_before_mutation(self):
        marker=Path(str(self.file)+'.remote.json')
        marker.write_text(json.dumps({'manager':'crowdsec-1key-remote-v1','sha256':'fixture-marker'}))
        Path(str(self.file)+'.local').write_text('api_url: https://remote.example/\napi_key: fixture-secret\n')
        before={p:p.read_bytes() for p in self.config.rglob('*') if p.is_file()}
        for profile in ('web','relay'):
            self.trace.write_text('')
            r=self.run_shell('install_crowdsec_core '+profile,'203.0.113.2\n')
            self.assertNotEqual(r.returncode,0)
            self.assertEqual(self.commands(),'','local install mutated before refusing remote state')
            self.assertEqual({p:p.read_bytes() for p in self.config.rglob('*') if p.is_file()},before)
            self.assertIn('自动迁移',r.stderr)
    def test_local_core_profiles_refuse_retained_standalone_unit_regular_and_symlink(self):
        unit=self.base/'etc/systemd/system/crowdsec-firewall-bouncer.service'
        unit.parent.mkdir(parents=True)
        content='[Unit]\nDescription=CrowdSec remote Firewall Bouncer (crowdsec-1key)\n[Service]\nExecStart=/usr/local/bin/crowdsec-firewall-bouncer -c /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml\n'
        target=self.base/'retained-unit';target.write_text(content)
        for symlink in (False,True):
            if unit.exists() or unit.is_symlink(): unit.unlink()
            if symlink: unit.symlink_to(target)
            else: unit.write_text(content)
            for profile in ('web','relay'):
                self.trace.write_text('')
                r=self.run_shell('install_crowdsec_core '+profile,'203.0.113.2\n')
                self.assertNotEqual(r.returncode,0)
                self.assertEqual(self.commands(),'','local install mutated before detecting retained unit')
                self.assertEqual(unit.read_text(),content)
                self.assertIn('自动迁移',r.stderr)
    def test_local_core_guard_allows_normal_regular_distro_unit(self):
        unit=self.base/'etc/systemd/system/crowdsec-firewall-bouncer.service'
        unit.parent.mkdir(parents=True)
        unit.write_text('[Unit]\nDescription=The firewall bouncer for CrowdSec\n')
        r=self.run_shell('remote_bouncer_local_core_guard')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(self.commands(),'')

    def test_local_core_profiles_refuse_irregular_unit_without_following_target(self):
        import os
        unit=self.base/'etc/systemd/system/crowdsec-firewall-bouncer.service'
        unit.parent.mkdir(parents=True)
        target=self.base/'credential-target';target.write_text('api_key: private-test-secret\n')
        for kind in ('credential_symlink','dangling_symlink','masked_symlink','fifo','directory'):
            with self.subTest(kind=kind):
                if unit.is_dir() and not unit.is_symlink(): unit.rmdir()
                elif unit.exists() or unit.is_symlink(): unit.unlink()
                if kind=='credential_symlink': unit.symlink_to(target)
                elif kind=='dangling_symlink': unit.symlink_to(self.base/'absent')
                elif kind=='masked_symlink': unit.symlink_to('/dev/null')
                elif kind=='fifo': os.mkfifo(unit)
                else: unit.mkdir()
                for profile in ('web','relay'):
                    self.trace.write_text('')
                    r=self.run_shell('install_crowdsec_core '+profile,'203.0.113.2\n')
                    self.assertNotEqual(r.returncode,0)
                    self.assertEqual(self.commands(),'','irregular unit allowed local mutation')
                    self.assertNotIn('private-test-secret',r.stdout+r.stderr)
                self.assertEqual(target.read_text(),'api_key: private-test-secret\n')
                if kind=='directory': unit.rmdir()
                else: unit.unlink()

    def test_ordinary_distro_unit_does_not_block_normal_local_relay_install(self):
        unit=self.base/'etc/systemd/system/crowdsec-firewall-bouncer.service'
        unit.parent.mkdir(parents=True)
        ordinary='[Unit]\nDescription=The firewall bouncer for CrowdSec\n[Service]\nExecStart=/usr/bin/crowdsec-firewall-bouncer\n'
        unit.write_text(ordinary)
        r=self.run_shell('install_crowdsec_core relay','203.0.113.2\n')
        self.assertEqual(r.returncode,0,r.stdout+r.stderr)
        self.assertIn('systemctl restart crowdsec',self.commands())
        self.assertEqual(unit.read_text(),ordinary)
        self.assertNotIn('自动迁移',r.stderr)

if __name__=='__main__': unittest.main()
