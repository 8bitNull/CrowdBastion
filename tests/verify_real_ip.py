#!/usr/bin/env python3
"""Verify real-IP trust boundaries and Lua handler IP with isolated OpenResty.

The trusted-loopback case is a test fixture only. Production generated config
trusts exclusively the supplied Cloudflare public ranges, never loopback.
"""
import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import urllib.request

import verify_web

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'lib'))
from crowdsec_realip import plan_real_ip


def check_case(base, binary, install, environment, config_text, trusted, name=None, server=False, requests=None, add_trust=True):
    prefix = base/(name or ('trusted-fixture' if trusted else 'untrusted'))
    prefix.mkdir()
    (prefix/'logs').mkdir()
    config_file = prefix/'real-ip.conf'
    config_file.write_text(config_text+('set_real_ip_from 127.0.0.1; # TEST FIXTURE ONLY\n' if trusted and add_trust else ''))
    port = verify_web.free_port()
    nginx_conf = prefix/'nginx.conf'
    nginx_conf.write_text(f'''worker_processes 1;
daemon off;
error_log {prefix}/error.log info;
pid {prefix}/nginx.pid;
events {{ worker_connections 64; }}
http {{
    lua_package_path "{install}/lualib/?.lua;;";
    lua_package_cpath "{install}/lualib/?.so;;";
    {('set_real_ip_from 127.0.0.1; real_ip_header X-Real-IP; real_ip_recursive on;' if server else 'include '+str(config_file)+';')}
    log_format ips '$remote_addr|$realip_remote_addr';
    access_log {prefix}/access.log ips;
    server {{
        listen 127.0.0.1:{port};
        {('include '+str(config_file)+';' if server else '')}
        location / {{
            access_by_lua_block {{ ngx.ctx.bouncer_ip = ngx.var.remote_addr }}
            content_by_lua_block {{ ngx.say(ngx.var.remote_addr .. "|" .. ngx.var.realip_remote_addr .. "|" .. ngx.ctx.bouncer_ip) }}
        }}
    }}
}}
''')
    verify_web.run([str(binary), '-p', str(prefix)+'/', '-c', str(nginx_conf), '-t'], env=environment)
    with (prefix/'stdout.log').open('w') as output:
        process = subprocess.Popen([str(binary), '-p', str(prefix)+'/', '-c', str(nginx_conf)],
                                   env=environment, stdout=output, stderr=output)
        try:
            verify_web.wait_port(process, port, prefix/'stdout.log')
            cases = requests or [({'CF-Connecting-IP':'8.8.8.8', 'X-Forwarded-For':'9.9.9.9', 'X-Real-IP':'1.1.1.1'}, '8.8.8.8' if trusted else '127.0.0.1')]
            for headers, client in cases:
                request = urllib.request.Request(f'http://127.0.0.1:{port}/', headers=headers)
                with urllib.request.urlopen(request, timeout=10) as response:
                    result = response.read().decode().strip()
                assert result == client+'|127.0.0.1|'+client, result
        finally:
            process.terminate()
            process.wait(timeout=15)
    assert (prefix/'access.log').read_text().splitlines() == [client+'|127.0.0.1' for _, client in cases]
    print(name or ('Trusted fixture: log and Lua access handler use visitor IP, original peer preserved.'
           if trusted else 'Production ranges: untrusted localhost cannot spoof CF-Connecting-IP.'), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--metadata', type=Path)
    parser.add_argument('--cache', type=Path, default=Path('/tmp/crowdsec-openresty-qa-downloads'))
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='crowdsec-real-ip-runtime-') as directory:
        base = Path(directory)
        binary, install, environment, _ = verify_web.unpack_openresty(args.cache, base/'packages', args.metadata)
        plan = plan_real_ip('http { include /etc/nginx/conf.d/*.conf; }',
                            [{'Type':'bind','RW':True,'Source':str(base),'Destination':'/etc/nginx/conf.d'}],
                            ['104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32'])
        assert '127.0.0.1' not in plan['text']
        check_case(base, binary, install, environment, plan['text'], False)
        check_case(base, binary, install, environment, plan['text'], True)
        cloudflare_xff = plan_real_ip('http { include /etc/nginx/conf.d/*.conf; }',
                            [{'Type':'bind','RW':True,'Source':str(base),'Destination':'/etc/nginx/conf.d'}],
                            ['104.16.0.0/13', '172.64.0.0/13', '2606:4700::/32'], header='X-Forwarded-For')
        check_case(base, binary, install, environment, cloudflare_xff['text'], False,
                   name='Cloudflare-XFF-untrusted-peer-cannot-spoof', requests=[
                       ({'X-Forwarded-For': '8.8.8.8'}, '127.0.0.1')])
        check_case(base, binary, install, environment, cloudflare_xff['text'], True,
                   name='Cloudflare-XFF-ignores-spoofed-leftmost', requests=[
                       ({'X-Forwarded-For': '1.1.1.1, 8.8.8.8'}, '8.8.8.8')])
        check_case(base, binary, install, environment, plan['text'], True, name='Missing-invalid-header-keeps-peer', requests=[
            ({'X-Forwarded-For': '9.9.9.9'}, '127.0.0.1'),
            ({'CF-Connecting-IP': 'invalid', 'X-Real-IP': '1.1.1.1'}, '127.0.0.1'),
            ({'CF-Connecting-IP': '2a00:1450:4001:800::200e'}, '2a00:1450:4001:800::200e')])
        check_case(base, binary, install, environment, plan['text'], False, name='NPM-child-trust-replaces-parent', server=True)
        npm_effective = '''# configuration file /etc/nginx/nginx.conf:
http { set_real_ip_from 10.0.0.0/8; real_ip_header X-Real-IP; real_ip_recursive on; include /data/nginx/custom/http_top[.]conf; }
# configuration file /data/nginx/proxy_host/10.conf:
server { include /data/nginx/custom/server_proxy[.]conf; }
'''
        npm_plan = plan_real_ip(npm_effective, [{'Type':'bind','RW':True,'Source':str(base),'Destination':'/data'}],
                               ['127.0.0.1/32'], provider='custom', header='CF-Connecting-IP')
        check_case(base, binary, install, environment, npm_plan['text'], True, name='NPM-generated-server-merge', server=True, add_trust=False)
        xff_plan = plan_real_ip('http { include /etc/nginx/conf.d/*.conf; }',
                               [{'Type':'bind','RW':True,'Source':str(base),'Destination':'/etc/nginx/conf.d'}],
                               ['127.0.0.1/32', '192.0.2.0/24'], provider='custom', header='X-Forwarded-For')
        check_case(base, binary, install, environment, xff_plan['text'], True, name='XFF-right-to-left-trusted-chain', add_trust=False, requests=[
            ({'X-Forwarded-For': '8.8.8.8, 192.0.2.10', 'CF-Connecting-IP': '1.1.1.1'}, '8.8.8.8'),
            ({'X-Forwarded-For': '1.1.1.1, 9.9.9.9, 192.0.2.10'}, '9.9.9.9')])
        print('Real OpenResty real-IP runtime verification: PASS', flush=True)


if __name__ == '__main__':
    main()
