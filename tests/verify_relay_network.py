#!/usr/bin/env python3
"""Real relay acceptance; full mode always enters private net/mount namespaces."""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
from relay_network_lab import (Processes, DecisionAPI, accepted, command, counter,
                               echo_server, guard, probe, wait_set, free_port)


def endpoint(host, port):
    return ('[%s]:%s' if ':' in host else '%s:%s') % (host, port)


def start_forwarder(args, owned, directory, tool, protocol, listen, target, port, target_port=29000):
    binary = getattr(args, tool)
    if tool == 'gost':
        argv = [binary, '-L', '%s://%s/%s' % (protocol, endpoint(listen, port), endpoint(target, target_port))]
    else:
        config = directory / ('realm-%s.toml' % port)
        config.write_text('[network]\nno_tcp = %s\nuse_udp = %s\n[[endpoints]]\nlisten = "%s"\nremote = "%s"\n' %
                          ('true' if protocol == 'udp' else 'false', 'true' if protocol == 'udp' else 'false', endpoint(listen, port), endpoint(target, target_port)))
        argv = [binary, '-c', str(config)]
    owned.start(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def client(namespace, host, port, protocol):
    argv = [sys.executable, str(Path(__file__).resolve()), '--probe', host, str(port), protocol]
    if namespace:
        argv = ['ip', 'netns', 'exec', namespace] + argv
    result = subprocess.run(argv, text=True, capture_output=True, timeout=5)
    return json.loads(result.stdout) if result.returncode == 0 else None


def setup():
    command(['mount', '--make-rprivate', '/'])
    command(['mount', '-t', 'tmpfs', 'tmpfs', '/run'])
    Path('/run/netns').mkdir(parents=True)
    command(['ip', 'link', 'set', 'lo', 'up'])
    for i, name in enumerate(('bad', 'good', 'backend'), 1):
        command(['ip', 'netns', 'add', name])
        command(['ip', 'link', 'add', 'r'+str(i), 'type', 'veth', 'peer', 'name', 'c'+str(i)])
        command(['ip', 'link', 'set', 'c'+str(i), 'netns', name])
        for namespace, device, suffix in ((None, 'r'+str(i), 1), (name, 'c'+str(i), 2)):
            prefix = ['ip'] if namespace is None else ['ip', '-n', namespace]
            command(prefix + ['addr', 'add', '10.231.%s.%s/24' % (i, suffix), 'dev', device])
            command(prefix + ['-6', 'addr', 'add', 'fd42:231:%s::%s/64' % (i, suffix), 'dev', device, 'nodad'])
            command(prefix + ['link', 'set', device, 'up'])
        command(['ip', '-n', name, 'link', 'set', 'lo', 'up'])
        command(['ip', '-n', name, 'route', 'add', 'default', 'via', '10.231.%s.1' % i])
        command(['ip', '-n', name, '-6', 'route', 'add', 'default', 'via', 'fd42:231:%s::1' % i])
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1')
    Path('/proc/sys/net/ipv6/conf/all/forwarding').write_text('1')


def run_cases(args, report):
    full = not args.forward_only
    if full:
        guard(args.original_inode, args.original_mount_inode)
        setup()
    with tempfile.TemporaryDirectory(prefix='relay-acceptance-') as temp, Processes(grace=3) as owned:
        directory = Path(temp)
        api_context = DecisionAPI() if full else None
        import contextlib
        with api_context if full else contextlib.nullcontext() as api:
            if full:
                import yaml
                config = dict(mode='nftables', update_frequency='1s', api_url=api.url, api_key=api.key,
                              log_mode='stdout', log_level='info', disable_ipv6=False, deny_action='DROP',
                              blacklists_ipv4='crowdsec-blacklists', blacklists_ipv6='crowdsec6-blacklists',
                              nftables_hooks=['input', 'forward'],
                              nftables={family: {'enabled': True, 'set-only': False, 'table': table,
                                                'chain': 'crowdsec-chain', 'priority': -10}
                                        for family, table in [('ipv4','crowdsec'), ('ipv6','crowdsec6')]})
                config_path = directory / 'bouncer.yaml'
                config_path.write_text(yaml.safe_dump(config))
                log = open(directory / 'bouncer.log', 'w+')
                try:
                    owned.start([args.bouncer, '-c', str(config_path)], stdout=log, stderr=log)
                    time.sleep(2)
                    for family in (4, 6):
                        backend = '10.231.3.2' if family == 4 else 'fd42:231:3::2'
                        for protocol in ('tcp', 'udp'):
                            owned.start(['ip', 'netns', 'exec', 'backend', sys.executable, str(Path(__file__).resolve()), '--echo', backend, '29000', protocol], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    execute_matrix(args, report, directory, owned, api)
                except Exception:
                    log.flush()
                    log.seek(0)
                    report['bouncer_log'] = log.read().replace(api.key, '<redacted>')[-12000:]
                    raise
                finally:
                    log.close()
            else:
                args.backend_ports = {}
                for family in (4, 6):
                    backend = '127.0.0.1' if family == 4 else '::1'
                    for protocol in ('tcp', 'udp'):
                        backend_port = free_port(backend, protocol)
                        args.backend_ports[(family, protocol)] = backend_port
                        owned.start([sys.executable, str(Path(__file__).resolve()), '--echo', backend, str(backend_port), protocol], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                execute_matrix(args, report, directory, owned, None)


def execute_matrix(args, report, directory, owned, api):
    port = 30000
    tools = ('gost', 'realm', 'nat') if api else ('gost', 'realm')
    for tool in tools:
        for family in (4, 6):
            for protocol in ('tcp', 'udp'):
                port += 1
                backend = ('10.231.3.2' if family == 4 else 'fd42:231:3::2') if api else ('127.0.0.1' if family == 4 else '::1')
                listen = ('0.0.0.0' if family == 4 else '::') if api else backend
                bad_host = ('10.231.1.1' if family == 4 else 'fd42:231:1::1') if api else backend
                good_host = '10.231.2.1' if family == 4 else 'fd42:231:2::1'
                ban_address = '10.231.1.2' if family == 4 else 'fd42:231:1::2'
                if not api:
                    port = free_port(backend, protocol)
                case = dict(tool=tool, family=family, protocol=protocol)
                report['cases'].append(case)
                if tool == 'nat':
                    # Unique table belongs exclusively to this private lab.
                    rules = 'add table inet relaytest%s\nadd chain inet relaytest%s pre { type nat hook prerouting priority -100; }\nadd chain inet relaytest%s post { type nat hook postrouting priority 100; }\n' % (port, port, port)
                    rules += 'add rule inet relaytest%s pre %s dport %s dnat %s to %s:29000\n' % (port, protocol, port, 'ip' if family == 4 else 'ip6', ('['+backend+']') if family == 6 else backend)
                    rules += 'add rule inet relaytest%s post oifname "r3" masquerade\n' % port
                    command(['nft', '-f', '-'], input=rules)
                else:
                    start_forwarder(args, owned, directory, tool, protocol, listen, backend, port, 29000 if api else args.backend_ports[(family, protocol)])
                normal = None
                for _ in range(20):
                    normal = client('bad' if api else None, bad_host, port, protocol)
                    if normal:
                        break
                    time.sleep(.1)
                case['normal_bad'] = bool(normal)
                case['backend_peer'] = normal.get('peer') if normal else None
                if not api:
                    case['status'] = 'passed' if normal else 'failed'
                    continue
                case['normal_good'] = bool(client('good', good_host, port, protocol))
                api.set_ban(ban_address, True)
                try:
                    wait_set(ban_address, True)
                    before = counter()
                    case['blocked_bad'] = bool(client('bad', bad_host, port, protocol))
                    case['counter_increased'] = counter() > before
                    case['healthy_good'] = bool(client('good', good_host, port, protocol))
                finally:
                    api.set_ban(ban_address, False)
                wait_set(ban_address, False)
                case['recovered_bad'] = bool(client('bad', bad_host, port, protocol))
                case['recovered_good'] = bool(client('good', good_host, port, protocol))
                case['status'] = 'passed' if accepted(case) else 'failed'
                if tool == 'nat':
                    command(['nft', 'delete', 'table', 'inet', 'relaytest'+str(port)])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--gost', default='gost')
    parser.add_argument('--realm', default='realm')
    parser.add_argument('--bouncer', default='crowdsec-firewall-bouncer')
    parser.add_argument('--output', required=False)
    parser.add_argument('--forward-only', action='store_true')
    parser.add_argument('--original-inode', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--original-mount-inode', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--echo', nargs=3, help=argparse.SUPPRESS)
    parser.add_argument('--probe', nargs=3, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.echo:
        host, port, protocol = args.echo
        echo_server(host, int(port), protocol)
        return 0
    if args.probe:
        host, port, protocol = args.probe
        try:
            print(json.dumps(probe(host, int(port), protocol)))
            return 0
        except (OSError, ValueError, RuntimeError):
            return 1
    report = dict(schema=1, mode='forward-only' if args.forward_only else 'isolated-firewall',
                  decision_api='synthetic loopback fixture; real official bouncer' if not args.forward_only else None,
                  scope='fresh sessions only; no throughput benchmark', cases=[], versions={})
    code = 2
    try:
        names = ['gost', 'realm'] + ([] if args.forward_only else ['bouncer'])
        for name in names:
            value = shutil.which(getattr(args, name))
            if not value:
                raise FileNotFoundError('missing executable: ' + name)
            setattr(args, name, str(Path(value).resolve()))
            version = subprocess.run([value, '-version' if name == 'bouncer' else '--version' if name == 'realm' else '-V'], capture_output=True, text=True, timeout=10)
            report['versions'][name] = (version.stdout + version.stderr).strip()[:1000]
        if not args.forward_only and args.original_inode is None:
            for name in ('unshare', 'ip', 'nft', 'mount'):
                if not shutil.which(name):
                    raise FileNotFoundError('missing executable: ' + name)
            invocation = [sys.executable, str(Path(__file__).resolve()), '--original-inode', str(os.stat('/proc/self/ns/net').st_ino), '--original-mount-inode', str(os.stat('/proc/self/ns/mnt').st_ino), '--gost', args.gost, '--realm', args.realm, '--bouncer', args.bouncer]
            with Processes() as owned:
                worker = owned.start(['unshare', '--net', '--mount', '--'] + invocation, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = worker.communicate()
            if stdout.strip():
                try:
                    report = json.loads(stdout)
                    code = worker.returncode
                except ValueError:
                    report['error'] = 'invalid isolated worker report'
            else:
                report['error'] = stderr.strip() or 'isolation unavailable'
        else:
            run_cases(args, report)
            code = 0 if report['cases'] and all(c['status'] == 'passed' for c in report['cases']) else 1
    except (FileNotFoundError, PermissionError) as exc:
        report['error'] = str(exc)
        code = 2
    except subprocess.CalledProcessError as exc:
        report['error'] = str(exc) + '\n' + (exc.output or '')
        code = 1
    except KeyboardInterrupt:
        report['error'] = 'acceptance interrupted; owned processes cleaned'
        code = 1
    except Exception as exc:
        report['error'] = str(exc)
        code = 1
    report['exit_code'] = code
    report['status'] = {0:'passed', 1:'failed', 2:'unverified'}[code]
    data = json.dumps(report, indent=2) + '\n'
    if args.output:
        Path(args.output).write_text(data)
    print(data, end='')
    return code

if __name__ == '__main__':
    sys.exit(main())
