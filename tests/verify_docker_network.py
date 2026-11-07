#!/usr/bin/env python3
"""Real Docker published-port packets; always use private net/mount namespaces."""
import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

from relay_network_lab import DecisionAPI, Processes, accepted, command, guard
import verify_relay_network as network
from verify_relay_iptables import drop_packets, has_address, wait_set


def accept_report(report):
    if (not isinstance(report, dict) or report.get('error') or
            report.get('path_coverage') != 'ok' or report.get('cleanup_complete') is not True or
            not isinstance(report.get('docker_version'), str) or not report['docker_version']):
        return False
    rows = report.get('cases')
    if not isinstance(rows, list) or len(rows) != 8:
        return False
    observed = set()
    for row in rows:
        if not isinstance(row, dict) or type(row.get('family')) is not int:
            return False
        key = (row.get('kind'), row['family'], row.get('protocol'))
        if key in observed:
            return False
        observed.add(key)
        before, after = row.get('counter_before'), row.get('counter_after')
        if (not accepted(row) or type(before) is not int or type(after) is not int or
                before < 0 or after <= before):
            return False
        source = '10.231.1.2' if row['family'] == 4 else 'fd42:231:1::2'
        if row.get('backend_peer') != source:
            return False
        if row.get('kind') == 'docker' and row.get('dnat_verified') is not True:
            return False
    expected = {(kind, family, protocol) for kind in ('host', 'docker')
                for family in (4, 6) for protocol in ('tcp', 'udp')}
    lifecycle = report.get('lifecycle')
    if observed != expected or not isinstance(lifecycle, dict):
        return False
    elapsed = lifecycle.get('original_deadline_elapsed')
    if (lifecycle.get('docker_restarted') is not True or
            lifecycle.get('initial_seconds') != 15 or lifecycle.get('renewed_seconds') != 45 or
            type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 15 or
            lifecycle.get('kernel_sets_expired') is not True):
        return False
    timeouts = lifecycle.get('renewed_timeouts')
    if (not isinstance(timeouts, dict) or set(timeouts) != {'4', '6'} or
            any(type(value) is not int or not 15 < value <= 45 for value in timeouts.values())):
        return False
    for field, reachable in (('renewal_probes', False), ('expiry_probes', True)):
        probes = lifecycle.get(field)
        if not isinstance(probes, list) or len(probes) != 4:
            return False
        keys = set()
        for probe in probes:
            if (not isinstance(probe, dict) or type(probe.get('family')) is not int or
                    probe.get('banned_reachable') is not reachable or probe.get('control_reachable') is not True):
                return False
            keys.add((probe['family'], probe.get('protocol')))
        if keys != {(family, protocol) for family in (4, 6) for protocol in ('tcp', 'udp')}:
            return False
    return True


def timed_ban(api, address, seconds):
    """Publish a short fixture decision; expiry is observed in real kernel sets."""
    with api.lock:
        decision = dict(id=100+ipaddress.ip_address(address).version, duration=str(seconds)+'s',
                        origin='cscli', scenario='docker-lifecycle', scope='Ip', type='ban', value=address)
        api.active[address] = decision
        api.pending['new'].append(decision)


def namespace_inode(descriptor, kind):
    if type(descriptor) is not int or descriptor < 0:
        raise RuntimeError('inherited namespace descriptors required')
    try:
        target = os.readlink('/proc/self/fd/'+str(descriptor))
        inode = os.fstat(descriptor).st_ino
    except OSError:
        raise RuntimeError('inherited namespace descriptors required') from None
    if target != kind+':['+str(inode)+']':
        raise RuntimeError('inherited namespace descriptors required')
    return inode


def checkpoint(report, descriptor):
    if descriptor is None:
        return
    data = (json.dumps(report, sort_keys=True)+'\n').encode()
    while data:
        data = data[os.write(descriptor, data):]
    os.fsync(descriptor)


def daemon_ready(docker):
    result = subprocess.run([*docker, 'info', '--format', '{{json .}}'],
                            capture_output=True, text=True, timeout=15)
    try:
        info = json.loads(result.stdout)
    except ValueError:
        return None
    if (result.returncode or not isinstance(info, dict) or info.get('ServerErrors') or
            not isinstance(info.get('ServerVersion'), str) or not info['ServerVersion']):
        return None
    return info['ServerVersion']


def execute_worker(invocation, descriptors, checkpoint_path, *, timeout=600, cleanup_timeout=90):
    stdout = stderr = ''
    interrupted = False
    with Processes(grace=0, subreaper=True) as owned:
        child = owned.start(invocation, pass_fds=descriptors, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            interrupted = True
            if child.poll() is None:
                child.terminate()
            try:
                stdout, stderr = child.communicate(timeout=cleanup_timeout)
            except subprocess.TimeoutExpired as exc:
                stdout, stderr = exc.stdout or '', exc.stderr or ''
                if isinstance(stdout, bytes):
                    stdout = stdout.decode(errors='replace')
                if isinstance(stderr, bytes):
                    stderr = stderr.decode(errors='replace')
    report = None
    try:
        report = json.loads(stdout)
    except ValueError:
        pass
    recovered_checkpoint = False
    if not isinstance(report, dict) and checkpoint_path.exists():
        for line in reversed(checkpoint_path.read_text().splitlines()):
            try:
                candidate = json.loads(line)
                if isinstance(candidate, dict):
                    report = candidate
                    recovered_checkpoint = True
                    break
            except ValueError:
                continue
    if not isinstance(report, dict):
        report = {'cases': [], 'error': stderr[-2000:] or 'no complete isolated worker report'}
    if interrupted:
        report['error'] = 'isolated Docker acceptance timeout or interruption'
    if stderr:
        report['worker_stderr'] = stderr[-8000:]
    code = 0 if not interrupted and child.returncode == 0 and accept_report(report) else 1
    if not stdout.strip() and not recovered_checkpoint and not interrupted:
        code = 2
    return report, code


def set_timeouts():
    found = {}
    for line in command(['ipset', 'save'], timeout=15).splitlines():
        words = shlex.split(line)
        if len(words) >= 5 and words[0] == 'add' and 'timeout' in words:
            for family, address in ((4, '10.231.1.2'), (6, 'fd42:231:1::2')):
                if words[2] == address:
                    found[str(family)] = int(words[words.index('timeout')+1])
    return found


def lifecycle_probes():
    rows = []
    for family in (4, 6):
        for protocol in ('tcp', 'udp'):
            bad = '10.231.1.1' if family == 4 else 'fd42:231:1::1'
            good = '10.231.2.1' if family == 4 else 'fd42:231:2::1'
            rows.append(dict(family=family, protocol=protocol,
                             banned_reachable=bool(network.client('bad', bad, 34000, protocol, process_timeout=15)),
                             control_reachable=bool(network.client('good', good, 34000, protocol, process_timeout=15))))
    return rows


def observe_lifecycle(api):
    sources = ('10.231.1.2', 'fd42:231:1::2')
    for address in sources:
        timed_ban(api, address, 15)
    for address in sources:
        wait_set(address, True)
    started = time.monotonic()
    for address in sources:
        timed_ban(api, address, 45)
    renewed = time.monotonic()
    deadline = renewed+20
    while time.monotonic() < deadline:
        timeouts = set_timeouts()
        if set(timeouts) == {'4', '6'} and all(15 < value <= 45 for value in timeouts.values()):
            break
        time.sleep(.2)
    else:
        raise RuntimeError('kernel set renewal did not extend both families')
    time.sleep(max(0, started+17-time.monotonic()))
    result = dict(initial_seconds=15, renewed_seconds=45, renewed_timeouts=timeouts,
                  original_deadline_elapsed=time.monotonic()-started, renewal_probes=lifecycle_probes())
    deadline = renewed+70
    while time.monotonic() < deadline:
        saved = command(['ipset', 'save'], timeout=15)
        if not any(has_address(saved, address) for address in sources):
            break
        time.sleep(.2)
    else:
        raise RuntimeError('kernel decisions did not expire naturally')
    result.update(kernel_sets_expired=True, expiry_probes=lifecycle_probes(),
                  expiry_elapsed_seconds=time.monotonic()-renewed)
    for address in sources:
        api.set_ban(address, False)
    return result


def build_image(docker, directory):
    """Import the guest's Python and its linked libraries without an image pull."""
    root = directory/'rootfs'
    root.mkdir()
    stdlib = Path(sys.base_prefix)/'lib'/('python%d.%d' % sys.version_info[:2])
    shutil.copytree(stdlib, root/stdlib.relative_to('/'),
                    ignore=shutil.ignore_patterns('__pycache__', 'site-packages', 'dist-packages'))
    interpreter = root/'usr/bin/python3'
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(sys.executable, interpreter)
    linked = subprocess.run(['ldd', sys.executable, *map(str, (stdlib/'lib-dynload').glob('*.so'))],
                            capture_output=True, text=True, timeout=30)
    if 'not found' in linked.stdout or linked.returncode:
        raise RuntimeError('Python container libraries unavailable')
    for name in set(re.findall(r'(/[^\s():]+)', linked.stdout)):
        source = Path(name)
        if source.is_file():
            target = root/source.relative_to('/')
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
    shutil.copy2(Path(__file__).with_name('relay_network_lab.py'), root/'relay_network_lab.py')
    (root/'echo.py').write_text(
        'import signal,threading\nfrom relay_network_lab import echo_server\n'
        "for address in ('0.0.0.0','::'):\n"
        " for protocol in ('tcp','udp'):\n"
        '  threading.Thread(target=echo_server,args=(address,29000,protocol),daemon=True).start()\n'
        'signal.pause()\n')
    archive = directory/'rootfs.tar'
    with tarfile.open(archive, 'w') as bundle:
        for path in root.iterdir():
            bundle.add(path, arcname=path.name)
    with archive.open('rb') as data:
        image = subprocess.run([*docker, 'import', '-'], stdin=data, capture_output=True,
                               text=True, timeout=120)
    if image.returncode or not re.fullmatch(r'sha256:[0-9a-f]{64}', image.stdout.strip()):
        raise RuntimeError('container image import failed')
    return image.stdout.strip()


def dnat_present(family, protocol, port, target):
    binary = 'iptables-save' if family == 4 else 'ip6tables-save'
    for line in command([binary, '-t', 'nat'], timeout=15).splitlines():
        words = shlex.split(line)
        if words[:2] != ['-A', 'DOCKER']:
            continue
        required = (('-p', protocol), ('--dport', str(port)), ('-j', 'DNAT'))
        if not all(any(words[i:i+2] == list(pair) for i in range(len(words)-1)) for pair in required):
            continue
        if '--to-destination' in words:
            destination = words[words.index('--to-destination')+1]
            if destination == ('[%s]:29000' if family == 6 else '%s:29000') % target:
                return True
    return False


def worker(args, report):
    guard(namespace_inode(args.net_fd, 'net'), namespace_inode(args.mount_fd, 'mnt'))
    checkpoint(report, args.checkpoint_fd)
    import yaml
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'lib'))
    from crowdsec_firewall_runtime import chain_coverage, expected_chains
    network.setup()
    with tempfile.TemporaryDirectory(prefix='cb-docker-acceptance-') as temp, Processes(grace=10) as owned:
        directory = Path(temp)
        socket = 'unix://'+str(directory/'docker.sock')
        docker = [args.docker, '--host', socket]
        daemon_log = (directory/'docker.log').open('w+')
        container = 'cb-packet-acceptance'
        network_name = 'cb-packet-network'
        created_container = created_network = False
        try:
            daemon_args = [args.dockerd, '--host='+socket,
                                  '--data-root='+str(directory/'data'), '--exec-root='+str(directory/'run'),
                                  '--pidfile='+str(directory/'pid'), '--bridge=none', '--storage-driver=vfs',
                                  '--iptables=true', '--ip6tables=true', '--userland-proxy=false',
                           '--exec-opt=native.cgroupdriver=cgroupfs']
            daemon = owned.start(daemon_args, stdout=daemon_log, stderr=daemon_log)
            deadline = time.monotonic()+100
            while time.monotonic() < deadline:
                version = daemon_ready(docker)
                if version:
                    report['docker_version'] = version
                    break
                if daemon.poll() is not None:
                    raise RuntimeError('isolated Docker daemon exited')
                time.sleep(.3)
            else:
                raise RuntimeError('isolated Docker daemon readiness timeout')
            command([*docker, 'network', 'create', '--driver', 'bridge', '--ipv6',
                     '--subnet', '10.232.0.0/24', '--subnet', 'fd42:232::/64', network_name], timeout=30)
            created_network = True
            image = build_image(docker, directory)
            report['container_image'] = image
            ports = []
            for protocol in ('tcp', 'udp'):
                for address in ('0.0.0.0', '[::]'):
                    ports += ['--publish', address+':34000:29000/'+protocol]
            command([*docker, 'run', '--detach', '--name', container, '--network', network_name,
                     '--sysctl', 'net.ipv6.bindv6only=1', *ports, image,
                     '/usr/bin/python3', '/echo.py'], timeout=60)
            created_container = True
            attached = json.loads(command([*docker, 'inspect', container], timeout=15))[0]['NetworkSettings']['Networks'][network_name]
            targets = {4: str(ipaddress.ip_address(attached['IPAddress'])),
                       6: str(ipaddress.ip_address(attached['GlobalIPv6Address']))}
            report['container_addresses'] = targets
            with DecisionAPI() as api:
                config = dict(mode='iptables', update_frequency='1s', api_url=api.url, api_key=api.key,
                              log_mode='stdout', log_level='info', disable_ipv6=False, deny_action='DROP',
                              blacklists_ipv4='crowdsec-blacklists', blacklists_ipv6='crowdsec6-blacklists',
                              ipset_type='nethash', iptables_chains=['INPUT', 'FORWARD', 'DOCKER-USER'])
                config.update(expected_chains(config, True))
                config_path = directory/'bouncer.yaml'
                config_path.write_text(yaml.safe_dump(config))
                config_path.chmod(0o600)
                bouncer_log = (directory/'bouncer.log').open('w+')
                try:
                    owned.start([args.bouncer, '-c', str(config_path)], stdout=bouncer_log, stderr=bouncer_log)
                    for address in ('10.231.1.1', '10.231.2.1', 'fd42:231:1::1', 'fd42:231:2::1'):
                        for protocol in ('tcp', 'udp'):
                            owned.start([sys.executable, str(Path(network.__file__).resolve()),
                                         '--echo', address, '34010', protocol],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    time.sleep(2)
                    report['cases'] = []
                    for kind in ('host', 'docker'):
                        for family in (4, 6):
                            for protocol in ('tcp', 'udp'):
                                port = 34000 if kind == 'docker' else 34010
                                bad_host = '10.231.1.1' if family == 4 else 'fd42:231:1::1'
                                good_host = '10.231.2.1' if family == 4 else 'fd42:231:2::1'
                                source = '10.231.1.2' if family == 4 else 'fd42:231:1::2'
                                row = dict(kind=kind, family=family, protocol=protocol)
                                report['cases'].append(row)
                                normal = None
                                deadline = time.monotonic()+20
                                while time.monotonic() < deadline and not normal:
                                    normal = network.client('bad', bad_host, port, protocol, process_timeout=15)
                                    if not normal:
                                        time.sleep(.2)
                                row.update(normal_bad=bool(normal), backend_peer=normal.get('peer') if normal else None,
                                           normal_good=bool(network.client('good', good_host, port, protocol, process_timeout=15)))
                                row['dnat_verified'] = kind == 'docker' and dnat_present(family, protocol, port, targets[family])
                                api.set_ban(source, True)
                                try:
                                    wait_set(source, True)
                                    report['path_coverage'] = chain_coverage(config_path, True)
                                    binary = 'iptables-save' if family == 4 else 'ip6tables-save'
                                    row['counter_before'] = drop_packets(command([binary, '-c', '-t', 'filter'], timeout=15))
                                    row['blocked_bad'] = bool(network.client('bad', bad_host, port, protocol, process_timeout=15))
                                    row['counter_after'] = drop_packets(command([binary, '-c', '-t', 'filter'], timeout=15))
                                    row['counter_increased'] = row['counter_after'] > row['counter_before']
                                    row['healthy_good'] = bool(network.client('good', good_host, port, protocol, process_timeout=15))
                                finally:
                                    api.set_ban(source, False)
                                wait_set(source, False)
                                row['recovered_bad'] = bool(network.client('bad', bad_host, port, protocol, process_timeout=15))
                                row['recovered_good'] = bool(network.client('good', good_host, port, protocol, process_timeout=15))
                                row['status'] = 'passed' if accepted(row) else 'failed'
                                checkpoint(report, args.checkpoint_fd)
                    daemon.terminate()
                    daemon.wait(timeout=40)
                    daemon = owned.start(daemon_args, stdout=daemon_log, stderr=daemon_log)
                    deadline = time.monotonic()+100
                    while time.monotonic() < deadline:
                        if daemon_ready(docker):
                            break
                        if daemon.poll() is not None:
                            raise RuntimeError('Docker daemon restart failed')
                        time.sleep(.3)
                    else:
                        raise RuntimeError('Docker daemon restart readiness timeout')
                    command([*docker, 'start', container], timeout=60)
                    report['lifecycle'] = observe_lifecycle(api)
                    report['lifecycle']['docker_restarted'] = True
                    checkpoint(report, args.checkpoint_fd)
                finally:
                    bouncer_log.flush()
                    bouncer_log.seek(0)
                    report['bouncer_log'] = bouncer_log.read().replace(api.key, '<redacted>')[-8000:]
                    bouncer_log.close()
        finally:
            cleaned = []
            actions = [[*docker, 'rm', '--force', container]] if created_container else []
            if created_network:
                actions.append([*docker, 'network', 'rm', network_name])
            for action in actions:
                try:
                    cleaned.append(subprocess.run(action, capture_output=True, timeout=30).returncode == 0)
                except subprocess.SubprocessError:
                    cleaned.append(False)
            report['cleanup_complete'] = bool(created_container and created_network and all(cleaned))
            daemon_log.flush()
            daemon_log.seek(0)
            report['docker_log'] = daemon_log.read()[-8000:]
            daemon_log.close()
            checkpoint(report, args.checkpoint_fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name, default in (('docker', 'docker'), ('dockerd', 'dockerd'), ('bouncer', 'crowdsec-firewall-bouncer')):
        parser.add_argument('--'+name, default=default)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--net-fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--mount-fd', type=int, help=argparse.SUPPRESS)
    parser.add_argument('--checkpoint-fd', type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    report = dict(schema=1, validation_level='real-kernel-real-docker-synthetic-decision-api', cases=[],
                  scope='private namespaces; fresh IPv4/IPv6 TCP/UDP host and Docker published-port sessions')
    code = 2
    try:
        if args.net_fd is None:
            for name in ('docker', 'dockerd', 'bouncer'):
                value = shutil.which(getattr(args, name))
                if not value:
                    raise FileNotFoundError('missing executable: '+name)
                setattr(args, name, str(Path(value).resolve()))
            with tempfile.TemporaryDirectory(prefix='cb-docker-report-') as directory:
                path = Path(directory)/'worker.jsonl'
                descriptors = []
                try:
                    for name in ('/proc/self/ns/net', '/proc/self/ns/mnt'):
                        descriptors.append(os.open(name, os.O_RDONLY))
                    descriptors.append(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, 0o600))
                    invocation = [sys.executable, str(Path(__file__).resolve()),
                                  '--net-fd', str(descriptors[0]), '--mount-fd', str(descriptors[1]),
                                  '--checkpoint-fd', str(descriptors[2])]
                    for name in ('docker', 'dockerd', 'bouncer'):
                        invocation += ['--'+name, getattr(args, name)]
                    report, code = execute_worker(['unshare', '--net', '--mount', '--', *invocation],
                                                  tuple(descriptors), path)
                finally:
                    for descriptor in descriptors:
                        os.close(descriptor)
        else:
            worker(args, report)
            code = 0 if accept_report(report) else 1
    except (FileNotFoundError, PermissionError) as exc:
        report['error'] = str(exc)
    except (Exception, KeyboardInterrupt) as exc:
        report['error'] = str(exc)
        if isinstance(exc, subprocess.CalledProcessError) and exc.output:
            report['command_output'] = str(exc.output)[-8000:]
        code = 1
    report.update(exit_code=code, status={0: 'passed', 1: 'failed', 2: 'unverified'}[code])
    data = json.dumps(report, indent=2)+'\n'
    if args.output:
        args.output.write_text(data)
    print(data, end='')
    return code


if __name__ == '__main__':
    sys.exit(main())
