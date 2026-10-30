"""Opt-in local dual-stack flow acceptance; creates only reserved test decisions."""
import subprocess as sp, pathlib, json, time, sys, os, signal, ipaddress, fcntl
BASE = pathlib.Path('/var/lib/crowdbastion/firewall-migration')
TAG = 'crowdbastion-flow'
from crowdsec_firewall_migrate import live
SOURCES = ['198.18.233.2', 'fd42:cb:1::2']
CONTROL = ['198.18.233.3', 'fd42:cb:1::3']
OWNS = False

def run(args, check=True, **kw):
    r = sp.run(args, text=True, capture_output=True, timeout=30, **kw)
    if check and r.returncode:
        raise RuntimeError(str(args[:6]) + ': ' + r.stderr[:500])
    return r

def decisions():
    return live()

def cleanup():
    if not (BASE/'flow-active').exists():
        return
    errors = []
    def attempt(action):
        try:
            return action()
        except (OSError, ValueError, RuntimeError, sp.SubprocessError, KeyError):
            errors.append(True)
            return None
    def stop(unit):
        state = run(['systemctl', 'show', unit, '--property=LoadState', '--value'], False).stdout.strip()
        if state == 'not-found':
            return
        if state != 'loaded':
            raise ValueError('test listener state unavailable')
        run(['systemctl', 'stop', unit])
    for unit in ('crowdbastion-flow-host', 'crowdbastion-flow-dst'):
        attempt(lambda unit=unit: stop(unit))
    rows = attempt(decisions)
    for decision in rows or []:
        if decision.get('scenario', '').startswith(TAG+'-') and decision['value'] in SOURCES:
            attempt(lambda decision=decision: run(['cscli', 'decisions', 'delete', '--id', str(decision['id'])]))
    import shlex
    for binary in ('iptables', 'ip6tables'):
        for chain in ('INPUT', 'DOCKER-USER'):
            result = attempt(lambda: run([binary, '-S', chain]))
            for line in result.stdout.splitlines() if result else []:
                tokens = shlex.split(line)
                if '--comment' in tokens and tokens[tokens.index('--comment')+1] == TAG:
                    tokens[0] = '-D'
                    attempt(lambda: run([binary, '-w', '5', *tokens]))
    for namespace in ('cbfw-src', 'cbfw-dst'):
        if pathlib.Path('/run/netns', namespace).exists():
            result = attempt(lambda: run(['ip', 'netns', 'pids', namespace]))
            for pid in result.stdout.split() if result else []:
                attempt(lambda: run(['kill', pid]))
            attempt(lambda: run(['ip', 'netns', 'delete', namespace]))
            if pathlib.Path('/run/netns', namespace).exists():
                errors.append(True)
    for device in ('cbfw-in', 'cbfw-out'):
        attempt(lambda: run(['ip', 'link', 'del', device], False))
    remaining = attempt(lambda: json.loads(run(['ip', '-j', 'link', 'show']).stdout))
    if remaining is not None:
        if any(link['ifname'] in ('cbfw-in', 'cbfw-out') for link in remaining):
            errors.append(True)
    rows = attempt(decisions)
    if rows and any(d.get('scenario', '').startswith(TAG+'-') and d['value'] in SOURCES for d in rows):
        errors.append(True)
    if errors:
        raise ValueError('test cleanup incomplete; marker retained for retry')
    (BASE/'flow-active').unlink(missing_ok=True)

def setup():
    global OWNS
    if (BASE / 'flow-active').exists():
        raise ValueError('another flow check is active')
    for ns in ['cbfw-src', 'cbfw-dst']:
        if pathlib.Path('/run/netns', ns).exists():
            raise ValueError('test namespace already exists')
    links = json.loads(run(['ip', '-j', 'address', 'show']).stdout)
    for link in links:
        if link['ifname'] in ['cbfw-in', 'cbfw-out']:
            raise ValueError('test interface collision')
        for addr in link.get('addr_info', []):
            net = ipaddress.ip_network(str(addr['local']) + '/' + str(addr['prefixlen']), strict=False)
            if any((ipaddress.ip_address(v) in net for v in SOURCES + CONTROL + ['198.18.234.2', 'fd42:cb:2::2'] if ipaddress.ip_address(v).version == net.version)):
                raise ValueError('test subnet overlaps host')
    test_networks = [ipaddress.ip_network(n) for n in
                     ('198.18.233.0/24', '198.18.234.0/24', 'fd42:cb:1::/64', 'fd42:cb:2::/64')]
    for family in ('-4', '-6'):
        for route in json.loads(run(['ip', family, '-j', 'route', 'show', 'table', 'all']).stdout):
            destination = route.get('dst', 'default')
            if destination == 'default':
                continue
            net = ipaddress.ip_network(destination, strict=False)
            if net.prefixlen and any(net.version == test.version and net.overlaps(test) for test in test_networks):
                raise ValueError('test subnet overlaps an existing host route')
    if any(field.endswith(':18080') for line in run(['ss', '-H', '-lnut']).stdout.splitlines() for field in line.split()):
        raise ValueError('test listener port is already in use')
    for binary in ['iptables', 'ip6tables']:
        if TAG in run([binary, '-S']).stdout:
            raise ValueError('test rule collision')
    from crowdsec_firewall_migrate import networks
    if any((ipaddress.ip_address(v).version == n.version and ipaddress.ip_address(v) in n for n in networks(decisions()) for v in SOURCES + CONTROL)):
        raise ValueError('test addresses have existing decisions')
    for unit in ('crowdbastion-flow-host', 'crowdbastion-flow-dst'):
        state = run(['systemctl', 'show', unit, '--property=LoadState', '--value'], False).stdout.strip()
        if state != 'not-found':
            raise ValueError('test listener service collision')
    run(['systemd-run', '--collect', '--unit=crowdbastion-flow-cleanup', '--on-active=4m', sys.executable, str(pathlib.Path(__file__).resolve()), 'cleanup', str(BASE)])
    (BASE / 'flow-active').touch(exist_ok=False)
    OWNS = True
    for ns, host, subnet in [('cbfw-src', 'cbfw-in', 233), ('cbfw-dst', 'cbfw-out', 234)]:
        run(['ip', 'netns', 'add', ns])
        run(['ip', 'link', 'add', host, 'type', 'veth', 'peer', 'name', 'peer0', 'netns', ns])
        run(['ip', 'addr', 'add', f'198.18.{subnet}.1/24', 'dev', host])
        v6 = '1' if subnet == 233 else '2'
        run(['ip', '-6', 'addr', 'add', f'fd42:cb:{v6}::1/64', 'dev', host, 'nodad'])
        run(['ip', 'link', 'set', host, 'up'])
        run(['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'lo', 'up'])
        run(['ip', 'netns', 'exec', ns, 'ip', 'link', 'set', 'peer0', 'up'])
        for suffix in [2, 3] if subnet == 233 else [2]:
            run(['ip', 'netns', 'exec', ns, 'ip', 'addr', 'add', f'198.18.{subnet}.{suffix}/24', 'dev', 'peer0'])
            run(['ip', 'netns', 'exec', ns, 'ip', '-6', 'addr', 'add', f'fd42:cb:{v6}::{suffix}/64', 'dev', 'peer0', 'nodad'])
        other = 234 if subnet == 233 else 233
        other6 = '2' if subnet == 233 else '1'
        run(['ip', 'netns', 'exec', ns, 'ip', 'route', 'add', f'198.18.{other}.0/24', 'via', f'198.18.{subnet}.1'])
        run(['ip', 'netns', 'exec', ns, 'ip', '-6', 'route', 'add', f'fd42:cb:{other6}::/64', 'via', f'fd42:cb:{v6}::1'])
    for binary, v4 in [('iptables', True), ('ip6tables', False)]:
        source = '198.18.233.0/24' if v4 else 'fd42:cb:1::/64'
        host = '198.18.233.1' if v4 else 'fd42:cb:1::1'
        dest = '198.18.234.2' if v4 else 'fd42:cb:2::2'
        for proto in ['tcp', 'udp']:
            run([binary, '-w', '5', '-I', 'INPUT', '2', '-i', 'cbfw-in', '-s', source, '-d', host, '-p', proto, '--dport', '18080', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'])
            run([binary, '-w', '5', '-I', 'DOCKER-USER', '2', '-i', 'cbfw-in', '-o', 'cbfw-out', '-s', source, '-d', dest, '-p', proto, '--dport', '18080', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'])
            run([binary, '-w', '5', '-I', 'DOCKER-USER', '2', '-i', 'cbfw-out', '-o', 'cbfw-in', '-s', dest, '-d', source, '-p', proto, '--sport', '18080', '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT'])
    server = """# crowdbastion-flow-listener
import socket,threading,time,sys

def serve(addr,kind):
 s=socket.socket(socket.AF_INET6 if ':' in addr else socket.AF_INET,kind)
 s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if ':' in addr:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind((addr,18080))
 if kind==socket.SOCK_STREAM:
  s.listen(32)
  while True:
   c,a=s.accept();c.sendall(b'ok');c.close()
 else:
  while True:
   b,a=s.recvfrom(64);s.sendto(b'ok',a)
for a in sys.argv[1:]:
 for k in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:threading.Thread(target=serve,args=(a,k),daemon=True).start()
while True:time.sleep(1)
"""
    for unit, args in [
        ('crowdbastion-flow-host', [sys.executable, '-c', server, '198.18.233.1', 'fd42:cb:1::1']),
        ('crowdbastion-flow-dst', ['ip', 'netns', 'exec', 'cbfw-dst', sys.executable, '-c', server, '198.18.234.2', 'fd42:cb:2::2'])
    ]:
        run(['systemd-run', '--collect', '--service-type=exec', '--property=RuntimeMaxSec=240s', '--unit='+unit, *args])
    time.sleep(0.5)

def probe():
    client = """import socket,json
rows=[]
for f,sources,targets in [(socket.AF_INET,['198.18.233.2','198.18.233.3'],['198.18.233.1','198.18.234.2']),(socket.AF_INET6,['fd42:cb:1::2','fd42:cb:1::3'],['fd42:cb:1::1','fd42:cb:2::2'])]:
 for src in sources:
  for dst in targets:
   for kind in [socket.SOCK_STREAM,socket.SOCK_DGRAM]:
    s=socket.socket(f,kind);s.settimeout(.4);s.bind((src,0));ok=False
    try:
     s.connect((dst,18080))
     if kind==socket.SOCK_DGRAM:s.send(b'probe')
     ok=s.recv(16)==b'ok'
    except OSError:pass
    finally:s.close()
    rows.append(dict(source=src,destination=dst,protocol='tcp' if kind==socket.SOCK_STREAM else 'udp',reachable=ok))
print(json.dumps(rows))
"""
    return json.loads(run(['ip', 'netns', 'exec', 'cbfw-src', 'python3', '-c', client]).stdout)

def expect(rows, blocked):
    expected = {(src, dst, proto) for src, targets in [(s, ['198.18.233.1', '198.18.234.2'] if ':' not in s else ['fd42:cb:1::1', 'fd42:cb:2::2']) for s in SOURCES + CONTROL] for dst in targets for proto in ['tcp', 'udp']}
    return len(rows) == 16 and {(r['source'], r['destination'], r['protocol']) for r in rows} == expected and all((r['reachable'] == (not blocked if r['source'] in SOURCES else True) for r in rows))

def poll(blocked, seconds=22):
    end = time.monotonic() + seconds
    while True:
        rows = probe()
        if expect(rows, blocked):
            return rows
        if time.monotonic() > end:
            raise AssertionError('flow mismatch: ' + json.dumps(rows))
        time.sleep(1)

def add(duration, reason):
    for source in SOURCES:
        run(['cscli', 'decisions', 'add', '--ip', source, '--duration', duration, '--reason', TAG + '-' + reason])

def main(mode):
    report = {'mode': mode, 'started': time.time()}
    try:
        setup()
        report['baseline'] = poll(False)
        add('40s', 'short')
        original_expiry = time.monotonic()+46
        report['initial_ban'] = poll(True)
        add('120s', 'renew')
        while time.monotonic() < original_expiry:
            time.sleep(min(1, original_expiry - time.monotonic()))
        report['after_original_expiry'] = probe()
        live = [{k: d.get(k) for k in ['id', 'value', 'duration', 'scenario']} for d in decisions() if d['value'] in SOURCES]
        report['live_decisions'] = live
        from crowdsec_firewall_migrate import seconds
        if not ({d['value'] for d in live} == set(SOURCES) and all((seconds(d['duration']) > 15 for d in live))):
            raise ValueError('flow validation failed')
        if mode == 'before':
            if not expect(report['after_original_expiry'], False):
                raise ValueError('expected old backend renewal defect')
        elif not expect(report['after_original_expiry'], True):
            raise ValueError('renewal still leaks traffic')
        for d in live:
            if d['scenario'].startswith(TAG):
                run(['cscli', 'decisions', 'delete', '--id', str(d['id'])])
        report['after_delete'] = poll(False)
        if mode != 'before':
            add('25s', 'natural-expiry')
            start = time.monotonic()
            report['expiry_ban'] = poll(True)
            while time.monotonic() < start + 29:
                time.sleep(min(1, start + 29 - time.monotonic()))
            report['natural_expiry'] = poll(False)
        report['passed'] = True
    except BaseException as e:
        report['passed'] = False
        report['error'] = str(e)
        raise
    finally:
        try:
            if OWNS:
                cleanup()
                run(['systemctl', 'stop', 'crowdbastion-flow-cleanup.timer'])
            report['cleanup'] = 'done' if OWNS else 'not-started'
        except Exception as e:
            report['cleanup'] = str(e)
        report['finished'] = time.time()
        (BASE / ('flow-' + mode + '.json')).write_text(json.dumps(report, indent=2))
        if OWNS and report['cleanup'] != 'done':
            raise ValueError('flow cleanup incomplete; retry using the cleanup timer')
if __name__ == '__main__':
    os.umask(63)
    for sig in [signal.SIGTERM, signal.SIGINT]:
        signal.signal(sig, lambda s, f: sys.exit(128 + s))
    if os.geteuid() != 0:
        sys.exit('需要 root。')
    if len(sys.argv) != 3:
        sys.exit('用法：after|cleanup 私有事务目录')
    BASE = pathlib.Path(sys.argv[2])
    if sys.argv[1] not in ('cleanup', 'after'):
        sys.exit('仅支持 after 或 cleanup。')
    if sys.argv[1] == 'cleanup':
        run(['systemctl', 'stop', 'crowdbastion-firewall-flow'], False)
    with (BASE/'flow.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if sys.argv[1] == 'cleanup':
            cleanup()
        else:
            main('after')
