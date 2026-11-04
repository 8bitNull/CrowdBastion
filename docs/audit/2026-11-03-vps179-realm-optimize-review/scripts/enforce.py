"""Controlled IPv4 ingress acceptance; owns only fresh token-named test resources.

Preserves the original audit evidence. SIGTERM/SIGHUP/SIGINT enter cleanup;
subsequent cancellation signals are ignored until bounded cleanup finishes.
"""
from pathlib import Path
import argparse
import datetime
import fcntl
import ipaddress
import json
import os
import re
import select
import shlex
import signal
import subprocess
import time

BASE = Path('/var/backups/crowdbastion/vps179-realm-opt-20261103T092310Z')
SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
CLIENT = r'''import socket,sys,json
proto,src,dst,port=sys.argv[1:];s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM);s.settimeout(.7);s.bind((src,0))
try:
 if proto=='udp':
  s.sendto(b'cb179-isolated-echo',(dst,int(port)));ok=s.recv(128)==b'cb179-isolated-echo'
 else:s.connect((dst,int(port)));ok=True
 print(json.dumps({'reachable':ok}))
except OSError as e:print(json.dumps({'reachable':False,'error':type(e).__name__}))
finally:s.close()
'''


class Cancelled(BaseException):
    pass


def command(args, timeout=20, check=True):
    process = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and process.returncode:
        raise RuntimeError(str(args) + ': ' + process.stdout[-700:] + process.stderr[-700:])
    return process


def input_evidence(text, names):
    """Retain exact filter-table rules and counters; require the actual INPUT path."""
    table, inputs, drops = None, [], []
    for line in text.splitlines():
        if line.startswith('*'):
            table = line[1:]
        if table != 'filter':
            continue
        match = re.match(r'^\[(\d+):(\d+)\] (.*)$', line)
        if not match:
            continue
        words = shlex.split(match[3])
        if words[:2] == ['-A', 'INPUT']:
            inputs.append((words, line))
        if words[:2] != ['-A', 'CROWDSEC_CHAIN'] or '--match-set' not in words or '-j' not in words:
            continue
        i = words.index('--match-set')
        if words[i + 1] in names and words[i + 2] == 'src' and words[words.index('-j') + 1] == 'DROP':
            drops.append({'table': table, 'chain': 'CROWDSEC_CHAIN', 'set': words[i + 1], 'packets': int(match[1]), 'bytes': int(match[2]), 'rule': line})
    if not inputs or inputs[0][0] != ['-A', 'INPUT', '-j', 'CROWDSEC_CHAIN']:
        raise RuntimeError('production INPUT does not start with the expected unconditional CrowdSec jump')
    if set(row['set'] for row in drops) != set(names):
        raise RuntimeError('missing production CROWDSEC_CHAIN source-set DROP rule')
    return {'input_jump': inputs[0][1], 'drop_rules': drops}


class Enforcement:
    def __init__(self, base=BASE, result_path=None, command=command, token=None):
        self.base = Path(base)
        self.result_path = Path(result_path) if result_path else self.base / 'enforcement-review-result.json'
        self.command = command
        token = token or os.urandom(4).hex()
        self.ns, self.vh, self.vn = 'cb179-' + token, 'cb179h' + token, 'cb179n' + token
        self.subnet = ipaddress.ip_network('203.0.113.240/29')
        self.host, self.test, self.control = '203.0.113.241', '203.0.113.242', '203.0.113.243'
        self.reason = 'crowdbastion-realm-review-' + token
        self.ns_attempted = self.veth_attempted = self.decision_attempted = False
        self.echo = None
        self.cleaning = self.launching = False
        self.pending_signal = None
        self.cancelled_signal = None
        self.previous_handlers = {}
        self.r = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'namespace': self.ns, 'reason': self.reason, 'test_source': self.test, 'control_source': self.control, 'coverage': 'actual realm TCP listeners; controlled UDP echo behind production INPUT; IPv4 synthetic ingress, not public WAN/backend authentication', 'checks': {}, 'cleanup': {}}

    def cmd(self, args, timeout=20, check=True):
        return self.command(args, timeout=min(timeout, 5) if self.cleaning else timeout, check=check)

    def on_signal(self, signum, frame):
        if self.cleaning or self.cancelled_signal is not None:
            return
        self.cancelled_signal = signum
        if self.launching:
            self.pending_signal = signum
            return
        raise Cancelled('cancelled by ' + signal.Signals(signum).name)

    def memberships(self, ip):
        names = self.cmd(['ipset', 'list', '-name']).stdout.splitlines()
        return [name for name in names if name.startswith('crowdsec-blacklists') and self.cmd(['ipset', 'test', name, ip], check=False).returncode == 0]

    def wait_member(self, present):
        until = time.monotonic() + (10 if self.cleaning else 30)
        while True:
            sets = self.memberships(self.test)
            if bool(sets) == present:
                return sets
            if time.monotonic() >= until:
                raise RuntimeError('Bouncer membership timeout, wanted ' + str(present))
            time.sleep(.5)

    def preflight(self):
        namespaces = {line.split()[0] for line in self.cmd(['ip', 'netns', 'list']).stdout.splitlines() if line.split()}
        links = {row['ifname'] for row in json.loads(self.cmd(['ip', '-j', 'link', 'show']).stdout)}
        if self.ns in namespaces or self.vh in links or self.vn in links:
            raise RuntimeError('refuse preexisting network resource name')
        for route in json.loads(self.cmd(['ip', '-j', 'route', 'show', 'table', 'all']).stdout):
            dst = route.get('dst')
            if dst and dst != 'default':
                try:
                    network = ipaddress.ip_network(dst, strict=False)
                except ValueError:
                    continue
                if network.overlaps(self.subnet):
                    raise RuntimeError('route overlap: ' + dst)
        for src in (self.test, self.control):
            if self.memberships(src) or json.loads(self.cmd(['cscli', 'decisions', 'list', '-i', src, '-o', 'json']).stdout):
                raise RuntimeError('preexisting blacklist/decision for ' + src)

    def create_network(self):
        # All exact names were absent in preflight. Record intent before commands:
        # a command may create its object and then time out or be interrupted.
        self.ns_attempted = True
        self.cmd(['ip', 'netns', 'add', self.ns])
        self.veth_attempted = True
        self.cmd(['ip', 'link', 'add', self.vh, 'type', 'veth', 'peer', 'name', self.vn])
        self.cmd(['ip', 'link', 'set', self.vn, 'netns', self.ns])
        self.cmd(['ip', 'address', 'add', self.host + '/29', 'dev', self.vh])
        self.cmd(['ip', 'link', 'set', self.vh, 'up'])
        self.cmd(['ip', 'netns', 'exec', self.ns, 'ip', 'link', 'set', 'lo', 'up'])
        for src in (self.test, self.control):
            self.cmd(['ip', 'netns', 'exec', self.ns, 'ip', 'address', 'add', src + '/29', 'dev', self.vn])
        self.cmd(['ip', 'netns', 'exec', self.ns, 'ip', 'link', 'set', self.vn, 'up'])
        self.cmd(['ip', 'netns', 'exec', self.ns, 'ip', 'route', 'add', '192.0.2.17/32', 'via', self.host, 'dev', self.vn])

    def start_echo(self):
        server = "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('" + self.host + "',17773)); print('ready',flush=True)\nwhile True:\n data,peer=s.recvfrom(2048);s.sendto(data,peer)"
        # Defer cancellation only across Popen ownership assignment. The child
        # keeps normal signal disposition, so terminate() remains effective.
        self.launching = True
        try:
            self.echo = subprocess.Popen(['python3', '-u', '-c', server], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        finally:
            self.launching = False
        if self.pending_signal is not None:
            raise Cancelled('cancelled during UDP process launch')
        if not select.select([self.echo.stdout], [], [], 5)[0] or self.echo.stdout.readline().strip() != 'ready':
            raise RuntimeError('UDP echo startup failed')

    def matrix(self, phase, banned):
        result = {}
        for proto, dst, port in [('tcp', '192.0.2.17', 56017), ('tcp', '192.0.2.17', 58372), ('udp', self.host, 17773)]:
            rows = {}
            for role, src in [('test', self.test), ('control', self.control)]:
                rows[role] = json.loads(self.cmd(['ip', 'netns', 'exec', self.ns, 'python3', '-c', CLIENT, proto, src, dst, str(port)], 5).stdout)
            result[proto + ':' + str(port)] = rows
            if rows['test']['reachable'] != (not banned) or not rows['control']['reachable']:
                raise RuntimeError(str((phase, proto, port, rows)))
        self.r['checks'][phase] = result

    def step(self, name, operation):
        try:
            return operation()
        except BaseException as error:
            self.r['cleanup'][name + '_error'] = type(error).__name__ + ': ' + str(error)
            return None

    def cleanup(self):
        self.cleaning = True
        for signum in SIGNALS:
            signal.signal(signum, signal.SIG_IGN)
        if self.decision_attempted:
            process = self.step('decision_delete', lambda: self.cmd(['cscli', 'decisions', 'delete', '--ip', self.test, '--scenario', self.reason], check=False))
            self.r['cleanup']['decision_delete_exit'] = process.returncode if process is not None else None
        if self.echo is not None:
            def stop_echo():
                if self.echo.poll() is None:
                    self.echo.terminate()
                    try:
                        self.echo.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.echo.kill()
                        self.echo.wait(timeout=3)
                for pipe in (self.echo.stdout, self.echo.stderr):
                    if pipe is not None:
                        pipe.close()
                return self.echo.poll() is not None
            self.r['cleanup']['udp_listener_stopped'] = bool(self.step('udp_listener', stop_echo))
        if self.veth_attempted:
            process = self.step('veth_delete', lambda: self.cmd(['ip', 'link', 'delete', self.vh], check=False))
            self.r['cleanup']['veth_delete_exit'] = process.returncode if process is not None else None
        if self.ns_attempted:
            process = self.step('namespace_delete', lambda: self.cmd(['ip', 'netns', 'delete', self.ns], check=False))
            self.r['cleanup']['namespace_delete_exit'] = process.returncode if process is not None else None
        if self.ns_attempted:
            process = self.step('namespace_verify', lambda: self.cmd(['ip', 'netns', 'list']))
            names = {line.split()[0] for line in process.stdout.splitlines() if line.split()} if process is not None else {self.ns}
            self.r['cleanup']['namespace_absent'] = self.ns not in names
        if self.veth_attempted:
            process = self.step('veth_verify', lambda: self.cmd(['ip', 'link', 'show', self.vh], check=False))
            self.r['cleanup']['veth_absent'] = bool(process is not None and process.returncode != 0)
        if self.decision_attempted:
            self.r['cleanup']['test_absent_from_sets'] = self.step('membership_verify', lambda: self.wait_member(False)) is not None
            process = self.step('decision_verify', lambda: self.cmd(['cscli', 'decisions', 'list', '-i', self.test, '-o', 'json']))
            remaining = self.step('decision_parse', lambda: json.loads(process.stdout)) if process is not None else None
            self.r['cleanup']['no_test_decision'] = bool(process is not None and 'decision_parse_error' not in self.r['cleanup'] and remaining in (None, []))

    def run(self):
        try:
            for signum in SIGNALS:
                self.previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self.on_signal)
            self.preflight()
            self.create_network()
            self.start_echo()
            self.matrix('before', False)
            self.decision_attempted = True
            self.r['decision_add_exit'] = self.cmd(['cscli', 'decisions', 'add', '--ip', self.test, '--duration', '2m', '--reason', self.reason]).returncode
            sets = self.wait_member(True)
            self.r['bouncer_sets'] = sets
            before = input_evidence(self.cmd(['iptables-save', '-c']).stdout, sets)
            self.matrix('banned', True)
            after = input_evidence(self.cmd(['iptables-save', '-c']).stdout, sets)
            self.r['input_rule_evidence'] = {'before': before, 'after': after}
            def counters(evidence):
                return {name: sum(row['packets'] for row in evidence['drop_rules'] if row['set'] == name) for name in sets}
            self.r['drop_counters'] = {'before': counters(before), 'after': counters(after)}
            if sum(counters(after).values()) <= sum(counters(before).values()):
                raise RuntimeError('no production INPUT source-set DROP counter increase')
            self.cmd(['cscli', 'decisions', 'delete', '--ip', self.test, '--scenario', self.reason])
            self.wait_member(False)
            self.matrix('recovered', False)
            self.r['status'] = 'passed'
        except BaseException as error:
            self.r['status'] = 'cancelled' if isinstance(error, (Cancelled, KeyboardInterrupt)) else 'failed'
            self.r['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            try:
                self.cleanup()
                required = ['namespace_absent', 'veth_absent', 'test_absent_from_sets', 'no_test_decision', 'udp_listener_stopped']
                if self.r.get('status') == 'passed' and (not all(self.r['cleanup'].get(key) for key in required) or any(key.endswith('_error') for key in self.r['cleanup'])):
                    self.r['status'] = 'cleanup_failed'
                self.result_path.write_text(json.dumps(self.r, indent=2))
            finally:
                for signum, handler in self.previous_handlers.items():
                    signal.signal(signum, handler)
        return self.r


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result', type=Path, default=BASE / 'enforcement-review-result.json')
    args = parser.parse_args()
    with open('/run/lock/crowdsec-1key.lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = Enforcement(result_path=args.result).run()
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
