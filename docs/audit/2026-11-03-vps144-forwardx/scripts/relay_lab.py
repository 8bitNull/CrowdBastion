#!/usr/bin/env python3
"""Local-only realm 2.9.4 TCP/UDP verification; requires root, ip and Python 3.

Run: python3 relay_lab.py --base /var/backups/<existing-root-private-backup>
Creates one private run directory and one fresh, loopback-only network namespace.
Never changes host sysctls, firewall, production configs or running services.
Results demonstrate local byte integrity/client isolation, not WAN performance,
public reachability, backend protocol support or production ens18 binding.
SIGINT/SIGHUP/SIGTERM enter bounded cleanup; SIGKILL cannot be handled.
"""
import argparse
import datetime
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import tempfile
import time

REALM = '/usr/local/bin/realm'
SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)
PORTS = ((53534, 2087), (53536, 2096), (53537, 2096))

# Separate TCP sockets and per-peer UDP replies preserve client identity. The
# namespace has no external interface or routes; only loopback is brought up.
BACKEND = r'''
import json,selectors,socket
sel=selectors.DefaultSelector()
for port in (2087,2096):
 for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
  s=socket.socket(socket.AF_INET,kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
  s.bind(('127.0.0.1',port));s.setblocking(False)
  if kind==socket.SOCK_STREAM:s.listen(32)
  sel.register(s,selectors.EVENT_READ,'listen' if kind==socket.SOCK_STREAM else 'udp')
ipv6=False
try:
 with socket.socket(socket.AF_INET6,socket.SOCK_STREAM) as probe:
  probe.bind(('::1',0));ipv6=True
except OSError:pass
print(json.dumps({'ready':True,'ipv6':ipv6}),flush=True)
while True:
 for key,events in sel.select(1):
  s=key.fileobj;role=key.data
  try:
   if role=='listen':
    c,_=s.accept();c.setblocking(False);sel.register(c,selectors.EVENT_READ,bytearray())
   elif role=='udp':
    data,peer=s.recvfrom(65535);s.sendto(data,peer)
   else:
    pending=role
    if events&selectors.EVENT_READ:
     data=s.recv(65535)
     if not data:sel.unregister(s);s.close();continue
     pending.extend(data)
    if pending and events&selectors.EVENT_WRITE:
     sent=s.send(pending);del pending[:sent]
    sel.modify(s,selectors.EVENT_READ|(selectors.EVENT_WRITE if pending else 0),pending)
  except BlockingIOError:pass
  except OSError:
   sel.unregister(s);s.close()
'''

CLIENT = r'''
import concurrent.futures,json,socket,time
families=json.loads(__import__('sys').argv[1])
def client(case):
 family,proto,port,identity=case
 af=socket.AF_INET6 if family=='ipv6' else socket.AF_INET
 kind=socket.SOCK_DGRAM if proto=='udp' else socket.SOCK_STREAM
 rtts=[]
 with socket.socket(af,kind) as s:
  s.settimeout(2);s.connect(('::1' if af==socket.AF_INET6 else '127.0.0.1',port))
  for seq,size in enumerate((64,512,1200)):
   token=('%s/%s/%s/%s/%s:'%(family,proto,port,identity,seq)).encode()
   payload=(token+bytes([65+identity])*size)[:size]
   start=time.monotonic()
   if kind==socket.SOCK_DGRAM:
    s.send(payload);returned=s.recv(65535)
   else:
    s.sendall(payload);returned=b''
    while len(returned)<len(payload):
     block=s.recv(len(payload)-len(returned))
     if not block:raise RuntimeError('unexpected_eof')
     returned+=block
   if returned!=payload:raise RuntimeError('payload_or_client_identity_mismatch')
   rtts.append(round((time.monotonic()-start)*1000,3))
 return {'family':family,'protocol':proto,'port':port,'client':identity,
         'sizes':[64,512,1200],'identity_preserved':True,'local_rtt_ms':rtts}
cases=[(f,p,port,i) for f in families for p in ('tcp','udp')
       for port in (53534,53536,53537) for i in range(3)]
with concurrent.futures.ThreadPoolExecutor(max_workers=len(cases)) as pool:
 rows=list(pool.map(client,cases))
print(json.dumps({'checks':rows,'roundtrips':len(rows)*3}))
'''


class Cancelled(BaseException):
    pass


def command(args, timeout=5, check=True):
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        # Keep command output (including realm diagnostics) in private logs only.
        raise RuntimeError('command_failed:' + Path(args[0]).name + ':' + str(result.returncode))
    return result


def private_base(path):
    """Reject symlinks and writable ancestors before creating result/config files."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('base_must_be_absolute')
    for item in (path, *path.parents):
        info = item.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
            raise ValueError('base_ancestry_not_root_owned_directory')
        writable = info.st_mode & 0o022
        if writable and not (item != path and info.st_mode & stat.S_ISVTX):
            raise ValueError('base_ancestry_writable')
    if path.stat().st_mode & 0o077:
        raise ValueError('base_must_be_root_private')
    return path


class RelayLab:
    def __init__(self, base, run_command=command):
        self.base = Path(base)
        self.command = run_command
        self.ns = 'cb144lab-' + os.urandom(6).hex()
        self.ns_attempted = False
        self.children = []
        self.logs = []
        self.launching = self.cleaning = False
        self.cancelled_signal = None
        self.handlers = {}
        self.directory = None
        self.result = {'at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       'namespace': self.ns, 'scope': 'isolated loopback realm byte-integrity lab; no WAN claim',
                       'status': 'failed', 'cleanup': {}}

    def on_signal(self, signum, frame):
        if self.cleaning or self.cancelled_signal is not None:
            return
        self.cancelled_signal = signum
        if not self.launching:
            raise Cancelled()

    def check_cancelled(self):
        if self.cancelled_signal is not None:
            raise Cancelled()

    def launch(self, label, args, ready=False):
        log = open(self.directory / (label + '.log'), 'x', encoding='utf-8')
        os.chmod(log.name, 0o600)
        self.logs.append(log)
        # A cancellation between Popen and assignment must not lose ownership.
        self.launching = True
        try:
            child = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.PIPE if ready else log,
                                     stderr=log, text=True)
            self.children.append((label, child))
        finally:
            self.launching = False
        self.check_cancelled()
        if ready:
            if not select.select([child.stdout], [], [], 5)[0]:
                raise RuntimeError('backend_startup_timeout')
            # Only our fixed Python backend emits this single short JSON line.
            row = json.loads(child.stdout.readline(1024))
            if row.get('ready') is not True:
                raise RuntimeError('backend_not_ready')
            return row
        return child

    def setup(self):
        names = {line.split()[0] for line in self.command(['ip', 'netns', 'list']).stdout.splitlines() if line.split()}
        if self.ns in names or Path('/run/netns', self.ns).exists():
            raise RuntimeError('namespace_name_already_exists')
        version = self.command([REALM, '--version']).stdout.strip()
        if not version.startswith('Realm 2.9.4 ') or '[batched-udp]' not in version:
            raise RuntimeError('expected_realm_2_9_4_batched_udp')
        self.result['realm_version'] = version
        self.launching = True
        try:
            # Record intent first: ip may create the namespace then time out.
            self.ns_attempted = True
            self.command(['ip', 'netns', 'add', self.ns])
        finally:
            self.launching = False
        self.check_cancelled()
        self.command(['ip', 'netns', 'exec', self.ns, 'ip', 'link', 'set', 'lo', 'up'])
        links = json.loads(self.command(['ip', '-n', self.ns, '-j', 'link', 'show']).stdout)
        if [row['ifname'] for row in links] != ['lo']:
            raise RuntimeError('namespace_is_not_loopback_only')
        backend = self.launch('backend', ['ip', 'netns', 'exec', self.ns,
                              sys.executable, '-I', '-S', '-u', '-c', BACKEND], ready=True)
        ipv6 = backend['ipv6']
        self.result['ipv6'] = 'tested' if ipv6 else 'unavailable_loopback_bind'
        for port, remote in PORTS:
            config = self.directory / ('realm-' + str(port) + '.toml')
            listen = '[::]' if ipv6 else '127.0.0.1'
            with open(config, 'x', encoding='utf-8') as stream:
                stream.write('[log]\nlevel = "warn"\n[network]\nuse_udp = true\n'
                             'tcp_timeout = 300\nudp_timeout = 30\nipv6_only = false\n'
                             'send_proxy = false\naccept_proxy = false\n[[endpoints]]\n'
                             'listen = "' + listen + ':' + str(port) + '"\n'
                             'remote = "127.0.0.1:' + str(remote) + '"\n')
            os.chmod(config, 0o600)
            self.launch('realm-' + str(port), ['ip', 'netns', 'exec', self.ns,
                        REALM, '-c', str(config), '--interface', 'lo'])
        # Namespace TCP connects test only startup; the matrix tests actual data.
        ready_code = ('import socket; '
                      '[socket.create_connection(("127.0.0.1",p),.2).close() '
                      'for p in (53534,53536,53537)]')
        deadline = time.monotonic() + 8
        while True:
            if any(child.poll() is not None for _, child in self.children):
                raise RuntimeError('lab_child_exited_during_startup')
            check = self.command(['ip', 'netns', 'exec', self.ns, sys.executable,
                                  '-I', '-S', '-c', ready_code], timeout=2, check=False)
            if check.returncode == 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError('realm_listener_startup_timeout')
            time.sleep(.1)
        return ['ipv4', 'ipv6'] if ipv6 else ['ipv4']

    def cleanup(self):
        self.cleaning = True
        for signum in SIGNALS:
            signal.signal(signum, signal.SIG_IGN)
        cleanup = self.result['cleanup']
        for label, child in reversed(self.children):
            try:
                if child.poll() is None:
                    child.terminate()
                    try:
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
                if child.stdout:
                    child.stdout.close()
                cleanup[label + '_stopped'] = child.poll() is not None
            except BaseException as error:
                cleanup[label + '_error'] = type(error).__name__
        for index, stream in enumerate(self.logs):
            try:
                stream.close()
            except BaseException as error:
                cleanup['log_' + str(index) + '_error'] = type(error).__name__
        if self.ns_attempted:
            try:
                # No wildcard lookup or killing namespace-member PIDs: only the
                # fresh exact name and Popen children owned by this invocation.
                self.command(['ip', 'netns', 'delete', self.ns], timeout=5, check=False)
                names = {line.split()[0] for line in self.command(['ip', 'netns', 'list'], timeout=5).stdout.splitlines() if line.split()}
                cleanup['namespace_absent'] = self.ns not in names
            except BaseException as error:
                cleanup['namespace_error'] = type(error).__name__
        else:
            cleanup['namespace_not_created'] = True

    def run(self):
        try:
            for signum in SIGNALS:
                self.handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self.on_signal)
            self.directory = Path(tempfile.mkdtemp(prefix='relay-lab-', dir=self.base))
            self.result['directory'] = str(self.directory)
            families = self.setup()
            output = self.command(['ip', 'netns', 'exec', self.ns, sys.executable,
                                   '-I', '-S', '-c', CLIENT, json.dumps(families)], timeout=20, check=False)
            with open(self.directory / 'client.log', 'x', encoding='utf-8') as stream:
                stream.write(output.stdout + output.stderr)
            if output.returncode:
                raise RuntimeError('client_matrix_failed')
            self.result.update(json.loads(output.stdout))
            if any(child.poll() is not None for _, child in self.children):
                raise RuntimeError('lab_child_exited_during_matrix')
            self.result['status'] = 'passed'
        except BaseException as error:
            self.result['status'] = 'cancelled' if isinstance(error, (Cancelled, KeyboardInterrupt)) else 'failed'
            self.result['error'] = type(error).__name__
            if isinstance(error, RuntimeError):
                self.result['error_code'] = str(error)
        finally:
            try:
                self.cleanup()
                cleanup = self.result['cleanup']
                if self.result['status'] == 'passed' and (not cleanup.get('namespace_absent') or
                        not all(cleanup.get(label + '_stopped') for label, _ in self.children) or
                        any(key.endswith('_error') for key in cleanup)):
                    self.result['status'] = 'cleanup_failed'
                if self.directory is not None:
                    path = self.directory / 'result.json'
                    with open(path, 'x', encoding='utf-8') as stream:
                        stream.write(json.dumps(self.result, indent=2) + '\n')
                    os.chmod(path, 0o600)
            finally:
                for signum, handler in self.handlers.items():
                    signal.signal(signum, handler)
        return self.result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    try:
        if os.geteuid() != 0:
            raise ValueError('root_required')
        result = RelayLab(private_base(args.base)).run()
    except (ValueError, OSError) as error:
        result = {'status': 'refused', 'error': type(error).__name__,
                  'error_code': str(error) if isinstance(error, ValueError) else 'private_result_io_failed'}
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
