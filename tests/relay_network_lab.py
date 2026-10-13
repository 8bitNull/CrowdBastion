"""Isolated real packet acceptance helpers. Never invoke setup in host netns."""
import contextlib
import http.server
import json
import os
import secrets
import signal
import socket
import subprocess
import threading
import time


def guard(original_inode, original_mount_inode=None):
    if os.stat('/proc/self/ns/net').st_ino == int(original_inode):
        raise RuntimeError('refusing mutation in original network namespace')
    if original_mount_inode is None or os.stat('/proc/self/ns/mnt').st_ino == int(original_mount_inode):
        raise RuntimeError('refusing mutation without private mount namespace')


def accepted(e):
    return all(e.get(k) is True for k in ('normal_bad', 'normal_good', 'healthy_good',
        'counter_increased', 'recovered_bad', 'recovered_good')) and e.get('blocked_bad') is False


class Processes:
    def __init__(self, grace=8):
        self.grace = grace
        self.children = []
    def __enter__(self):
        self.old_sigterm = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self.terminate)
        return self
    @staticmethod
    def terminate(signum, frame):
        raise KeyboardInterrupt('acceptance interrupted')
    def start(self, args, **kwargs):
        child = subprocess.Popen(args, start_new_session=True, **kwargs)
        self.children.append(child)
        return child
    def __exit__(self, *args):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        for child in reversed(self.children):
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGTERM)
        deadline = time.monotonic() + self.grace
        for child in reversed(self.children):
            try:
                child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        for child in reversed(self.children):
            if child.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(child.pid, signal.SIGKILL)
            child.wait()
        signal.signal(signal.SIGTERM, self.old_sigterm)


class DecisionAPI:
    def __init__(self):
        self.key = secrets.token_hex(24)
        self.active = {}
        self.pending = {'new': [], 'deleted': []}
        self.lock = threading.Lock()
        api = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_GET(self):
                if self.headers.get('X-Api-Key') != api.key:
                    self.send_error(403)
                    return
                if not self.path.startswith('/v1/decisions/stream'):
                    self.send_error(404)
                    return
                with api.lock:
                    data = dict(new=list(api.active.values()), deleted=[]) if 'startup=true' in self.path else api.pending
                    api.pending = {'new': [], 'deleted': []}
                body = json.dumps(data).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            def do_POST(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(204 if self.headers.get('X-Api-Key') == api.key else 403)
                self.end_headers()
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = 'http://127.0.0.1:%s/' % self.server.server_port
    def __enter__(self):
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self
    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
    def set_ban(self, address, enabled):
        with self.lock:
            if enabled:
                decision = dict(id=1, duration='1h', origin='cscli', scenario='relay-acceptance', scope='Ip', type='ban', value=address)
                self.active[address] = decision
                self.pending['new'].append(decision)
            else:
                self.pending['deleted'].append(self.active.pop(address))


def command(args, **kwargs):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, **kwargs)


def echo_server(host, port, protocol):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
    sock.bind((host, port))
    if protocol == 'tcp':
        sock.listen()
    while True:
        if protocol == 'udp':
            data, peer = sock.recvfrom(4096)
            sock.sendto(json.dumps(dict(token=data.decode(), peer=peer[0])).encode(), peer)
        else:
            conn, peer = sock.accept()
            with conn:
                data = conn.recv(4096)
                conn.sendall(json.dumps(dict(token=data.decode(), peer=peer[0])).encode())


def probe(host, port, protocol):
    token = secrets.token_hex(16)
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
        sock.settimeout(1.5)
        sock.connect((host, port))
        sock.send(token.encode())
        response = json.loads(sock.recv(4096))
        if response.get('token') != token:
            raise RuntimeError('echo token mismatch')
        return response


def drop_packets(data):
    total = 0
    references = set()
    for item in data['nftables']:
        rule = item.get('rule', {})
        if rule.get('table') not in ('crowdsec', 'crowdsec6'):
            continue
        expressions = rule.get('expr', [])
        if not any('drop' in expr or 'reject' in expr for expr in expressions):
            continue
        for expr in expressions:
            value = expr.get('counter')
            if isinstance(value, str):
                references.add((rule['table'], value))
            elif isinstance(value, dict):
                total += value.get('packets', 0)
    for item in data['nftables']:
        value = item.get('counter', {})
        if (value.get('table'), value.get('name')) in references:
            total += value.get('packets', 0)
    return total


def counter():
    return drop_packets(json.loads(command(['nft', '-j', 'list', 'ruleset'])))


def wait_set(address, enabled):
    import ipaddress
    needle = str(ipaddress.ip_address(address))
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        data = command(['nft', '-j', 'list', 'ruleset'])
        if (needle in data) == enabled:
            return
        time.sleep(.2)
    raise RuntimeError('bouncer set synchronization timeout: ' + address)


def free_port(host, protocol):
    family = socket.AF_INET6 if ':' in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]
