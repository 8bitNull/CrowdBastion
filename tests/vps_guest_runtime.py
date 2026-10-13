"""Bounded guest diagnostics; importing this module never changes services/firewalls."""
import os
import re
import signal
import subprocess
import tempfile
import time
from pathlib import Path


def _process_table():
    table={}
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():continue
        try:
            fields=(entry/'stat').read_text().rsplit(')',1)[1].split()
            table[int(entry.name)]=(int(fields[1]),fields[19])
        except (OSError,ValueError,IndexError):continue
    return table


def _descendants(root,known=None):
    table=_process_table();found=dict(known or {})
    roots={root}|{pid for pid,start in found.items() if pid in table and table[pid][1]==start}
    changed=True
    while changed:
        changed=False
        for pid,(parent,start) in table.items():
            if parent in roots and pid not in roots:
                roots.add(pid);found[pid]=start;changed=True
    return found


def _signal_owned(known,signum):
    table=_process_table()
    for pid,start in known.items():
        if pid not in table or table[pid][1]!=start:continue
        try:os.kill(pid,signum)
        except ProcessLookupError:pass


def run_bounded(argv, *, timeout=30, input_text=None, output_limit=65536):
    if timeout <= 0 or output_limit < 1:
        raise ValueError('positive timeout and output limit required')
    start = time.monotonic()
    with tempfile.TemporaryFile() as output:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                                   stdout=output, stderr=subprocess.STDOUT, text=True, start_new_session=True)
        expired = False
        try:
            process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            expired = True
            descendants=_descendants(process.pid)
            _signal_owned(descendants,signal.SIGTERM)
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=.2)
            except subprocess.TimeoutExpired:
                pass
            descendants=_descendants(process.pid,descendants)
            _signal_owned(descendants,signal.SIGKILL)
            # The group can outlive its leader; kill descendants even if leader exited.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        output.seek(0, os.SEEK_END)
        size = output.tell()
        output.seek(max(0, size-output_limit))
        data = output.read().decode(errors='replace')
    return 124 if expired else process.returncode, data, time.monotonic()-start


def service_healthy(properties):
    if not isinstance(properties, str):
        return False
    fields = {}
    for line in properties.splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        if key in fields:
            return False
        fields[key] = value
    return (fields.get('ActiveState') == 'active' and fields.get('SubState') == 'running'
            and fields.get('Result') == 'success')


def service_removed(active_rc, properties, enabled_rc, enabled_text):
    return (type(active_rc) is int and active_rc==0
            and properties.strip() in ('ActiveState=inactive','ActiveState=failed')
            and type(enabled_rc) is int and enabled_rc in (0,1)
            and enabled_text.strip()=='disabled')


def wait_ready(probe, *, timeout=120, interval=1, clock=time.monotonic, sleep=time.sleep):
    deadline = clock()+timeout
    while clock() < deadline:
        ready = probe()
        if ready and clock() <= deadline:
            return True
        remaining = deadline-clock()
        if remaining > 0:
            sleep(min(interval, remaining))
    return False


def nft_synced(returncode, output, address, present):
    return type(returncode) is int and returncode == 0 and (address in output) == present


class Scrubber:
    def __init__(self, secrets=()):
        self.secrets = sorted({str(s) for s in secrets if s}, key=len, reverse=True)

    @classmethod
    def from_configs(cls, paths):
        try:
            import yaml
        except ImportError:
            return cls()
        secrets=[]
        def visit(value):
            pending=[value];seen=set()
            while pending:
                node=pending.pop()
                if not isinstance(node,(dict,list)) or id(node) in seen:continue
                seen.add(id(node))
                if isinstance(node,dict):
                    for key,item in node.items():
                        if any(word in str(key).lower() for word in ('api_key','password','token','secret')) and isinstance(item,str) and item:
                            secrets.append(item)
                        pending.append(item)
                else:pending.extend(node)
        for path in paths:
            try:
                if path.is_file() and not path.is_symlink() and path.stat().st_size<=65536:
                    visit(yaml.safe_load(path.read_text()))
            except (OSError,UnicodeError,yaml.YAMLError,RecursionError):
                continue
        return cls(secrets)

    def summary(self, text, *, limit=4096):
        if limit < 1:
            raise ValueError('positive output limit required')
        text = str(text)
        for secret in self.secrets:
            text = text.replace(secret, '<redacted>')
        text = re.sub(r'(?i)((?:api[_ -]?key|password|token|secret)\s*[:=]\s*)\S+', r'\1<redacted>', text)
        text = re.sub(r'[A-Za-z0-9_+/=-]{32,}', '<opaque-redacted>', text)
        return text.encode()[-limit:].decode(errors='ignore')
