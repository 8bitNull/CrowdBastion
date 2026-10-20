#!/usr/bin/env python3
"""Read bounded, fresh master error-log evidence of a completed HUP cycle."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from crowdsec_web import directives

MAX_LOG_BYTES = 1024 * 1024
RECORD = re.compile(r'^\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2} '
                    r'\[([a-z]+)\] (\d+)#\d+: (.*)\n$')


def namespace_pid(pid, proc=Path('/proc')):
    if not str(pid).isdecimal():
        raise ValueError('Invalid process identity')
    text = (proc/str(pid)/'status').read_text()
    match = re.search(r'^NSpid:\s*([\d\t ]+)$', text, re.M)
    if not match:
        raise ValueError('Process namespace identity unavailable')
    return match[1].split()[-1]


def unambiguous_master(master, metadata, proc):
    logged_pid = namespace_pid(master, proc)
    # Log records contain namespace PIDs, not host PIDs. Reject another
    # possible producer with the same logged PID and open inode, including
    # containers whose masters both appear as PID 1 in a shared log file.
    # Inspect all matching processes, without trusting their process titles.
    for process in proc.iterdir():
        if not process.name.isdecimal() or process.name == str(master):
            continue
        try:
            if namespace_pid(process.name, proc) != logged_pid:
                continue
            for fd in (process/'fd').iterdir():
                try:
                    opened = fd.stat()
                    if (opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino):
                        raise ValueError('Error log has ambiguous namespace producers')
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue  # Processes and file descriptors may disappear normally.
    return logged_pid


def locate(master, effective, proc=Path('/proc')):
    # -T concatenates files without preserving include scope. Only direct
    # main-file directives are unambiguous here; included error_log directives
    # must never be confused with the master's error_log.
    sections = re.split(r'(?m)^# configuration file [^\n]+:\n', effective)
    if len(sections) < 2:
        raise ValueError('Main configuration unavailable')
    root = proc/str(master)
    candidates = []
    for context, words, block in directives(sections[1]):
        if context or block or not words or words[0] != 'error_log':
            continue
        if len(words) != 3 or words[2] not in ('notice', 'info', 'debug'):
            continue
        if words[1] == 'stderr':
            candidates.append(root/'fd/2')
        elif words[1].startswith('/'):
            candidates.append(root/'root'/words[1].lstrip('/'))
    for candidate in candidates:
        try:
            target = candidate.stat()
            if not stat.S_ISREG(target.st_mode):
                continue
            for fd in sorted((root/'fd').iterdir()):
                try:
                    opened = fd.stat()
                    if (opened.st_dev, opened.st_ino) == (target.st_dev, target.st_ino):
                        unambiguous_master(master, opened, proc)
                        return fd
                except OSError:
                    continue
        except OSError:
            continue
    raise ValueError('A readable regular main error_log at notice level is required')


def capture(master, log, proc=Path('/proc')):
    with open(log, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError('Error log is not a regular file')
        offset = metadata.st_size
        anchor = os.pread(stream.fileno(), min(128, offset), max(0, offset-128))
    return {'master': unambiguous_master(master, metadata, proc), 'master_host': str(master), 'device': metadata.st_dev,
            'inode': metadata.st_ino, 'offset': offset,
            'anchor': hashlib.sha256(anchor).hexdigest(),
            'line_boundary': not anchor or anchor.endswith(b'\n')}


def accepted(cursor, log, workers, proc=Path('/proc')):
    with open(log, 'rb') as stream:
        metadata = os.fstat(stream.fileno())
        if unambiguous_master(cursor['master_host'], metadata, proc) != cursor['master']:
            raise ValueError('Master process namespace identity changed')
        offset = cursor['offset']
        if ((metadata.st_dev, metadata.st_ino) != (cursor['device'], cursor['inode']) or
                metadata.st_size < offset or metadata.st_size-offset > MAX_LOG_BYTES):
            raise ValueError('Error log identity, length or read budget changed')
        anchor = os.pread(stream.fileno(), min(128, offset), max(0, offset-128))
        if hashlib.sha256(anchor).hexdigest() != cursor['anchor']:
            raise ValueError('Error log was truncated or overwritten')
        data = os.pread(stream.fileno(), metadata.st_size-offset, offset)
    if not cursor['line_boundary']:
        data = data.partition(b'\n')[2]
    pending, cohort, spawned = False, False, set()
    for line in data.decode('utf-8', errors='replace').splitlines(keepends=True):
        match = RECORD.fullmatch(line)
        if not match or match[2] != cursor['master']:
            continue
        level, _, message = match.groups()
        if message == 'reconfiguring' and level == 'notice':
            pending, cohort, spawned = True, False, set()
        elif (level == 'emerg' or 'init_by_lua' in message and ' error' in message or
              re.search(r'\b(?:SIGUSR1|SIGUSR2|SIGWINCH|SIGQUIT|SIGTERM|SIGINT|SIGHUP)\b', message) or
              message.startswith(('changing binary', 'reopening logs', 'exiting', 'exit',
                                  'gracefully shutting down', 'noaccepting'))):
            pending, cohort, spawned = False, False, set()
        elif pending and level == 'notice':
            if message == 'start worker processes':
                cohort, spawned = True, set()
            elif cohort:
                worker = re.fullmatch(r'start worker process (\d+)', message)
                if worker:
                    spawned.add(worker[1])
    if not cohort or not spawned or not workers:
        return False
    return {namespace_pid(pid, proc) for pid in workers} <= spawned


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--proc-root', type=Path, default=Path('/proc'))
    parser.add_argument('action', choices=('locate', 'capture', 'check'))
    parser.add_argument('args', nargs='+')
    args = parser.parse_args()
    if args.action == 'locate':
        master, effective = args.args
        print(locate(master, Path(effective).read_text(), args.proc_root))
    elif args.action == 'capture':
        master, log = args.args
        print(json.dumps(capture(master, log, args.proc_root)))
    else:
        cursor, log, *workers = args.args
        return 0 if accepted(json.loads(Path(cursor).read_text()), log, workers, args.proc_root) else 2
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError):
        print('无法确认本次 Nginx master 重载记录；请核对主配置的可读普通 error_log 文件、notice 日志级别及进程权限。', file=sys.stderr)
        sys.exit(1)
