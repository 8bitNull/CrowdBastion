#!/usr/bin/env python3
"""Restore only VPS144's reviewed static rules, never a dynamic snapshot.

The nine-rule manifest is deliberately pinned. Future policy changes require
an explicit review and helper update; unexpected JSON is rejected untouched.
"""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys

POLICY = Path('/usr/local/lib/crowdbastion-static-policy')
LOCK = Path('/run/lock/crowdsec-1key.lock')
SIGNALS = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
REVIEWED = [
    {'binary': 'iptables', 'table': table, 'rule': rule.split()}
    for table, rule in [
        ('mangle', '-A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'),
        ('mangle', '-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448'),
        ('mangle', '-A OUTPUT -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu'),
        ('mangle', '-A POSTROUTING -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1448'),
        ('filter', '-A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT'),
        ('filter', '-A INPUT -i lo -j ACCEPT'),
        ('filter', '-A INPUT -p tcp -m tcp --dport 53322 -j ACCEPT'),
        ('filter', '-A FORWARD -i lo -j ACCEPT'),
        ('filter', '-A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT'),
    ]
]


def command(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=10)


def checked(result, argv, allowed=(0,)):
    if result.returncode not in allowed:
        raise RuntimeError('command failed: ' + repr(argv) + ': ' + str(result.stderr)[-1000:])
    return result.returncode


def apply(rules, runner=command):
    """Apply an already loaded manifest; caller holds the maintenance lock."""
    if rules != REVIEWED:
        raise ValueError('static manifest differs from the reviewed nine-rule policy')
    # Copy the validated values before calling any external runner.
    commands = [(['/usr/sbin/iptables', '-w', '5', '-t', item['table']], item['rule'][1:])
                for item in rules]
    intended = []
    previous = {number: signal.getsignal(number) for number in SIGNALS}
    cancelled = False
    recovering = False

    def interrupted(number, frame):
        nonlocal cancelled
        if cancelled or recovering:
            return
        cancelled = True
        raise InterruptedError('static policy cancelled by signal ' + str(number))

    try:
        for number in SIGNALS:
            signal.signal(number, interrupted)
        missing = []
        # A late inspection failure must not leave earlier rules appended.
        for prefix, rule in commands:
            argv = prefix + ['-C'] + rule
            if checked(runner(argv), argv, (0, 1)) == 1:
                missing.append((prefix, rule))
        for prefix, rule in missing:
            # Record ownership intent first: even a timeout/cancellation can
            # arrive after the kernel accepted the append.
            intended.append((prefix, rule))
            argv = prefix + ['-A'] + rule
            checked(runner(argv), argv)
        for prefix, rule in commands:
            argv = prefix + ['-C'] + rule
            checked(runner(argv), argv)
    except BaseException as error:
        recovering = True
        # Further TERM/HUP/INT must not interrupt the cleanup of this attempt.
        for number in SIGNALS:
            signal.signal(number, signal.SIG_IGN)
        failures = []
        for prefix, rule in reversed(intended):
            try:
                argv = prefix + ['-C'] + rule
                if checked(runner(argv), argv, (0, 1)) == 0:
                    argv = prefix + ['-D'] + rule
                    checked(runner(argv), argv)
            except BaseException as cleanup_error:
                failures.append(str(cleanup_error))
        if failures:
            raise RuntimeError(str(error) + '; rollback incomplete: ' + '; '.join(failures)) from error
        raise
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def safe_info(info, directory=False, private=False):
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    forbidden = 0o077 if private else 0o022
    if (not kind(info.st_mode) or info.st_uid != 0 or info.st_mode & forbidden
            or (not directory and info.st_nlink != 1)):
        raise RuntimeError('unsafe root-owned static policy file or lock')


def load_rules():
    # Reject replaced/link-based policy paths before reading privileged input.
    for parent in reversed((POLICY, *POLICY.parents)):
        safe_info(parent.lstat(), directory=True)
    directory = os.open(POLICY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        safe_info(os.fstat(directory), directory=True, private=True)
        fd = os.open('rules.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        try:
            safe_info(os.fstat(fd), private=True)
            with os.fdopen(fd, 'r') as stream:
                fd = None
                return json.load(stream)
        finally:
            if fd is not None:
                os.close(fd)
    finally:
        os.close(directory)


@contextmanager
def maintenance_lock():
    # /run/lock is root-owned sticky 1777 on this host. Root-owned entries
    # cannot be replaced by other users there; reject unsafe files and links.
    parent = LOCK.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or (parent.st_mode & 0o022 and not parent.st_mode & stat.S_ISVTX)):
        raise RuntimeError('unsafe maintenance lock directory')
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    try:
        safe_info(os.fstat(fd))
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = LOCK.lstat()
        safe_info(current)
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise RuntimeError('maintenance lock replaced')
        yield
    finally:
        os.close(fd)


def main():
    if len(sys.argv) != 1 or os.geteuid() != 0:
        raise RuntimeError('root required; this helper accepts no arguments')
    os.umask(0o077)
    with maintenance_lock():
        apply(load_rules())


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Static policy failed: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
