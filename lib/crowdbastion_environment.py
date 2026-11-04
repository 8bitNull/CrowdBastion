#!/usr/bin/env python3
"""Read-only, bounded host pressure sampling shared by change preflights.

Only fixed proc counters are read. This is a short observation, not a benchmark
or a guarantee that a later command (including a task in D state) can terminate.
"""
import argparse
import json
from pathlib import Path
import time


class EnvironmentNotReady(ValueError):
    def __init__(self, report):
        super().__init__('环境未确认稳定，未执行修改；请检查宿主机存储、内存及负载后重试。')
        self.report = report


def _read(path):
    with path.open(encoding='ascii') as stream:
        text = stream.read(262145)
    if len(text) > 262144:
        raise ValueError('proc counter capacity exceeded')
    return text


def _snapshot(root, clock):
    rows = dict((parts[0].rstrip(':'), parts[1:]) for line in _read(root/'stat').splitlines() if (parts := line.split()))
    cpu = [int(value) for value in rows['cpu'][:8]]
    if len(cpu) != 8 or any(value < 0 for value in cpu):
        raise ValueError('invalid cpu counters')
    memory = dict((parts[0].rstrip(':'), parts[1:]) for line in _read(root/'meminfo').splitlines() if (parts := line.split()))
    total, available = int(memory['MemTotal'][0]), int(memory['MemAvailable'][0])
    if not 0 <= available <= total or total <= 0:
        raise ValueError('invalid memory counters')
    sample = {'at': clock(), 'cpu': cpu, 'memory_available_percent': 100*available/total,
              'blocked_tasks': int(rows['procs_blocked'][0])}
    for kind in ('io', 'memory'):
        value = None
        try:
            # avg10/60/300 describe earlier history. Use full stall totals only.
            for line in _read(root/'pressure'/kind).splitlines():
                parts = line.split()
                if parts and parts[0] == 'full':
                    value = int(dict(part.split('=', 1) for part in parts[1:])['total'])
                    if value < 0:
                        value = None
        except (OSError, ValueError, KeyError, UnicodeError):
            pass
        sample[kind+'_pressure'] = value
    return sample


def check_environment(proc_root=Path('/proc'), interval=0.25, samples=3, *, sleep=time.sleep, clock=time.monotonic):
    """Return version 1 report; 3–5 snapshots, 0.05–1s intervals, no writes.

    Stable requires valid /proc/stat and MemAvailable counters. PSI is optional.
    Persistent means a threshold is exceeded in at least two adjacent windows.
    sleep/clock are injectable for replaying proc snapshots without real waits.
    """
    if type(samples) is not int or not 3 <= samples <= 5 or not 0.05 <= interval <= 1:
        raise ValueError('采样范围无效。')
    started = clock()
    report = {'version': 1, 'state': 'unknown', 'phase': 'environment_sample',
              'error_code': 'counters_unavailable', 'retryable': True,
              'duration_seconds': 0, 'windows': [], 'unavailable': [],
              'transient_pressure': False,
              'reason': '计数器不可用或发生重置；检查 /proc 挂载与权限后重新采样，暂缓修改。'}
    try:
        before = _snapshot(Path(proc_root), clock)
        for _ in range(samples-1):
            sleep(interval)
            after = _snapshot(Path(proc_root), clock)
            elapsed = after['at']-before['at']
            delta = [new-old for old, new in zip(before['cpu'], after['cpu'])]
            if elapsed <= 0 or any(value < 0 for value in delta) or sum(delta) <= 0:
                raise ValueError('counter reset or insufficient interval')
            window = {'seconds': round(elapsed, 6), 'iowait_percent': round(100*delta[4]/sum(delta), 3),
                      'blocked_tasks': after['blocked_tasks'],
                      'memory_available_percent': round(after['memory_available_percent'], 3)}
            for kind in ('io', 'memory'):
                key = kind+'_pressure'
                old, new = before[key], after[key]
                if old is None or new is None or new < old:
                    window[key+'_percent'] = None
                    report['unavailable'].append(key)
                else:
                    window[key+'_percent'] = round(min(100, 100*(new-old)/(elapsed*1000000)), 3)
            report['windows'].append(window)
            before = after
    except (OSError, ValueError, KeyError, IndexError, UnicodeError):
        report['duration_seconds'] = round(max(0, clock()-started), 6)
        report['unavailable'] = sorted(set(report['unavailable']+['stat_or_meminfo']))
        return report
    conditions = [
        ('persistent_io_wait', [w['iowait_percent'] >= 25 for w in report['windows']]),
        ('persistent_io_pressure', [(w['io_pressure_percent'] or 0) >= 20 for w in report['windows']]),
        ('persistent_memory_pressure', [w['memory_available_percent'] < 1 or (w['memory_pressure_percent'] or 0) >= 10 for w in report['windows']]),
    ]
    report.update(state='stable', error_code='none', retryable=False,
                  reason='短时采样未发现持续压力；此结论不代表吞吐或后续执行耗时保证。')
    for code, flags in conditions:
        if any(a and b for a, b in zip(flags, flags[1:])):
            report.update(state='unstable', error_code=code, retryable=True,
                          reason='连续采样发现持续 I/O 或内存压力；先检查宿主机存储与内存，压力解除后重试，暂缓修改。')
            break
    report['transient_pressure'] = report['state'] == 'stable' and any(any(flags) for _, flags in conditions)
    report['unavailable'] = sorted(set(report['unavailable']))
    report['duration_seconds'] = round(max(0, clock()-started), 6)
    return report


def require_stable(report=None):
    """Call while holding the maintenance lock, immediately before writes.

    This does not acquire a lock. New transactions must use the same maintenance
    lock as the shell manager; unknown and unstable both fail closed.
    """
    report = check_environment() if report is None else report
    if report.get('state') != 'stable':
        raise EnvironmentNotReady(report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--guard', action='store_true')
    parser.add_argument('--human', action='store_true', help='show the same sampled report’s short reason')
    parser.add_argument('--proc-root', type=Path, default=Path('/proc'))
    args = parser.parse_args(argv)
    report = check_environment(args.proc_root)
    print(report['reason'] if args.human else json.dumps(report, ensure_ascii=False, sort_keys=True))
    if args.guard:
        return 0 if report['state'] == 'stable' else 75
    return {'stable': 0, 'unstable': 1, 'unknown': 2}[report['state']]


if __name__ == '__main__':
    raise SystemExit(main())
