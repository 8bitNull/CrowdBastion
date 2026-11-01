"""Shared maintenance exclusion and local bot deployment checks; no Telegram I/O."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import hashlib
import sys
import stat
import json
import math
import signal
import subprocess
import tempfile

from crowdbastion_ux import code_fingerprint, read_regular, validate_private_destination


def validate_runtime_pointer(runtime):
    runtime = Path(runtime)
    validate_private_destination(runtime / '.guard', missing_parents=True)
    if runtime.exists():
        marker = runtime / '.crowdsec-1key-managed'
        validate_private_destination(marker)
        try:
            read_regular(marker, 4096)
        except FileNotFoundError:
            raise ValueError('unknown runtime directory') from None
    current = runtime / 'current'
    if current.exists() or current.is_symlink():
        if not current.is_symlink():
            raise ValueError('unknown runtime pointer')
        target = Path(os.readlink(current))
        if target.parent != runtime or not target.name.startswith('release-'):
            raise ValueError('foreign runtime pointer')
        validate_private_destination(target / 'manager.sh', missing_parents=True)


def deployment_preflight(config, script, unit, state, runtime, *helpers):
    for filename in (config, script, unit, *helpers):
        validate_private_destination(Path(filename), missing_parents=True)
    validate_private_destination(Path(state) / '.guard', missing_parents=True)
    validate_runtime_pointer(runtime)


def deployment_status(manager, installed, runtime, *helpers):
    def program(root):
        digest = hashlib.sha256()
        for name in ('crowdsec_bot.py', *helpers):
            if Path(name).name != name or not name.endswith('.py'):
                raise ValueError('invalid helper')
            path = Path(root) / name
            validate_private_destination(path)
            digest.update(name.encode() + b'\0' + read_regular(path) + b'\0')
        return digest.hexdigest()

    manager = Path(manager).resolve(strict=True)
    source_program = program(manager.parent / 'lib')
    source_runtime = code_fingerprint(manager)
    validate_runtime_pointer(runtime)
    try:
        installed_program = program(Path(installed).parent)
    except FileNotFoundError:
        installed_program = None
    try:
        installed_runtime = code_fingerprint(Path(runtime) / 'current/manager.sh')
    except FileNotFoundError:
        installed_runtime = None
    except ValueError as error:
        if str(error) != 'missing helpers':
            raise
        installed_runtime = None
    matches = source_program == installed_program and source_runtime == installed_runtime
    print('源码程序指纹：'+source_program[:16])
    print('已安装机器人：'+(installed_program[:16] if installed_program else '缺失或不完整')+
          ('（一致）' if source_program == installed_program else '（不同）'))
    print('源码主脚本指纹：'+source_runtime[:16])
    print('机器人随附主脚本：'+(installed_runtime[:16] if installed_runtime else '缺失或不完整')+
          ('（一致）' if source_runtime == installed_runtime else '（不同）'))
    print('此结果只比较代码；源码、定时任务副本、机器人副本分别更新，不证明服务或 TG 轮询正常。')
    return 0 if matches else 2


def read_manager_report(manager_path, config_path, timeout=20):
    """Run only the fixed read-only interface; kill its entire process group on timeout."""
    from crowdbastion_health import CATALOG, STATES, summarize

    manager = Path(manager_path).resolve(strict=True)
    validate_private_destination(manager)
    # A file keeps diagnostic volume out of memory; only bounded JSON is read back.
    with tempfile.TemporaryFile() as output:
        with subprocess.Popen(['/bin/bash', str(manager), '--status-json'],
                              stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.DEVNULL,
                              start_new_session=True) as process:
            try:
                process.wait(timeout=timeout)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                raise
            if process.returncode not in (0, 1, 2):
                raise ValueError('incomplete check')
            output.seek(0)
            data = output.read(65537)
    if len(data) > 65536:
        raise ValueError('oversized check')
    report = json.loads(data)
    if (not isinstance(report, dict) or type(report.get('version')) is not int or report['version'] != 1
            or report.get('config_path') != config_path
            or type(report.get('checked_at')) not in (int, float)
            or not math.isfinite(report['checked_at']) or report['checked_at'] <= 0
            or not isinstance(report.get('scope'), str) or not 1 <= len(report['scope']) <= 160):
        raise ValueError('invalid check report')
    checks = report.get('checks')
    if (not isinstance(checks, dict) or not checks or checks.get('traffic') != 'pending'
            or any(key not in CATALOG or not isinstance(value, str)
                   or value not in STATES - {'required', 'verified'} for key, value in checks.items())):
        raise ValueError('invalid observations')
    required = report.get('required')
    if (not isinstance(required, list) or any(not isinstance(key, str) or key not in checks for key in required)
            or len(set(required)) != len(required)):
        raise ValueError('invalid required observations')
    roles = report.get('roles', [])
    if (not isinstance(roles, list) or any(not isinstance(role, str) or role not in ('web', 'relay', 'remote', 'node') for role in roles)):
        raise ValueError('invalid roles')
    records = [(key, 'required') for key in required] + list(checks.items())
    summary = summarize(records, process.returncode, 'overall', ' '.join(roles))
    if report.get('summary') != summary or summary['status'] != process.returncode:
        raise ValueError('inconsistent check conclusion')
    return {key: report[key] for key in ('checked_at', 'checks', 'summary', 'scope')}


class MaintenanceRefused(RuntimeError):
    """A known precondition prevented a mutation; nothing was executed."""


@contextmanager
def maintenance_guard(lock_path, migration_path):
    descriptor = None
    try:
        lock = Path(lock_path)
        if not lock.is_absolute() or not Path(migration_path).is_absolute():
            raise ValueError('absolute paths required')
        # A root-owned sticky /run/lock protects this owned regular lock file.
        # Private report/config destinations retain the stricter default policy.
        validate_private_destination(lock, missing_parents=True, allow_sticky_parent=True)
        lock.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        validate_private_destination(lock, allow_sticky_parent=True)
        descriptor = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise ValueError('unsafe lock')
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise MaintenanceRefused('另一个管理操作正在执行，本次未执行；请稍后重新发起。') from None
        migration = Path(migration_path)
        if migration.is_symlink():
            raise ValueError('unsafe migration')
        if migration.exists():
            if not migration.is_dir():
                raise ValueError('unsafe migration')
            validate_private_destination(migration / '.guard')
            complete = False
            for name in ('committed', 'rolled-back'):
                marker = migration / name
                if marker.is_symlink():
                    raise ValueError('unsafe migration marker')
                if marker.exists():
                    validate_private_destination(marker)
                    complete = True
            if not complete:
                raise MaintenanceRefused('防火墙迁移尚未结束，本次未执行；请先在终端完成或回退迁移。')
        else:
            validate_private_destination(migration, missing_parents=True)
    except (OSError, ValueError):
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise MaintenanceRefused('维护锁或迁移状态无法安全确认，本次未执行；请在终端核对。') from None
    except MaintenanceRefused:
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
        raise
    try:
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)


if __name__ == '__main__':
    try:
        action, *arguments = sys.argv[1:]
        if action == 'status':
            sys.exit(deployment_status(*arguments))
        if action != 'preflight':
            raise ValueError('unknown action')
        deployment_preflight(*arguments)
    except (OSError, ValueError, TypeError):
        print('机器人路径、归属或代码检查失败；未输出配置与凭据。', file=sys.stderr)
        sys.exit(1)
