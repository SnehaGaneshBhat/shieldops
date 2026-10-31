import os
import secrets
import shutil
import subprocess
from dataclasses import dataclass


DOCKER_BIN = os.environ.get('BUILDGUARD_DOCKER_BIN', 'docker')


@dataclass
class DockerResult:
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    container: str = ''
    error: str | None = None  # None | 'TIMEOUT' | 'DOCKER_UNAVAILABLE'


def _s(x) -> str:
    if x is None:
        return ''
    return x.decode('utf-8', 'replace') if isinstance(x, bytes) else str(x)


def docker_available(timeout: int = 10) -> bool:
    if not shutil.which(DOCKER_BIN):
        return False

    try:
        r = subprocess.run(
            [DOCKER_BIN, 'info', '--format', '{{.ServerVersion}}'],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return r.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def image_present(image: str, timeout: int = 10) -> bool:
    """Return whether a local Docker image is available for an offline run."""
    if not shutil.which(DOCKER_BIN):
        return False

    try:
        result = subprocess.run(
            [DOCKER_BIN, 'image', 'inspect', image],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def kill_scan_containers(scan_id: str) -> None:
    """Force-remove every container this scan started (names start with bg-<scan_id>)."""
    if not shutil.which(DOCKER_BIN):
        return

    try:
        r = subprocess.run(
            [DOCKER_BIN, 'ps', '-aq', '--filter', f'name=bg-{scan_id}'],
            capture_output=True,
            text=True,
            timeout=15,
            check=False
        )

        ids = r.stdout.split()

        if ids:
            subprocess.run(
                [DOCKER_BIN, 'rm', '-f', *ids],
                capture_output=True,
                timeout=30,
                check=False
            )

    except (subprocess.TimeoutExpired, OSError):
        pass


def run_container(
    image,
    command,
    *,
    mounts=(),
    env=None,
    network_none=True,
    timeout=120,
    workdir=None,
    scan_id='adhoc',
    user=None,
    memory='1g',
    cpus='1.0',
    pids=256,
    extra_args=()
) -> DockerResult:
    """mounts: iterable of (host_path, container_path, 'ro'|'rw').
    command: list of str."""

    name = f'bg-{scan_id}-{secrets.token_hex(3)}'

    args = [DOCKER_BIN, 'run', '--rm', '--name', name]

    if network_none:
        args += ['--network', 'none']

    args += [
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges',
        '--tmpfs', '/tmp:rw,nosuid,size=64m',
        '--memory', memory,
        '--cpus', cpus,
        '--pids-limit', str(pids)
    ]

    if user is None and hasattr(os, 'getuid'):
        user = f'{os.getuid()}:{os.getgid()}'  # outputs stay owned by you, not root

    if user:
        args += ['--user', user]

    for host, cont, mode in mounts:
        args += ['-v', f'{os.path.abspath(host)}:{cont}:{mode}']

    for k, v in (env or {}).items():
        args += ['-e', f'{k}={v}']

    if workdir:
        args += ['-w', workdir]

    args += list(extra_args)
    args.append(image)
    args += list(command)

    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False
        )

        return DockerResult(
            r.returncode,
            r.stdout,
            r.stderr,
            container=name
        )

    except subprocess.TimeoutExpired as e:
        subprocess.run(
            [DOCKER_BIN, 'rm', '-f', name],
            capture_output=True,
            timeout=30,
            check=False
        )

        return DockerResult(
            -1,
            _s(e.stdout),
            _s(e.stderr),
            True,
            name,
            'TIMEOUT'
        )

    except FileNotFoundError:
        return DockerResult(
            -1,
            '',
            'docker binary not found',
            False,
            name,
            'DOCKER_UNAVAILABLE'
        )
