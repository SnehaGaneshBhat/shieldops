import os
import shutil
import subprocess
from dataclasses import dataclass

from backend import docker_runner
from .hashing import sha256_file


SKIP_DIRS = ('.git', '.buildguard', 'node_modules', '__pycache__', '.venv')


def _git(project, *args):
    return subprocess.run(
        ['git', '-C', project, *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False
    )


def snapshot_source(project_path: str, dest: str):
    """Copy the project into dest. Returns the git commit hash or None."""
    os.makedirs(dest, exist_ok=True)

    try:
        r = _git(
            project_path,
            'ls-files',
            '--cached',
            '--others',
            '--exclude-standard',
            '-z'
        )

        if r.returncode == 0 and r.stdout:
            for rel in filter(None, r.stdout.split('\0')):
                src = os.path.join(project_path, rel)

                if os.path.isfile(src):
                    dst = os.path.join(dest, rel)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)

            h = _git(project_path, 'rev-parse', 'HEAD')
            return h.stdout.strip() if h.returncode == 0 else None

    except (OSError, subprocess.SubprocessError):
        pass

    shutil.copytree(
        project_path,
        dest,
        dirs_exist_ok=True,
        ignore=shutil.ignore_patterns(*SKIP_DIRS)
    )

    return None


@dataclass
class BuildOutcome:
    ok: bool
    artifact_path: str | None = None
    sha256: str | None = None
    size: int | None = None
    returncode: int = 0
    stdout: str = ''
    stderr: str = ''
    error_code: str | None = None


def collect_tool_versions(recipe, scan_id: str, timeout: int) -> dict:
    out = {}

    for cmd in recipe.version_commands:
        r = docker_runner.run_container(
            recipe.image,
            ['sh', '-c', cmd],
            network_none=True,
            timeout=min(timeout, 60),
            scan_id=scan_id
        )

        text = (r.stdout or r.stderr).strip()
        out[cmd] = text.splitlines()[0] if text else 'unknown'

    return out


def build_once(
    src_dir: str,
    recipe,
    out_dir: str,
    *,
    scan_id: str = 'adhoc',
    timeout: int = 120
) -> BuildOutcome:
    os.makedirs(out_dir, exist_ok=True)

    script = 'set -e\n' + '\n'.join(recipe.commands)

    res = docker_runner.run_container(
        recipe.image,
        ['sh', '-c', script],
        mounts=[
            (src_dir, recipe.workdir, 'ro'),
            (out_dir, '/out', 'rw')
        ],
        env=recipe.env,
        network_none=True,
        timeout=timeout,
        workdir=recipe.workdir,
        scan_id=scan_id
    )

    if res.error:
        return BuildOutcome(
            False,
            returncode=res.returncode,
            stdout=res.stdout,
            stderr=res.stderr,
            error_code=res.error
        )

    if res.returncode != 0:
        return BuildOutcome(
            False,
            returncode=res.returncode,
            stdout=res.stdout,
            stderr=res.stderr,
            error_code='BUILD_FAILED'
        )

    path = os.path.join(
        out_dir,
        os.path.relpath(recipe.artifact, '/out')
    )

    if not os.path.isfile(path):
        return BuildOutcome(
            False,
            returncode=0,
            stdout=res.stdout,
            stderr=res.stderr + f' artifact not found: {recipe.artifact}',
            error_code='BUILD_FAILED'
        )

    return BuildOutcome(
        True,
        path,
        sha256_file(path),
        os.path.getsize(path),
        0,
        res.stdout,
        res.stderr
    )
