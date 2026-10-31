import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from backend import docker_runner
from backend.schemas import Evidence, Finding, ModuleResult

from . import diagnose, manifest
from .rebuild import build_once, collect_tool_versions, snapshot_source
from .recipe import RecipeError, RecipeMissing, load_recipe


TIMESTAMP_RE = re.compile(r'__(DATE|TIME|TIMESTAMP)__')
SRC_SUFFIXES = ('.c', '.h', '.cc', '.cpp', '.hpp')


class ReleaseError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _err(code, message, detail=''):
    return {
        'code': code,
        'message': message,
        'detail': detail
    }


def _uses_timestamp_macros(src_dir):
    for p in Path(src_dir).rglob('*'):
        if p.is_file() and p.suffix in SRC_SUFFIXES:
            try:
                if TIMESTAMP_RE.search(p.read_text(errors='ignore')):
                    return True
            except OSError:
                pass

    return False


def _resolve(project_path, p):
    q = Path(p)
    return str(q if q.is_absolute() else Path(project_path) / q)


def _unresolved(title, data):
    return Finding(
        id='B-TMP',
        module='build',
        category='UNRESOLVED',
        severity='INFO',
        confidence='HIGH',
        subject={'check': 'rebuild_comparison'},
        title=title,
        file_hint='buildguard.yml',
        evidence=[
            Evidence(
                type='tool_output',
                rule_id='NOT_COMPARABLE',
                data=data
            )
        ]
    )


def run(project_path, options=None):
    options = options or {}
    started = time.time()

    findings, errors, checks, tools = [], [], [], {}
    tmp = None

    def result(status):
        for i, f in enumerate(findings, 1):
            f.id = f'B-{i:03d}'

        return ModuleResult(
            module='build',
            status=status,
            findings=findings,
            errors=errors,
            tool_versions=tools,
            duration_ms=int((time.time() - started) * 1000),
            checks_performed=checks
        )

    def cancelled():
        cb = options.get('cancel_check')
        return bool(cb and cb())

    try:
        try:
            recipe = load_recipe(
                project_path,
                options.get('recipe_path') or 'buildguard.yml'
            )

        except RecipeMissing as e:
            findings.append(
                _unresolved(
                    'No build recipe found, so the build was not compared (NOT_COMPARABLE)',
                    {'reason': str(e)}
                )
            )
            return result('skipped')

        except RecipeError as e:
            errors.append(_err('RECIPE_INVALID', str(e)))
            return result('error')

        if not recipe.pinned and not options.get('allow_unpinned'):
            findings.append(
                _unresolved(
                    'Build image is not pinned by digest (NOT_COMPARABLE)',
                    {
                        'image': recipe.image,
                        'fix': 'use image@sha256:<digest>'
                    }
                )
            )
            return result('skipped')

        if not docker_runner.docker_available():
            errors.append(
                _err(
                    'DOCKER_UNAVAILABLE',
                    'Docker daemon is not reachable'
                )
            )
            return result('error')

        scan_id = options.get('scan_id', 'adhoc')
        timeout = int(options.get('docker_timeout', 120))

        tmp = tempfile.mkdtemp(prefix='bg-build-')

        src_a = os.path.join(tmp, 'src_a')
        src_b = os.path.join(tmp, 'src_b')

        commit = snapshot_source(project_path, src_a)
        snapshot_source(project_path, src_b)

        tools = collect_tool_versions(recipe, scan_id, timeout)
        tools['image'] = recipe.image

        outcomes = []

        for label, src, out in (
            ('original', src_a, 'out_a'),
            ('rebuild', src_b, 'out_b')
        ):
            if cancelled():
                errors.append(_err('CANCELLED', 'scan cancelled'))
                return result('error')

            o = build_once(
                src,
                recipe,
                os.path.join(tmp, out),
                scan_id=scan_id,
                timeout=timeout
            )

            outcomes.append(o)

            if not o.ok:
                errors.append(
                    _err(
                        o.error_code or 'BUILD_FAILED',
                        f'{label} build failed',
                        (o.stderr or '')[-1500:]
                    )
                )
                return result('error')

        a, b = outcomes

        checks.append(
            'Built the artifact twice from separate source snapshots in a pinned '
            'container with networking disabled'
        )

        checks.append('Compared SHA-256 of both artifacts')

        keep = options.get('scan_dir')

        if keep:
            dest = Path(keep) / 'build'
            dest.mkdir(parents=True, exist_ok=True)

            shutil.copy2(a.artifact_path, dest / 'artifact_original')
            shutil.copy2(b.artifact_path, dest / 'artifact_rebuild')

        subject = {
            'artifact': recipe.artifact,
            'image': recipe.image
        }

        pair = {
            'original_sha256': a.sha256,
            'rebuild_sha256': b.sha256,
            'original_size': a.size,
            'rebuild_size': b.size,
            'git_commit': commit,
            'image_pinned': recipe.pinned
        }

        if a.sha256 == b.sha256:
            findings.append(
                Finding(
                    id='B-TMP',
                    module='build',
                    category='NO_KNOWN_ISSUES',
                    severity='INFO',
                    confidence='HIGH',
                    subject=subject,
                    file_hint='buildguard.yml',
                    title='Independent rebuild produced identical bytes (MATCH)',
                    evidence=[
                        Evidence(
                            type='hash_pair',
                            rule_id='REBUILD_MATCH',
                            data=pair
                        )
                    ]
                )
            )

        else:
            diag = diagnose.diagnose(
                a.artifact_path,
                b.artifact_path,
                recipe.env
            )

            diag['timestamp_macros_in_source'] = _uses_timestamp_macros(src_a)

            benign = (
                diag['benign']
                or (
                    diag['timestamp_macros_in_source']
                    and 'SOURCE_DATE_EPOCH' not in recipe.env
                )
            )

            findings.append(
                Finding(
                    id='B-TMP',
                    module='build',
                    category='BUILD_MISMATCH',
                    severity='MEDIUM' if benign else 'HIGH',
                    confidence='LOW' if benign else 'MEDIUM',
                    subject=subject,
                    file_hint='buildguard.yml',
                    title='The original build and the independent rebuild differ '
                          '(cause not determined)',
                    evidence=[
                        Evidence(
                            type='hash_pair',
                            rule_id='REBUILD_MISMATCH',
                            data={**pair, 'diagnostic': diag}
                        )
                    ]
                )
            )

        if options.get('manifest_path') and options.get('distributed_artifact'):
            v = manifest.verify_artifact(
                _resolve(project_path, options['manifest_path']),
                _resolve(project_path, options['distributed_artifact'])
            )

            findings.append(manifest.finding_from_verify(v))

            checks.append(
                'Compared the distributed file with the trusted release manifest'
            )

        return result('ok')

    except Exception as e:  # a module never raises to the orchestrator
        errors.append(
            _err('INTERNAL_ERROR', f'{type(e).__name__}: {e}')
        )
        return result('error')

    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


def create_release(project_path, options=None):
    options = options or {}

    try:
        recipe = load_recipe(
            project_path,
            options.get('recipe_path') or 'buildguard.yml'
        )

    except RecipeError as e:
        raise ReleaseError('RECIPE_INVALID', str(e))

    if not recipe.pinned and not options.get('allow_unpinned'):
        raise ReleaseError(
            'RECIPE_INVALID',
            'build.image must be pinned by digest (image@sha256:...)'
        )

    if not docker_runner.docker_available():
        raise ReleaseError(
            'DOCKER_UNAVAILABLE',
            'Docker daemon is not reachable'
        )

    tmp = tempfile.mkdtemp(prefix='bg-release-')

    try:
        src = os.path.join(tmp, 'src')
        commit = snapshot_source(project_path, src)

        o = build_once(
            src,
            recipe,
            os.path.join(tmp, 'out'),
            scan_id='release',
            timeout=int(options.get('docker_timeout', 120))
        )

        if not o.ok:
            raise ReleaseError(
                o.error_code or 'BUILD_FAILED',
                (o.stderr or '')[-1500:]
            )

        dist = Path(project_path) / 'dist'
        dist.mkdir(exist_ok=True)

        name = os.path.basename(recipe.artifact)
        shutil.copy2(o.artifact_path, dist / name)

        mpath = manifest.write_manifest(
            project_path,
            recipe,
            o,
            commit
        )

        return {
            'manifest_path': mpath,
            'artifact': str(dist / name),
            'sha256': o.sha256,
            'size': o.size
        }

    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verify(manifest_path, distributed_artifact):
    v = manifest.verify_artifact(
        manifest_path,
        distributed_artifact
    )

    v['finding'] = manifest.finding_from_verify(v).model_dump()

    return v
