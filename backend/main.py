import os
import secrets
import shutil
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse

from backend import docker_runner, orchestrator, store
from backend.schemas import ManifestRequest, ScanRequest, VerifyRequest
from modules.build_integrity import ReleaseError, create_release, verify


VERSION = '0.1.0'

TOKEN = os.environ.get('BUILDGUARD_TOKEN') or secrets.token_urlsafe(24)

if not os.environ.get('BUILDGUARD_TOKEN'):
    print(f'BUILDGUARD_TOKEN={TOKEN}')  # generated at start; extension must be given it

app = FastAPI(title='BuildGuard backend', version=VERSION)


def require_token(x_buildguard_token: str = Header(default='')):
    if not secrets.compare_digest(x_buildguard_token.encode(), TOKEN.encode()):
        raise HTTPException(
            status_code=401,
            detail='missing or invalid X-BuildGuard-Token'
        )


AUTH = [Depends(require_token)]


def _inside_workspace(path: Path) -> bool:
    root = os.environ.get('BUILDGUARD_WORKSPACE_ROOT')

    if not root:
        return True

    r = Path(root).resolve()
    return path == r or r in path.parents


def safe_dir(p: str) -> str:
    path = Path(p).expanduser().resolve()

    if not path.is_dir():
        raise HTTPException(400, f'not a directory: {p}')

    if not _inside_workspace(path):
        raise HTTPException(400, 'path is outside the workspace folder')

    return str(path)


def safe_file(p: str) -> str:
    path = Path(p).expanduser().resolve()

    if not path.is_file():
        raise HTTPException(400, f'not a file: {p}')

    if not _inside_workspace(path):
        raise HTTPException(400, 'path is outside the workspace folder')

    return str(path)


def _need(scan_id: str):
    if not store.exists(scan_id):
        raise HTTPException(
            404,
            'unknown scan_id (the backend forgets scans on restart)'
        )


@app.get('/v1/health')
def health():
    return {
        'status': 'ok',
        'version': VERSION,
        'tools': {
            'docker': docker_runner.docker_available(),
            'syft': bool(
                shutil.which(os.environ.get('BUILDGUARD_SYFT_BIN', 'syft'))
            ),
            'llm_configured': bool(
                os.environ.get('BUILDGUARD_LLM_API_KEY')
            )
        }
    }


@app.post('/v1/scans', status_code=202, dependencies=AUTH)
def start_scan(req: ScanRequest):
    project = safe_dir(req.project_path)

    scan_id = orchestrator.start_scan(
        project,
        req.modules,
        req.options.model_dump()
    )

    return {'scan_id': scan_id}


@app.get('/v1/scans/{scan_id}', dependencies=AUTH)
def get_scan(scan_id: str):
    _need(scan_id)
    return store.public_state(scan_id)


@app.get('/v1/scans/{scan_id}/findings', dependencies=AUTH)
def get_findings(scan_id: str):
    _need(scan_id)

    data = store.read_json(scan_id, 'findings.json')

    if data is None:
        raise HTTPException(409, 'findings not ready')

    return data


@app.get('/v1/scans/{scan_id}/report', dependencies=AUTH)
def get_report(scan_id: str):
    _need(scan_id)

    data = store.read_json(scan_id, 'report.json')

    if data is None:
        raise HTTPException(409, 'report not ready')

    return data


@app.get(
    '/v1/scans/{scan_id}/report.html',
    dependencies=AUTH,
    response_class=HTMLResponse
)
def get_report_html(scan_id: str):
    _need(scan_id)

    text = store.read_text(scan_id, 'report.html')

    if text is None:
        raise HTTPException(409, 'report not ready')

    return HTMLResponse(text)


@app.post('/v1/scans/{scan_id}/cancel', dependencies=AUTH)
def cancel(scan_id: str):
    _need(scan_id)
    orchestrator.cancel_scan(scan_id)

    return {'scan_id': scan_id, 'state': 'cancelled'}


@app.post('/v1/release-manifests', status_code=201, dependencies=AUTH)
def release_manifest(req: ManifestRequest):
    # plain def: FastAPI runs it in a worker thread
    project = safe_dir(req.project_path)

    try:
        return create_release(
            project,
            {
                'recipe_path': req.recipe_path,
                'allow_unpinned': req.allow_unpinned
            }
        )

    except ReleaseError as e:
        code = 503 if e.code == 'DOCKER_UNAVAILABLE' else 400

        raise HTTPException(
            code,
            {'code': e.code, 'message': str(e)}
        )


@app.post('/v1/verify-artifact', dependencies=AUTH)
def verify_artifact(req: VerifyRequest):
    try:
        return verify(
            safe_file(req.manifest_path),
            safe_file(req.distributed_artifact)
        )

    except HTTPException:
        raise

    except (OSError, ValueError, KeyError) as e:
        raise HTTPException(400, f'cannot verify: {e}')
