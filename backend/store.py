import json
import os
import secrets
import shutil
import threading
from datetime import datetime, timezone
from pathlib import Path


_LOCK = threading.RLock()
_SCANS: dict = {}
PRIVATE_KEYS = ('folder', 'project_path')


def _now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def new_scan_id() -> str:
    return datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S-') + secrets.token_hex(2)


def data_root(project_path: str) -> Path:
    env = os.environ.get('BUILDGUARD_DATA_DIR')
    return Path(env) if env else Path(project_path) / '.buildguard'


def _persist(scan_id: str) -> None:
    with _LOCK:
        state = dict(_SCANS[scan_id])
        Path(state['folder'], 'state.json').write_text(
            json.dumps(state, indent=2),
            encoding='utf-8'
        )


def create_scan(project_path: str, modules: list) -> str:
    scan_id = new_scan_id()
    folder = data_root(project_path) / 'scans' / scan_id
    folder.mkdir(parents=True, exist_ok=True)

    state = {
        'scan_id': scan_id,
        'state': 'queued',
        'modules': {m: 'queued' for m in modules},
        'errors': [],
        'started_at': _now(),
        'folder': str(folder),
        'project_path': project_path,
    }

    with _LOCK:
        _SCANS[scan_id] = state

    _persist(scan_id)
    return scan_id


def exists(scan_id: str) -> bool:
    return scan_id in _SCANS


def scan_folder(scan_id: str) -> Path:
    return Path(_SCANS[scan_id]['folder'])


def public_state(scan_id: str):
    with _LOCK:
        s = _SCANS.get(scan_id)
        if s is None:
            return None

        return {
            k: v
            for k, v in json.loads(json.dumps(s)).items()
            if k not in PRIVATE_KEYS
        }


def set_state(scan_id: str, state: str) -> None:
    with _LOCK:
        _SCANS[scan_id]['state'] = state

    _persist(scan_id)


def update_module(scan_id: str, module: str, status: str) -> None:
    with _LOCK:
        _SCANS[scan_id]['modules'][module] = status

    _persist(scan_id)


def add_error(scan_id: str, error: dict) -> None:
    with _LOCK:
        _SCANS[scan_id]['errors'].append(error)

    _persist(scan_id)


def write_json(scan_id: str, name: str, obj) -> None:
    (scan_folder(scan_id) / name).write_text(
        json.dumps(obj, indent=2, default=str),
        encoding='utf-8'
    )


def write_text(scan_id: str, name: str, text: str) -> None:
    (scan_folder(scan_id) / name).write_text(
        text,
        encoding='utf-8'
    )


def read_json(scan_id: str, name: str):
    p = scan_folder(scan_id) / name
    return json.loads(p.read_text(encoding='utf-8')) if p.is_file() else None


def read_text(scan_id: str, name: str):
    p = scan_folder(scan_id) / name
    return p.read_text(encoding='utf-8') if p.is_file() else None


def delete_scan(scan_id: str) -> None:
    folder = scan_folder(scan_id)
    shutil.rmtree(folder, ignore_errors=True)

    with _LOCK:
        _SCANS.pop(scan_id, None)
