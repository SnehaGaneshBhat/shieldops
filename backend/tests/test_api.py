import time

from fastapi.testclient import TestClient

from backend import orchestrator
from backend.main import app
from backend.schemas import ModuleResult


H = {'X-BuildGuard-Token': 'test-token'}
client = TestClient(app)


def fake_call(name, project_path, options):
    return ModuleResult(module=name, status='ok', checks_performed=['fake'])


def test_health_is_open():
    r = client.get('/v1/health')
    assert r.status_code == 200 and r.json()['status'] == 'ok'


def test_scan_requires_token(tmp_path):
    r = client.post('/v1/scans', json={'project_path': str(tmp_path)})
    assert r.status_code == 401


def test_bad_project_path_rejected():
    r = client.post('/v1/scans', headers=H, json={
        'project_path': '/definitely/not/here'
    })
    assert r.status_code == 400


def test_full_scan_with_fake_modules(tmp_path, monkeypatch):
    monkeypatch.setattr(orchestrator, '_call_module', fake_call)
    r = client.post(
        '/v1/scans',
        headers=H,
        json={'project_path': str(tmp_path), 'modules': ['dependency', 'build']}
    )
    assert r.status_code == 202
    sid = r.json()['scan_id']

    for _ in range(50):
        s = client.get(f'/v1/scans/{sid}', headers=H).json()
        if s['state'] in ('completed', 'completed_with_errors', 'failed'):
            break
        time.sleep(0.2)

    assert s['state'] == 'completed'

    rep = client.get(f'/v1/scans/{sid}/report', headers=H)
    assert rep.status_code == 200
    assert set(rep.json()['module_status']) == {'dependency', 'build'}

    assert client.get(
        f'/v1/scans/{sid}/findings', headers=H
    ).status_code == 200
