import time
import uuid

from fastapi import FastAPI, HTTPException


app = FastAPI(title='BuildGuard MOCK backend (canned data, no real scanning)')

SCANS = {}

STEPS = {
    'dependency': (1, 3),
    'build': (2, 6),
    'compiler': (3, 9)
}  # (start, end) seconds


def _item(i, module, category, severity, confidence, title, text, hint=None):
    return {
        'id': f'F-{i:03d}',
        'module': module,
        'category': category,
        'severity': severity,
        'confidence': confidence,
        'subject': {},
        'title': title,
        'evidence': [],
        'file_hint': hint,
        'line_hint': None,
        'plain_explanation': text,
        'explanation_source': 'template'
    }


REPORT_ITEMS = [
    _item(
        1, 'dependency', 'KNOWN_VULNERABILITY', 'HIGH', 'CONFIRMED',
        'lodash 4.17.20 has a published advisory (MOCK)',
        'Upgrade to the fixed version listed in the evidence.',
        'package.json'
    ),
    _item(
        2, 'dependency', 'KNOWN_MALICIOUS_ADVISORY', 'CRITICAL', 'CONFIRMED',
        'Package has a malicious-package advisory (MOCK)',
        'A published advisory marks this package as malicious.',
        'package.json'
    ),
    _item(
        3, 'dependency', 'SUSPICIOUS_INDICATOR', 'HIGH', 'HIGH',
        'lodahs-demo shows several suspicious indicators (MOCK)',
        'Suspicious, not confirmed malicious. Review the source.',
        'package.json'
    ),
    _item(
        4, 'build', 'BUILD_MISMATCH', 'HIGH', 'HIGH',
        'Distributed file differs from the trusted build (MOCK)',
        'The cause is not determined.'
    ),
    _item(
        5, 'compiler', 'COMPILER_ANOMALY', 'MEDIUM', 'MEDIUM',
        'Potential compiler anomaly: unexpected function (MOCK)',
        'A function exists in the binary that the source does not explain.'
    ),
    _item(
        6, 'dependency', 'UNRESOLVED', 'INFO', 'HIGH',
        'requests has no exact version (MOCK)',
        'Not a clean result: the check could not complete.',
        'requirements.txt'
    ),
    _item(
        7, 'build', 'NO_KNOWN_ISSUES', 'INFO', 'HIGH',
        'Independent rebuild matched (MOCK)',
        'No known issues were detected by the checks performed.'
    ),
]


def _progress(sid):
    s = SCANS.get(sid)

    if s is None:
        raise HTTPException(404, 'unknown scan_id')

    t = time.time() - s['t0']
    mods = {}

    for m in s['modules']:
        a, b = STEPS[m]
        mods[m] = 'queued' if t < a else (
            'running' if t < b else 'completed'
        )

    done = all(v == 'completed' for v in mods.values())

    state = {
        'scan_id': sid,
        'state': 'completed' if done else 'running',
        'modules': mods,
        'errors': [],
        'started_at': s['started']
    }

    return state, done


def _report(sid):
    cats, sevs = {}, {}

    for it in REPORT_ITEMS:
        cats[it['category']] = cats.get(it['category'], 0) + 1
        sevs[it['severity']] = sevs.get(it['severity'], 0) + 1

    return {
        'scan_id': sid,
        'generated_at': time.strftime(
            '%Y-%m-%dT%H:%M:%SZ',
            time.gmtime()
        ),
        'overall_summary': 'MOCK DATA for UI development. Nothing was scanned.',
        'summary_counts': {
            'by_category': cats,
            'by_severity': sevs
        },
        'items': REPORT_ITEMS,
        'module_status': {
            m: {
                'status': 'ok',
                'errors': [],
                'checks_performed': ['mock']
            }
            for m in SCANS[sid]['modules']
        },
        'limitations': ['This is mock data.']
    }


@app.get('/v1/health')
def health():
    return {
        'status': 'ok',
        'version': 'mock',
        'tools': {
            'docker': True,
            'syft': True,
            'llm_configured': False
        }
    }


@app.post('/v1/scans', status_code=202)
def start_scan(body: dict):
    sid = time.strftime('%Y%m%d-%H%M%S-') + uuid.uuid4().hex[:4]

    mods = body.get('modules') or ['dependency', 'build', 'compiler']

    SCANS[sid] = {
        't0': time.time(),
        'modules': [m for m in mods if m in STEPS],
        'started': time.strftime(
            '%Y-%m-%dT%H:%M:%SZ',
            time.gmtime()
        )
    }

    return {'scan_id': sid}


@app.get('/v1/scans/{sid}')
def get_scan(sid: str):
    return _progress(sid)[0]


@app.get('/v1/scans/{sid}/findings')
def findings(sid: str):
    if not _progress(sid)[1]:
        raise HTTPException(409, 'findings not ready')

    return {
        'scan_id': sid,
        'findings': REPORT_ITEMS
    }


@app.get('/v1/scans/{sid}/report')
def report(sid: str):
    if not _progress(sid)[1]:
        raise HTTPException(409, 'report not ready')

    return _report(sid)


@app.post('/v1/scans/{sid}/cancel')
def cancel(sid: str):
    _progress(sid)

    return {
        'scan_id': sid,
        'state': 'cancelled'
    }


@app.post('/v1/release-manifests', status_code=201)
def release(body: dict):
    return {
        'manifest_path': 'release_manifest.json',
        'artifact': 'dist/app',
        'sha256': '0' * 64,
        'size': 0
    }


@app.post('/v1/verify-artifact')
def verify(body: dict):
    return {
        'result': 'DISTRIBUTED_DIFFERS_FROM_TRUSTED',
        'artifact_name': 'app',
        'trusted_sha256': '1' * 64,
        'distributed_sha256': '2' * 64,
        'diagnostic': None
    }
