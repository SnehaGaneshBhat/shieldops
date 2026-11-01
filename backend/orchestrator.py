import html
import importlib
import logging
import threading
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from backend import docker_runner, store
from backend.schemas import ModuleResult
from modules.reporting import build_report, correlate


REPO_ROOT = Path(__file__).resolve().parent.parent
LOG = logging.getLogger(__name__)

ENTRY = {
    'dependency': 'modules.dependency_scanner',
    'build': 'modules.build_integrity',
    'compiler': 'modules.compiler_analysis',
}

MODULE_STATE = {
    'ok': 'completed',
    'partial': 'completed',
    'error': 'failed',
    'skipped': 'skipped'
}

SEV_ORDER = {
    'CRITICAL': 0,
    'HIGH': 1,
    'MEDIUM': 2,
    'LOW': 3,
    'UNKNOWN': 4,
    'INFO': 5
}

_CANCELLED = set()

TEMPLATES = {
    'KNOWN_VULNERABILITY': 'A published advisory exists for this exact version. See the evidence for the advisory ID and fixed version.',
    'KNOWN_MALICIOUS_ADVISORY': 'A published malicious-package advisory exists for this package. See the evidence.',
    'SUSPICIOUS_INDICATOR': 'One or more heuristic rules fired. This is suspicious, not confirmed malicious. Review the evidence.',
    'UNRESOLVED': 'This check could not be completed. It is not a clean result.',
    'BUILD_MISMATCH': 'Two files that should be identical differ. The cause is not determined. A mismatch is not proof of tampering.',
    'COMPILER_ANOMALY': 'Potential compiler anomaly: the binary contains something the source does not explain. Needs human review.',
    'NO_KNOWN_ISSUES': 'No known issues were detected by the checks performed. This is not a guarantee.',
}

LIMITS = [
    'A match between two builds shows identical bytes, not that the source, image or compiler is clean.',
    'No known issues detected means only that the listed checks found nothing. Unknown vulnerabilities are not covered.',
    'A hash mismatch is not proof of tampering; the cause is not determined.',
    'Docker is used to control build environments, not as a malware sandbox.',
]


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _failed(module, status, code, message):
    return ModuleResult(
        module=module,
        status=status,
        errors=[{'code': code, 'message': message, 'detail': ''}]
    )


def _resolve_dir(p, project_path):
    q = Path(p)

    for c in (
        [q] if q.is_absolute()
        else [Path(project_path) / q, REPO_ROOT / q]
    ):
        if c.is_dir():
            return str(c)

    return None


def _call_module(name, project_path, options):
    try:
        mod = importlib.import_module(ENTRY[name])

    except ModuleNotFoundError as e:
        if e.name and ENTRY[name].startswith(e.name):
            return _failed(
                name,
                'skipped',
                'MODULE_NOT_AVAILABLE',
                f'{ENTRY[name]} has not been merged yet'
            )

        return _failed(
            name,
            'error',
            'TOOL_MISSING',
            f'missing Python package: {e.name}'
        )

    except Exception as e:
        return _failed(
            name,
            'error',
            'INTERNAL_ERROR',
            f'import failed: {type(e).__name__}: {e}'
        )

    target = project_path

    if name == 'compiler':
        sample = options.get('compiler_sample')
        target = _resolve_dir(sample, project_path) if sample else None

        if not target:
            return _failed(
                name,
                'skipped',
                'INVALID_INPUT',
                'compiler_sample is missing or not found'
            )

    try:
        res = mod.run(target, options)

        return (
            res if isinstance(res, ModuleResult)
            else ModuleResult.model_validate(res)
        )

    except ValidationError as e:
        return _failed(
            name,
            'error',
            'PARSE_ERROR',
            f'module output does not match schemas.py: {e}'
        )

    except Exception as e:  # modules should never raise, but never trust that
        return _failed(
            name,
            'error',
            'INTERNAL_ERROR',
            f'{type(e).__name__}: {e}'
        )


def _dump(f):
    return f.model_dump() if hasattr(f, 'model_dump') else dict(f)


def _correlate(results, scan_id):
    try:
        serialized = [result.model_dump(mode='json') for result in results.values()]
        return correlate(serialized, scan_id=scan_id)
    except Exception:
        LOG.exception('Reporting correlation failed for scan %s', scan_id)

    items = [
        f
        for r in results.values()
        for f in r.findings
    ]

    items.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))

    for i, f in enumerate(items, 1):
        f.id = f'F-{i:03d}'

    return {
        'scan_id': scan_id,
        'generated_at': _now(),
        'findings': [_dump(f) for f in items],
        'module_status': {
            name: {
                'status': result.status,
                'errors': result.errors,
                'checks_performed': result.checks_performed
            }
            for name, result in results.items()
        },
        'tool_versions': {},
        'correlations': [],
        'allowed_ids': [],
        'simulation_present': False
    }


def _fallback_report(scan_id, findings_doc):
    by_cat, by_sev, items = {}, {}, []

    for d in findings_doc.get('findings', []):
        d = dict(d)

        by_cat[d['category']] = by_cat.get(d['category'], 0) + 1
        by_sev[d['severity']] = by_sev.get(d['severity'], 0) + 1

        items.append({
            **d,
            'plain_explanation': TEMPLATES[d['category']],
            'explanation_source': 'template'
        })

    return {
        'scan_id': scan_id,
        'generated_at': _now(),
        'overall_summary': (
            f'{len(items)} finding(s) from the checks that ran. '
            'See module status for checks that did not run.'
        ),
        'summary_counts': {
            'by_category': by_cat,
            'by_severity': by_sev
        },
        'explanation_source': 'template',
        'items': items,
        'module_status': {},
        'limitations': list(LIMITS)
    }


def _build_report(scan_id, findings_doc, results, use_llm):
    try:
        report = build_report(findings_doc, use_llm)
    except Exception:
        LOG.exception('Report generation failed for scan %s', scan_id)
        report = _fallback_report(scan_id, findings_doc)

    report['scan_id'] = scan_id

    report['module_status'] = {
        m: {
            'status': r.status,
            'errors': r.errors,
            'checks_performed': r.checks_performed
        }
        for m, r in results.items()
    }

    notes = [
        f'{m} check did not complete: {e.get("code")}: {e.get("message")}'
        for m, r in results.items()
        if r.status in ('error', 'skipped', 'partial')
        for e in r.errors
    ]

    report['limitations'] = (
        list(report.get('limitations') or LIMITS) + notes
    )

    return report


def _render_html(report):
    esc = lambda x: html.escape(str(x))
    rows = []

    for it in report.get('items', []):
        sev, cat, title, expl = (
            esc(it.get(k, ''))
            for k in (
                'severity',
                'category',
                'title',
                'plain_explanation'
            )
        )

        rows.append(
            f'<li><b>{sev}</b> {cat}: {title}<br><small>{expl}</small></li>'
        )

    mods = ''.join(
        f'<li>{esc(m)}: {esc(s.get("status"))}</li>'
        for m, s in report.get('module_status', {}).items()
    )

    lim = ''.join(
        f'<li>{esc(x)}</li>'
        for x in report.get('limitations', [])
    )

    return (
        f'<!doctype html><meta charset=utf-8><title>BuildGuard report</title>'
        f'<h1>BuildGuard report {esc(report.get("scan_id"))}</h1>'
        f'<p>{esc(report.get("overall_summary"))}</p>'
        f'<h2>Findings</h2><ul>{"".join(rows)}</ul>'
        f'<h2>Module status</h2><ul>{mods}</ul>'
        f'<h2>Limitations</h2><ul>{lim}</ul>'
    )


def _run_scan(scan_id, project_path, modules, options):
    store.set_state(scan_id, 'running')

    opts = {
        **options,
        'scan_id': scan_id,
        'scan_dir': str(store.scan_folder(scan_id)),
        'cancel_check': lambda: scan_id in _CANCELLED
    }

    results = {}

    def worker(name):
        store.update_module(scan_id, name, 'running')

        try:
            res = _call_module(name, project_path, opts)
            results[name] = res

            store.write_json(
                scan_id,
                f'{name}_findings.json',
                res.model_dump()
            )

            for e in res.errors:
                store.add_error(scan_id, {'module': name, **e})

            state = (
                'cancelled'
                if scan_id in _CANCELLED
                else MODULE_STATE.get(res.status, 'failed')
            )

        except Exception as e:
            results[name] = _failed(
                name,
                'error',
                'INTERNAL_ERROR',
                str(e)
            )
            state = 'failed'

        store.update_module(scan_id, name, state)

    threads = [
        threading.Thread(target=worker, args=(m,), daemon=True)
        for m in modules
    ]

    for t in threads:
        t.start()

    for t in threads:
        t.join()

    if scan_id in _CANCELLED:
        try:
            findings_doc = _correlate(results, scan_id)
            store.write_json(
                scan_id,
                'findings.json',
                findings_doc
            )
            report = _build_report(
                scan_id,
                findings_doc,
                results,
                bool(options.get('use_llm'))
            )
            report['overall_summary'] = f'Scan was cancelled. {len(findings_doc["findings"])} partial finding(s) collected.'
            store.write_json(scan_id, 'report.json', report)
            store.write_text(scan_id, 'report.html', _render_html(report))
        except Exception:
            pass
        return

    try:
        findings_doc = _correlate(results, scan_id)

        store.write_json(
            scan_id,
            'findings.json',
            findings_doc
        )

        report = _build_report(
            scan_id,
            findings_doc,
            results,
            bool(options.get('use_llm'))
        )

        store.write_json(scan_id, 'report.json', report)
        store.write_text(scan_id, 'report.html', _render_html(report))

        bad = [
            r
            for r in results.values()
            if r.status != 'ok'
        ]

        if results and all(
            r.status == 'error'
            for r in results.values()
        ):
            store.set_state(scan_id, 'failed')
        else:
            store.set_state(
                scan_id,
                'completed_with_errors' if bad else 'completed'
            )

    except Exception as e:
        store.add_error(
            scan_id,
            {
                'module': 'orchestrator',
                'code': 'INTERNAL_ERROR',
                'message': str(e)
            }
        )

        store.set_state(scan_id, 'failed')


def start_scan(project_path, modules, options):
    scan_id = store.create_scan(project_path, modules)

    threading.Thread(
        target=_run_scan,
        args=(scan_id, project_path, modules, options),
        daemon=True
    ).start()

    return scan_id


def cancel_scan(scan_id):
    _CANCELLED.add(scan_id)
    docker_runner.kill_scan_containers(scan_id)
    store.set_state(scan_id, 'cancelled')
