import html
import importlib
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from backend import docker_runner, store
from backend.schemas import ModuleResult


REPO_ROOT = Path(__file__).resolve().parent.parent

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


def _resolve_compiler_target(sample, project_path):
    """Safely resolve compiler target directory against the selected project workspace.

    Requirements:
    1. Resolve user-specified relative compiler paths against project_path.
    2. Prevent paths escaping the project workspace.
    3. Explicit absolute paths are permitted only within permitted workspace or project.
    4. Preserve bundled compiler sample fallback for the demo workflow on REPO_ROOT.
    5. Do not silently substitute the bundled sample when a user workspace was requested.
    """
    proj = Path(project_path).resolve()
    repo = REPO_ROOT.resolve()
    ws_root = os.environ.get('BUILDGUARD_WORKSPACE_ROOT')
    ws_root_path = Path(ws_root).resolve() if ws_root else None

    def _is_within(inner: Path, outer: Path) -> bool:
        return inner == outer or outer in inner.parents

    # 1. User supplied an absolute path
    if sample and Path(sample).is_absolute():
        cand = Path(sample).resolve()
        if not cand.is_dir():
            return None
        if ws_root_path:
            if not _is_within(cand, ws_root_path):
                return None
            return str(cand)
        if _is_within(cand, proj) or _is_within(cand, repo / 'test_samples'):
            return str(cand)
        return None

    # 2. User supplied a relative path (or default from VS Code settings)
    if sample:
        q = Path(sample)
        cand = (proj / q).resolve()

        # Reject path traversal attempting to escape project workspace
        if not _is_within(cand, proj):
            return None

        if cand.is_dir():
            return str(cand)

        # If sample did not resolve directly in project_path:
        # Check if project_path itself has C source code and sample was the default 'test_samples/compiler_hello'
        if sample == 'test_samples/compiler_hello' and (proj / 'src').is_dir():
            return str(proj)

        # Demo workflow fallback only if project_path is within REPO_ROOT
        if _is_within(proj, repo):
            repo_cand = (repo / q).resolve()
            if _is_within(repo_cand, repo) and repo_cand.is_dir():
                return str(repo_cand)

        # For an external workspace, do not substitute bundled sample!
        return None

    # 3. No sample supplied (None or "")
    if (proj / 'src').is_dir():
        return str(proj)

    # Demo workflow fallback on repo root
    if _is_within(proj, repo):
        bundled = repo / 'test_samples' / 'compiler_hello'
        if bundled.is_dir():
            return str(bundled)

    return None


def _resolve_build_target(options, project_path):
    """Safely resolve build target directory and recipe.

    1. If the workspace root contains the configured recipe, use the workspace root.
    2. Otherwise, if an explicitly configured sample target (build_sample or compiler_sample)
       resolves safely inside the workspace and contains the configured recipe, use that sample directory.
    3. If neither condition applies, retain the original workspace root so Build Integrity
       reports NOT_COMPARABLE.
    """
    proj = Path(project_path).resolve()
    recipe_file = options.get('recipe_path') or 'buildguard.yml'
    recipe_p = Path(recipe_file)

    def _is_within(inner: Path, outer: Path) -> bool:
        return inner == outer or outer in inner.parents

    # 1. Workspace root contains the configured recipe
    if not recipe_p.is_absolute():
        recipe_in_proj = (proj / recipe_p).resolve()
        if _is_within(recipe_in_proj, proj) and recipe_in_proj.is_file():
            return str(proj)
    elif recipe_p.is_file() and _is_within(recipe_p.resolve(), proj):
        return str(proj)

    # 2. Explicitly configured sample target (build_sample or compiler_sample)
    sample = options.get('build_sample') or options.get('compiler_sample')
    if sample:
        sample_target = _resolve_compiler_target(sample, project_path)
        if sample_target:
            sample_dir = Path(sample_target).resolve()
            if not recipe_p.is_absolute():
                recipe_in_sample = (sample_dir / recipe_p).resolve()
                if _is_within(recipe_in_sample, sample_dir) and recipe_in_sample.is_file():
                    return str(sample_dir)
            elif recipe_p.is_file() and _is_within(recipe_p.resolve(), sample_dir):
                return str(sample_dir)

    # 3. Retain the original workspace root
    return str(proj)


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
        target = _resolve_compiler_target(sample, project_path)

        if not target:
            return _failed(
                name,
                'skipped',
                'INVALID_INPUT',
                f"compiler target '{sample or project_path}' is missing or not found in workspace"
            )

    elif name == 'build':
        target = _resolve_build_target(options, project_path)

    try:
        res = mod.run(target, options)
        result = (
            res if isinstance(res, ModuleResult)
            else ModuleResult.model_validate(res)
        )
        if target and not result.tool_versions.get('target'):
            result.tool_versions['target'] = str(target)
        return result

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


def _correlate(results, scan_id=None):
    try:
        from modules.reporting.correlate import correlate  # P3

        serialized = [
            r.model_dump() if hasattr(r, 'model_dump') else dict(r)
            for r in results.values()
        ]
        return correlate(serialized, scan_id=scan_id)

    except Exception:
        pass

    items = [
        f
        for r in results.values()
        for f in r.findings
    ]

    items.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))

    for i, f in enumerate(items, 1):
        f.id = f'F-{i:03d}'

    return {
        'scan_id': scan_id or _now(),
        'findings': [_dump(f) for f in items],
        'allowed_ids': [f.id for f in items],
    }


def _fallback_report(scan_id, findings):
    by_cat, by_sev, items = {}, {}, []

    for f in findings:
        d = _dump(f)

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
        'explanation_source': 'template',
        'summary_counts': {
            'by_category': by_cat,
            'by_severity': by_sev
        },
        'items': items,
        'module_status': {},
        'limitations': list(LIMITS)
    }


def _build_report(scan_id, findings, results, use_llm):
    findings_doc = findings if isinstance(findings, dict) else {
        'scan_id': scan_id,
        'findings': [_dump(f) for f in findings],
        'allowed_ids': [getattr(f, 'id', f.get('id', '')) for f in findings],
    }
    findings_doc['scan_id'] = scan_id

    try:
        from modules.reporting.build_report import build_report  # P3

        rep = build_report(findings_doc, use_llm=use_llm)
        report = (
            rep.model_dump()
            if hasattr(rep, 'model_dump')
            else dict(rep)
        )

    except Exception:
        findings_list = findings_doc.get('findings', [])
        report = _fallback_report(scan_id, findings_list)

    report['scan_id'] = scan_id

    if 'summary_counts' not in report:
        by_cat, by_sev = {}, {}
        for it in report.get('items', []):
            cat = it.get('category', 'UNKNOWN')
            sev = it.get('severity', 'UNKNOWN')
            by_cat[cat] = by_cat.get(cat, 0) + 1
            by_sev[sev] = by_sev.get(sev, 0) + 1
        report['summary_counts'] = {
            'by_category': by_cat,
            'by_severity': by_sev,
        }

    report['module_status'] = {
        m: {
            'status': r.status,
            'errors': r.errors,
            'checks_performed': r.checks_performed,
            **({'target': r.tool_versions['target']} if r.tool_versions.get('target') else {}),
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
            findings_doc = _correlate(results, scan_id=scan_id)
            findings = findings_doc.get('findings', []) if isinstance(findings_doc, dict) else findings_doc
            store.write_json(
                scan_id,
                'findings.json',
                {
                    'scan_id': scan_id,
                    'findings': [_dump(f) for f in findings]
                }
            )
            report = _build_report(
                scan_id,
                findings_doc,
                results,
                bool(options.get('use_llm'))
            )
            report['overall_summary'] = f'Scan was cancelled. {len(findings)} partial finding(s) collected.'
            store.write_json(scan_id, 'report.json', report)
            store.write_text(scan_id, 'report.html', _render_html(report))
        except Exception:
            pass
        return

    try:
        findings_doc = _correlate(results, scan_id=scan_id)
        findings = findings_doc.get('findings', []) if isinstance(findings_doc, dict) else findings_doc

        store.write_json(
            scan_id,
            'findings.json',
            {
                'scan_id': scan_id,
                'findings': [_dump(f) for f in findings]
            }
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
