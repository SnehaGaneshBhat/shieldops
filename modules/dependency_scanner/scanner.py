import json
import tempfile
import time
import os
from datetime import datetime, timezone
from pathlib import Path

from . import heuristics as H
from .discover import discover, find_line
from .lockfiles import Pkg, norm_pypi, parse_npm_lock, parse_requirements
from .models import Evidence, Finding, ModuleResult
from .osv_client import OSVClient, OSVError, fixed_versions, vuln_severity
from .registry import fetch_age, load_meta
from .syft_runner import ECOSYSTEMS, SyftError, parse_cyclonedx, run_syft


ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"]
MANIFEST_HINTS = {
    "npm": ["package.json", "package-lock.json", "yarn.lock"],
    "pypi": ["requirements.txt", "Pipfile.lock", "poetry.lock"],
    "golang": ["go.mod", "go.sum"],
    "cargo": ["Cargo.toml", "Cargo.lock"],
    "maven": ["pom.xml"],
}


def _find_data_file(filename):
    env_dir = os.environ.get("BUILDGUARD_DATA_DIR") or os.environ.get("SHIELDOPS_DATA_DIR")
    if env_dir:
        cand = Path(env_dir) / filename
        if cand.is_file():
            return cand

    current = Path(__file__).resolve()
    for parent in current.parents:
        cand = parent / "data" / filename
        if cand.is_file():
            return cand

    cand = Path.cwd() / "data" / filename
    if cand.is_file():
        return cand

    cand = current.parent / "data" / filename
    if cand.is_file():
        return cand

    return None


def _top(filename):
    path = _find_data_file(filename)
    if not path or not path.is_file():
        return None

    try:
        return set(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError):
        return None


def run(project_path, options=None):
    started = time.time()

    try:
        result = _run(project_path, options or {})
    except Exception as exc:
        result = ModuleResult(
            module="dependency",
            status="error",
            errors=[{
                "code": "PARSE_ERROR",
                "message": str(exc)[:300],
                "detail": type(exc).__name__,
            }],
        )

    result.duration_ms = int((time.time() - started) * 1000)
    return result


def scan_dependencies(project_path, options=None):
    return run(project_path, options).findings


def _run(project_path, options):
    root = Path(project_path).resolve()

    if not root.is_dir():
        return ModuleResult(
            module="dependency",
            status="error",
            errors=[{
                "code": "INVALID_INPUT",
                "message": "project_path is not a folder",
            }],
        )

    offline = bool(options.get("offline"))
    errors = []
    checks = []
    versions = {}
    packages = {}

    manifests = discover(root)
    checks.append("manifest_discovery")

    def package_key(pkg):
        name = norm_pypi(pkg.name) if pkg.eco == "pypi" else pkg.name
        return pkg.eco, name, pkg.version

    # 1. Syft SBOM
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            sbom_path = str(Path(temp_dir) / "sbom.json")
            run_syft(str(root), sbom_path)
            components, versions["syft"] = parse_cyclonedx(sbom_path)

        # npm lockfiles provide better dependency names and local-source
        # information than Syft's npm PURLs. Avoid duplicate SBOM entries.
        has_npm_lock = any(
            manifest.name == "package-lock.json" for manifest in manifests
        )

        for ecosystem, name, version in components:
            if ecosystem == "npm" and has_npm_lock:
                continue

            pkg = Pkg(ecosystem or "unsupported", name, version)
            packages[package_key(pkg)] = pkg

        checks.append("syft_sbom")

    except SyftError as exc:
        errors.append({"code": exc.code, "message": str(exc)})
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append({"code": "PARSE_ERROR", "message": str(exc)[:300]})

    # 2. Explicit lockfile parsing adds integrity and source information.
    for manifest in manifests:
        parsed = []

        if manifest.name == "package-lock.json":
            parsed = parse_npm_lock(manifest)
            checks.append("npm_lockfile_parse")

        elif manifest.name == "requirements.txt":
            parsed = parse_requirements(manifest)
            checks.append("requirements_parse")

        for pkg in parsed:
            packages[package_key(pkg)] = pkg

    # Prefer an exact resolved version over an unpinned entry.
    for key in list(packages):
        if key[2] is None and any(
            other[:2] == key[:2] and other[2] is not None
            for other in packages
        ):
            del packages[key]

    findings = []
    counter = [0]

    def add(category, severity, confidence, pkg, title, evidence):
        counter[0] += 1
        base = Path(pkg.manifest).parent if pkg.manifest else root
        hint_file = None
        for candidate_name in MANIFEST_HINTS.get(pkg.eco, []):
            cand = base / candidate_name
            if cand.is_file():
                hint_file = cand
                break

        if not hint_file:
            if pkg.manifest and Path(pkg.manifest).is_file():
                hint_file = Path(pkg.manifest)
            else:
                fallback = base / (
                    "package.json" if pkg.eco == "npm" else "requirements.txt"
                )
                if fallback.is_file():
                    hint_file = fallback

        exists = hint_file is not None and hint_file.is_file()
        try:
            file_hint = str(hint_file.relative_to(root)) if exists else None
        except (ValueError, AttributeError):
            file_hint = None

        findings.append(Finding(
            id=f"D-{counter[0]:03d}",
            module="dependency",
            category=category,
            severity=severity,
            confidence=confidence,
            subject={
                "ecosystem": pkg.eco,
                "name": pkg.name,
                "version": pkg.version,
            },
            title=title,
            evidence=evidence,
            file_hint=file_hint,
            line_hint=find_line(hint_file, pkg.name) if exists else None,
        ))

    # 3. Unresolved dependencies and supported package list.
    resolved = []

    for pkg in packages.values():
        if pkg.eco not in ECOSYSTEMS:
            add(
                "UNRESOLVED", "INFO", "LOW", pkg,
                f"{pkg.name}: ecosystem not supported",
                [Evidence(type="tool_output", data={
                    "reason": "unsupported_ecosystem"
                })],
            )
        elif not pkg.version:
            add(
                "UNRESOLVED", "INFO", "LOW", pkg,
                f"{pkg.name}: no exact version",
                [Evidence(type="tool_output", data={
                    "reason": "no_exact_version"
                })],
            )
        else:
            resolved.append(pkg)

    # 4. OSV lookups.
    status = "ok"
    cache_dir = options.get("osv_cache_dir") or str(
        root / ".buildguard" / "cache" / "osv"
    )
    osv = OSVClient(cache_dir, offline=offline)

    # Local file dependencies are part of the project, not published
    # registry packages. Keep them for heuristics, but do not query OSV.
    osv_eligible = [pkg for pkg in resolved if pkg.source != "local"]

    osv_packages = [
        (ECOSYSTEMS[pkg.eco], pkg.name, pkg.version)
        for pkg in osv_eligible
    ]
    ids_by_package, failed = osv.query_ids(osv_packages)

    query_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    versions["osv_query_time"] = query_time

    if failed:
        status = "partial"
        errors.append({
            "code": "NETWORK_ERROR",
            "message": f"OSV lookup failed for {len(failed)} package(s)",
        })
    else:
        checks.append("osv_lookup")

    for pkg in osv_eligible:
        key = (ECOSYSTEMS[pkg.eco], pkg.name, pkg.version)

        if key in failed:
            add(
                "UNRESOLVED", "INFO", "LOW", pkg,
                f"{pkg.name}@{pkg.version}: OSV lookup failed",
                [Evidence(type="tool_output", data={
                    "reason": "osv_unreachable"
                })],
            )
            continue

        advisories = []
        for vuln_id in ids_by_package.get(key, []):
            try:
                advisories.append(osv.get_vuln(vuln_id))
            except OSVError:
                advisories.append({"id": vuln_id})

        malicious = [
            item for item in advisories
            if str(item.get("id", "")).startswith("MAL-")
        ]
        vulnerabilities = [
            item for item in advisories if item not in malicious
        ]

        for group, category in (
            (malicious, "KNOWN_MALICIOUS_ADVISORY"),
            (vulnerabilities, "KNOWN_VULNERABILITY"),
        ):
            if not group:
                continue

            evidence = [
                Evidence(type="osv_advisory", data={
                    "id": item.get("id"),
                    "aliases": item.get("aliases", []),
                    "summary": H.clean(item.get("summary", "")),
                    "fixed_in": fixed_versions(item),
                    "severity": vuln_severity(item),
                })
                for item in group
            ]

            severity = (
                "CRITICAL"
                if category == "KNOWN_MALICIOUS_ADVISORY"
                else min(
                    (vuln_severity(item) for item in group),
                    key=ORDER.index,
                )
            )

            add(
                category, severity, "CONFIRMED", pkg,
                f"{pkg.name} {pkg.version}: {len(group)} OSV advisory record(s)",
                evidence,
            )

    # 5. Heuristic rules.
    npm_top = _top("top_packages_npm.json")
    pypi_top = _top("top_packages_pypi.json")
    if npm_top is None or pypi_top is None:
        errors.append({
            "code": "DATA_MISSING",
            "message": "Top packages data file not found",
        })
    top = (npm_top or set()) | (pypi_top or set())
    budget = options.get("max_registry_lookups", 100)

    for pkg in packages.values():
        hits = []

        typo = H.typosquat(pkg.name, top) if top else None
        if typo:
            hits.append(Evidence(
                type="rule_hit",
                rule_id="TYPOSQUAT",
                data={"similar_to": typo[0], "distance": typo[1]},
            ))

        if pkg.source in ("git", "url"):
            hits.append(Evidence(
                type="rule_hit",
                rule_id="NONREGISTRY_SOURCE",
                data={"source": pkg.source},
                untrusted_text=[H.clean(pkg.resolved or "")],
            ))

        if (
            pkg.eco == "npm"
            and pkg.source in ("registry", "url")
            and pkg.manifest
            and not pkg.integrity
        ):
            hits.append(Evidence(
                type="rule_hit",
                rule_id="MISSING_INTEGRITY",
                data={},
            ))

        metadata = {}

        if pkg.eco == "npm" and pkg.local_dir:
            metadata = load_meta(pkg, root, offline)

        elif (
            pkg.eco == "npm"
            and pkg.source == "registry"
            and budget > 0
        ):
            budget -= 1
            metadata = load_meta(pkg, root, offline)

        for hook, body in H.install_script_hits(
            metadata.get("scripts") or {}
        ):
            hits.append(Evidence(
                type="rule_hit",
                rule_id="INSTALL_SCRIPT",
                data={"hook": hook},
                untrusted_text=[H.clean(body)],
            ))

        if (
            hits
            and "age_days" not in metadata
            and not offline
            and pkg.source == "registry"
            and pkg.eco == "npm"
        ):
            metadata.update(fetch_age(pkg))

        if (
            metadata.get("age_days") is not None
            and metadata["age_days"] < 30
        ) or metadata.get("version_count") == 1:
            hits.append(Evidence(
                type="rule_hit",
                rule_id="NEW_OR_THIN_PACKAGE",
                data={
                    "age_days": metadata.get("age_days"),
                    "version_count": metadata.get("version_count"),
                },
            ))

        if hits:
            rules = sorted({hit.rule_id for hit in hits})

            if len(rules) >= 3:
                severity, confidence = "HIGH", "HIGH"
            elif len(rules) == 2:
                severity, confidence = "HIGH", "MEDIUM"
            else:
                severity = (
                    "MEDIUM"
                    if rules[0] in ("INSTALL_SCRIPT", "NONREGISTRY_SOURCE")
                    else "LOW"
                )
                confidence = "LOW"

            add(
                "SUSPICIOUS_INDICATOR", severity, confidence, pkg,
                f"{pkg.name}: {len(rules)} suspicious indicator(s) "
                f"({', '.join(rules)})",
                hits,
            )

    checks.append("heuristics")

    # 6. Only claim no known issues when the full required checks completed.
    has_unresolved = any(
        finding.category == "UNRESOLVED" for finding in findings
    )
    real_findings = [
        finding for finding in findings
        if finding.category != "UNRESOLVED"
    ]

    if (
        len(resolved) > 0
        and not has_unresolved
        and not real_findings
        and "osv_lookup" in checks
        and "syft_sbom" in checks
    ):
        counter[0] += 1
        findings.append(Finding(
            id=f"D-{counter[0]:03d}",
            module="dependency",
            category="NO_KNOWN_ISSUES",
            severity="INFO",
            confidence="LOW",
            subject={"packages_checked": len(resolved)},
            title="No known issues detected by the checks performed",
            evidence=[Evidence(
                type="tool_output",
                data={
                    "checks": list(checks),
                    "osv_query_time": query_time,
                },
            )],
        ))

    if errors and status == "ok":
        status = "partial"

    return ModuleResult(
        module="dependency",
        status=status,
        findings=findings,
        errors=errors,
        tool_versions=versions,
        checks_performed=checks,
    )
