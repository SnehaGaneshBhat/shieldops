import json
import tempfile
import time
import os
from datetime import datetime, timezone
from pathlib import Path

from . import heuristics as H
from .discover import discover, find_line
from .installer import install_all
from .lockfiles import Pkg, norm_pypi, parse_npm_lock, parse_package_json, parse_requirements
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
    "vcpkg": ["vcpkg.json", "vcpkg-configuration.json"],
    "conan": ["conanfile.txt", "conan.lock"],
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


def _detect_language(root, manifests):
    manifest_names = {m.name for m in manifests}
    if {"vcpkg.json", "vcpkg-configuration.json", "conanfile.txt", "conan.lock"} & manifest_names:
        return "C"
    for ext in (".c", ".h"):
        if list(root.glob(f"*{ext}")):
            return "C"
    for ext in (".cpp", ".cc", ".cxx", ".hpp"):
        if list(root.glob(f"*{ext}")):
            return "C++"
    if {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"} & manifest_names:
        return "JavaScript"
    if {"requirements.txt", "Pipfile.lock", "poetry.lock"} & manifest_names or list(root.glob("*.py")):
        return "Python"
    if {"go.mod", "go.sum"} & manifest_names or list(root.glob("*.go")):
        return "Go"
    if {"Cargo.lock"} & manifest_names or list(root.glob("*.rs")):
        return "Rust"
    if {"pom.xml"} & manifest_names or list(root.glob("*.java")):
        return "Java"
    return "Generic"


def _print_summary(result, project_path):
    print("=" * 50)
    print("                  SCAN SUMMARY")
    print("=" * 50)
    print(f"      Target: {Path(project_path).name}")
    print(f"      Status: {result.status.upper()}")
    print(f"      Duration: {result.duration_ms}ms")
    print(f"      Checks Performed: {len(result.checks_performed)}")
    print(f"      Total Findings: {len(result.findings)}")
    counts = {}
    for f in result.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ORDER:
        if counts.get(sev, 0) > 0:
            print(f"      - {sev}: {counts[sev]}")
    print("=" * 50)
    print()


def run(project_path, options=None):
    started = time.time()
    opts = options or {}

    try:
        result = _run(project_path, opts)
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
    if opts.get("out_path"):
        out_p = Path(opts["out_path"])
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    if opts.get("verbose"):
        _print_summary(result, project_path)
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
    verbose = bool(options.get("verbose"))
    errors = []
    checks = []
    versions = {}
    packages = {}

    if verbose:
        print("=" * 50)
        print("             BUILDGUARD DEPENDENCY SCANNER")
        print("=" * 50)
        print()

    manifests = discover(root)
    checks.append("manifest_discovery")

    # Dependency installation
    install_opt = options.get("install")
    should_install = install_opt is True or (install_opt is not False and not offline and options.get("auto_install", False))
    install_res = install_all(manifests, offline=(offline or not should_install))
    if should_install and not offline and install_res.get("attempted", 0) > 0:
        if "dependency_installation" not in checks:
            checks.append("dependency_installation")
        if install_res.get("failed", 0) > 0:
            for proj in install_res.get("projects", []):
                if proj.get("status") == "failed":
                    errors.append({
                        "code": "INSTALL_ERROR",
                        "message": f"Dependency installation failed for {proj.get('manifest')}: {proj.get('error')}",
                        "manifest": proj.get("manifest"),
                    })

    if verbose:
        lang = _detect_language(root, manifests)
        if len(manifests) > 1:
            manifest_counts = {}
            for m in manifests:
                manifest_counts[m.name] = manifest_counts.get(m.name, 0) + 1
            mf_parts = [f"{cnt} {name}" if cnt > 1 else name for name, cnt in sorted(manifest_counts.items())]
            mf_display = f"{len(manifests)} manifest(s) ({', '.join(mf_parts)})"
        elif manifests:
            mf_display = manifests[0].name
        else:
            mf_display = "none"

        has_pkg_json = any(m.name == "package.json" for m in manifests)
        if offline:
            inst_status_str = "skipped (offline mode)"
        elif not has_pkg_json:
            inst_status_str = "skipped (no package.json manifests)"
        elif not should_install:
            inst_status_str = "skipped (installation not requested)"
        elif install_res.get("succeeded", 0) > 0 and install_res.get("failed", 0) == 0:
            inst_status_str = f"completed ({install_res['succeeded']} project(s) installed)"
        elif install_res.get("failed", 0) > 0:
            inst_status_str = f"failed ({install_res['failed']} project(s) failed)"
        else:
            inst_status_str = install_res.get("detail", "skipped")

        print("[1/7] PROJECT DISCOVERY")
        print(f"      Project: {root.name}")
        print(f"      Language: {lang}")
        print(f"      Manifests found: {mf_display}")
        print(f"      Installation status: {inst_status_str}")
        if should_install and not offline and install_res.get("projects"):
            for proj in install_res["projects"]:
                try:
                    p_rel = Path(proj["manifest"]).relative_to(root).as_posix()
                except Exception:
                    p_rel = Path(proj["manifest"]).name
                p_status = proj.get("status")
                p_pm = proj.get("package_manager", "npm")
                p_cmd = proj.get("command", "")
                print(f"        - {p_rel} ({p_pm}): {p_status} [{p_cmd}]")
                if proj.get("error"):
                    print(f"          Error: {proj['error'][:100]}")
        print()

    def package_key(pkg):
        name = norm_pypi(pkg.name) if pkg.eco == "pypi" else pkg.name
        return pkg.eco, name, pkg.version

    # Determine inspectable SBOM output path if requested or for C/C++ demo
    sbom_out = options.get("sbom_path")
    if not sbom_out and (
        (root / "vcpkg.json").is_file()
        or (root / "conanfile.txt").is_file()
        or root.name == "deps_vuln_cpp"
    ):
        sbom_out = "reports/cpp_demo.sbom.json"

    if verbose:
        print("[2/7] SYFT DEPENDENCY ANALYSIS")
        print("      Running Syft...")

    # 1. Syft SBOM
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            sbom_temp = str(Path(temp_dir) / "sbom.json")
            run_syft(str(root), sbom_temp)
            components, versions["syft"] = parse_cyclonedx(sbom_temp)
            if sbom_out:
                out_sbom_file = Path(sbom_out)
                out_sbom_file.parent.mkdir(parents=True, exist_ok=True)
                out_sbom_file.write_text(
                    Path(sbom_temp).read_text(encoding="utf-8"),
                    encoding="utf-8",
                )

        if verbose:
            print(f"      Syft version: {versions.get('syft', '1.55.0')}")
            print()
            print("[3/7] SBOM GENERATION")
            print("      Format: CycloneDX JSON")
            print("      SBOM generated successfully")
            print(f"      Location: {sbom_out or 'in-memory'}")
            print()

        # npm lockfiles provide better dependency names and local-source
        # information than Syft's npm PURLs. Avoid duplicate SBOM entries.
        has_npm_lock = any(
            manifest.name == "package-lock.json" for manifest in manifests
        )

        root_vcpkg = root / "vcpkg.json"
        root_vcpkg_name = None
        if root_vcpkg.is_file():
            try:
                vdata = json.loads(root_vcpkg.read_text(encoding="utf-8"))
                root_vcpkg_name = vdata.get("name")
            except Exception:
                pass

        for ecosystem, name, version in components:
            if ecosystem == "npm" and has_npm_lock:
                continue
            if ecosystem == "vcpkg" and root_vcpkg_name and name == root_vcpkg_name:
                continue

            pkg = Pkg(ecosystem or "unsupported", name, version)
            packages[package_key(pkg)] = pkg

        checks.append("syft_sbom")

    except SyftError as exc:
        errors.append({"code": exc.code, "message": str(exc)})
        if verbose:
            print(f"      Syft failed: {exc}")
            print()
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        errors.append({"code": "PARSE_ERROR", "message": str(exc)[:300]})
        if verbose:
            print(f"      SBOM parsing error: {exc}")
            print()

    # 2. Explicit manifest and lockfile parsing adds integrity, source, and complete dependency coverage.
    for manifest in manifests:
        parsed = []

        if manifest.name == "package-lock.json":
            parsed = parse_npm_lock(manifest)
            if "npm_lockfile_parse" not in checks:
                checks.append("npm_lockfile_parse")

        elif manifest.name == "package.json":
            try:
                parsed = parse_package_json(manifest)
                if "package_json_parse" not in checks:
                    checks.append("package_json_parse")
            except ValueError as exc:
                errors.append({
                    "code": "MALFORMED_MANIFEST",
                    "message": str(exc),
                    "file": str(manifest.relative_to(root) if manifest.is_relative_to(root) else manifest),
                })
                if verbose:
                    print(f"      Warning: Malformed manifest: {manifest.name} ({exc})")

        elif manifest.name == "requirements.txt":
            parsed = parse_requirements(manifest)
            if "requirements_parse" not in checks:
                checks.append("requirements_parse")

        for pkg in parsed:
            key = package_key(pkg)
            if key in packages:
                existing = packages[key]
                if existing.integrity and not pkg.integrity:
                    continue
                if existing.resolved and not pkg.resolved:
                    continue
            packages[key] = pkg

    # Prefer an exact resolved version over an unpinned entry.
    for key in list(packages):
        if key[2] is None and any(
            other[:2] == key[:2] and other[2] is not None
            for other in packages
        ):
            del packages[key]

    if verbose:
        print("[4/7] PACKAGE IDENTIFICATION")
        print(f"      Dependencies identified: {len(packages)}")
        if packages:
            for pkg in packages.values():
                purl = f"pkg:{pkg.eco}/{pkg.name}" + (f"@{pkg.version}" if pkg.version else "")
                print(f"      Package: {pkg.name}")
                print(f"      Version: {pkg.version or 'unpinned'}")
                print(f"      Ecosystem: {pkg.eco}")
                print(f"      PURL: {purl}")
        else:
            print("      No packages identified")
        print()

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

    if verbose:
        total_advisories = sum(len(v) for v in ids_by_package.values())
        print("[5/7] OSV VULNERABILITY LOOKUP")
        print("      Endpoint: https://api.osv.dev/v1/querybatch")
        print("      Submitting package identity to OSV...")
        lookup_status = "partial" if failed else ("ok" if osv_eligible else "skipped")
        print(f"      Lookup status: {lookup_status}")
        print(f"      Advisories found: {total_advisories}")
        print()

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

    if verbose:
        print("[6/7] FINDING ANALYSIS")
        print("      Processing vulnerability evidence...")
        if findings:
            f0 = findings[0]
            print(f"      Category: {f0.category}")
            print(f"      Severity: {f0.severity}")
            print(f"      Confidence: {f0.confidence}")
        else:
            print("      Findings: none")
        print()

        print("[7/7] REPORT GENERATION")
        out_path = options.get("out_path")
        if out_path:
            print("      JSON report saved successfully")
            print(f"      Location: {out_path}")
        else:
            print("      JSON report generated successfully")
        print()

    return ModuleResult(
        module="dependency",
        status=status,
        findings=findings,
        errors=errors,
        tool_versions=versions,
        checks_performed=checks,
    )
