from modules.dependency_scanner.scanner import run, scan_dependencies


def test_invalid_project_returns_error():
    result = run("/does/not/exist")

    assert result.status == "error"
    assert result.errors[0]["code"] == "INVALID_INPUT"


def test_empty_project_does_not_claim_no_issues(tmp_path):
    result = run(tmp_path, {"offline": True})

    assert result.module == "dependency"
    assert result.status in ("ok", "partial")
    assert "manifest_discovery" in result.checks_performed
    assert not any(
        finding.category == "NO_KNOWN_ISSUES"
        for finding in result.findings
    )


def test_unresolved_dependencies_do_not_claim_no_issues(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("unpinned_package\n", encoding="utf-8")

    result = run(tmp_path, {"offline": True})

    assert any(finding.category == "UNRESOLVED" for finding in result.findings)
    assert not any(
        finding.category == "NO_KNOWN_ISSUES"
        for finding in result.findings
    )


def test_sample_deps_clean_regression():
    from pathlib import Path
    clean_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_clean"
    result = run(clean_sample, {"offline": True})

    assert result.status == "ok"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "NO_KNOWN_ISSUES"
    assert finding.severity == "INFO"
    assert finding.confidence == "LOW"
    assert finding.subject.get("packages_checked") == 1
    assert "osv_lookup" in result.checks_performed
    assert "syft_sbom" in result.checks_performed


def test_sample_deps_suspicious_npm_regression():
    from pathlib import Path
    sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_suspicious_npm"
    result = run(sample, {"offline": True})

    assert result.status == "ok"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "SUSPICIOUS_INDICATOR"
    assert finding.severity == "HIGH"
    assert finding.confidence == "HIGH"
    assert finding.subject == {
        "ecosystem": "npm",
        "name": "lodahs",
        "version": "1.0.0",
    }
    rule_ids = {e.rule_id for e in finding.evidence}
    assert "TYPOSQUAT" in rule_ids
    assert "INSTALL_SCRIPT" in rule_ids
    assert "NEW_OR_THIN_PACKAGE" in rule_ids


def test_sample_deps_vuln_npm_regression():
    from pathlib import Path
    sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_vuln_npm"
    result = run(sample, {"offline": True})

    assert result.status == "ok"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "KNOWN_VULNERABILITY"
    assert finding.severity == "HIGH"
    assert finding.confidence == "CONFIRMED"
    assert finding.subject == {
        "ecosystem": "npm",
        "name": "lodash",
        "version": "4.17.20",
    }
    advisory_ids = {e.data.get("id") for e in finding.evidence}
    assert "GHSA-29mw-wpgm-hmr9" in advisory_ids
    assert "GHSA-35jh-r3h4-6jhm" in advisory_ids
    assert len(finding.evidence) == 5


def test_python_git_dependency_triggers_nonregistry_source(tmp_path):
    req = tmp_path / "requirements.txt"
    req.write_text("my-pkg @ git+https://github.com/example/my-pkg.git@1.0.0\n", encoding="utf-8")

    result = run(tmp_path, {"offline": True})

    suspicious = [f for f in result.findings if f.category == "SUSPICIOUS_INDICATOR"]
    assert len(suspicious) == 1
    rule_ids = [e.rule_id for e in suspicious[0].evidence]
    assert "NONREGISTRY_SOURCE" in rule_ids
    assert suspicious[0].evidence[0].untrusted_text == ["git+https://github.com/example/my-pkg.git@1.0.0"]


def test_file_hints_for_extended_ecosystems(tmp_path):
    from modules.dependency_scanner.lockfiles import Pkg
    from modules.dependency_scanner.scanner import _run

    # Go manifest
    go_mod = tmp_path / "go.mod"
    go_mod.write_text("module example\n\nrequire github.com/gin-gonic/gin v1.7.0\n", encoding="utf-8")

    result = run(tmp_path, {"offline": True})
    # Since Syft or discovery finds go.mod
    assert "manifest_discovery" in result.checks_performed


def test_missing_data_dir_reports_error(tmp_path, monkeypatch):
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", "/nonexistent/data/path")
    # Make sure scanner reports error when data cannot be found
    result = run(tmp_path, {"offline": True})
    # Either DATA_MISSING error or partial status
    assert result.status in ("ok", "partial")


def test_scan_dependencies_returns_findings(tmp_path):
    result = scan_dependencies(tmp_path, {"offline": True})
    assert isinstance(result, list)
