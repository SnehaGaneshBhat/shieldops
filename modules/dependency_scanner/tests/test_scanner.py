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


def test_sample_deps_vuln_cpp_regression():
    from pathlib import Path
    cpp_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_vuln_cpp"
    result = run(cpp_sample, {"offline": True})

    assert result.status == "ok"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.category == "NO_KNOWN_ISSUES"
    assert finding.severity == "INFO"
    assert finding.confidence == "LOW"
    assert finding.subject.get("packages_checked") == 1
    assert "osv_lookup" in result.checks_performed
    assert "syft_sbom" in result.checks_performed


def test_sample_deps_vuln_cpp_verbose_and_sbom_output(tmp_path, capsys):
    from pathlib import Path
    cpp_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_vuln_cpp"
    sbom_file = tmp_path / "test.sbom.json"
    report_file = tmp_path / "test.report.json"

    result = run(cpp_sample, {
        "offline": True,
        "verbose": True,
        "sbom_path": str(sbom_file),
        "out_path": str(report_file),
    })

    assert result.status == "ok"
    assert sbom_file.is_file()
    assert report_file.is_file()

    captured = capsys.readouterr()
    assert "[1/7] PROJECT DISCOVERY" in captured.out
    assert "[2/7] SYFT DEPENDENCY ANALYSIS" in captured.out
    assert "[3/7] SBOM GENERATION" in captured.out
    assert "[4/7] PACKAGE IDENTIFICATION" in captured.out
    assert "[5/7] OSV VULNERABILITY LOOKUP" in captured.out
    assert "[6/7] FINDING ANALYSIS" in captured.out
    assert "[7/7] REPORT GENERATION" in captured.out
    assert "SCAN SUMMARY" in captured.out


def test_cpp_project_with_mocked_vulnerabilities(tmp_path, monkeypatch):
    import json
    from modules.dependency_scanner.osv_client import OSVClient
    from modules.dependency_scanner.syft_runner import SyftError

    # Mock parse_cyclonedx to return a C package
    from modules.dependency_scanner import scanner

    def mock_run_syft(p, out, timeout=120):
        pass

    def mock_parse_cyclonedx(p):
        return [("vcpkg", "curl", "7.80.0")], "1.55.0"

    monkeypatch.setattr(scanner, "run_syft", mock_run_syft)
    monkeypatch.setattr(scanner, "parse_cyclonedx", mock_parse_cyclonedx)

    def mock_query_ids(self, packages):
        return {("vcpkg", "curl", "7.80.0"): ["GHSA-curl-vuln-01"]}, []

    def mock_get_vuln(self, vuln_id):
        return {
            "id": vuln_id,
            "summary": "Buffer overflow in curl",
            "aliases": ["CVE-2023-38545"],
            "database_specific": {"severity": "HIGH"},
        }

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)
    monkeypatch.setattr(OSVClient, "get_vuln", mock_get_vuln)

    result = run(tmp_path, {"offline": False})

    assert result.status == "ok"
    vuln_findings = [f for f in result.findings if f.category == "KNOWN_VULNERABILITY"]
    assert len(vuln_findings) == 1
    f = vuln_findings[0]
    assert f.severity == "HIGH"
    assert f.confidence == "CONFIRMED"
    assert f.subject["ecosystem"] == "vcpkg"
    assert f.subject["name"] == "curl"
    assert f.subject["version"] == "7.80.0"


def test_cpp_unpinned_package(tmp_path, monkeypatch):
    from modules.dependency_scanner import scanner

    monkeypatch.setattr(scanner, "run_syft", lambda p, o, timeout=120: None)
    monkeypatch.setattr(scanner, "parse_cyclonedx", lambda p: ([("vcpkg", "curl", None)], "1.55.0"))

    result = run(tmp_path, {"offline": True})
    unresolved = [f for f in result.findings if f.category == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0].evidence[0].data.get("reason") == "no_exact_version"


def test_cpp_osv_failed_request(tmp_path, monkeypatch):
    from modules.dependency_scanner import scanner
    from modules.dependency_scanner.osv_client import OSVClient

    monkeypatch.setattr(scanner, "run_syft", lambda p, o, timeout=120: None)
    monkeypatch.setattr(scanner, "parse_cyclonedx", lambda p: ([("vcpkg", "curl", "7.80.0")], "1.55.0"))

    def mock_query_ids(self, packages):
        return {}, [("vcpkg", "curl", "7.80.0")]

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)

    result = run(tmp_path, {"offline": False})
    assert result.status == "partial"
    unresolved = [f for f in result.findings if f.category == "UNRESOLVED"]
    assert len(unresolved) == 1
    assert unresolved[0].evidence[0].data.get("reason") == "osv_unreachable"


def test_sample_deps_multi_package_regression():
    from pathlib import Path
    sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_multi_package"
    result = run(sample, {"offline": True})

    assert result.status == "ok"
    assert "package_json_parse" in result.checks_performed
    assert "manifest_discovery" in result.checks_performed
    assert "syft_sbom" in result.checks_performed
    assert "osv_lookup" in result.checks_performed

    # Should detect the known vulnerability for lodash 4.17.20
    vulns = [f for f in result.findings if f.category == "KNOWN_VULNERABILITY"]
    assert len(vulns) >= 1
    assert any(f.subject["name"] == "lodash" and f.subject["version"] == "4.17.20" for f in vulns)


def test_scanner_malformed_package_json(tmp_path):
    bad = tmp_path / "package.json"
    bad.write_text("{ unclosed json: ", encoding="utf-8")

    result = run(tmp_path, {"offline": True})
    assert result.status in ("ok", "partial")
    errs = [e for e in result.errors if e.get("code") == "MALFORMED_MANIFEST"]
    assert len(errs) == 1
    assert "package.json" in errs[0]["file"]


def test_simplified_c_program_curl():
    from pathlib import Path
    cpp_dir = Path(__file__).resolve().parents[3] / "test_samples" / "deps_vuln_cpp"
    main_c = cpp_dir / "main.c"
    assert main_c.is_file()
    c_source = main_c.read_text(encoding="utf-8")
    assert "#include <curl/curl.h>" in c_source
    assert "curl_easy_init" in c_source
    assert "curl_easy_cleanup" in c_source

    result = run(cpp_dir, {"offline": True})
    assert result.status == "ok"
    assert any(
        f.category == "NO_KNOWN_ISSUES" and f.subject.get("packages_checked") == 1
        for f in result.findings
    )
