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

    if "syft_sbom" not in result.checks_performed:
        assert not any(
            finding.category == "NO_KNOWN_ISSUES"
            for finding in result.findings
        )


def test_scan_dependencies_returns_findings(tmp_path):
    result = scan_dependencies(tmp_path, {"offline": True})
    assert isinstance(result, list)
