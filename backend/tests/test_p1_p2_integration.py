"""Comprehensive end-to-end integration tests between P1 and P2.

These tests exercise the actual execution path through the FastAPI API routes,
authentication, request validation, the orchestrator, shared schemas, storage
persistence, and real module execution without bypassing the architecture.
"""

import json
import os
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.main import app, TOKEN
from backend import store
from modules.dependency_scanner.osv_client import OSVClient


H = {"X-BuildGuard-Token": TOKEN}
client = TestClient(app)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _wait_for_scan(client, scan_id, timeout=15.0):
    """Poll scan state until terminal state or timeout."""
    start = time.time()
    state = {}
    while time.time() - start < timeout:
        res = client.get(f"/v1/scans/{scan_id}", headers=H)
        assert res.status_code == 200
        state = res.json()
        if state["state"] in ("completed", "completed_with_errors", "failed", "cancelled"):
            return state
        time.sleep(0.15)
    raise TimeoutError(f"Scan {scan_id} did not finish within {timeout}s (last state: {state})")


# 1. Clean dependency scan
def test_real_api_dependency_scan_clean(tmp_path, monkeypatch):
    """Test real API scan on clean sample project verifying complete pipeline and persistence."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed"
    assert state["modules"] == {"dependency": "completed"}
    assert state["errors"] == []

    # Verify findings endpoint
    findings_resp = client.get(f"/v1/scans/{scan_id}/findings", headers=H)
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert len(findings_data["findings"]) == 1
    f0 = findings_data["findings"][0]
    assert f0["category"] == "NO_KNOWN_ISSUES"
    assert f0["module"] == "dependency"
    assert f0["severity"] == "INFO"

    # Verify report endpoint
    report_resp = client.get(f"/v1/scans/{scan_id}/report", headers=H)
    assert report_resp.status_code == 200
    report = report_resp.json()
    assert report["scan_id"] == scan_id
    assert report["module_status"]["dependency"]["status"] == "ok"
    assert "syft_sbom" in report["module_status"]["dependency"]["checks_performed"]
    assert "npm_lockfile_parse" in report["module_status"]["dependency"]["checks_performed"]
    assert len(report["items"]) == 1
    assert report["items"][0]["category"] == "NO_KNOWN_ISSUES"
    assert report["items"][0]["plain_explanation"] != ""


# 2. Vulnerable npm dependency
def test_real_api_dependency_scan_vuln_npm(tmp_path, monkeypatch):
    """Test real API scan on vulnerable sample detecting known vulnerabilities."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    vuln_sample = REPO_ROOT / "test_samples" / "deps_vuln_npm"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(vuln_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed"

    report_resp = client.get(f"/v1/scans/{scan_id}/report", headers=H)
    assert report_resp.status_code == 200
    report = report_resp.json()
    assert len(report["items"]) >= 1

    vuln_items = [it for it in report["items"] if it["category"] == "KNOWN_VULNERABILITY"]
    assert len(vuln_items) == 1
    item = vuln_items[0]
    assert item["subject"]["name"] == "lodash"
    assert item["subject"]["version"] == "4.17.20"
    assert item["severity"] in ("HIGH", "CRITICAL")
    assert item["confidence"] == "CONFIRMED"
    assert item["explanation_source"] == "template"
    assert "advisory exists" in item["plain_explanation"]


# 3. Suspicious npm dependency
def test_real_api_dependency_scan_suspicious_npm(tmp_path, monkeypatch):
    """Test real API scan detecting suspicious indicators (typosquat, install script, new package)."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    suspicious_sample = REPO_ROOT / "test_samples" / "deps_suspicious_npm"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(suspicious_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed"

    report_resp = client.get(f"/v1/scans/{scan_id}/report", headers=H)
    report = report_resp.json()

    susp_items = [it for it in report["items"] if it["category"] == "SUSPICIOUS_INDICATOR"]
    assert len(susp_items) == 1
    item = susp_items[0]
    assert item["subject"]["name"] == "lodahs"
    evidence_types = {ev["rule_id"] for ev in item["evidence"] if ev.get("rule_id")}
    assert "TYPOSQUAT" in evidence_types
    assert "INSTALL_SCRIPT" in evidence_types


# 4. Multiple package manifests
def test_real_api_dependency_scan_multi_package(tmp_path, monkeypatch):
    """Test real API scan on multi-package project with nested directories."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    multi_sample = REPO_ROOT / "test_samples" / "deps_multi_package"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(multi_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "ok"
    items = report["items"]
    assert any(it["category"] == "KNOWN_VULNERABILITY" and it["subject"].get("name") == "lodash" for it in items)


# 5. C/C++ dependency scan regression
def test_real_api_cpp_dependency_scan(tmp_path, monkeypatch):
    """Test real API scan against C/C++ project with vcpkg manifest."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    cpp_sample = REPO_ROOT / "test_samples" / "deps_vuln_cpp"

    def mock_query_ids(self, packages):
        return {package: [] for package in packages}, []

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(cpp_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "ok"
    assert "syft_sbom" in report["module_status"]["dependency"]["checks_performed"]
    assert len(report["items"]) == 1
    assert report["items"][0]["category"] == "NO_KNOWN_ISSUES"


# 6. Combined dependency and build scan
def test_real_api_combined_dependency_and_build(tmp_path, monkeypatch):
    """Test real API scan running both dependency and build integrity modules concurrently."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency", "build"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"
    assert state["modules"]["dependency"] == "completed"
    assert state["modules"]["build"] == "skipped"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert set(report["module_status"].keys()) == {"dependency", "build"}
    assert report["module_status"]["dependency"]["status"] == "ok"
    assert report["module_status"]["build"]["status"] == "skipped"

    modules_in_items = {it["module"] for it in report["items"]}
    assert "dependency" in modules_in_items
    assert "build" in modules_in_items


# 7. Module failure while another module succeeds
def test_real_api_module_failure_isolation(tmp_path, monkeypatch):
    """Test that a failure in one module does not erase valid results from another module."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency", "build"],
            "options": {"offline": True, "recipe_path": "nonexistent.yml"},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"
    assert state["modules"]["dependency"] == "completed"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "ok"
    dep_items = [it for it in report["items"] if it["module"] == "dependency"]
    assert len(dep_items) == 1
    assert dep_items[0]["category"] == "NO_KNOWN_ISSUES"


# 8. Malformed manifest
def test_real_api_dependency_scan_malformed_manifest(tmp_path, monkeypatch):
    """Test scan error resilience when encountering a malformed package.json."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "package.json").write_text("{ not valid json")

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(proj),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "partial"
    errs = report["module_status"]["dependency"]["errors"]
    assert any(e.get("code") == "MALFORMED_MANIFEST" for e in errs)
    assert any("MALFORMED_MANIFEST" in limit for limit in report["limitations"])


# 9. Offline OSV cache miss
def test_real_api_offline_cache_miss_reports_unresolved(tmp_path, monkeypatch):
    """Test that an uncached dependency in offline mode reports UNRESOLVED rather than clean."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    proj = tmp_path / "proj_uncached"
    proj.mkdir()
    (proj / "package.json").write_text('{"name": "test", "dependencies": {"uncached-pkg-xyz": "1.0.0"}}')

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(proj),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "partial"
    assert not any(it["category"] == "NO_KNOWN_ISSUES" for it in report["items"])
    assert any(it["category"] == "UNRESOLVED" for it in report["items"])


# 10. Partial OSV results
def test_real_api_partial_osv_results(tmp_path, monkeypatch):
    """Test handling when some dependencies succeed in OSV lookup while others fail."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    proj = tmp_path / "proj_partial_osv"
    proj.mkdir()
    (proj / "package.json").write_text(
        '{"name": "test", "dependencies": {"pkg-success": "1.0.0", "pkg-fail": "2.0.0"}}'
    )

    def mock_query_ids(self, packages):
        success_pkg = ("npm", "pkg-success", "1.0.0")
        fail_pkg = ("npm", "pkg-fail", "2.0.0")
        return {success_pkg: ["GHSA-sample-advisory"]}, [fail_pkg]

    def mock_get_vuln(self, vuln_id):
        return {
            "id": "GHSA-sample-advisory",
            "summary": "Sample advisory",
            "aliases": ["CVE-2026-99999"],
            "severity": "HIGH",
            "fixed_in": ["1.0.1"],
        }

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)
    monkeypatch.setattr(OSVClient, "get_vuln", mock_get_vuln)

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(proj),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "partial"
    categories = {it["category"] for it in report["items"]}
    assert "KNOWN_VULNERABILITY" in categories
    assert "UNRESOLVED" in categories


# 11. SBOM persistence and contents
def test_real_api_sbom_persistence_and_contents(tmp_path, monkeypatch):
    """Test that Syft generates a valid CycloneDX SBOM persisted in the scan directory."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    _wait_for_scan(client, scan_id)

    scan_dir = store.scan_folder(scan_id)
    sbom_path = scan_dir / "sbom.json"
    assert sbom_path.is_file()

    sbom_data = json.loads(sbom_path.read_text(encoding="utf-8"))
    assert sbom_data.get("bomFormat") == "CycloneDX"
    assert "components" in sbom_data
    assert len(sbom_data["components"]) >= 1


# 12. Explicit SBOM output path precedence
def test_real_api_explicit_sbom_path_precedence(tmp_path, monkeypatch):
    """Test that explicit sbom_path / sbom_out is respected and written to the requested path."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"
    custom_sbom = tmp_path / "custom_output" / "my_sbom.json"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency"],
            "options": {"offline": True, "sbom_path": str(custom_sbom)},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    _wait_for_scan(client, scan_id)

    assert custom_sbom.is_file()
    custom_data = json.loads(custom_sbom.read_text(encoding="utf-8"))
    assert custom_data.get("bomFormat") == "CycloneDX"

    scan_dir_sbom = store.scan_folder(scan_id) / "sbom.json"
    assert scan_dir_sbom.is_file()


# 13. Cancellation
def test_real_api_scan_cancellation(tmp_path, monkeypatch):
    """Test scan cancellation through API route and verification of cancelled state."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency"],
            "options": {"offline": True},
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    cancel_resp = client.post(f"/v1/scans/{scan_id}/cancel", headers=H)
    assert cancel_resp.status_code == 200
    assert cancel_resp.json()["state"] == "cancelled"

    state = client.get(f"/v1/scans/{scan_id}", headers=H).json()
    assert state["state"] == "cancelled"


# 14. Correct terminal scan states
def test_real_api_terminal_scan_states(tmp_path, monkeypatch):
    """Test transitions to correct terminal states: completed, completed_with_errors."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))

    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"
    r1 = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(clean_sample), "modules": ["dependency"], "options": {"offline": True}},
    )
    s1 = _wait_for_scan(client, r1.json()["scan_id"])
    assert s1["state"] == "completed"

    r2 = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(clean_sample), "modules": ["dependency", "build"], "options": {"offline": True}},
    )
    s2 = _wait_for_scan(client, r2.json()["scan_id"])
    assert s2["state"] == "completed_with_errors"


# 15. Partial result reporting
def test_real_api_partial_result_reporting(tmp_path, monkeypatch):
    """Test that partial results are clearly reported as partial with limitations populated."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    proj = tmp_path / "proj_partial_rep"
    proj.mkdir()
    (proj / "package.json").write_text("{ malformed")

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(proj), "modules": ["dependency"], "options": {"offline": True}},
    )
    scan_id = resp.json()["scan_id"]
    state = _wait_for_scan(client, scan_id)
    assert state["state"] == "completed_with_errors"

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert report["module_status"]["dependency"]["status"] == "partial"
    assert len(report["limitations"]) > len(store.LIMITS if hasattr(store, "LIMITS") else [])


# 16. Finding aggregation and unique IDs
def test_real_api_finding_aggregation_and_unique_ids(tmp_path, monkeypatch):
    """Test that findings from multiple modules/rules are aggregated with sequential unique IDs."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    suspicious_sample = REPO_ROOT / "test_samples" / "deps_suspicious_npm"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(suspicious_sample), "modules": ["dependency", "build"], "options": {"offline": True}},
    )
    scan_id = resp.json()["scan_id"]
    _wait_for_scan(client, scan_id)

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    items = report["items"]
    assert len(items) >= 2

    ids = [it["id"] for it in items]
    assert len(ids) == len(set(ids))
    for i, fid in enumerate(ids, 1):
        assert fid == f"F-{i:03d}"


# 17. Invalid API options rejected
def test_real_api_invalid_options_rejected():
    """Test that arbitrary or unsupported options are rejected with HTTP 422."""
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"
    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(clean_sample),
            "modules": ["dependency"],
            "options": {"unsupported_arbitrary_flag": 123},
        },
    )
    assert resp.status_code == 422


# 18. Authentication and authorization
def test_real_api_auth_requirements(tmp_path, monkeypatch):
    """Test that unauthenticated requests to protected endpoints return 401."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))

    r1 = client.post("/v1/scans", json={"project_path": str(tmp_path)})
    assert r1.status_code == 401

    r2 = client.post(
        "/v1/scans",
        headers={"X-BuildGuard-Token": "invalid-token-value"},
        json={"project_path": str(tmp_path)},
    )
    assert r2.status_code == 401

    r3 = client.get("/v1/scans/dummy-scan-id", headers={"X-BuildGuard-Token": "invalid"})
    assert r3.status_code == 401


# 19. Result persistence and retrieval
def test_real_api_persistence_and_retrieval(tmp_path, monkeypatch):
    """Test retrieval of persisted state, findings, report JSON, and report HTML."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    clean_sample = REPO_ROOT / "test_samples" / "deps_clean"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(clean_sample), "modules": ["dependency"], "options": {"offline": True}},
    )
    scan_id = resp.json()["scan_id"]
    _wait_for_scan(client, scan_id)

    st = client.get(f"/v1/scans/{scan_id}", headers=H)
    assert st.status_code == 200
    assert st.json()["scan_id"] == scan_id

    fd = client.get(f"/v1/scans/{scan_id}/findings", headers=H)
    assert fd.status_code == 200
    assert "findings" in fd.json()

    rp = client.get(f"/v1/scans/{scan_id}/report", headers=H)
    assert rp.status_code == 200
    assert rp.json()["scan_id"] == scan_id

    ht = client.get(f"/v1/scans/{scan_id}/report.html", headers=H)
    assert ht.status_code == 200
    assert "text/html" in ht.headers.get("content-type", "")


# 20. Report generation structure
def test_real_api_report_generation_structure(tmp_path, monkeypatch):
    """Test that generated report complies with expected schema and summary counts."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))
    vuln_sample = REPO_ROOT / "test_samples" / "deps_vuln_npm"

    resp = client.post(
        "/v1/scans",
        headers=H,
        json={"project_path": str(vuln_sample), "modules": ["dependency"], "options": {"offline": True}},
    )
    scan_id = resp.json()["scan_id"]
    _wait_for_scan(client, scan_id)

    report = client.get(f"/v1/scans/{scan_id}/report", headers=H).json()
    assert "scan_id" in report
    assert "generated_at" in report
    assert "overall_summary" in report
    assert "summary_counts" in report
    assert "by_category" in report["summary_counts"]
    assert "by_severity" in report["summary_counts"]
    assert "module_status" in report
    assert "limitations" in report
    assert "items" in report

    for item in report["items"]:
        assert item["explanation_source"] == "template"
        assert item["plain_explanation"] != ""
