"""Focused tests for compiler target resolution and external workspace handling.

Verifies:
1. User-specified relative compiler paths resolve against the project workspace.
2. Explicit absolute paths are validated and preserved only within permitted roots.
3. Path traversal escaping the project workspace is rejected.
4. Bundled compiler sample fallback is preserved for the repo demo workflow.
5. Bundled sample is NOT silently substituted when an external user workspace is scanned.
6. Real external workspace with C source files identifies the actual target in report.
"""

import time
from pathlib import Path
import pytest
from starlette.testclient import TestClient

from backend.main import app, TOKEN
from backend.orchestrator import _resolve_compiler_target, REPO_ROOT, start_scan
from backend import store


H = {"X-BuildGuard-Token": TOKEN}
client = TestClient(app)


def test_external_workspace_with_c_source_resolves_to_user_project(tmp_path):
    """External workspace containing src/main.c resolves to user workspace, not repo sample."""
    external_ws = tmp_path / "external_c_project"
    (external_ws / "src").mkdir(parents=True)
    (external_ws / "src" / "main.c").write_text("int main(void) { return 0; }\n")

    # 1. No sample specified: resolves to external workspace
    resolved = _resolve_compiler_target(None, str(external_ws))
    assert resolved == str(external_ws.resolve())

    # 2. Dot sample specified: resolves to external workspace
    resolved_dot = _resolve_compiler_target(".", str(external_ws))
    assert resolved_dot == str(external_ws.resolve())

    # 3. Default VS Code setting ('test_samples/compiler_hello') does NOT substitute repo sample
    # It recognizes the user workspace itself as the C project
    resolved_default = _resolve_compiler_target("test_samples/compiler_hello", str(external_ws))
    assert resolved_default == str(external_ws.resolve())
    assert "shieldops" not in resolved_default or str(external_ws) in resolved_default


def test_external_workspace_without_c_source_does_not_substitute_bundled_sample(tmp_path):
    """External workspace without C sources must NOT silently scan the bundled sample."""
    empty_ws = tmp_path / "empty_workspace"
    empty_ws.mkdir()

    # When no C sources exist in the external workspace and default sample is given:
    # Must return None (module will skip with clear error), NEVER silently scan bundled sample
    resolved = _resolve_compiler_target("test_samples/compiler_hello", str(empty_ws))
    assert resolved is None

    # When no sample is given:
    resolved_none = _resolve_compiler_target(None, str(empty_ws))
    assert resolved_none is None


def test_compiler_target_path_traversal_is_blocked(tmp_path):
    """Path traversal escaping the project workspace is strictly blocked."""
    ws = tmp_path / "project"
    ws.mkdir()

    # Traversal escaping workspace root
    assert _resolve_compiler_target("../../etc", str(ws)) is None
    assert _resolve_compiler_target("../other", str(ws)) is None


def test_compiler_target_absolute_paths_validation(tmp_path, monkeypatch):
    """Explicit absolute paths are validated against permitted workspace boundaries."""
    ws = tmp_path / "project"
    sub = ws / "sub_c"
    sub.mkdir(parents=True)

    # Absolute path inside project workspace is permitted
    assert _resolve_compiler_target(str(sub), str(ws)) == str(sub.resolve())

    # Outside absolute path without workspace root permission
    outside = tmp_path / "outside_dir"
    outside.mkdir()
    assert _resolve_compiler_target(str(outside), str(ws)) is None

    # Outside absolute path with explicit BUILDGUARD_WORKSPACE_ROOT covering both
    monkeypatch.setenv("BUILDGUARD_WORKSPACE_ROOT", str(tmp_path))
    assert _resolve_compiler_target(str(outside), str(ws)) == str(outside.resolve())


def test_bundled_compiler_sample_preserved_for_demo_workflow():
    """Demo workflow on REPO_ROOT resolves bundled sample correctly."""
    resolved = _resolve_compiler_target("test_samples/compiler_hello", str(REPO_ROOT))
    expected = (REPO_ROOT / "test_samples" / "compiler_hello").resolve()
    assert resolved == str(expected)

    # When no sample is given on REPO_ROOT, fallback to bundled sample
    resolved_none = _resolve_compiler_target(None, str(REPO_ROOT))
    assert resolved_none == str(expected)


def test_real_external_workspace_scan_identifies_target_in_report(tmp_path, monkeypatch):
    """API scan on external workspace records the actual workspace target in report."""
    monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))

    ext_project = tmp_path / "ext_user_app"
    src_dir = ext_project / "src"
    src_dir.mkdir(parents=True)
    (src_dir / "main.c").write_text("int user_custom_func(void) { return 42; }\nint main(void) { return user_custom_func(); }\n")

    # Start scan via API
    resp = client.post(
        "/v1/scans",
        headers=H,
        json={
            "project_path": str(ext_project),
            "modules": ["compiler"],
            "options": {
                "compiler_sample": "test_samples/compiler_hello",  # Extension default
                "use_llm": False,
            },
        },
    )
    assert resp.status_code == 202
    scan_id = resp.json()["scan_id"]

    # Wait for completion (bounded timeout with diagnostic on expiration)
    start_time = time.time()
    timeout = 30.0
    state = {}
    report_resp = None

    while time.time() - start_time < timeout:
        r = client.get(f"/v1/scans/{scan_id}", headers=H)
        assert r.status_code == 200
        state = r.json()
        if state.get("state") in ("completed", "completed_with_errors", "failed", "cancelled"):
            report_resp = client.get(f"/v1/scans/{scan_id}/report", headers=H)
            break
        time.sleep(0.15)

    if report_resp is None:
        elapsed = time.time() - start_time
        raise TimeoutError(
            f"Scan {scan_id} did not finish within {timeout}s (elapsed: {elapsed:.2f}s, last state: {state})"
        )

    assert report_resp.status_code == 200
    report = report_resp.json()

    # The report module status must record the actual analyzed target
    compiler_status = report["module_status"]["compiler"]
    assert "target" in compiler_status
    assert compiler_status["target"] == str(ext_project.resolve())
    assert "compiler_hello" not in compiler_status["target"]
