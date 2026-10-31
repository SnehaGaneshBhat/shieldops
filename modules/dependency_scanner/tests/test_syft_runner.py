import json
import subprocess
from pathlib import Path
import pytest

from modules.dependency_scanner.syft_runner import (
    SyftError,
    parse_cyclonedx,
    run_syft,
)


def test_run_syft_tool_missing(tmp_path, monkeypatch):
    monkeypatch.setenv("BUILDGUARD_SYFT_BIN", "/nonexistent/binary/path/to/syft")
    with pytest.raises(SyftError) as exc_info:
        run_syft(str(tmp_path), str(tmp_path / "sbom.json"))
    assert exc_info.value.code == "TOOL_MISSING"


def test_run_syft_timeout(tmp_path, monkeypatch):
    def mock_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="syft", timeout=1)

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(SyftError) as exc_info:
        run_syft(str(tmp_path), str(tmp_path / "sbom.json"))
    assert exc_info.value.code == "TIMEOUT"


def test_run_syft_nonzero_returncode(tmp_path, monkeypatch):
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="Fatal error")

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(SyftError) as exc_info:
        run_syft(str(tmp_path), str(tmp_path / "sbom.json"))
    assert exc_info.value.code == "PARSE_ERROR"


def test_run_syft_missing_output_file(tmp_path, monkeypatch):
    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)
    with pytest.raises(SyftError) as exc_info:
        run_syft(str(tmp_path), str(tmp_path / "sbom.json"))
    assert exc_info.value.code == "PARSE_ERROR"


def test_run_syft_success(tmp_path, monkeypatch):
    out_file = tmp_path / "sbom.json"

    def mock_run(*args, **kwargs):
        out_file.write_text("{}", encoding="utf-8")
        return subprocess.CompletedProcess(args=args, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)
    run_syft(str(tmp_path), str(out_file))
    assert out_file.is_file()


def test_parse_cyclonedx_valid(tmp_path):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps({
        "metadata": {
            "tools": {
                "components": [{"name": "syft", "version": "1.55.0"}]
            }
        },
        "components": [
            {
                "type": "library",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
            },
            {
                "type": "library",
                "name": "custom-lib",
                "version": "2.0.0",
            }
        ]
    }), encoding="utf-8")

    components, version = parse_cyclonedx(sbom)
    assert version == "1.55.0"
    assert ("npm", "lodash", "4.17.20") in components
    assert (None, "custom-lib", "2.0.0") in components

