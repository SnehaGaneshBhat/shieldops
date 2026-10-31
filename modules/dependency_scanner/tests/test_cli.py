import json
from pathlib import Path

from modules.dependency_scanner.cli import main


def test_cli_default_run(capsys):
    clean_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_clean"
    exit_code = main([str(clean_sample), "--offline"])

    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["module"] == "dependency"
    assert data["status"] == "ok"


def test_cli_out_file(tmp_path):
    clean_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_clean"
    out_file = tmp_path / "result.json"

    exit_code = main([str(clean_sample), "--offline", "--out", str(out_file)])

    assert exit_code == 0
    assert out_file.is_file()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["module"] == "dependency"


def test_cli_error_returns_one():
    exit_code = main(["/nonexistent/directory/path", "--offline"])
    assert exit_code == 1


def test_cli_verbose_flag(capsys, tmp_path):
    clean_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_clean"
    out_file = tmp_path / "report.json"
    exit_code = main([str(clean_sample), "--offline", "--verbose", "--out", str(out_file)])

    assert exit_code == 0
    assert out_file.is_file()
    captured = capsys.readouterr()
    assert "BUILDGUARD DEPENDENCY SCANNER" in captured.out
    assert "[1/7] PROJECT DISCOVERY" in captured.out
    assert "[7/7] REPORT GENERATION" in captured.out
    assert "SCAN SUMMARY" in captured.out


def test_cli_sbom_option(tmp_path):
    cpp_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_vuln_cpp"
    sbom_file = tmp_path / "custom.sbom.json"
    exit_code = main([str(cpp_sample), "--offline", "--sbom", str(sbom_file)])

    assert exit_code == 0
    assert sbom_file.is_file()
    data = json.loads(sbom_file.read_text(encoding="utf-8"))
    assert "bomFormat" in data


def test_cli_install_flags(tmp_path):
    clean_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_clean"
    out_file = tmp_path / "out.json"

    # --no-install
    exit_code = main([str(clean_sample), "--offline", "--no-install", "--out", str(out_file)])
    assert exit_code == 0
    assert out_file.is_file()

    # --install
    exit_code2 = main([str(clean_sample), "--offline", "--install", "--out", str(out_file)])
    assert exit_code2 == 0


def test_cli_multi_package_demo(capsys, tmp_path):
    multi_sample = Path(__file__).resolve().parents[3] / "test_samples" / "deps_multi_package"
    out_file = tmp_path / "multi_report.json"
    exit_code = main([str(multi_sample), "--offline", "--verbose", "--out", str(out_file)])

    assert exit_code == 0
    assert out_file.is_file()
    captured = capsys.readouterr()
    assert "[1/7] PROJECT DISCOVERY" in captured.out
    assert "Dependencies identified:" in captured.out
    assert "express" in captured.out
    assert "lodash" in captured.out
    assert "[7/7] REPORT GENERATION" in captured.out
