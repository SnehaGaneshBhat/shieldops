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

