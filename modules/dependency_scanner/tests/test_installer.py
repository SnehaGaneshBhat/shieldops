import json
import subprocess
from pathlib import Path

from modules.dependency_scanner.installer import (
    check_has_scripts,
    detect_package_manager,
    install_all,
    install_manifest_dependencies,
)


def test_detect_package_manager_npm_lock(tmp_path):
    (tmp_path / "package-lock.json").touch()
    pm, cmd, lockfile = detect_package_manager(tmp_path)
    assert pm == "npm"
    assert "ci" in cmd
    assert "--ignore-scripts" in cmd
    assert lockfile == "package-lock.json"


def test_detect_package_manager_pnpm_lock(tmp_path):
    (tmp_path / "pnpm-lock.yaml").touch()
    pm, cmd, lockfile = detect_package_manager(tmp_path)
    assert pm == "pnpm"
    assert "--frozen-lockfile" in cmd
    assert lockfile == "pnpm-lock.yaml"


def test_detect_package_manager_yarn_lock(tmp_path):
    (tmp_path / "yarn.lock").touch()
    pm, cmd, lockfile = detect_package_manager(tmp_path)
    assert pm == "yarn"
    assert "--frozen-lockfile" in cmd
    assert lockfile == "yarn.lock"


def test_detect_package_manager_bun_lock(tmp_path):
    (tmp_path / "bun.lockb").touch()
    pm, cmd, lockfile = detect_package_manager(tmp_path)
    assert pm == "bun"
    assert "--frozen-lockfile" in cmd
    assert lockfile == "bun.lockb"


def test_detect_package_manager_default(tmp_path):
    pm, cmd, lockfile = detect_package_manager(tmp_path)
    assert pm == "npm"
    assert "install" in cmd
    assert "--no-save" in cmd
    assert lockfile is None


def test_check_has_scripts(tmp_path):
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({
        "name": "pkg-with-scripts",
        "scripts": {
            "postinstall": "node build.js",
            "test": "jest",
        }
    }), encoding="utf-8")

    hooks = check_has_scripts(manifest)
    assert hooks == ["postinstall"]


def test_install_manifest_missing_binary(tmp_path, monkeypatch):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: None)

    rep = install_manifest_dependencies(manifest)
    assert rep["status"] == "skipped"
    assert "not found in PATH" in rep["error"]


def test_install_manifest_failure_captured(tmp_path, monkeypatch):
    manifest = tmp_path / "package.json"
    manifest.write_text("{}", encoding="utf-8")

    import shutil
    monkeypatch.setattr(shutil, "which", lambda cmd: "/fake/npm")

    def mock_run(*args, **kwargs):
        return subprocess.CompletedProcess(
            args=args, returncode=1, stdout="", stderr="npm ERR! 404 Not Found"
        )

    monkeypatch.setattr(subprocess, "run", mock_run)

    rep = install_manifest_dependencies(manifest)
    assert rep["status"] == "failed"
    assert "npm ERR! 404" in rep["error"]


def test_install_all_offline_skips(tmp_path):
    (tmp_path / "package.json").touch()
    res = install_all([tmp_path / "package.json"], offline=True)
    assert res["status"] == "skipped"
    assert res["skipped"] == 1
