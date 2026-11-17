import os
import shutil
import stat
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
CHECK_ENV_SCRIPT = REPO_ROOT / "scripts" / "check_env.sh"


def test_check_env_script_exists_and_is_executable():
    assert CHECK_ENV_SCRIPT.exists()
    assert os.access(CHECK_ENV_SCRIPT, os.R_OK)


def test_check_env_node_current_system():
    # Run the real script; git, python3.12, node, syft should pass
    res = subprocess.run(["bash", str(CHECK_ENV_SCRIPT)], capture_output=True, text=True)
    assert "PASS git" in res.stdout
    assert "PASS python3.12" in res.stdout
    assert "PASS node" in res.stdout


def test_check_env_accepts_node_20(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_node = bin_dir / "node"
    fake_node.write_text("#!/bin/sh\necho 'v20.18.0'\n")
    fake_node.chmod(fake_node.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    res = subprocess.run(["bash", str(CHECK_ENV_SCRIPT)], env=env, capture_output=True, text=True)
    assert "PASS node (v20)" in res.stdout


def test_check_env_accepts_node_22(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_node = bin_dir / "node"
    fake_node.write_text("#!/bin/sh\necho 'v22.1.0'\n")
    fake_node.chmod(fake_node.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    res = subprocess.run(["bash", str(CHECK_ENV_SCRIPT)], env=env, capture_output=True, text=True)
    assert "PASS node (v22)" in res.stdout


def test_check_env_rejects_node_below_20(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    fake_node = bin_dir / "node"
    fake_node.write_text("#!/bin/sh\necho 'v18.19.1'\n")
    fake_node.chmod(fake_node.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    res = subprocess.run(["bash", str(CHECK_ENV_SCRIPT)], env=env, capture_output=True, text=True)
    assert "FAIL node - found v18.19.1; Node.js 20 or later required" in res.stdout


def test_check_env_handles_missing_node(tmp_path):
    # Remove any directory containing 'node' from PATH
    paths = os.environ.get("PATH", "").split(os.pathsep)
    filtered_paths = []
    for p in paths:
        if not (Path(p) / "node").exists():
            filtered_paths.append(p)

    env = os.environ.copy()
    env["PATH"] = os.pathsep.join(filtered_paths)

    bash_bin = shutil.which("bash") or "/bin/bash"
    res = subprocess.run([bash_bin, str(CHECK_ENV_SCRIPT)], env=env, capture_output=True, text=True)
    assert "FAIL node - install Node.js 20 or later (needed by P4 only)" in res.stdout
