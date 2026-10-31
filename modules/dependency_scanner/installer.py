"""Dependency installer and package manager detector for BuildGuard."""

import json
import os
import shutil
import subprocess
from pathlib import Path


PACKAGE_MANAGERS = {
    "package-lock.json": "npm",
    "pnpm-lock.yaml": "pnpm",
    "yarn.lock": "yarn",
    "bun.lock": "bun",
    "bun.lockb": "bun",
}


def detect_package_manager(dir_path):
    """Detect the appropriate package manager and installation command for a directory."""
    dir_p = Path(dir_path)

    for lockfile, pm in PACKAGE_MANAGERS.items():
        if (dir_p / lockfile).is_file():
            if pm == "npm":
                cmd = ["npm", "ci", "--ignore-scripts"]
            elif pm == "pnpm":
                cmd = ["pnpm", "install", "--frozen-lockfile", "--ignore-scripts"]
            elif pm == "yarn":
                cmd = ["yarn", "install", "--frozen-lockfile", "--ignore-scripts"]
            elif pm == "bun":
                cmd = ["bun", "install", "--frozen-lockfile", "--ignore-scripts"]
            return pm, cmd, lockfile

    # Default to npm if no lockfile is found
    return "npm", ["npm", "install", "--ignore-scripts", "--no-save"], None


def check_has_scripts(manifest_path):
    """Check if package.json defines install lifecycle scripts."""
    try:
        data = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
        scripts = data.get("scripts", {})
        if isinstance(scripts, dict):
            lifecycle_hooks = {"preinstall", "install", "postinstall", "prepublish", "prepare"}
            return [hook for hook in lifecycle_hooks if hook in scripts]
    except Exception:
        pass
    return []


def install_manifest_dependencies(manifest_path, timeout=120, dry_run=False):
    """Install dependencies declared in a single package.json manifest."""
    manifest_p = Path(manifest_path).resolve()
    dir_p = manifest_p.parent

    pm, cmd, lockfile = detect_package_manager(dir_p)
    lifecycle_hooks = check_has_scripts(manifest_p)

    report = {
        "manifest": str(manifest_p),
        "directory": str(dir_p),
        "package_manager": pm,
        "lockfile": lockfile,
        "command": " ".join(cmd),
        "status": "pending",
        "has_lifecycle_scripts": bool(lifecycle_hooks),
        "lifecycle_hooks": lifecycle_hooks,
        "error": None,
    }

    bin_name = cmd[0]
    bin_path = shutil.which(bin_name)
    if not bin_path:
        report["status"] = "skipped"
        report["error"] = f"Package manager binary '{bin_name}' not found in PATH"
        return report

    if dry_run:
        report["status"] = "dry_run"
        return report

    env = dict(os.environ, COREPACK_ENABLE_DOWNLOAD_PROMPT="0")

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(dir_p),
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            check=False,
        )
        if proc.returncode == 0:
            report["status"] = "success"
        else:
            # If frozen/ci command failed due to lockfile sync issues, attempt fallback with safe flags
            fallback_cmd = None
            if cmd[:2] == ["npm", "ci"]:
                fallback_cmd = ["npm", "install", "--ignore-scripts", "--no-save"]
            elif cmd[:2] == ["yarn", "install"] and "--frozen-lockfile" in cmd:
                fallback_cmd = ["yarn", "install", "--ignore-scripts"]
            elif cmd[:2] == ["pnpm", "install"] and "--frozen-lockfile" in cmd:
                fallback_cmd = ["pnpm", "install", "--ignore-scripts"]

            if fallback_cmd:
                proc_fb = subprocess.run(
                    fallback_cmd,
                    cwd=str(dir_p),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    check=False,
                )
                if proc_fb.returncode == 0:
                    report["status"] = "success"
                    report["command"] = " ".join(fallback_cmd)
                    return report

            report["status"] = "failed"
            err_msg = (proc.stderr or proc.stdout or "").strip()
            report["error"] = err_msg[:300] if err_msg else f"Command exited with code {proc.returncode}"
    except subprocess.TimeoutExpired:
        report["status"] = "failed"
        report["error"] = f"Installation timed out after {timeout}s"
    except Exception as exc:
        report["status"] = "failed"
        report["error"] = str(exc)[:300]

    return report


def install_all(manifests, offline=False, timeout=120):
    """Install dependencies for all discovered package.json files."""
    results = {
        "status": "ok",
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "skipped": 0,
        "projects": [],
    }

    pkg_json_files = []
    seen_dirs = set()
    for m in manifests:
        p = Path(m)
        if p.name == "package.json":
            parent = str(p.parent.resolve())
            if parent not in seen_dirs:
                seen_dirs.add(parent)
                pkg_json_files.append(p)

    if not pkg_json_files:
        results["status"] = "skipped"
        results["detail"] = "no package.json manifests found"
        return results

    if offline:
        results["status"] = "skipped"
        results["detail"] = "offline mode enabled"
        for p in pkg_json_files:
            results["projects"].append({
                "manifest": str(p),
                "directory": str(p.parent),
                "status": "skipped",
                "reason": "offline mode enabled",
            })
            results["skipped"] += 1
        return results

    for p in pkg_json_files:
        results["attempted"] += 1
        rep = install_manifest_dependencies(p, timeout=timeout)
        results["projects"].append(rep)
        if rep["status"] == "success":
            results["succeeded"] += 1
        elif rep["status"] == "failed":
            results["failed"] += 1
            results["status"] = "partial" if results["succeeded"] > 0 else "failed"
        elif rep["status"] == "skipped":
            results["skipped"] += 1

    return results
