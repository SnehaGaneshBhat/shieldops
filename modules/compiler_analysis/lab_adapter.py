"""Thin adapter around the shared P2 Docker runner."""

import os

try:
    from backend import docker_runner as dr
except Exception:
    dr = None

IMAGE = os.environ.get("BUILDGUARD_COMPILER_LAB_IMAGE", "buildguard/compiler-lab:0.1")


class LabError(Exception):
    def __init__(self, code, message, detail=""):
        super().__init__(message)
        self.code, self.message, self.detail = code, message, detail


def check():
    if dr is None:
        return ("TOOL_MISSING", "backend/docker_runner.py not found. Merge the P2 runner and retry")
    if not dr.docker_available():
        return ("DOCKER_UNAVAILABLE", "Docker is not running or not installed")
    if not dr.image_present(IMAGE):
        return ("TOOL_MISSING", f"Image {IMAGE} not found. Build it: docker build -t {IMAGE} docker/compiler-lab")
    return None


def run_lab(sample_dir, out_dir, project_cc="clang", opt_level="-O0", strip=False,
            timeout=180, scan_id="adhoc"):
    if dr is None:
        raise LabError("TOOL_MISSING", "backend/docker_runner.py not found")
    try:
        result = dr.run_container(
            IMAGE, ["lab_run.sh"],
            mounts=[(str(sample_dir), "/work/sample", "ro"), (str(out_dir), "/out", "rw")],
            env={"PROJECT_CC": project_cc, "BG_OPT": opt_level, "BG_STRIP": "1" if strip else "0"},
            network_none=True, timeout=timeout, scan_id=scan_id,
        )
    except Exception as exc:
        raise LabError(getattr(exc, "code", "DOCKER_UNAVAILABLE"), getattr(exc, "message", str(exc)),
                       getattr(exc, "detail", "")) from exc
    if result.timed_out or result.error == "TIMEOUT":
        raise LabError("TIMEOUT", f"Compiler lab exceeded {timeout}s", result.stderr[-2000:])
    if result.error:
        raise LabError(result.error, "Compiler lab could not start", result.stderr[-2000:])
    if result.returncode != 0:
        raise LabError("PARSE_ERROR", "Compiler lab script failed", (result.stderr or result.stdout)[-2000:])
    return result.stdout
