import json
import os
import subprocess
from pathlib import Path
from urllib.parse import unquote


ECOSYSTEMS = {
    "npm": "npm",
    "pypi": "PyPI",
    "golang": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
}


class SyftError(Exception):
    def __init__(self, code, msg=""):
        super().__init__(msg or code)
        self.code = code


def parse_purl(purl):
    if not purl or not purl.startswith("pkg:"):
        return None

    body = purl[4:].split("#")[0].split("?")[0]
    typ, _, rest = body.partition("/")

    if not typ or not rest:
        return None

    if rest.startswith("@"):
        if rest.count("@") >= 2:
            name, _, version = rest.rpartition("@")
        else:
            name, version = rest, ""
    else:
        if "@" in rest:
            name, _, version = rest.rpartition("@")
        else:
            name, version = rest, ""

    name = unquote(name)
    version = unquote(version)

    if not name:
        return None

    if typ == "maven":
        name = name.replace("/", ":")

    return typ, name, version or None


def run_syft(project_path, out_path, timeout=120):
    syft = os.environ.get("BUILDGUARD_SYFT_BIN", "syft")
    cmd = [
        syft,
        "scan",
        f"dir:{project_path}",
        "-o",
        f"cyclonedx-json={out_path}",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        raise SyftError("TOOL_MISSING", "syft not found")
    except subprocess.TimeoutExpired:
        raise SyftError("TIMEOUT", "syft timed out")

    if result.returncode != 0:
        raise SyftError("PARSE_ERROR", result.stderr[:300])

    if not Path(out_path).is_file():
        raise SyftError("PARSE_ERROR", "Syft did not create the SBOM file")


def parse_cyclonedx(path):
    with Path(path).open(encoding="utf-8") as file:
        data = json.load(file)

    components = []

    for component in data.get("components", []):
        parsed = parse_purl(component.get("purl"))

        if parsed:
            components.append(parsed)
        elif component.get("type") == "library" and component.get("name"):
            components.append(
                (None, component["name"], component.get("version"))
            )

    version = None
    try:
        version = data["metadata"]["tools"]["components"][0]["version"]
    except (KeyError, IndexError, TypeError):
        pass

    return components, version
