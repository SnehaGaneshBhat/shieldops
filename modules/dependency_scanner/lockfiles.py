import json
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Pkg:
    eco: str
    name: str
    version: str = None
    source: str = "registry"
    resolved: str = None
    integrity: str = None
    local_dir: str = None
    manifest: str = None


def parse_npm_lock(lock):
    data = json.loads(Path(lock).read_text(encoding="utf-8"))
    out = []

    for key, metadata in (data.get("packages") or {}).items():
        if key == "" or metadata.get("link"):
            continue

        name = metadata.get("name") or key.split("node_modules/")[-1].rstrip("/").split("/")[-1]
        resolved = metadata.get("resolved")
        local = None

        if "node_modules/" not in key:
            source, local = "local", key
        elif resolved and resolved.startswith(
            "https://registry.npmjs.org/"
        ):
            source = "registry"
        elif resolved and (
            resolved.startswith(("git", "github:")) or ".git" in resolved
        ):
            source = "git"
        elif resolved and resolved.startswith("http"):
            source = "url"
        else:
            source = "unknown"

        out.append(
            Pkg(
                "npm",
                name,
                metadata.get("version"),
                source,
                resolved,
                metadata.get("integrity"),
                local,
                str(lock),
            )
        )

    return out


def norm_pypi(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path):
    out = []

    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.split("#")[0].split(";")[0].strip()

        if not line or line.startswith("-"):
            continue

        if "==" in line:
            name, version = [part.strip() for part in line.split("==", 1)]
            version = version.split(",")[0].split(" ")[0]
        else:
            name = re.split(r"[<>=!~ ]", line)[0]
            version = None

        name = norm_pypi(name.split("[")[0])

        if name:
            out.append(
                Pkg(
                    "pypi",
                    name,
                    version,
                    "registry",
                    manifest=str(path),
                )
            )

    return out
