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


def _parse_npm_v1(dependencies, lock_path, out=None):
    if out is None:
        out = []

    for name, metadata in dependencies.items():
        resolved = metadata.get("resolved")
        version = metadata.get("version")
        local = None

        if version and str(version).startswith("file:"):
            source = "local"
            local = str(version)[5:]
        elif resolved and resolved.startswith("https://registry.npmjs.org/"):
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
                version,
                source,
                resolved,
                metadata.get("integrity"),
                local,
                str(lock_path),
            )
        )

        nested = metadata.get("dependencies")
        if isinstance(nested, dict):
            _parse_npm_v1(nested, lock_path, out)

    return out

def parse_npm_lock(lock):
    data = json.loads(Path(lock).read_text(encoding="utf-8"))
    out = []

    packages = data.get("packages")
    if packages:
        for key, metadata in packages.items():
            if key == "" or metadata.get("link"):
                continue

            if metadata.get("name"):
                name = metadata["name"]
            elif "node_modules/" in key:
                rel = key.split("node_modules/")[-1].rstrip("/")
                if rel.startswith("@"):
                    name = "/".join(rel.split("/")[:2])
                else:
                    name = rel.split("/")[0]
            else:
                name = key.rstrip("/").split("/")[-1]
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
    elif isinstance(data.get("dependencies"), dict):
        out = _parse_npm_v1(data["dependencies"], lock)

    return out

def norm_pypi(name):
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path):
    out = []

    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        if " #" in raw:
            line = raw.split(" #", 1)[0].strip()
        elif raw.strip().startswith("#"):
            continue
        else:
            line = raw.strip()

        if not line or line.startswith("-"):
            continue

        if " ;" in line:
            line = line.split(" ;", 1)[0].strip()
        elif ";" in line and not line.startswith("http"):
            line = line.split(";")[0].strip()

        source = "registry"
        resolved = None
        version = None

        if line.startswith(("git+", "git://")):
            source = "git"
            resolved = line
            if "#egg=" in line:
                name_raw = line.split("#egg=")[-1].split("&")[0].strip()
                if "==" in name_raw:
                    name, version = name_raw.split("==", 1)
                else:
                    name = re.split(r"[<>=!~ ]", name_raw)[0]
            else:
                name = line.split("/")[-1].split("@")[0].replace(".git", "").strip()

            if not version and "@" in line:
                ref = line.split("#")[0].rpartition("@")[-1]
                if re.match(r"^v?\d+(\.\d+)*", ref):
                    version = ref.lstrip("v")

        elif line.startswith(("http://", "https://")):
            source = "url"
            resolved = line
            if "#egg=" in line:
                name_raw = line.split("#egg=")[-1].split("&")[0].strip()
                if "==" in name_raw:
                    name, version = name_raw.split("==", 1)
                else:
                    name = re.split(r"[<>=!~ ]", name_raw)[0]
            else:
                filename = line.split("?")[0].split("#")[0].split("/")[-1]
                m = re.match(r"^([a-zA-Z0-9_\-\.]+?)-(\d+\.\d+[^/]*?)(\.tar\.gz|\.tgz|\.zip|\.whl)$", filename)
                if m:
                    name, version = m.group(1), m.group(2)
                else:
                    name = Path(filename).stem

        elif " @ " in line or ("@" in line and not line.startswith("@") and ("https://" in line or "http://" in line or "git+" in line or "git:" in line)):
            parts = line.split("@", 1)
            name_part = parts[0].strip()
            url_part = parts[1].strip()

            if "==" in name_part:
                name, version = [p.strip() for p in name_part.split("==", 1)]
                version = version.split(",")[0].split(" ")[0]
            else:
                name = re.split(r"[<>=!~ ]", name_part)[0].strip()

            resolved = url_part
            if url_part.startswith(("git+", "git:")) or ".git" in url_part or "github:" in url_part:
                source = "git"
            elif url_part.startswith(("http://", "https://", "file://")):
                source = "url"
            else:
                source = "url"

            if not version:
                if "@" in url_part and not url_part.startswith("@"):
                    ref = url_part.rpartition("@")[-1].split("#")[0]
                    if re.match(r"^v?\d+(\.\d+)*", ref):
                        version = ref.lstrip("v")
                if not version:
                    m = re.search(r"-(\d+\.\d+[^/]*?)(\.tar\.gz|\.tgz|\.zip|\.whl)$", url_part)
                    if m:
                        version = m.group(1)

        else:
            if "==" in line:
                name, version = [part.strip() for part in line.split("==", 1)]
                version = version.split(",")[0].split(" ")[0]
            else:
                name = re.split(r"[<>=!~ ]", line)[0]
                version = None

        name = norm_pypi(name.split("[")[0].strip())

        if name:
            out.append(
                Pkg(
                    "pypi",
                    name,
                    version,
                    source,
                    resolved=resolved,
                    manifest=str(path),
                )
            )

    return out


def parse_package_json(path):
    """Extract dependencies from a package.json manifest."""
    path_obj = Path(path)
    try:
        data = json.loads(path_obj.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Malformed package.json in {path}: {exc}")

    if not isinstance(data, dict):
        raise ValueError(f"Invalid package.json (root is not an object) in {path}")

    out = []
    seen = set()

    sections = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ]

    for section in sections:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue

        for name, spec in deps.items():
            if not name or not isinstance(name, str):
                continue

            name = name.strip()
            if name in seen:
                continue
            seen.add(name)

            spec_str = str(spec).strip() if spec is not None else ""
            source = "registry"
            resolved = None
            version = None
            local = None

            if spec_str.startswith("file:"):
                source = "local"
                local = spec_str[5:]
                resolved = spec_str
            elif spec_str.startswith(("git+", "git://", "github:")) or ".git" in spec_str:
                source = "git"
                resolved = spec_str
                # Attempt to extract version tag/branch if present
                if "#" in spec_str:
                    tag = spec_str.split("#")[-1]
                    tag_clean = re.sub(r"^[~^=v\s]+", "", tag)
                    if re.match(r"^\d+(\.\d+)*", tag_clean):
                        version = tag_clean
            elif spec_str.startswith(("http://", "https://")):
                source = "url"
                resolved = spec_str
            else:
                clean_ver = re.sub(r"^[~^=v\s<>]+", "", spec_str).split(" ")[0]
                if clean_ver and re.match(r"^\d+(\.\d+)*", clean_ver):
                    version = clean_ver
                elif spec_str and re.match(r"^\d+(\.\d+)*", spec_str):
                    version = spec_str
                else:
                    version = None

            out.append(
                Pkg(
                    eco="npm",
                    name=name,
                    version=version,
                    source=source,
                    resolved=resolved,
                    integrity=None,
                    local_dir=local,
                    manifest=str(path_obj),
                )
            )

    return out
