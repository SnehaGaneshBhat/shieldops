from pathlib import Path


MANIFESTS = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "Pipfile.lock",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "pom.xml",
}

SKIP = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".buildguard",
}


def discover(project_path):
    root = Path(project_path).resolve()
    found = []

    for path in root.rglob("*"):
        relative_parts = path.relative_to(root).parts

        if any(part in SKIP for part in relative_parts):
            continue

        if path.is_file() and path.name in MANIFESTS:
            found.append(path)

    return sorted(found)


def find_line(file_path, needle):
    """Return the 1-based line number of the first occurrence."""
    try:
        lines = Path(file_path).read_text(
            encoding="utf-8"
        ).splitlines()

        for number, line in enumerate(lines, 1):
            if needle in line:
                return number

    except OSError:
        pass

    return None