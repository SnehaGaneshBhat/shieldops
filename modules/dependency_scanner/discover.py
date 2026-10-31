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
    "vcpkg.json",
    "vcpkg-configuration.json",
    "conanfile.txt",
    "conan.lock",
}

SKIP = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "env",
    ".env",
    "__pycache__",
    ".buildguard",
    "dist",
    "build",
    "out",
    "target",
    "bin",
    "obj",
    ".next",
    ".nuxt",
    ".output",
    ".cache",
    ".turbo",
    ".gradle",
    ".yarn",
    ".pnpm-store",
    ".npm",
    ".pytest_cache",
    ".mypy_cache",
    ".tox",
    "coverage",
    ".nyc_output",
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