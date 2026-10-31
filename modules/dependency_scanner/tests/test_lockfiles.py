import json

from modules.dependency_scanner.lockfiles import (
    norm_pypi,
    parse_npm_lock,
    parse_requirements,
)


def test_parse_npm_lock_sources(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                "integrity": "sha512-example",
            },
            "node_modules/git-package": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/example/repo.git",
            },
            "node_modules/url-package": {
                "version": "2.0.0",
                "resolved": "https://example.invalid/pkg.tgz",
            },
            "node_modules/unknown-package": {"version": "3.0.0"},
            "packages/local-lib": {"version": "1.0.0"},
            "node_modules/linked": {"link": True},
        },
    }), encoding="utf-8")

    packages = parse_npm_lock(lock)
    by_name = {pkg.name: pkg for pkg in packages}

    assert by_name["lodash"].source == "registry"
    assert by_name["lodash"].integrity == "sha512-example"
    assert by_name["git-package"].source == "git"
    assert by_name["url-package"].source == "url"
    assert by_name["unknown-package"].source == "unknown"
    assert by_name["local-lib"].source == "local"
    assert "linked" not in by_name


def test_parse_requirements_pinned_and_unpinned(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "Flask==3.0.0\n"
        "my_package>=1.0\n"
        "Requests==2.31.0 ; python_version >= '3.8'\n"
        "# comment\n"
        "-r other.txt\n",
        encoding="utf-8",
    )

    packages = parse_requirements(requirements)
    by_name = {pkg.name: pkg for pkg in packages}

    assert by_name["flask"].version == "3.0.0"
    assert by_name["my-package"].version is None
    assert by_name["requests"].version == "2.31.0"
    assert all(pkg.source == "registry" for pkg in packages)


def test_norm_pypi():
    assert norm_pypi("My_Package.Name") == "my-package-name"
