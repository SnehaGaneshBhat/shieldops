import json

from modules.dependency_scanner.lockfiles import (
    norm_pypi,
    parse_npm_lock,
    parse_package_json,
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


def test_parse_npm_lock_scoped_packages(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/@babel/core": {
                "version": "7.20.0",
                "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.20.0.tgz",
                "integrity": "sha512-test",
            },
            "node_modules/@types/node": {
                "version": "18.0.0",
                "resolved": "https://registry.npmjs.org/@types/node/-/node-18.0.0.tgz",
            },
            "node_modules/parent/node_modules/@scope/nested": {
                "version": "1.0.0",
            },
        },
    }), encoding="utf-8")

    packages = parse_npm_lock(lock)
    by_name = {pkg.name: pkg for pkg in packages}

    assert "@babel/core" in by_name
    assert by_name["@babel/core"].version == "7.20.0"
    assert by_name["@babel/core"].integrity == "sha512-test"
    assert "@types/node" in by_name
    assert by_name["@types/node"].version == "18.0.0"
    assert "@scope/nested" in by_name
    assert by_name["@scope/nested"].version == "1.0.0"


def test_parse_npm_lock_v1(tmp_path):
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "name": "v1-app",
        "version": "1.0.0",
        "lockfileVersion": 1,
        "dependencies": {
            "lodash": {
                "version": "4.17.20",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz",
                "integrity": "sha512-test",
                "dependencies": {
                    "sub-dep": {
                        "version": "1.0.0",
                        "resolved": "https://registry.npmjs.org/sub-dep/-/sub-dep-1.0.0.tgz"
                    }
                }
            },
            "@babel/core": {
                "version": "7.20.0",
                "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.20.0.tgz"
            },
            "local-pkg": {
                "version": "file:vendor/local-pkg"
            },
            "git-pkg": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/example/repo.git"
            }
        }
    }), encoding="utf-8")

    packages = parse_npm_lock(lock)
    by_name = {pkg.name: pkg for pkg in packages}

    assert "lodash" in by_name
    assert by_name["lodash"].source == "registry"
    assert by_name["lodash"].integrity == "sha512-test"
    assert "sub-dep" in by_name
    assert by_name["sub-dep"].source == "registry"
    assert "@babel/core" in by_name
    assert by_name["@babel/core"].source == "registry"
    assert "local-pkg" in by_name
    assert by_name["local-pkg"].source == "local"
    assert "git-pkg" in by_name
    assert by_name["git-pkg"].source == "git"


def test_parse_requirements_direct_url_and_git(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "requests @ https://example.invalid/requests-2.31.0.tar.gz\n"
        "flask @ git+https://github.com/pallets/flask.git@v3.0.0\n"
        "unpinned-git @ git+https://github.com/example/unpinned.git\n"
        "git+https://github.com/example/tool.git@1.0.0#egg=tool\n"
        "https://example.invalid/dist/my-pkg-1.2.3.tar.gz\n",
        encoding="utf-8",
    )

    packages = parse_requirements(requirements)
    by_name = {pkg.name: pkg for pkg in packages}

    assert "requests" in by_name
    assert by_name["requests"].source == "url"
    assert by_name["requests"].version == "2.31.0"
    assert by_name["requests"].resolved == "https://example.invalid/requests-2.31.0.tar.gz"

    assert "flask" in by_name
    assert by_name["flask"].source == "git"
    assert by_name["flask"].version == "3.0.0"
    assert by_name["flask"].resolved == "git+https://github.com/pallets/flask.git@v3.0.0"

    assert "unpinned-git" in by_name
    assert by_name["unpinned-git"].source == "git"
    assert by_name["unpinned-git"].version is None
    assert by_name["unpinned-git"].resolved == "git+https://github.com/example/unpinned.git"

    assert "tool" in by_name
    assert by_name["tool"].source == "git"
    assert by_name["tool"].version == "1.0.0"

    assert "my-pkg" in by_name
    assert by_name["my-pkg"].source == "url"
    assert by_name["my-pkg"].version == "1.2.3"


def test_parse_package_json_all_sections(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "name": "test-app",
        "version": "1.0.0",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "4.17.20"
        },
        "devDependencies": {
            "mocha": "~10.2.0"
        },
        "optionalDependencies": {
            "fsevents": "^2.3.3"
        },
        "peerDependencies": {
            "react": ">=18.0.0"
        }
    }), encoding="utf-8")

    pkgs = parse_package_json(pkg_json)
    by_name = {p.name: p for p in pkgs}

    assert len(pkgs) == 5
    assert by_name["express"].version == "4.18.2"
    assert by_name["express"].manifest == str(pkg_json)
    assert by_name["lodash"].version == "4.17.20"
    assert by_name["mocha"].version == "10.2.0"
    assert by_name["fsevents"].version == "2.3.3"
    assert by_name["react"].version == "18.0.0"


def test_parse_package_json_duplicates(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "dependencies": {
            "lodash": "4.17.20"
        },
        "devDependencies": {
            "lodash": "4.17.21"
        }
    }), encoding="utf-8")

    pkgs = parse_package_json(pkg_json)
    assert len(pkgs) == 1
    assert pkgs[0].name == "lodash"
    assert pkgs[0].version == "4.17.20"


def test_parse_package_json_sources(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(json.dumps({
        "dependencies": {
            "local-lib": "file:../local-lib",
            "git-lib": "git+https://github.com/example/git-lib.git#v1.2.3",
            "url-lib": "https://example.com/tarballs/url-lib.tgz",
            "unpinned": "*"
        }
    }), encoding="utf-8")

    pkgs = parse_package_json(pkg_json)
    by_name = {p.name: p for p in pkgs}

    assert by_name["local-lib"].source == "local"
    assert by_name["local-lib"].local_dir == "../local-lib"
    assert by_name["git-lib"].source == "git"
    assert by_name["git-lib"].version == "1.2.3"
    assert by_name["url-lib"].source == "url"
    assert by_name["unpinned"].version is None


def test_parse_package_json_malformed(tmp_path):
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text("{ this is not valid json", encoding="utf-8")

    import pytest
    with pytest.raises(ValueError, match="Malformed package.json"):
        parse_package_json(pkg_json)
