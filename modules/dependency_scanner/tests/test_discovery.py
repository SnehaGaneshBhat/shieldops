from modules.dependency_scanner.discover import discover, find_line


def test_discover_finds_manifests_and_skips_node_modules(tmp_path):
    (tmp_path / "package.json").touch()
    (tmp_path / "package-lock.json").touch()

    src = tmp_path / "src"
    src.mkdir()
    (src / "requirements.txt").touch()

    ignored = tmp_path / "node_modules" / "example"
    ignored.mkdir(parents=True)
    (ignored / "package.json").touch()

    found = discover(tmp_path)

    names = [path.relative_to(tmp_path).as_posix() for path in found]

    assert names == [
        "package-lock.json",
        "package.json",
        "src/requirements.txt",
    ]


def test_find_line_returns_correct_line(tmp_path):
    file = tmp_path / "requirements.txt"
    file.write_text(
        "flask==3.0.0\nrequests==2.31.0\n",
        encoding="utf-8",
    )

    assert find_line(file, "requests") == 2
    assert find_line(file, "missing") is None


def test_discover_cpp_manifests(tmp_path):
    (tmp_path / "vcpkg.json").touch()
    (tmp_path / "vcpkg-configuration.json").touch()
    (tmp_path / "conanfile.txt").touch()
    (tmp_path / "conan.lock").touch()

    found = discover(tmp_path)
    names = [path.relative_to(tmp_path).as_posix() for path in found]
    assert "vcpkg.json" in names
    assert "vcpkg-configuration.json" in names
    assert "conanfile.txt" in names
    assert "conan.lock" in names


def test_find_line_in_vcpkg_manifest(tmp_path):
    vcpkg = tmp_path / "vcpkg.json"
    vcpkg.write_text('{\n  "dependencies": [\n    {"name": "curl"}\n  ]\n}', encoding="utf-8")
    assert find_line(vcpkg, "curl") == 3


def test_discover_recursive_nested_package_json(tmp_path):
    (tmp_path / "package.json").touch()
    nested1 = tmp_path / "apps" / "web"
    nested1.mkdir(parents=True)
    (nested1 / "package.json").touch()

    nested2 = tmp_path / "packages" / "ui" / "core"
    nested2.mkdir(parents=True)
    (nested2 / "package.json").touch()

    found = discover(tmp_path)
    names = [path.relative_to(tmp_path).as_posix() for path in found]
    assert names == [
        "apps/web/package.json",
        "package.json",
        "packages/ui/core/package.json",
    ]


def test_discover_excludes_build_dist_cache_dirs(tmp_path):
    (tmp_path / "package.json").touch()

    for excluded in [
        "node_modules/dep",
        ".git/hooks",
        ".venv/lib",
        "dist/bundle",
        "build/output",
        "out/prod",
        "target/classes",
        ".cache/tmp",
        ".turbo/cache",
        ".gradle/caches",
        ".yarn/cache",
        ".pnpm-store/v3",
    ]:
        d = tmp_path / excluded
        d.mkdir(parents=True)
        (d / "package.json").touch()

    found = discover(tmp_path)
    names = [path.relative_to(tmp_path).as_posix() for path in found]
    assert names == ["package.json"]
