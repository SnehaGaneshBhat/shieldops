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
