import json
from pathlib import Path
import httpx
import pytest

from modules.dependency_scanner.lockfiles import Pkg
from modules.dependency_scanner.registry import fetch_age, load_meta


def test_load_meta_local_package(tmp_path):
    local_dir = tmp_path / "vendor" / "helper"
    local_dir.mkdir(parents=True)
    (local_dir / "package.json").write_text(
        json.dumps({"scripts": {"postinstall": "echo 1"}}),
        encoding="utf-8",
    )

    pkg = Pkg("npm", "helper", "1.0.0", source="local", local_dir="vendor/helper")
    meta = load_meta(pkg, tmp_path, offline=True)
    assert meta.get("scripts") == {"postinstall": "echo 1"}


def test_load_meta_fixture(tmp_path):
    fixtures = tmp_path / "registry_fixtures"
    fixtures.mkdir()
    (fixtures / "test-pkg.json").write_text(
        json.dumps({"age_days": 10, "version_count": 2}),
        encoding="utf-8",
    )

    pkg = Pkg("npm", "test-pkg", "1.0.0", source="registry")
    meta = load_meta(pkg, tmp_path, offline=True)
    assert meta["age_days"] == 10
    assert meta["version_count"] == 2


def test_load_meta_offline_returns_empty(tmp_path):
    pkg = Pkg("npm", "remote-pkg", "1.0.0", source="registry")
    meta = load_meta(pkg, tmp_path, offline=True)
    assert meta == {}


def test_load_meta_http_success(tmp_path):
    def handler(request):
        return httpx.Response(200, json={"scripts": {"build": "tsc"}})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = Pkg("npm", "remote-pkg", "1.0.0", source="registry")
    meta = load_meta(pkg, tmp_path, offline=False, http=client)
    assert meta.get("scripts") == {"build": "tsc"}


def test_load_meta_http_failure(tmp_path):
    def handler(request):
        return httpx.Response(500)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = Pkg("npm", "remote-pkg", "1.0.0", source="registry")
    meta = load_meta(pkg, tmp_path, offline=False, http=client)
    assert meta == {}


def test_fetch_age_success():
    def handler(request):
        return httpx.Response(
            200,
            json={
                "time": {"created": "2026-01-01T00:00:00Z"},
                "versions": {"1.0.0": {}, "1.0.1": {}},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = Pkg("npm", "remote-pkg", "1.0.1", source="registry")
    info = fetch_age(pkg, http=client)
    assert "age_days" in info
    assert info["version_count"] == 2


def test_fetch_age_failure():
    def handler(request):
        return httpx.Response(404)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    pkg = Pkg("npm", "missing-pkg", "1.0.0", source="registry")
    info = fetch_age(pkg, http=client)
    assert info == {}

