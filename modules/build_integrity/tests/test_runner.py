from backend import docker_runner
from modules.build_integrity import runner


RECIPE = '''version: 1
build:
    image: gcc@sha256:abc
    commands:
      - gcc -o /out/app src/main.c
    artifact: /out/app
'''


def test_missing_recipe_is_unresolved_never_clean(tmp_path):
    res = runner.run(str(tmp_path), {})
    assert res.status == 'skipped'
    assert [f.category for f in res.findings] == ['UNRESOLVED']


def test_unpinned_image_is_not_comparable(tmp_path):
    (tmp_path / 'buildguard.yml').write_text(
        RECIPE.replace('gcc@sha256:abc', 'gcc:13')
    )
    res = runner.run(str(tmp_path), {})
    assert res.findings[0].category == 'UNRESOLVED'


def test_docker_down_reports_error_and_no_findings(tmp_path, monkeypatch):
    (tmp_path / 'buildguard.yml').write_text(RECIPE)
    monkeypatch.setattr(
        docker_runner, 'docker_available', lambda *a, **k: False
    )
    res = runner.run(str(tmp_path), {})
    assert res.status == 'error' and res.findings == []
    assert res.errors[0]['code'] == 'DOCKER_UNAVAILABLE'


def test_invalid_recipe_is_an_error(tmp_path):
    (tmp_path / 'buildguard.yml').write_text('version: 2\n')
    res = runner.run(str(tmp_path), {})
    assert res.status == 'error' and res.errors[0]['code'] == 'RECIPE_INVALID'
