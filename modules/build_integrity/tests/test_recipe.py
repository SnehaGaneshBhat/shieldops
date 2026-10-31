import pytest

from modules.build_integrity.recipe import RecipeError, RecipeMissing, load_recipe


GOOD = '''version: 1
build:
    image: gcc@sha256:abc
    commands:
      - gcc -o /out/app src/main.c
    artifact: /out/app
    env:
        SOURCE_DATE_EPOCH: '1700000000'
'''


def test_valid_pinned_recipe(tmp_path):
    (tmp_path / 'buildguard.yml').write_text(GOOD)
    r = load_recipe(str(tmp_path))
    assert r.pinned and r.workdir == '/src' and r.env['SOURCE_DATE_EPOCH'] == '1700000000'


def test_tag_is_not_pinned(tmp_path):
    (tmp_path / 'buildguard.yml').write_text(
        GOOD.replace('gcc@sha256:abc', 'gcc:13')
    )
    assert not load_recipe(str(tmp_path)).pinned


def test_missing_recipe(tmp_path):
    with pytest.raises(RecipeMissing):
        load_recipe(str(tmp_path))


def test_artifact_must_be_under_out(tmp_path):
    (tmp_path / 'buildguard.yml').write_text(
        GOOD.replace('artifact: /out/app', 'artifact: /tmp/app')
    )
    with pytest.raises(RecipeError):
        load_recipe(str(tmp_path))


def test_recipe_outside_project_rejected(tmp_path):
    with pytest.raises(RecipeError):
        load_recipe(str(tmp_path), '../x.yml')
