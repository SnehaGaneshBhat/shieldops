from dataclasses import dataclass
from pathlib import Path
import hashlib
import yaml


class RecipeError(Exception):
    pass


class RecipeMissing(RecipeError):
    pass


@dataclass
class Recipe:
    image: str
    workdir: str
    commands: list
    artifact: str
    env: dict
    version_commands: list
    raw_sha256: str
    pinned: bool
    path: str


def load_recipe(project_path: str, recipe_path: str = 'buildguard.yml') -> Recipe:
    root = Path(project_path).resolve()
    p = Path(recipe_path)
    p = (p if p.is_absolute() else root / p).resolve()

    if root not in p.parents:
        raise RecipeError('recipe must be inside the project folder')

    if not p.is_file():
        raise RecipeMissing(f'recipe not found: {p}')

    raw = p.read_bytes()

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        raise RecipeError(f'invalid YAML: {e}')

    if not isinstance(data, dict) or data.get('version') != 1:
        raise RecipeError('recipe must contain version: 1')

    b = data.get('build')

    if not isinstance(b, dict):
        raise RecipeError('recipe needs a build: section')

    image, commands, artifact = b.get('image'), b.get('commands'), b.get('artifact')

    if not isinstance(image, str) or not image.strip():
        raise RecipeError('build.image is required')

    if not (
        isinstance(commands, list)
        and commands
        and all(isinstance(c, str) for c in commands)
    ):
        raise RecipeError('build.commands must be a non-empty list of strings')

    if not isinstance(artifact, str) or not artifact.startswith('/out/'):
        raise RecipeError('build.artifact must be a path under /out/')

    workdir = b.get('workdir', '/src')

    if not isinstance(workdir, str) or not workdir.startswith('/') or workdir.startswith('/out'):
        raise RecipeError('build.workdir must be an absolute path such as /src')

    env = {
        str(k): str(v)
        for k, v in (b.get('env') or data.get('env') or {}).items()
    }

    versions = b.get('version_commands') or []

    return Recipe(
        image=image.strip(),
        workdir=workdir,
        commands=commands,
        artifact=artifact,
        env=env,
        version_commands=[str(v) for v in versions],
        raw_sha256=hashlib.sha256(raw).hexdigest(),
        pinned='@sha256:' in image,
        path=str(p)
    )
