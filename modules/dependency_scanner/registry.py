import json
from pathlib import Path
from urllib.parse import quote

import httpx


REG = "https://registry.npmjs.org/"


def load_meta(pkg, project, offline=False, http=None):
    metadata = {}
    root = Path(project)

    if pkg.local_dir:
        local_file = root / pkg.local_dir / "package.json"
        if local_file.is_file():
            try:
                metadata["scripts"] = json.loads(
                    local_file.read_text(encoding="utf-8")
                ).get("scripts", {})
            except (OSError, json.JSONDecodeError):
                pass

    fixture = (
        root / "registry_fixtures"
        / (pkg.name.replace("/", "__") + ".json")
    )
    if fixture.is_file():
        try:
            metadata.update(
                json.loads(fixture.read_text(encoding="utf-8"))
            )
        except (OSError, json.JSONDecodeError):
            pass
        return metadata

    if (
        offline
        or pkg.eco != "npm"
        or pkg.source != "registry"
        or not pkg.version
    ):
        return metadata

    try:
        response = (http or httpx).get(
            REG + quote(pkg.name, safe="@") + "/" + quote(pkg.version),
            timeout=10,
        )
        if response.status_code == 200:
            metadata["scripts"] = response.json().get("scripts", {})
    except (httpx.HTTPError, ValueError):
        pass

    return metadata


def fetch_age(pkg, http=None):
    from datetime import datetime, timezone

    try:
        response = (http or httpx).get(
            REG + quote(pkg.name, safe="@"), timeout=15
        )
        if response.status_code != 200:
            return {}

        data = response.json()
        created = datetime.fromisoformat(
            data["time"]["created"].replace("Z", "+00:00")
        )

        return {
            "age_days": (
                datetime.now(timezone.utc) - created
            ).days,
            "version_count": len(data.get("versions", {})),
        }
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        return {}
