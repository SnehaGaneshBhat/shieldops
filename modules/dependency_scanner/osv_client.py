import hashlib
import json
import os
import time
from pathlib import Path

import httpx


class OSVError(Exception):
    pass


class OSVClient:
    def __init__(self, cache_dir, offline=False, client=None, base=None):
        self.base = (
            base or os.environ.get("BUILDGUARD_OSV_URL", "https://api.osv.dev")
        ).rstrip("/")
        self.dir = Path(cache_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.offline = offline
        self.http = client or httpx.Client(timeout=20)

    def _path(self, kind, key):
        digest = hashlib.sha1(key.encode()).hexdigest()
        return self.dir / f"{kind}_{digest}.json"

    def _read(self, kind, key):
        path = self._path(kind, key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _write(self, kind, key, value):
        self._path(kind, key).write_text(
            json.dumps(value), encoding="utf-8"
        )

    def _request(self, method, path, payload=None):
        last = "unknown"

        for attempt in range(3):
            try:
                response = self.http.request(
                    method, self.base + path, json=payload
                )

                if response.status_code == 200:
                    return response.json()

                if response.status_code not in (429, 500, 502, 503, 504):
                    raise OSVError(f"HTTP {response.status_code}")

                last = f"HTTP {response.status_code}"

            except httpx.HTTPError as exc:
                last = str(exc)

            if attempt < 2:
                time.sleep(0.5 * (2 ** attempt))

        raise OSVError(last)

    def _paginate(self, package):
        ecosystem, name, version = package
        ids = []
        token = None

        while True:
            body = {
                "package": {"name": name, "ecosystem": ecosystem},
                "version": version,
            }
            if token:
                body["page_token"] = token

            result = self._request("POST", "/v1/query", body)
            ids.extend(v["id"] for v in result.get("vulns", []))
            token = result.get("next_page_token")

            if not token:
                return ids

    def query_ids(self, packages):
        output = {}
        todo = []

        for package in packages:
            key = "|".join(package)
            cached = self._read("q", key)

            if cached is not None:
                output[package] = cached
            else:
                todo.append(package)

        if not todo:
            return output, []

        if self.offline:
            return output, todo

        failed = []

        for start in range(0, len(todo), 500):
            chunk = todo[start:start + 500]
            queries = [
                {
                    "package": {"name": name, "ecosystem": ecosystem},
                    "version": version,
                }
                for ecosystem, name, version in chunk
            ]

            try:
                results = self._request(
                    "POST", "/v1/querybatch", {"queries": queries}
                )["results"]

                if len(results) != len(chunk):
                    raise OSVError("Unexpected OSV batch response length")

            except (OSVError, KeyError, TypeError):
                failed.extend(chunk)
                continue

            for package, result in zip(chunk, results):
                try:
                    if result.get("next_page_token"):
                        ids = self._paginate(package)
                    else:
                        ids = [v["id"] for v in result.get("vulns", [])]

                    key = "|".join(package)
                    self._write("q", key, ids)
                    output[package] = ids

                except (OSVError, KeyError, TypeError):
                    failed.append(package)

        return output, failed

    def get_vuln(self, vuln_id):
        cached = self._read("v", vuln_id)

        if cached is not None:
            return cached

        if self.offline:
            raise OSVError("offline and not cached")

        result = self._request("GET", f"/v1/vulns/{vuln_id}")
        self._write("v", vuln_id, result)
        return result


def vuln_severity(vulnerability):
    severity = str(
        (vulnerability.get("database_specific") or {}).get("severity", "")
    ).upper()

    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }.get(severity, "UNKNOWN")


def fixed_versions(vulnerability):
    output = []

    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in output:
                    output.append(fixed)

    return output
