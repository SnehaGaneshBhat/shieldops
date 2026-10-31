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

    def _pkg_key(self, package):
        return "|".join("" if part is None else str(part) for part in package)

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
                **({"version": version} if version is not None else {}),
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
            key = self._pkg_key(package)
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
                    **({"version": version} if version is not None else {}),
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

                    key = self._pkg_key(package)
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


def cvss_score_from_vector(vector):
    import math
    parts = dict(p.split(":") for p in str(vector).split("/") if ":" in p)
    scope_changed = parts.get("S") == "C"

    c_map = {"N": 0.0, "L": 0.22, "H": 0.56}
    av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_map = {"L": 0.77, "H": 0.44}
    ui_map = {"N": 0.85, "R": 0.62}
    pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}

    c = c_map.get(parts.get("C", "N"), 0.0)
    i = c_map.get(parts.get("I", "N"), 0.0)
    a = c_map.get(parts.get("A", "N"), 0.0)

    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
    if iss <= 0:
        return 0.0

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        pr = pr_map_c.get(parts.get("PR", "N"), 0.85)
    else:
        impact = 6.42 * iss
        pr = pr_map_u.get(parts.get("PR", "N"), 0.85)

    av = av_map.get(parts.get("AV", "N"), 0.85)
    ac = ac_map.get(parts.get("AC", "L"), 0.77)
    ui = ui_map.get(parts.get("UI", "N"), 0.85)

    exploitability = 8.22 * av * ac * pr * ui

    if scope_changed:
        score = min(1.08 * (impact + exploitability), 10.0)
    else:
        score = min(impact + exploitability, 10.0)

    return math.ceil(score * 10.0) / 10.0


def score_to_severity(score):
    try:
        val = float(score)
    except (TypeError, ValueError):
        return None

    if val >= 9.0:
        return "CRITICAL"
    elif val >= 7.0:
        return "HIGH"
    elif val >= 4.0:
        return "MEDIUM"
    elif val > 0.0:
        return "LOW"
    elif val == 0.0:
        return "LOW"
    return None


def vuln_severity(vulnerability):
    severity = str(
        (vulnerability.get("database_specific") or {}).get("severity", "")
    ).upper()

    mapped = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MODERATE": "MEDIUM",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    }.get(severity)

    if mapped:
        return mapped

    severities = vulnerability.get("severity") or []
    if isinstance(severities, dict):
        severities = [severities]

    for item in severities:
        if not isinstance(item, dict):
            continue
        raw_score = item.get("score")
        if raw_score is None:
            continue

        sev = score_to_severity(raw_score)
        if sev:
            return sev

        if isinstance(raw_score, str) and ("CVSS:" in raw_score or "AV:" in raw_score):
            try:
                calc_score = cvss_score_from_vector(raw_score)
                sev = score_to_severity(calc_score)
                if sev:
                    return sev
            except Exception:
                pass

    return "UNKNOWN"


def fixed_versions(vulnerability):
    output = []

    for affected in vulnerability.get("affected", []):
        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in output:
                    output.append(fixed)

    return output
