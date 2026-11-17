import hashlib
import json
import os
import time
from pathlib import Path

import httpx


OSV_BASE_URL = "https://api.osv.dev"
OSV_QUERY_ENDPOINT = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_ENDPOINT = "https://api.osv.dev/v1/querybatch"


class OSVError(Exception):
    pass


class OSVClient:
    def __init__(self, cache_dir, offline=False, client=None, base=None):
        self.base = (
            base or os.environ.get("BUILDGUARD_OSV_URL", OSV_BASE_URL)
        ).rstrip("/")
        self.query_url = f"{self.base}/v1/query"
        self.querybatch_url = f"{self.base}/v1/querybatch"
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

    def _request(self, method, url_or_path, payload=None):
        url = url_or_path if str(url_or_path).startswith("http") else self.base + url_or_path
        last = "unknown"

        for attempt in range(3):
            try:
                response = self.http.request(
                    method, url, json=payload
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

            result = self._request("POST", self.query_url, body)
            ids.extend(v["id"] for v in result.get("vulns", []))
            token = result.get("next_page_token")

            if not token:
                return ids

    def query(self, package):
        """Query a single package using the official OSV /v1/query endpoint."""
        ecosystem, name, version = package
        key = self._pkg_key(package)
        cached = self._read("q", key)

        if cached is not None:
            return cached

        if self.offline:
            raise OSVError("offline and not cached")

        body = {
            "package": {"name": name, "ecosystem": ecosystem},
            **({"version": version} if version is not None else {}),
        }

        try:
            result = self._request("POST", self.query_url, body)
            if result.get("next_page_token"):
                ids = self._paginate(package)
            else:
                ids = [v["id"] for v in result.get("vulns", [])]

            self._write("q", key, ids)
            return ids
        except (OSVError, KeyError, TypeError) as exc:
            raise OSVError(f"OSV query failed for {package}: {exc}") from exc

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
                    "POST", self.querybatch_url, {"queries": queries}
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
    if "_merged_severity" in vulnerability:
        return vulnerability["_merged_severity"]

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


def fixed_versions(vulnerability, package_name=None):
    if "_merged_fixed" in vulnerability:
        return vulnerability["_merged_fixed"]

    output = []

    for affected in vulnerability.get("affected", []):
        if package_name:
            aff_pkg = (affected.get("package") or {}).get("name")
            if aff_pkg and aff_pkg.lower() != package_name.lower():
                continue

        for version_range in affected.get("ranges", []):
            for event in version_range.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed not in output:
                    output.append(fixed)

    return output


class SemVer:
    """Minimal SemVer 2.0.0 parser and comparator supporting prereleases and Go pseudo-versions."""
    __slots__ = ("major", "minor", "patch", "prerelease", "build")

    def __init__(self, major, minor, patch, prerelease=None, build=None):
        self.major = major
        self.minor = minor
        self.patch = patch
        self.prerelease = prerelease
        self.build = build

    @classmethod
    def parse(cls, version_str):
        if not version_str or not isinstance(version_str, str):
            return None
        import re
        s = version_str.strip()
        if s.startswith(("v", "V")):
            s = s[1:]
        elif s.lower().startswith("go"):
            s = s[2:]

        # Split build metadata
        if "+" in s:
            s, build = s.split("+", 1)
        else:
            build = None

        # Split prerelease
        if "-" in s:
            core, pre = s.split("-", 1)
        else:
            core, pre = s, None

        core_parts = core.split(".")
        if len(core_parts) == 3:
            if not all(p.isdigit() for p in core_parts):
                return None
            major, minor, patch = (int(p) for p in core_parts)
        elif len(core_parts) == 2:
            if not all(p.isdigit() for p in core_parts):
                return None
            major, minor = (int(p) for p in core_parts)
            patch = 0
        elif len(core_parts) == 1:
            if not core_parts[0].isdigit():
                return None
            major = int(core_parts[0])
            minor = patch = 0
        else:
            return None

        parsed_pre = None
        if pre is not None:
            if not pre:
                return None
            raw_ids = pre.split(".")
            parsed_ids = []
            for raw_id in raw_ids:
                if not raw_id:
                    return None
                if not re.match(r"^[0-9A-Za-z-]+$", raw_id):
                    return None
                if raw_id.isdigit():
                    parsed_ids.append((0, int(raw_id)))
                else:
                    parsed_ids.append((1, raw_id))
            parsed_pre = tuple(parsed_ids)

        return cls(major, minor, patch, parsed_pre, build)

    def _sort_key(self):
        # In SemVer, release versions have higher precedence than prereleases:
        # (1, ()) for normal release > (0, prerelease_tuple) for prerelease
        pre_key = (1, ()) if self.prerelease is None else (0, self.prerelease)
        return (self.major, self.minor, self.patch, pre_key)

    def __eq__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() == other._sort_key()

    def __ne__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() != other._sort_key()

    def __lt__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() < other._sort_key()

    def __le__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() <= other._sort_key()

    def __gt__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() > other._sort_key()

    def __ge__(self, other):
        if not isinstance(other, SemVer):
            return NotImplemented
        return self._sort_key() >= other._sort_key()

    def __repr__(self):
        pre = f"-{'.'.join(str(p[1]) for p in self.prerelease)}" if self.prerelease else ""
        build = f"+{self.build}" if self.build else ""
        return f"SemVer({self.major}.{self.minor}.{self.patch}{pre}{build})"


def is_version_affected(version_str, affected_entry):
    """Return whether version_str is affected according to an OSV affected entry.

    Returns:
        True: confirmed affected within range or versions list.
        False: confirmed unaffected.
        None: indeterminate (unparseable, unsupported range, or missing data).
    """
    if not version_str or not isinstance(affected_entry, dict):
        return None

    # 1. Exact list of versions
    specific_versions = affected_entry.get("versions")
    if specific_versions and isinstance(specific_versions, list):
        norm_v = str(version_str).strip()
        norm_set = set()
        for sv in specific_versions:
            if isinstance(sv, str):
                s = sv.strip()
                norm_set.add(s)
                if s.startswith(("v", "V")):
                    norm_set.add(s[1:])
                else:
                    norm_set.add(f"v{s}")
        if norm_v in norm_set:
            return True
        if not affected_entry.get("ranges"):
            return False

    v = SemVer.parse(str(version_str))
    if v is None:
        return None

    ranges = affected_entry.get("ranges")
    if not ranges or not isinstance(ranges, list):
        return None

    semver_ranges = [
        r for r in ranges
        if isinstance(r, dict) and r.get("type") in ("SEMVER", None, "")
    ]
    if not semver_ranges:
        return None

    has_indeterminate = False

    for r in semver_ranges:
        events = r.get("events")
        if not events or not isinstance(events, list):
            has_indeterminate = True
            continue

        current_introduced = None
        range_had_error = False

        for ev in events:
            if not isinstance(ev, dict):
                range_had_error = True
                continue

            if "introduced" in ev:
                intro_raw = str(ev["introduced"]).strip()
                if intro_raw == "0":
                    current_introduced = "0"
                else:
                    intro_v = SemVer.parse(intro_raw)
                    if intro_v is None:
                        current_introduced = None
                        range_had_error = True
                    else:
                        current_introduced = intro_v

            elif "fixed" in ev:
                fix_raw = str(ev["fixed"]).strip()
                fix_v = SemVer.parse(fix_raw)
                if fix_v is None or current_introduced is None:
                    range_had_error = True
                else:
                    if current_introduced == "0":
                        if v < fix_v:
                            return True
                    else:
                        if current_introduced <= v < fix_v:
                            return True
                current_introduced = None

            elif "last_affected" in ev:
                last_raw = str(ev["last_affected"]).strip()
                last_v = SemVer.parse(last_raw)
                if last_v is None or current_introduced is None:
                    range_had_error = True
                else:
                    if current_introduced == "0":
                        if v <= last_v:
                            return True
                    else:
                        if current_introduced <= v <= last_v:
                            return True
                current_introduced = None

            elif "limit" in ev:
                current_introduced = None
            else:
                range_had_error = True

        if current_introduced is not None:
            if current_introduced == "0":
                return True
            elif current_introduced <= v:
                return True

        if range_had_error:
            has_indeterminate = True

    if has_indeterminate:
        return None

    return False
