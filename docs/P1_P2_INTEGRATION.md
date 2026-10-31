# BuildGuard P1–P2 Integration Reference & Developer Handoff

This document details the architectural contract, end-to-end data flow, schemas, error isolation, cancellation semantics, and verification evidence for the integration of **P1 (Dependency Scanner)** with **P2 (FastAPI Backend & Orchestrator)** in ShieldOps / BuildGuard.

---

## 1. System Architecture & End-to-End Data Flow

The platform executes a unified security analysis pipeline coordinated by the P2 orchestrator:

```
[Client / Extension]
        │
        ├── 1. POST /v1/scans (ScanRequest: project_path, modules, options)
        ▼
[FastAPI Backend (main.py)]
        │
        ├── 2. Path & Token Verification (safe_dir, require_token)
        ▼
[Orchestrator (orchestrator.py)]
        │
        ├── 3. Store Initialization (store.create_scan -> .buildguard/scans/<scan_id>)
        │
        ├── 4. Concurrent Module Dispatch (worker threads per module)
        │       ├── Worker "dependency": modules.dependency_scanner.run(project_path, opts)
        │       └── Worker "build": modules.build_integrity.run(project_path, opts)
        │
        ├── 5. Result Collection & Persistence
        │       ├── <name>_findings.json
        │       └── Module state updates in store
        │
        ├── 6. Finding Correlation (_correlate)
        │       └── Normalizes findings, sorts by severity, assigns unified IDs (F-001, F-002...)
        │
        ├── 7. Report Generation (_build_report)
        │       ├── Attaches template plain explanations
        │       ├── Compiles limitation notes from partial/error/skipped modules
        │       └── Writes findings.json, report.json, report.html
        │
        ├── 8. Final Status Update (completed, completed_with_errors, failed, cancelled)
        ▼
[Client Polling & Retrieval]
        ├── GET /v1/scans/{scan_id}          -> public scan state
        ├── GET /v1/scans/{scan_id}/findings -> correlated findings list
        ├── GET /v1/scans/{scan_id}/report   -> structured JSON report
        └── GET /v1/scans/{scan_id}/report.html -> HTML report rendering
```

---

## 2. P1–P2 Module Invocation Contract

### Entry Point
- **Module import path:** `modules.dependency_scanner` (configured in `ENTRY['dependency']`).
- **Function signature:** `run(project_path: str, options: dict = None) -> ModuleResult`

### Input Options Contract (`backend.schemas.ScanOptions`)
The orchestrator validates API options strictly against `ScanOptions` (`model_config = {"extra": "forbid"}`). Arbitrary or undeclared options are rejected upfront with HTTP 422.

Supported options:
- **Build integrity & general:**
  - `use_llm: bool = True` — Controls LLM summary generation in reporting.
  - `recipe_path: str = "buildguard.yml"` — Path to reproducible build recipe.
  - `manifest_path: Optional[str] = None` — Path to release manifest for artifact verification.
  - `distributed_artifact: Optional[str] = None` — Distributed binary path.
  - `compiler_sample: Optional[str] = None` — Compiler analysis sample path.
  - `run_sandbox: bool = False` — Enable sandbox verification.
  - `allow_unpinned: bool = False` — Allow Docker tags instead of digests (dev mode).
  - `docker_timeout: int = 120` — Timeout for Docker operations.
- **Dependency scanner:**
  - `offline: bool = False` — Disables live network requests (OSV API, npm registry).
  - `install: Optional[bool] = None` — Forces dependency installation prior to Syft SBOM generation.
  - `auto_install: bool = False` — Automatic dependency installation toggle.
  - `sbom_path: Optional[str] = None` — Explicit output path for the generated CycloneDX SBOM.
  - `sbom_out: Optional[str] = None` — Alias for `sbom_path`.
  - `verbose: bool = False` — Verbose console logging flag.
  - `max_registry_lookups: int = 100` — Maximum network lookups budget.

At runtime, `orchestrator.py` enriches options with internal scan context:
- `scan_id: str` — Unique scan identifier.
- `scan_dir: str` — Absolute filesystem path to `.buildguard/scans/<scan_id>/`.
- `cancel_check: Callable[[], bool]` — Callback returning `True` if cancellation has been requested.

### Output Contract (`backend.schemas.ModuleResult`)
The dependency scanner returns a `ModuleResult` adhering strictly to `backend.schemas`:
- `module: "dependency"`
- `status: "ok" | "partial" | "error" | "skipped"`
- `findings: list[Finding]`
- `errors: list[dict]` (e.g. `{"code": "...", "message": "...", "detail": "..."}`)
- `tool_versions: dict` (e.g. `{"syft": "1.55.0", "osv_query_time": "..."}`)
- `duration_ms: int`
- `checks_performed: list[str]` (`["manifest_discovery", "syft_sbom", "npm_lockfile_parse", "package_json_parse", "osv_lookup", "heuristics"]`)

---

## 3. Shared Schemas & Status Semantics

### Status Semantics
- **`ok`**: All requested checks completed successfully with zero unhandled errors.
- **`partial`**: Analysis ran but encountered non-fatal issues (e.g., an OSV cache miss in offline mode or a secondary malformed manifest). Findings identified prior to the error are preserved.
- **`error`**: Fatal error preventing analysis (e.g., nonexistent project directory).
- **`skipped`**: Analysis skipped (e.g., cancelled before start or missing required inputs).

### Finding Schema (`backend.schemas.Finding`)
- `id`: Module temporary identifier (`D-001`, etc.); reassigned sequentially during correlation (`F-001`, `F-002`).
- `module`: `"dependency"`
- `category`: `KNOWN_VULNERABILITY`, `KNOWN_MALICIOUS_ADVISORY`, `SUSPICIOUS_INDICATOR`, `UNRESOLVED`, `NO_KNOWN_ISSUES`.
- `severity`: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`, `UNKNOWN`.
- `confidence`: `CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`.
- `subject`: Dictionary containing ecosystem, package name, version, or package count.
- `title`: Concise, deterministic description.
- `evidence`: List of `Evidence(type, rule_id, data, untrusted_text)`.
- `file_hint`: Relative path to originating manifest (e.g. `package.json`, `vcpkg.json`).
- `line_hint`: 1-based line number of the dependency in the manifest.

---

## 4. Key Fixes & Integration Enhancements Implemented

1. **Explicit `ScanOptions` Validation (`backend/schemas.py`)**:
   - Explicitly declared all supported P1 and P2 options.
   - Set `model_config = {"extra": "forbid"}` to reject arbitrary unrecognized parameters with HTTP 422.

2. **Error Visibility in Reports (`backend/orchestrator.py`)**:
   - Updated `_build_report` to include `partial` modules when compiling report limitation notes: `if r.status in ('error', 'skipped', 'partial')`.
   - Prevents partial failures from being silently obscured in report summaries.

3. **Responsive Scan Cancellation (`modules/dependency_scanner/scanner.py`)**:
   - Integrated cooperative cancellation checks (`options.get("cancel_check")`) across scanning phases: after discovery, after installation, before Syft execution, before OSV lookup, and before heuristic rules.
   - If cancelled, returns `status="skipped"` with code `"CANCELLED"`.
   - `orchestrator.py` saves partial findings and generates a cancellation report summarizing items collected before cancellation.

4. **SBOM Persistence & Path Precedence (`modules/dependency_scanner/scanner.py`)**:
   - Explicit `sbom_path` / `sbom_out` is prioritized and written directly.
   - If `scan_dir` is provided, `<scan_dir>/sbom.json` is automatically persisted.
   - Handles write failures gracefully with `"SBOM_WRITE_ERROR"`, setting status to `partial` without crashing.

5. **Report Write Error Safety (`modules/dependency_scanner/scanner.py`)**:
   - Wrapped `out_path` report file writes in try/except; records `"REPORT_WRITE_ERROR"` if the path is invalid or unwritable.

---

## 5. Build-Integrity Coexistence & Parallel Execution

- P1 (`dependency`) and P2 (`build`) execute concurrently in independent daemon worker threads.
- Thread isolation ensures a missing recipe or build failure does not crash or invalidate dependency scan results.
- Findings from all executed modules are aggregated, sorted by severity (`CRITICAL` &rarr; `HIGH` &rarr; `MEDIUM` &rarr; `LOW` &rarr; `UNKNOWN` &rarr; `INFO`), and assigned unified identifiers (`F-001`, `F-002`, ...).

---

## 6. Cancellation Semantics & Limitations

- **Cancellation Mechanism:** When `POST /v1/scans/{scan_id}/cancel` is called, `scan_id` is registered in `_CANCELLED`, running Docker containers are force-removed via `docker_runner.kill_scan_containers(scan_id)`, and `cancel_check` returns `True`.
- **Cooperative Cancellation:** Dependency scanner checks `cancel_check` between pipeline stages.
- **Limitation:** In-flight Syft subprocesses execute under `subprocess.run()` with a 120-second timeout. Process termination occurs cooperatively upon completion of the active subprocess step rather than through hard process killing.

---

## 7. Security Boundaries & Hardening

1. **Path Traversal Protection:**
   - `safe_dir()` and `safe_file()` in `backend/main.py` enforce resolution and verify paths stay within `BUILDGUARD_WORKSPACE_ROOT` when configured.
2. **Subprocess Safety:**
   - All external commands (`syft`, `npm`, `pnpm`, `yarn`, `docker`) are executed as list arguments (`subprocess.run(cmd, ...)`). Shell invocation (`shell=True`) is never used.
3. **Dependency Installation Isolation:**
   - Package manager invocations strictly include `--ignore-scripts`.
   - Non-destructive flags (`--frozen-lockfile`, `npm ci`, `--no-save`) prevent modification of existing lockfiles.
4. **Authentication & Authorization:**
   - Protected API routes require a valid `X-BuildGuard-Token` header. Missing or invalid tokens return HTTP 401.

---

## 8. Verification Summary

Executed with `.venv/bin/pytest -v -m "not docker"`:

| Test Suite | Tests Run | Result | Notes |
|------------|-----------|--------|-------|
| `backend/tests/test_p1_p2_integration.py` | 20 | **20 PASSED** | Comprehensive API-to-scanner pipeline tests |
| `backend/tests/test_api.py` | 4 | **4 PASSED** | API route & auth verification |
| `backend/tests/test_contracts.py` | 1 | **1 PASSED** | Contract validation |
| `modules/dependency_scanner/tests/` | 96 | **96 PASSED** | P1 unit and regression suite |
| `modules/build_integrity/tests/` | 15 | **15 PASSED** | P2 build integrity tests (2 docker deselected) |
| `modules/compiler_analysis/tests/` | 12 | **12 PASSED** | P3 compatibility tests |
| `modules/reporting/tests/` | 5 | **5 PASSED** | Reporting & correlation tests |
| **Total Non-Docker Test Suite** | **153** | **153 PASSED** | **100% Pass Rate** |

### Docker Test Requirements
- `modules/build_integrity/tests/test_docker_build.py` (2 tests) requires a running Docker daemon (`/var/run/docker.sock`).
- When Docker is unavailable, these tests are marked with `@pytest.mark.docker` and deselected via `-m "not docker"`. All other build integrity tests pass without Docker.

---

## 9. Developer Handoff Guide for P2

### 1. Module Registration
To register a new module in the orchestrator, add its entry to `ENTRY` in `backend/orchestrator.py`:
```python
ENTRY = {
    'dependency': 'modules.dependency_scanner',
    'build': 'modules.build_integrity',
    'compiler': 'modules.compiler_analysis',
    # 'new_module': 'modules.new_module',
}
```

### 2. Module Contract
Every module must implement:
```python
def run(project_path: str, options: dict = None) -> ModuleResult:
    ...
```
Modules must return a `backend.schemas.ModuleResult` (or a dictionary validatable against `ModuleResult`). Modules must handle their own internal errors and never raise unhandled exceptions.

### 3. Adding New Options
Add explicit fields to `backend/schemas.py:ScanOptions`:
```python
class ScanOptions(BaseModel):
    model_config = {"extra": "forbid"}

    # Existing options...
    my_new_option: bool = False
```
Because `extra="forbid"` is enforced, undeclared options will be rejected. Always add new parameters explicitly to `ScanOptions`.

### 4. Adding Integration Tests
Add end-to-end tests in `backend/tests/test_p1_p2_integration.py` using `TestClient(app)` and temporary directories (`tmp_path`). Always set `monkeypatch.setenv("BUILDGUARD_DATA_DIR", str(tmp_path / "data"))` to isolate persistent scan artifacts.
