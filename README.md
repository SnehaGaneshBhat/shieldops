# BuildGuard

BuildGuard brings dependency safety, build-integrity verification, and compiler anomaly checks into a unified local workflow. It inspects software supply-chain components, compares build reproducibility and release artifacts, flags compiler discrepancies, and correlates findings into an actionable report accessible via a local REST API and a VS Code extension.

## Architecture and Core Functionality

BuildGuard consists of three core analysis modules, a correlation and reporting engine, a local authenticated REST backend, and a VS Code extension:

```
                  +-----------------------------------+
                  |         VS Code Extension         |
                  |  (Commands, Webview, Diagnostics)  |
                  +-----------------+-----------------+
                                    | HTTP / REST
                                    v
                  +-----------------------------------+
                  |      BuildGuard Local Backend     |
                  |     (FastAPI / Uvicorn Service)   |
                  +-----------------+-----------------+
                                    |
          +-------------------------+-------------------------+
          |                         |                         |
          v                         v                         v
+-------------------+     +-------------------+     +-------------------+
|    P1: Module     |     |    P2: Module     |     |    P3: Module     |
| Dependency Safety |     |  Build Integrity  |     | Compiler Analysis |
+-------------------+     +-------------------+     +-------------------+
          |                         |                         |
          +-------------------------+-------------------------+
                                    |
                                    v
                  +-----------------------------------+
                  |     Correlation & Reporting       |
                  |  (Finding Synthesis, Templates,  |
                  |      Optional Gemini LLM)         |
                  +-----------------------------------+
```

### 1. Dependency Safety (`modules/dependency_scanner`)
- **Manifest & Lockfile Discovery:** Scans project directories for supported ecosystem manifests:
  - JavaScript / Node: `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  - Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`
  - Go: `go.mod`, `go.sum`
  - Rust: `Cargo.lock`
  - Java: `pom.xml`
  - C / C++: `vcpkg.json`, `vcpkg-configuration.json`, `conanfile.txt`, `conan.lock`
- **Advisory Lookup:** Queries the Open Source Vulnerabilities (OSV) database for known CVEs and security advisories, caching results locally in `.buildguard/cache/osv/`.
- **Heuristic Indicators:** Evaluates package metadata for suspicious install scripts, typo-squatting, and unpinned repository commits.
- **SBOM Generation:** Invokes Syft when installed to generate a CycloneDX Software Bill of Materials.

### 2. Build Integrity Verification (`modules/build_integrity`)
- **Reproducible Rebuilds:** Executes independent, dual builds inside a pinned, network-isolated container (`--network none`) and compares output cryptographic hashes (SHA-256).
- **Pinned Recipes:** Enforces build recipes (e.g. `buildguard.yml`) with container images pinned by immutable digests (`@sha256:...`) and outputs constrained to `out/`.
- **Release Manifest Verification:** Verifies distributed release artifacts against trusted cryptographic manifests (`manifest.json`), operating standalone without Docker when rebuilds are not requested.
- **Diagnostic Inspection:** Detects byte flips, size differences, and timestamp anomalies when builds diverge.

### 3. Compiler Anomaly Analysis (`modules/compiler_analysis`)
- **Scope:** Analyzes C source code (recursively discovered across all directory levels under `src/`) and compiled Linux ELF binaries (`app`) against a reference GCC build.
- **Recursive Source Discovery:** Discovers all nested C translation units (`find "$SRC" -type f -name "*.c"`) using null-delimited processing, safely handling filenames and directory paths containing whitespace.
- **Compiler Lab:** Orchestrates compilation and reference analysis in an isolated container environment (`docker/compiler-lab`).
- **Trusted Compiler Path Validation:** Validates container compiler IDs (`clang`, `gcc`) and verifies executable paths reside strictly in approved container system directories (`/usr/bin`, `/usr/local/bin`, `/bin`).
- **Exact Simulated-Wrapper Recognition:** Enforces exact configuration matching for authorized simulated compiler compromise wrapper scripts, rejecting arbitrary commands or loose substring spoofs.
- **Authoritative Source Extraction:** Uses verified container compilers (`/usr/bin/clang`, `/usr/bin/gcc`, `/usr/local/bin`, `/bin`) to extract active source function definitions from preprocessed sources (`-E`).
- **Anomaly Detection:** Identifies hidden injected functions (simulated compromise wrappers), missing source functions, risky dynamic imports (e.g., `system`, `execve`), and unknown `.rodata` strings.
- **Graceful Degradation:** Transitions cleanly to `partial` status with explicit notices when binaries are stripped or when offline fallback extraction is utilized.

### 4. Correlation, Reporting & Gemini Integration (`modules/reporting`)
- **Unified Findings Schema:** Combines module outputs into standardized categories:
  - `DEPENDENCY_VULNERABILITY`
  - `SUSPICIOUS_PACKAGE`
  - `BUILD_ANOMALY`
  - `COMPILER_ANOMALY`
  - `POLICY_VIOLATION`
  - `UNRESOLVED`
  - `NO_KNOWN_ISSUES`
- **AI-Assisted Explanations:** Optionally queries Google Gemini API to generate contextual summaries and remediation guidance.
- **Robust Fallback:** Uses deterministic templated explanations if the Gemini API key is unconfigured, unreachable, or disabled (`buildguard.useLLM: false`).
- **Local LLM Cache:** Caches responses in `.buildguard/cache/llm/` (bypassable via `BUILDGUARD_NO_CACHE=1`).

### 5. VS Code Extension (`extension/`)
- Connects to the local BuildGuard backend via loopback HTTP (`127.0.0.1:8787`).
- **Commands:**
  - `BuildGuard: Scan Workspace` (`buildguard.scan`): Initiates full analysis across selected modules.
  - `BuildGuard: Show Last Report` (`buildguard.showReport`): Displays the formatted report in an interactive Webview.
  - `BuildGuard: Show Demo Report (No Backend)` (`buildguard.showDemoReport`): Previews a bundled comprehensive report without backend or Docker dependencies.
  - `BuildGuard: Export Report as HTML` (`buildguard.exportHtml`): Exports the report as a standalone HTML file with a strict Content Security Policy.
  - `BuildGuard: Clear Problems` (`buildguard.clearDiagnostics`): Clears BuildGuard diagnostics from the Problems panel.
- **Problems Integration:** Maps supported manifest dependency findings directly into the VS Code Problems panel with file line references.

---

## Prerequisites and System Requirements

- **Operating System:** Linux or macOS (Windows supported via PowerShell).
- **Python:** Python 3.12 (`python3.12` and `python3.12-venv`).
- **Node.js:** Node.js major version 20 or later (v20, v22+) and `npm`.
- **Git:** Required for versioning and environment checks.
- **Docker:** Required for reproducible container builds (P2) and compiler lab execution (P3).
- **Syft:** Optional; required on `PATH` for CycloneDX SBOM generation in P1.
- **VS Code:** Version 1.85 or newer for the extension.

### Environment Check

Verify your local environment with the included check script:

```sh
bash scripts/check_env.sh
```

Or via Makefile:

```sh
make setup
```

---

## Backend Setup and Startup

### 1. Python Virtual Environment

From the repository root:

```sh
# Using GNU Make
make venv

# Or manually:
python3.12 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r backend/requirements.txt
```

### 2. Configuration & Environment Variables

Copy the example configuration to `.env` if using Gemini explanations:

```sh
cp .env.example .env
```

Supported environment variables:

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `BUILDGUARD_TOKEN` | Shared secret for backend API authentication (`X-BuildGuard-Token`) | Auto-generated or `TOKEN=dev-token` |
| `BUILDGUARD_WORKSPACE_ROOT` | Restricts scans to paths within this directory | None (allows any valid local path) |
| `GEMINI_API_KEY` | Google Gemini API key for generated explanations | `paste-your-key-here` |
| `GEMINI_MODEL` | Google Gemini model identifier | `gemini-2.5-flash` |
| `BUILDGUARD_LLM_API_KEY` | Legacy fallback for Gemini API key | None |
| `BUILDGUARD_LLM_MODEL` | Legacy fallback for Gemini model ID | `gemini-2.5-flash` |
| `BUILDGUARD_NO_CACHE` | Set to `1` to bypass local LLM caching | `0` (caching enabled) |
| `BUILDGUARD_DOCKER_BIN` | Custom path to Docker executable | `docker` |
| `BUILDGUARD_SYFT_BIN` | Custom path to Syft executable | `syft` |

> [!IMPORTANT]
> Keep API keys and tokens out of committed code and workspace settings. Never commit `.env` or hardcode production credentials.

### 3. Starting the Backend Service

Start the local backend API with:

```sh
# Using GNU Make (listens on 127.0.0.1:8787)
make run-backend TOKEN=dev-token

# Or manually via uvicorn:
BUILDGUARD_TOKEN=dev-token .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

- **Health check endpoint:** `http://127.0.0.1:8787/v1/health` (open)
- **Scan initiation:** `POST http://127.0.0.1:8787/v1/scan` (requires `X-BuildGuard-Token: dev-token`)
- **Report retrieval:** `GET http://127.0.0.1:8787/v1/scans/{scan_id}/report` (requires `X-BuildGuard-Token: dev-token`)

For extension preview without running scans, a lightweight mock server is also available:

```sh
make run-mock
# or
.venv/bin/python -m uvicorn backend.mock_server:app --host 127.0.0.1 --port 8787
```

---

## Extension Build and Launch

From the repository root:

```sh
# Install extension dependencies
npm --prefix extension ci

# Typecheck and compile extension bundle
npm --prefix extension run lint
npm --prefix extension run compile
```

### Launching in VS Code

1. Open this repository in VS Code.
2. Select **Run and Debug** from the sidebar (or press `Ctrl+Shift+D` / `Cmd+Shift+D`).
3. Choose **Run BuildGuard Extension** and press `F5`.
4. An **Extension Development Host** window will open with BuildGuard loaded.

### Extension Settings

In the Extension Development Host settings (`settings.json`):

```json
{
  "buildguard.backendUrl": "http://127.0.0.1:8787",
  "buildguard.token": "dev-token",
  "buildguard.autoStartBackend": true,
  "buildguard.backendCwd": "/absolute/path/to/shieldops",
  "buildguard.modules": ["dependency", "build", "compiler"],
  "buildguard.compilerSample": "test_samples/compiler_hello",
  "buildguard.useLLM": true
}
```

- When `buildguard.autoStartBackend` is `true` and `buildguard.backendCwd` points to the repository root, the extension automatically spins up the backend if it is not already running.

---

## Example and Demo Workflows

BuildGuard provides built-in sample projects and an offline demo mode for testing:

### 1. Offline Demo Report (No Backend Required)
In VS Code, open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run:
`BuildGuard: Show Demo Report (No Backend)`

This renders a rich sample report with findings across all 7 categories (`DEPENDENCY_VULNERABILITY`, `BUILD_ANOMALY`, `COMPILER_ANOMALY`, etc.) using bundled fixture data in `extension/media/demo-report.json`. You can also test `BuildGuard: Export Report as HTML` from this view.

### 2. Sample Projects (`test_samples/`)
- `test_samples/compiler_hello`: C source sample with clean compilation and simulated wrapper configurations for testing compiler anomaly detection.
- `test_samples/deps_clean_npm`: Sample project with verified dependency lockfile.
- `test_samples/deps_vuln_npm`: Sample project containing known vulnerable dependencies for testing OSV advisory reporting.
- `test_samples/deps_vuln_cpp`: C/C++ sample using `vcpkg.json` for dependency scanning.
- `test_samples/reproducible_c`: C project equipped with a pinned `buildguard.yml` container recipe for reproducible build testing.

---

## Testing

### Python Non-Docker Tests
Run the consolidated Python test suite (fast unit and integration tests excluding Docker):

```sh
make test
# Or directly with pytest:
.venv/bin/pytest -m 'not docker' -v
```

### Compiler Analysis Tests
Run all compiler analysis rules, scope limitations, and preprocessor hardening tests:

```sh
.venv/bin/pytest modules/compiler_analysis/tests/ -v
```

### Environment Checker Tests
Run tests for `scripts/check_env.sh` (Node >= 20 validation):

```sh
.venv/bin/pytest backend/tests/test_check_env.py -v
```

### Extension Tests
Run the VS Code extension test suite:

```sh
npm --prefix extension test
```

### Docker-Dependent Tests
When a local Docker daemon is running and lab images are built:

```sh
make test-docker
# Or directly with pytest:
.venv/bin/pytest -m docker -v -s
```

---

## Docker Requirements & Operational Limitations

1. **Docker Daemon Dependency:**
   - **Required for:** P2 container rebuilds (`modules/build_integrity`) and P3 compiler lab container runs (`modules/compiler_analysis`).
   - **Not required for:** P1 dependency scanning, OSV lookups, Syft SBOM generation, release manifest verification (`manifest.json`), report correlation, or extension demo workflows.
2. **Graceful Handling when Docker is Inactive:**
   - If the Docker daemon is down or unreachable, the backend reports `DOCKER_UNAVAILABLE` rather than crashing, and sets module status to `error`.
   - Standalone release manifest verification and dependency scanning continue to operate independently.
3. **Compiler Analysis Scope:**
   - Limited to C translation units (`.c`) compiled into Linux ELF executables.
   - Non-ELF binaries, C++, or unsupported architectures are identified early and rejected with descriptive scope errors.
4. **Scope of Safety Claims:**
   - A `NO_KNOWN_ISSUES` finding indicates only that no anomalies were detected by the specific checks performed. It is not formal verification or proof of absolute system safety.

---

## Repository Structure

```
├── backend/                     # FastAPI backend service, REST routes, store, and orchestrator
│   ├── tests/                  # Backend unit and integration tests
│   └── requirements.txt        # Backend Python dependencies
├── modules/
│   ├── dependency_scanner/     # P1: Manifest discovery, OSV client, heuristics, Syft SBOM
│   ├── build_integrity/        # P2: Pinned container builds, hash comparison, manifest check
│   ├── compiler_analysis/      # P3: Containerized compiler lab, ELF parsing, anomaly rules
│   └── reporting/              # Combined report correlation, templates, Gemini LLM client
├── extension/                  # VS Code extension (TypeScript, Webview, esbuild, tests)
│   ├── src/                    # Extension client, diagnostics, backend manager, HTML export
│   ├── test/                   # Extension test suites (Node test runner)
│   └── package.json            # Extension manifests and contribute points
├── docker/
│   └── compiler-lab/           # Dockerfile and lab_run.sh script for compiler analysis
├── scripts/
│   └── check_env.sh            # Environment dependency verification script
├── test_samples/               # Bundled sample projects for testing and verification
├── Makefile                    # Common developer targets (venv, setup, test, run-backend)
└── .env.example                # Template for Gemini and backend environment variables
```
