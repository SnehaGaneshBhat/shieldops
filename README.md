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
- **Docker Requirement:** Runs entirely **without Docker**.

### 2. Build Integrity Verification (`modules/build_integrity`)
- **Reproducible Rebuilds (Docker Required):** Executes independent, dual builds inside a pinned, network-isolated container (`--network none`) and compares output cryptographic hashes (SHA-256).
- **Pinned Recipes:** Enforces build recipes (e.g. `buildguard.yml`) with container images pinned by immutable digests (`@sha256:...`) and outputs constrained to `out/`.
- **Release Manifest Verification (No Docker Required):** Verifies distributed release artifacts against trusted cryptographic manifests (`manifest.json`), operating standalone without Docker when container rebuilds are not requested.
- **Diagnostic Inspection:** Detects byte flips, size differences, and timestamp anomalies when builds diverge.

### 3. Compiler Anomaly Analysis (`modules/compiler_analysis`)
- **Scope:** Strictly limited to supported C source code (`src/**/*.c`) and compiled Linux ELF binaries (`app`) against a reference GCC build. C++, non-ELF binary formats, and other architectures are outside the supported scope.
- **Recursive Source Discovery:** Discovers all nested C translation units (`find "$SRC" -type f -name "*.c"`) using null-delimited processing, safely handling filenames and directory paths containing whitespace.
- **Compiler Lab (Docker Required for Live Builds):** Orchestrates compilation and reference analysis in an isolated container environment (`docker/compiler-lab`).
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
- **Docker Requirement:** Runs entirely **without Docker**.

### 5. VS Code Extension (`extension/`)
- Connects to the local BuildGuard backend via loopback HTTP (`127.0.0.1:8787`).
- **Commands:**
  - `BuildGuard: Scan Workspace` (`buildguard.scan`): Initiates full analysis across selected modules.
  - `BuildGuard: Show Last Report` (`buildguard.showReport`): Displays the formatted report in an interactive Webview.
  - `BuildGuard: Show Demo Report (No Backend)` (`buildguard.showDemoReport`): Displays a rich, bundled sample report. Requires **no running backend, no Docker, and does not scan workspace files**.
  - `BuildGuard: Export Report as HTML` (`buildguard.exportHtml`): Exports the report as a standalone HTML file with a strict Content Security Policy.
  - `BuildGuard: Clear Problems` (`buildguard.clearDiagnostics`): Clears BuildGuard diagnostics from the Problems panel.
- **Problems Integration:** Maps supported manifest dependency findings directly into the VS Code Problems panel with file line references.

---

## Docker Requirements & Operational Breakdown

BuildGuard is designed to allow standalone and offline operation where possible. Here is the operational breakdown:

| Feature / Component | Docker Required? | Notes |
| :--- | :--- | :--- |
| **Dependency Scanner (P1)** | **No** | Discovers manifests, queries OSV, and evaluates heuristics locally |
| **Syft SBOM Generation** | **No** | Requires `syft` binary on `PATH` (standalone CLI tool) |
| **Release Manifest Verification (P2)** | **No** | Cryptographic SHA-256 verification against `manifest.json` |
| **Reproducible Container Rebuilds (P2)** | **Yes** | Requires running Docker daemon for isolated container builds (`--network none`) |
| **Live Compiler Lab Analysis (P3)** | **Yes** | Live compilation, reference builds, and disassembly analysis require Docker and the `compiler-lab` image |
| **Compiler Rule Evaluation (Standalone)** | **No** | C parsing, tokenization, and rule logic can evaluate standalone without Docker when precomputed artifacts or test mocks are provided |
| **Report Correlation & Templates** | **No** | Runs locally in the backend; deterministic template fallback works without Gemini, network access, or Docker |
| **Gemini AI Explanations** | **No** | Requires outbound network access and a configured API key; does not require Docker |
| **Offline Demo Report** | **No** | Bundled static fixtures; does not require backend, Docker, or project scan |
| **VS Code Problems Panel** | **No** | Extension diagnostic UI does not require Docker, but populating live scan findings requires a running backend |
| **HTML Report Export** | **No** | Does not require Docker, but requires an available report (from a live scan or the demo report) |

If the Docker daemon is down or unreachable, the backend catches the failure, reports `DOCKER_UNAVAILABLE` rather than crashing, and sets module status to `error`. Standalone checks continue to run normally.

---

## Prerequisites and System Requirements

- **Operating System:** Linux or macOS (Windows supported via PowerShell).
- **Python:** Python 3.12 (`python3.12` and `python3.12-venv`).
- **Node.js:** Node.js major version 20 or later (v20, v22+) and `npm`.
- **Git:** Required for versioning and environment checks.
- **Docker:** Required for reproducible container builds (P2) and compiler lab execution (P3). Optional for dependency scanning and demo reports.
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
- **Scan initiation:** `POST http://127.0.0.1:8787/v1/scans` (requires `X-BuildGuard-Token: dev-token`)
- **Scan status:** `GET http://127.0.0.1:8787/v1/scans/{scan_id}` (requires `X-BuildGuard-Token: dev-token`)
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

### Setting Up `.vscode/launch.json` for a Fresh Clone

Because `.vscode/launch.json` is untracked by default in git, contributors opening the repository in VS Code need to create `.vscode/launch.json` with the following configuration to debug the extension:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "Run BuildGuard Extension",
      "type": "extensionHost",
      "request": "launch",
      "args": [
        "--extensionDevelopmentPath=${workspaceFolder}/extension",
        "--disable-extensions",
        "--disable-gpu"
      ],
      "outFiles": [
        "${workspaceFolder}/extension/dist/**/*.js"
      ]
    }
  ]
}
```

### Launching the Extension in VS Code

1. Open the repository root in VS Code.
2. Ensure the extension is compiled: `npm --prefix extension run compile`.
3. Select **Run and Debug** from the Activity Bar (`Ctrl+Shift+D` / `Cmd+Shift+D`).
4. Select **Run BuildGuard Extension** and press `F5`.
5. An **Extension Development Host** window will launch with the BuildGuard extension active.

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

- When `buildguard.autoStartBackend` is `true` and `buildguard.backendCwd` points to the repository root, the extension automatically starts the backend if it is not already running.

---

## Example and Demo Workflows

BuildGuard provides built-in sample projects and an offline demo mode for evaluation:

### 1. Offline Demo Report (No Backend or Docker Required)

In VS Code, open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) and run:
`BuildGuard: Show Demo Report (No Backend)`

**Key properties of the demo report:**
- **No backend service needed:** Operates completely offline without connecting to the REST API.
- **No Docker needed:** Does not build or run any Docker containers.
- **Does not scan project files:** Uses static, bundled fictional fixture data from `extension/media/demo-report.json`.
- **Full visual preview:** Renders findings across all 7 categories (`DEPENDENCY_VULNERABILITY`, `BUILD_ANOMALY`, `COMPILER_ANOMALY`, `SUSPICIOUS_PACKAGE`, `POLICY_VIOLATION`, `UNRESOLVED`, and `NO_KNOWN_ISSUES`).
- **HTML export preview:** You can test `BuildGuard: Export Report as HTML` directly from the demo view.

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
Run all compiler analysis rules, scope limitations, preprocessor hardening, and recursive source discovery tests:

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

## Scope and Security Limitations

1. **Compiler Analysis Scope:**
   - Exclusively supports C translation units (`src/**/*.c`) compiled into Linux ELF executables (`app`).
   - C++, Windows PE executables, macOS Mach-O, and other target architectures are outside the supported MVP scope.
2. **Docker Isolation Boundaries:**
   - Reproducible builds run inside pinned container images with network access explicitly disabled (`--network none`).
   - Compiler lab analysis executes inside a dedicated sandbox container (`compiler-lab`).
3. **Safety Claims Scope:**
   - A `NO_KNOWN_ISSUES` finding indicates only that no anomalies were detected by the specific checks performed. It is not formal verification or proof of absolute system safety.
4. **Credential Security:**
   - Scan tokens and LLM API keys must remain strictly in environment variables or uncommitted `.env` files.

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
