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
  - Rust: `Cargo.lock`, `Cargo.toml`
  - Java: `pom.xml`
  - C / C++: `vcpkg.json`, `vcpkg-configuration.json`, `conanfile.txt`, `conan.lock`
  - .NET / NuGet: `packages.config`, `*.csproj`, `packages.lock.json`
- **Advisory Lookup & Caching:** Queries the Open Source Vulnerabilities (OSV) database for known CVEs and security advisories, caching results locally in `.buildguard/cache/osv/`.
  - In offline mode (`offline=True`), cached queries and advisories are used. Versionless packages participate in cache lookups: cache hits report `UNRESOLVED` (`version_comparison_unknown`) explaining that the installed version is unavailable, and cache misses report `UNRESOLVED` (`osv_unreachable`) rather than silently skipping the package.
- **Heuristic Indicators:** Evaluates package metadata and manifest declarations:
  - `TYPOSQUAT`: Levenshtein distance check against top packages with strict ecosystem isolation (npm vs. PyPI).
  - `INSTALL_SCRIPT`: Detects npm lifecycle scripts (`preinstall`, `install`, `postinstall`).
  - `MISSING_INTEGRITY`: Flags npm dependencies lacking SHA integrity hashes in lockfile manifests (`package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml`).
  - `NONREGISTRY_SOURCE`: Flags dependencies sourced from git repositories or direct URLs instead of verified registries.
  - `NEW_OR_THIN_PACKAGE`: Flags packages published within 30 days or having only a single release version.
- **SBOM Generation:** Invokes Syft when installed to generate a CycloneDX Software Bill of Materials.
- **Docker Requirement:** Runs entirely **without Docker**.

### 2. Build Integrity Verification (`modules/build_integrity`)
- **Reproducible Rebuilds (Docker Required):** Executes independent, dual builds inside a pinned, network-isolated container (`--network none`) and compares output cryptographic hashes (SHA-256).
- **Pinned Recipes & Target Resolution:** Enforces build recipes (e.g. `buildguard.yml`) with container images pinned by immutable digests (`@sha256:...`) and outputs constrained to `out/`.
  - Target resolution checks the workspace root for `buildguard.yml`. If absent, it checks an explicitly configured sample directory (e.g., `test_samples/compiler_hello`). If neither contains the recipe, it retains the workspace root and reports `NOT_COMPARABLE` (`recipe not found`). External workspaces never substitute bundled samples.
- **Release Manifest Verification (No Docker Required):** Verifies distributed release artifacts against trusted cryptographic manifests (`manifest.json` or `release_manifest.json`), operating standalone without Docker when container rebuilds are not requested.
- **Diagnostic Inspection:** Detects byte flips, size differences, and timestamp anomalies when builds diverge.

### 3. Compiler Anomaly Analysis (`modules/compiler_analysis`)
- **Scope:** Strictly limited to supported C source code (`src/**/*.c`) and compiled Linux ELF binaries (`app`) against a reference GCC build. C++, non-ELF binary formats, and other architectures are outside the supported scope.
- **Recursive Source Discovery:** Discovers all nested C translation units (`find "$SRC" -type f -name "*.c"`) using null-delimited processing, safely handling filenames and directory paths containing whitespace.
- **Target Resolution:** Scans the user workspace if `src/` contains `.c` source files; otherwise safely resolves an explicitly configured `compiler_sample` (e.g., `test_samples/compiler_hello`).
- **Compiler Lab (Docker Required for Live Builds):** Orchestrates compilation and reference analysis in an isolated container environment (`docker/compiler-lab`).
- **Trusted Compiler Path Validation:** Validates container compiler IDs (`clang`, `gcc`) and verifies executable paths reside strictly in approved container system directories (`/usr/bin`, `/usr/local/bin`, `/bin`).
- **Exact Simulated-Wrapper Recognition:** Enforces exact configuration matching for authorized simulated compiler compromise wrapper scripts, rejecting arbitrary commands or loose substring spoofs.
- **Authoritative Source Extraction:** Uses verified container compilers (`/usr/bin/clang`, `/usr/bin/gcc`, `/usr/local/bin`, `/bin`) to extract active source function definitions from preprocessed sources (`-E`).
- **Anomaly Detection:** Identifies hidden injected functions (simulated compromise wrappers), missing source functions, risky dynamic imports (e.g., `system`, `execve`), and unknown `.rodata` strings.
- **Graceful Degradation:** Transitions cleanly to `partial` status with explicit notices when binaries are stripped or when offline fallback extraction is utilized.

### 4. Correlation, Reporting & Gemini Integration (`modules/reporting`)
- **Unified Findings Schema:** Combines module outputs into standardized categories:
  - `KNOWN_VULNERABILITY`: Exact match against published security advisories for the resolved package version.
  - `KNOWN_MALICIOUS_ADVISORY`: Published malicious package record (e.g., `MAL-*`).
  - `SUSPICIOUS_INDICATOR`: Heuristic security flags (typosquatting, lifecycle scripts, missing lockfile integrity, non-registry source, new package).
  - `BUILD_MISMATCH`: Cryptographic hash divergence between independent reproducible rebuilds or release manifests.
  - `COMPILER_ANOMALY`: Discrepancy between C source symbols and compiled binary artifacts (injected functions, missing source functions, risky dynamic imports).
  - `UNRESOLVED`: Incomplete check (e.g., versionless package, offline cache miss, unsupported ecosystem, missing tools, parsing error).
  - `NO_KNOWN_ISSUES`: Informational finding indicating all requested checks completed cleanly with zero findings detected.
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

Prerequisites differ depending on whether you are using the packaged extension or contributing to the codebase:

### For VS Code End Users (Using the Packaged Extension)
- **Operating System:** Linux, macOS, or Windows.
- **VS Code:** Version 1.85 or newer.
- **Python 3.12:** Required if running the BuildGuard backend locally (`python3.12` and `python3.12-venv`).
- **Docker (Optional):** Required only if running containerized reproducible rebuilds (P2) or live compiler-lab anomaly checks (P3). Not needed for dependency scanning, standalone release manifest verification, or demo reports.
- **Syft (Optional):** Standalone `syft` CLI on `PATH` for CycloneDX SBOM generation in P1.
- *Note:* Node.js, npm, Git, and source build tools are **not** required for users who receive and install the pre-packaged `.vsix` extension file.

### For Extension Developers and Contributors
- **Node.js & npm:** Node.js major version 20 or later (v20, v22+) and `npm` (required for extension bundling, linting, packaging, and tests).
- **Git:** Required for source checkout, versioning, and environment checks.
- **Python 3.12:** Python virtual environment with backend dependencies (`make venv`).
- **Docker:** Running Docker daemon for container rebuild and compiler lab testing (`make test-docker`).
- **Extension Development Host:** VS Code for live extension debugging (`F5`).

### Environment Check

Contributors can verify their local development environment with the included check script:

```sh
bash scripts/check_env.sh
```

Or via Makefile:

```sh
make setup
```

---

## Using BuildGuard as a VS Code User

This section covers the standard workflow for installing and using BuildGuard in VS Code without requiring the Extension Development Host or developer tools.

### 1. Install the Packaged Extension

BuildGuard is packaged as a standard VS Code extension package (`.vsix`):

1. **Generate or Obtain the Package:**
   If building from the repository, package the extension artifact:
   ```sh
   npm --prefix extension run package
   ```
   This generates `buildguard-0.1.0.vsix` in the repository root.

2. **Install into VS Code:**
   - **Via VS Code UI:** Open the **Extensions** view (`Ctrl+Shift+X` / `Cmd+Shift+X`), click the **Views and More Actions** (`...`) menu at the top-right of the Extensions pane, select **Install from VSIX...**, and choose `buildguard-0.1.0.vsix`.
   - **Via Command Palette:** Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`), run `Extensions: Install from VSIX...`, and select the file.
   - **Via Terminal / CLI:** Run:
     ```sh
     code --install-extension buildguard-0.1.0.vsix
     ```

> [!NOTE]
> Installing a packaged `.vsix` does **not** require Node.js, npm, Git, or an active extension source checkout on the user's machine. The extension runs directly inside standard VS Code.

### 2. Start and Configure the Backend

The BuildGuard extension communicates with a local backend service to perform live scans. The `.vsix` package provides the editor interface, diagnostics, and report views, but does not bundle or automatically install Python dependencies or the backend service.

1. **Start the Backend:**
   Ensure the Python environment is set up (see [Backend Setup and Startup](#backend-setup-and-startup)), then launch the backend service:
   ```sh
   # Start with a shared development token
   make run-backend TOKEN=dev-token

   # Or manually:
   BUILDGUARD_TOKEN=dev-token .venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
   ```

2. **Configure Extension Settings:**
   In VS Code, open Settings (`Ctrl+,` / `Cmd+,` or **File > Preferences > Settings**), search for `buildguard`, or configure in your user or workspace `settings.json`:

   ```json
   {
     "buildguard.backendUrl": "http://127.0.0.1:8787",
     "buildguard.token": "dev-token"
   }
   ```

   **Core Extension Settings:**
   | Setting | Type | Default | Description |
   | :--- | :--- | :--- | :--- |
   | `buildguard.backendUrl` | `string` | `"http://127.0.0.1:8787"` | URL of the running BuildGuard backend service. |
   | `buildguard.token` | `string` | `""` | Shared secret token matching `BUILDGUARD_TOKEN` passed to the backend. |
   | `buildguard.modules` | `array` | `["dependency", "build", "compiler"]` | Analysis modules to execute during scans. |
   | `buildguard.useLLM` | `boolean` | `true` | Generate AI explanations via Gemini (falls back to deterministic templates). |
   | `buildguard.autoStartBackend` | `boolean` | `true` | Automatically starts the backend if stopped (requires `backendCwd`). |
   | `buildguard.backendCwd` | `string` | `""` | Absolute repository path containing `.venv` and `backend/` for auto-start. |
   | `buildguard.compilerSample` | `string` | `"test_samples/compiler_hello"` | Sample path relative to workspace for compiler demo evaluation. |

### 3. Run a Scan and Inspect Results

1. **Open a Project Folder:** Open the workspace or project directory you want to inspect in VS Code (**File > Open Folder...**).
2. **Execute a Workspace Scan:**
   - Open the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`).
   - Run **BuildGuard: Scan Workspace** (`buildguard.scan`).
   - BuildGuard initiates the scan against the backend across selected modules (`dependency`, `build`, `compiler`).
3. **Inspect Diagnostics in Problems Panel:**
   - Supported dependency and manifest issues appear directly in the VS Code **Problems** panel (`Ctrl+Shift+M` / `Cmd+Shift+M`) with direct file and line references.
   - To clear these diagnostics, run **BuildGuard: Clear Problems** (`buildguard.clearDiagnostics`).
4. **View and Export Findings:**
   - **Show Interactive Report:** Run **BuildGuard: Show Last Report** (`buildguard.showReport`) to display findings, severity levels, confidence, and remediation actions in an interactive Webview.
   - **Export HTML Report:** Run **BuildGuard: Export Report as HTML** (`buildguard.exportHtml`) to generate a standalone HTML document secured with a strict Content Security Policy.
5. **Backend-Free Preview (Demo Report):**
   - Run **BuildGuard: Show Demo Report (No Backend)** (`buildguard.showDemoReport`) from the Command Palette to preview the report UI using bundled static fictional data.
   - *Note:* The demo report requires no backend and does not scan workspace files; live analysis of your project always requires a running backend.

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
| `BUILDGUARD_DATA_DIR` | Custom path to heuristics package data directory (or `SHIELDOPS_DATA_DIR`) | Bundled data directory |
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

Supported REST API endpoints:
- `GET http://127.0.0.1:8787/v1/health` (open) — Service status, version, and tool availability (Docker, Syft, LLM configuration).
- `POST http://127.0.0.1:8787/v1/scans` (auth) — Starts a workspace scan across requested modules (`dependency`, `build`, `compiler`).
- `GET http://127.0.0.1:8787/v1/scans/{scan_id}` (auth) — Polls scan state (`queued`, `running`, `completed`, `failed`, `cancelled`) and module-level progress.
- `GET http://127.0.0.1:8787/v1/scans/{scan_id}/findings` (auth) — Retrieves raw structured findings array.
- `GET http://127.0.0.1:8787/v1/scans/{scan_id}/report` (auth) — Retrieves the correlated JSON report with synthesized explanations.
- `GET http://127.0.0.1:8787/v1/scans/{scan_id}/report.html` (auth) — Retrieves the rendered standalone HTML report.
- `POST http://127.0.0.1:8787/v1/scans/{scan_id}/cancel` (auth) — Cancels an in-progress scan.
- `POST http://127.0.0.1:8787/v1/release-manifests` (auth) — Builds the trusted release artifact into `dist/` and writes `release_manifest.json`.
- `POST http://127.0.0.1:8787/v1/verify-artifact` (auth) — Verifies a distributed artifact against a cryptographic release manifest (no Docker needed).

For extension preview without running scans, a lightweight mock server is also available:

```sh
make run-mock
# or
.venv/bin/python -m uvicorn backend.mock_server:app --host 127.0.0.1 --port 8787
```

### 4. Standalone Module CLI Execution

Each core analysis module can be invoked directly from the command line:

```sh
# Dependency Scanner (P1)
.venv/bin/python -m modules.dependency_scanner <project_path> [--offline] [--cache-dir <dir>] [--out <file>] [--sbom <file>] [-v]

# Build Integrity Verification (P2)
.venv/bin/python -m modules.build_integrity <project_path> [--recipe buildguard.yml] [--release] [--manifest <file>] [--distributed <file>] [--verify-only]

# Compiler Anomaly Analysis (P3)
.venv/bin/python -m modules.compiler_analysis <sample_path> [--project-cc <cmd>] [--out-dir <dir>] [--opt-level -O0] [--strip]
```

---

## Extension Development Workflow (Contributors)

> [!NOTE]
> This section is intended for contributors modifying, building, or debugging the extension source code using the Extension Development Host. Ordinary users should follow the packaged extension workflow in [Using BuildGuard as a VS Code User](#using-buildguard-as-a-vs-code-user).

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
- **Full visual preview:** Renders findings across all 7 categories (`KNOWN_VULNERABILITY`, `KNOWN_MALICIOUS_ADVISORY`, `SUSPICIOUS_INDICATOR`, `BUILD_MISMATCH`, `COMPILER_ANOMALY`, `UNRESOLVED`, and `NO_KNOWN_ISSUES`).
- **HTML export preview:** You can test `BuildGuard: Export Report as HTML` directly from the demo view.

### 2. Sample Projects (`test_samples/`)
- `test_samples/compiler_hello`: Clean C compilation and simulated wrapper configurations for testing compiler anomaly detection.
- `test_samples/compiler_wrapper_inject`: Sample demonstrating unauthorized compiler wrapper injection detection.
- `test_samples/build_reproducible_c`: C project equipped with a pinned `buildguard.yml` container recipe demonstrating reproducible build matching (`MATCH`).
- `test_samples/build_unreproducible_c`: C project demonstrating non-reproducible builds via embedded timestamps (`BUILD_MISMATCH`).
- `test_samples/build_tampered_c`: Post-build artifact tampering sample demonstrating one-byte difference detection (`POST_BUILD_DIFF`).
- `test_samples/deps_clean`: Clean project with verified dependency manifests.
- `test_samples/deps_vuln_npm`: Node.js sample containing known vulnerable dependencies for testing OSV advisory reporting.
- `test_samples/deps_suspicious_npm`: Node.js sample containing heuristic security indicators (lifecycle scripts, typosquatting, non-registry sources, missing integrity).
- `test_samples/deps_vuln_cpp`: C/C++ sample using `vcpkg.json` for dependency scanning.
- `test_samples/deps_multi_package`: Multi-package monorepo sample containing npm, PyPI, Go, and lockfiles.

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

### Extension Tests & Packaging
Run the VS Code extension test suites and packaging commands:

```sh
# Consolidated extension tests (Node test runner)
npm --prefix extension test

# Focused demo report fixture test
npm --prefix extension run test:demo

# Typecheck and lint extension TypeScript
npm --prefix extension run lint

# Package extension into .vsix artifact (buildguard-0.1.0.vsix)
npm --prefix extension run package
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
