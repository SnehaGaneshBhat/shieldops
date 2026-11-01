# BuildGuard

BuildGuard brings dependency, build-integrity, and compiler checks into one VS Code workflow. It connects findings from the software supply chain to the project being built, shows what ran and what could not be verified, and produces a scan-specific report.

## What BuildGuard Does

- **Dependency safety:** inspects supported dependency manifests and lockfiles, checks for known vulnerabilities and suspicious package indicators, and can generate a software bill of materials (SBOM) with Syft.
- **Build integrity:** checks reproducibility by building twice in a pinned, network-disabled container and comparing artifact hashes. When a trusted release manifest and distributed artifact are provided, it also compares their hashes.
- **Compiler security:** analyzes supported C/Linux ELF samples against a reference build for compiler-related anomalies. This is a focused MVP, not a general-purpose compiler certification system.
- **Combined reporting:** correlates findings from the selected modules into one report with evidence, explanations, module status, and limitations. Explanations use the reporting module when configured and otherwise fall back to templates.
- **VS Code workflow:** displays findings in a report view, adds supported dependency findings to the Problems panel, and exports the latest scan as a standalone HTML file.

BuildGuard reports only on checks that ran. A clean result is not proof that a project, compiler, or artifact is safe.

## Requirements

- Python 3.12 and the `python3.12-venv` package
- Python packages listed in `backend/requirements.txt`
- Node.js 20 and npm
- Docker running for build-integrity and compiler checks
- Syft on `PATH` for SBOM generation
- VS Code 1.85 or newer

An LLM API key is optional. Set `BUILDGUARD_LLM_API_KEY` for the backend if generated explanations are desired; without it, BuildGuard uses template explanations. Keep tokens and API keys out of committed workspace settings.

Python packages are installed from `backend/requirements.txt`. Extension packages are managed separately by npm in `extension/package-lock.json`. Docker, Syft, Node.js, and GNU Make are system tools, not Python packages.

## Set Up The Backend

### Windows PowerShell

Run these commands from the repository root. This setup does not require GNU Make or winget:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

To start the backend manually:

```powershell
$env:BUILDGUARD_TOKEN = "dev-token"
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8787
```

For a manually started backend, use these VS Code settings:

```json
{
  "buildguard.backendUrl": "http://127.0.0.1:8787",
  "buildguard.token": "dev-token",
  "buildguard.autoStartBackend": false
}
```

Run backend tests in PowerShell with:

```powershell
.\.venv\Scripts\python.exe -m pytest -m 'not docker' -q
```

### Linux And macOS

GNU Make is a command-line task runner, not a GUI. It is optional; the commands below are shortcuts for the repository's Makefile. From the repository root:

```sh
make venv
make setup
make run-backend TOKEN=dev-token
```

The API listens on `http://127.0.0.1:8787`. Its health endpoint is `http://127.0.0.1:8787/v1/health`; scan and report endpoints require the `X-BuildGuard-Token` header. The service is intended for local use and binds to loopback.

On Windows, use the PowerShell commands above. You do not need to install winget, a GUI, or GNU Make to set up or run the backend.

Use workspace Settings to choose modules or configure paths:

- `buildguard.recipePath`: build recipe path, relative to the open workspace; defaults to `buildguard.yml`.
- `buildguard.compilerSample`: compiler sample directory; defaults to `test_samples/compiler_hello`.
- `buildguard.manifestPath` and `buildguard.distributedArtifact`: set both to include trusted-manifest verification in the combined report. The verification can run without Docker or a build recipe.
- `buildguard.useLLM`: request generated explanations from the backend; template explanations remain available as fallback.

Build reproducibility requires a valid recipe with a container image pinned by digest and an available Docker daemon. If no recipe is present, the build check is reported as skipped; if only artifact verification runs, the module is reported as partial.

## Develop The Extension

From the repository root:

```sh
npm --prefix extension ci
npm --prefix extension run lint
npm --prefix extension run compile
```

Open the repository in VS Code, choose **Run BuildGuard Extension** in Run and Debug, and press F5. The launch configuration builds the extension and opens an Extension Development Host. Set `buildguard.backendCwd` in that host to the absolute repository path to enable automatic backend startup.

## Tests

Run the extension typecheck and the real non-Docker backend test suite with the npm script on systems that have GNU Make:

```sh
npm --prefix extension test
```

Or run backend tests directly with `make test`. Docker-dependent tests are separate:

```sh
make test-docker
```

Dependency scan tests that expect SBOM generation require Syft; build and compiler tests may require Docker and their configured images.

## Repository Layout

- `extension/`: VS Code extension source, configuration, and packaging scripts.
- `backend/`: authenticated local REST API, scan orchestration, storage, and API tests.
- `modules/dependency_scanner/`: dependency discovery, advisory lookup, heuristics, and SBOM integration.
- `modules/build_integrity/`: reproducible builds, release manifests, and artifact verification.
- `modules/compiler_analysis/`: compiler and binary analysis for the supported sample format.
- `modules/reporting/`: finding correlation, explanations, report generation, and validation.
- `test_samples/`: sample projects used by modules and tests.

For details specific to the extension, see [extension/README.md](extension/README.md).