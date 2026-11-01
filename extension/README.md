# BuildGuard VS Code Extension

The extension runs the real BuildGuard backend against the open workspace. A scan combines the selected dependency, build-integrity, and compiler checks into one report. Completed findings appear in the report view, supported dependency findings are added to Problems, and the report can be exported as a standalone HTML file.

## Prerequisites

- Python 3.12 and `python3.12-venv`
- Node.js and npm
- Docker running for reproducible-build and compiler checks
- Syft on `PATH` for dependency SBOM generation

Dependency checks use the configured registry/advisory sources. Template explanations are used unless `BUILDGUARD_LLM_API_KEY` is configured for the backend.

## Set Up And Run

From the repository root:

```sh
make venv
npm --prefix extension ci
npm --prefix extension test
```

Open the repository root in VS Code, choose **Run BuildGuard Extension** in Run and Debug, and press F5. In the Extension Development Host, open the project folder to scan. Set `buildguard.backendCwd` to the absolute repository path in Settings; the extension will start the backend from `.venv` and pass it a local token automatically.

Run **BuildGuard: Scan Workspace** from the Command Palette or click the BuildGuard status-bar item. By default, all three modules are requested. Select **BuildGuard: Show Last Report** to reopen the latest result and **BuildGuard: Export Report as HTML** to save it. The backend also persists HTML at `/v1/scans/{scan_id}/report.html`.

To use a manually started backend instead, run `make run-backend TOKEN=dev-token` from the repository root, then set `buildguard.backendUrl` to `http://127.0.0.1:8787` and `buildguard.token` to `dev-token` in the Extension Development Host.

## Scan Settings

Use workspace Settings to configure `buildguard.modules` (`dependency`, `build`, and `compiler`), `buildguard.recipePath`, and `buildguard.compilerSample`. Paths are relative to the open workspace. For release-integrity checking, set both `buildguard.manifestPath` and `buildguard.distributedArtifact`; the manifest comparison runs even when Docker or a build recipe is unavailable. The report marks checks that could not run as partial or skipped rather than treating them as clean.

Build reproducibility requires a valid `buildguard.yml` with an image pinned by digest and an available Docker daemon. The compiler MVP analyzes C/Linux ELF samples. A missing compiler sample, unavailable tool, missing manifest, or incomplete analysis is reported as a limitation in the combined report.

## Tests And Packaging

`npm --prefix extension test` typechecks the extension and runs the repository's real non-Docker backend pytest suite through `make test`. This suite covers API scans, real sample projects, combined reports, and HTML generation. `make test-docker` runs the additional Docker-dependent tests.

Build the extension with `npm --prefix extension run compile`. Package the VSIX from the repository root with `make package`; the artifact is `buildguard-0.1.0.vsix`.
