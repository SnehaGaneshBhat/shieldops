# BuildGuard VS Code Extension

BuildGuard connects VS Code to the local BuildGuard REST service at `127.0.0.1:8787`. Run **BuildGuard: Scan Workspace** from the command palette or the status bar. Findings open in a grouped report; supported manifest findings also appear in the Problems panel.

## Development

```sh
npm install
npm run lint
npm run compile
```

Press F5 to open an Extension Development Host. Set `buildguard.backendUrl` and `buildguard.token` for a manually started service. Automatic startup requires `buildguard.backendCwd` to point at the repository root containing `.venv` and `backend/`.

### Preview with the local mock

In the extension directory, start the mock service with `npm run mock`. In the Extension Development Host workspace settings, set:

```json
{
  "buildguard.backendUrl": "http://127.0.0.1:8788",
  "buildguard.token": "buildguard-local-mock-token"
}
```

Then run **BuildGuard: Scan Workspace**. The mock cycles through queued, running, and completed module states and returns a labelled fixture; it does not scan files. Do not use this token outside the local mock.

Package from the repository root with `make package`; the artifact is `buildguard-0.1.0.vsix`.
