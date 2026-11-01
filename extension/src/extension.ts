import * as vscode from 'vscode';
import { BuildGuardClient, ApiError } from './api';
import { BackendManager } from './backend';
import { applyDiagnostics } from './diagnostics';
import { renderStandaloneReport, showReport } from './panel';
import type { Report, ScanRequest, ScanStatus } from './types';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const TERMINAL = new Set(['completed', 'completed_with_errors', 'failed', 'cancelled']);
const SCAN_TIMEOUT_MS = 20 * 60 * 1000;
let lastReport: Report | undefined; let lastRoot: vscode.Uri | undefined;
export function activate(context: vscode.ExtensionContext) {
  const out = vscode.window.createOutputChannel('BuildGuard'); const backend = new BackendManager(out);
  const client = new BuildGuardClient(() => { const c = backend.config(); return { url: c.url, token: c.token }; });
  const diagnostics = vscode.languages.createDiagnosticCollection('buildguard');
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100); status.text = '$(shield) BuildGuard'; status.tooltip = 'Scan this workspace with BuildGuard'; status.command = 'buildguard.scan'; status.show();
  let running = false;
  async function runScan() {
    if (running) { void vscode.window.showInformationMessage('A BuildGuard scan is already running.'); return; }
    const folder = vscode.workspace.workspaceFolders?.[0]; if (!folder) { void vscode.window.showErrorMessage('BuildGuard: open a project folder first.'); return; }
    running = true; status.text = '$(sync~spin) BuildGuard';
    try {
      const result = await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'BuildGuard · Workspace scan', cancellable: true }, async (progress, token) => {
        progress.report({ message: 'Connecting to local analysis service' }); await backend.ensure(() => client.health());
        if (token.isCancellationRequested) throw new Error('Scan cancelled.');
        const cfg = vscode.workspace.getConfiguration('buildguard');
        const modules = cfg.get<string[]>('modules', ['dependency', 'build', 'compiler']);
        const allowedModules = new Set(['dependency', 'build', 'compiler']);
        if (!Array.isArray(modules) || modules.length === 0 || modules.some((name) => !allowedModules.has(name))) throw new Error('Choose at least one supported module in buildguard.modules: dependency, build, or compiler.');
        const recipePath = cfg.get<string>('recipePath', 'buildguard.yml').trim() || 'buildguard.yml';
        const manifestPath = cfg.get<string>('manifestPath', '').trim();
        const distributedArtifact = cfg.get<string>('distributedArtifact', '').trim();
        if (Boolean(manifestPath) !== Boolean(distributedArtifact)) throw new Error('Set both buildguard.manifestPath and buildguard.distributedArtifact to verify an artifact, or leave both empty.');
        const request: ScanRequest = { project_path: folder.uri.fsPath, modules, options: { use_llm: cfg.get<boolean>('useLLM', true), recipe_path: recipePath, manifest_path: manifestPath || null, distributed_artifact: distributedArtifact || null, compiler_sample: cfg.get<string>('compilerSample', 'test_samples/compiler_hello'), run_sandbox: false } };
        const { scan_id } = await client.startScan(request); out.appendLine(`Started scan ${scan_id}`); let state: ScanStatus | undefined;
        try {
          const startedAt = Date.now();
          for (;;) {
            if (token.isCancellationRequested) throw new Error('Scan cancelled.');
            if (Date.now() - startedAt > SCAN_TIMEOUT_MS) throw new Error('Scan exceeded the 20 minute time limit.');
            state = await client.getScan(scan_id);
            const moduleProgress = Object.entries(state.modules ?? {}).map(([name, s]) => `${name}: ${s}`).join('  ·  ');
            progress.report({ message: moduleProgress || state.state });
            if (TERMINAL.has(state.state)) break;
            await sleep(1500);
          }
        } catch (e) {
          await client.cancel(scan_id).catch(() => undefined);
          throw e;
        }
        if (!state) throw new Error('The backend did not return a scan status.');
        if (state.state === 'failed' || state.state === 'cancelled') throw new Error(`Scan ${state.state}. ${JSON.stringify(state.errors ?? []).slice(0, 300)}`);
        progress.report({ message: 'Preparing report' }); let report: Report | undefined;
        for (let i = 0; i < 20 && !report; i++) { try { report = await client.getReport(scan_id); } catch (e) { if (e instanceof ApiError && e.status === 409) await sleep(1000); else throw e; } }
        if (!report) throw new Error('The report was not ready after 20 seconds.');
        return { report, scan_id, state: state.state };
      });
      lastReport = result.report; lastRoot = folder.uri; showReport(result.report); await applyDiagnostics(diagnostics, result.report, folder.uri);
      const count = result.report.items.filter((it) => it.category !== 'NO_KNOWN_ISSUES').length; status.text = `$(shield) BuildGuard: ${count} to review`;
      if (result.state === 'completed_with_errors') void vscode.window.showWarningMessage('BuildGuard: one or more checks did not complete. Review module status and report limitations.');
    } catch (e) { status.text = '$(shield) BuildGuard'; const choice = await vscode.window.showErrorMessage(`BuildGuard: ${(e as Error).message}`, 'Show log'); if (choice === 'Show log') out.show(); }
    finally { running = false; }
  }
  async function exportHtml() {
    if (!lastReport) { void vscode.window.showInformationMessage('Run a scan before exporting a report.'); return; }
    try { const html = renderStandaloneReport(lastReport); const base = lastRoot ?? vscode.workspace.workspaceFolders?.[0]?.uri; const uri = await vscode.window.showSaveDialog({ defaultUri: base ? vscode.Uri.joinPath(base, 'buildguard-report.html') : undefined, filters: { HTML: ['html'] } }); if (!uri) return; await vscode.workspace.fs.writeFile(uri, Buffer.from(html, 'utf8')); void vscode.window.showInformationMessage(`Report saved to ${uri.fsPath}`); }
    catch (e) { void vscode.window.showErrorMessage(`BuildGuard export failed: ${(e as Error).message}`); }
  }
  context.subscriptions.push(out, backend, diagnostics, status,
    vscode.commands.registerCommand('buildguard.scan', runScan),
    vscode.commands.registerCommand('buildguard.showReport', () => lastReport ? showReport(lastReport) : vscode.window.showInformationMessage('No report yet. Run BuildGuard: Scan Workspace.')),
    vscode.commands.registerCommand('buildguard.exportHtml', exportHtml),
    vscode.commands.registerCommand('buildguard.clearDiagnostics', () => diagnostics.clear()));
}
export function deactivate() {}
