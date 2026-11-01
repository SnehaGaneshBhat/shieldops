import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as crypto from 'crypto';
import * as path from 'path';
import { ApiError } from './api';
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
export class BackendManager implements vscode.Disposable {
  private child?: cp.ChildProcess;
  private childFailure?: string;
  private generatedToken = crypto.randomBytes(24).toString('hex');
  constructor(private out: vscode.OutputChannel) {}
  config() {
    const c = vscode.workspace.getConfiguration('buildguard');
    let url = c.get<string>('backendUrl', 'http://127.0.0.1:8787');
    try { const parsed = new URL(url); if (parsed.protocol === 'http:' && !parsed.port) parsed.port = '8787'; url = parsed.toString().replace(/\/$/, ''); } catch { /* the API client reports malformed settings clearly */ }
    return { url, token: c.get<string>('token', '') || this.generatedToken, autoStart: c.get<boolean>('autoStartBackend', true), cwd: c.get<string>('backendCwd', '') };
  }
  async ensure(health: () => Promise<unknown>, workspaceRoot: string): Promise<void> {
    try {
      const response = await health() as { workspace_root?: unknown };
      if (typeof response.workspace_root !== 'string' || !this.isInside(response.workspace_root, workspaceRoot)) {
        throw new Error('The backend is not configured to scan this workspace. Restart it with BUILDGUARD_WORKSPACE_ROOT set to the workspace folder.');
      }
      this.out.appendLine('Backend health check passed.'); return;
    }
    catch (e) {
      if (!(e instanceof ApiError)) throw e;
      if (e instanceof ApiError && e.status < 0) throw new Error(e.message);
      if (e instanceof ApiError && (e.status === 401 || e.status === 403)) throw new Error('The backend rejected the token. Set buildguard.token to the same value as BUILDGUARD_TOKEN on the backend.');
      if (e instanceof ApiError && e.status > 0) throw new Error(`BuildGuard backend responded with HTTP ${e.status}. Check its health endpoint and token.`);
    }
    const cfg = this.config();
    if (!cfg.autoStart || !cfg.cwd) throw new Error(`BuildGuard backend is not reachable at ${cfg.url}. Start it with "make run-backend" in the backend environment, or set buildguard.backendCwd to enable auto-start.`);
    if (new URL(cfg.url).protocol !== 'http:') throw new Error('Automatic backend startup supports HTTP loopback URLs only. Start the HTTPS backend manually or use http://127.0.0.1:8787.');
    if (!this.child || this.child.exitCode !== null || this.child.signalCode !== null) this.start(cfg.cwd, cfg.url, cfg.token, workspaceRoot);
    for (let i = 0; i < 30; i++) {
      await sleep(500);
      try {
        const response = await health() as { workspace_root?: unknown };
        if (typeof response.workspace_root !== 'string' || !this.isInside(response.workspace_root, workspaceRoot)) throw new Error('The started backend is not restricted to the active workspace.');
        return;
      }
      catch (e) {
        if (!(e instanceof ApiError)) throw e;
        if (e instanceof ApiError && (e.status === 401 || e.status === 403)) throw new Error('The started backend rejected its token. Review the BuildGuard output channel and token configuration.');
        if (e instanceof ApiError && e.status > 0 && e.status !== 502 && e.status !== 503) throw new Error(`BuildGuard backend responded with HTTP ${e.status} while starting. Check the BuildGuard output channel.`);
        if (this.childFailure) throw new Error(`The BuildGuard backend failed during startup: ${this.childFailure}. See the BuildGuard output channel.`);
      }
    }
    throw new Error('BuildGuard did not become healthy within 15 seconds. See the BuildGuard output channel.');
  }
  private isInside(root: string, target: string): boolean {
    const relative = path.relative(path.resolve(root), path.resolve(target));
    return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
  }
  private start(cwd: string, url: string, token: string, workspaceRoot: string) {
    const python = process.platform === 'win32' ? path.join(cwd, '.venv', 'Scripts', 'python.exe') : path.join(cwd, '.venv', 'bin', 'python');
    const port = new URL(url).port || '8787';
    this.out.appendLine(`Starting backend from ${cwd} on port ${port}`);
    this.childFailure = undefined;
    const child = cp.spawn(python, ['-m', 'uvicorn', 'backend.main:app', '--host', '127.0.0.1', '--port', port], { cwd, env: { ...process.env, BUILDGUARD_TOKEN: token, BUILDGUARD_WORKSPACE_ROOT: workspaceRoot } });
    this.child = child;
    child.stdout?.on('data', (d) => this.out.append(d.toString()));
    child.stderr?.on('data', (d) => this.out.append(d.toString()));
    child.on('error', (e) => { this.childFailure = e.message; this.out.appendLine(`Backend failed to start: ${e.message}`); });
    child.on('exit', (code, signal) => {
      this.out.appendLine(`Backend exited (code ${code ?? 'unknown'}${signal ? `, signal ${signal}` : ''})`);
      if (this.child === child) this.child = undefined;
      this.childFailure = `process exited (code ${code ?? 'unknown'}${signal ? `, signal ${signal}` : ''})`;
    });
  }
  dispose() { this.child?.kill(); }
}
