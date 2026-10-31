import * as vscode from 'vscode';
import * as path from 'path';
import type { Report, ReportItem, Severity } from './types';
function toSeverity(s: Severity): vscode.DiagnosticSeverity { if (s === 'CRITICAL' || s === 'HIGH') return vscode.DiagnosticSeverity.Error; if (s === 'MEDIUM') return vscode.DiagnosticSeverity.Warning; if (s === 'LOW') return vscode.DiagnosticSeverity.Information; return vscode.DiagnosticSeverity.Hint; }
function guessFile(it: ReportItem): string | undefined { const eco = String(it.subject?.ecosystem ?? ''); if (eco === 'npm') return 'package.json'; if (eco.toLowerCase() === 'pypi') return 'requirements.txt'; return undefined; }
export async function applyDiagnostics(coll: vscode.DiagnosticCollection, report: Report, root: vscode.Uri) {
  coll.clear(); const byFile = new Map<string, { uri: vscode.Uri; diags: vscode.Diagnostic[] }>();
  for (const it of report.items ?? []) { if (it.category === 'NO_KNOWN_ISSUES') continue; const rel = it.file_hint ?? guessFile(it); if (!rel) continue;
    const uri = path.isAbsolute(rel) ? vscode.Uri.file(rel) : vscode.Uri.joinPath(root, rel);
    // Restrict diagnostics to the workspace so a backend hint cannot open an unrelated local file.
    const relative = path.relative(root.fsPath, uri.fsPath); if (relative.startsWith('..') || path.isAbsolute(relative)) continue;
    let doc: vscode.TextDocument; try { doc = await vscode.workspace.openTextDocument(uri); } catch { continue; }
    let line = Number.isInteger(it.line_hint) && (it.line_hint ?? 0) > 0 ? (it.line_hint as number) - 1 : 0;
    if (!Number.isInteger(it.line_hint) || (it.line_hint ?? 0) <= 0) { const name = String(it.subject?.name ?? ''); if (name) for (let i = 0; i < doc.lineCount; i++) if (doc.lineAt(i).text.includes(name)) { line = i; break; } }
    line = Math.min(Math.max(line, 0), Math.max(doc.lineCount - 1, 0)); const d = new vscode.Diagnostic(doc.lineAt(line).range, `[${it.category}] ${it.title} (${it.severity}, confidence ${it.confidence})`, toSeverity(it.severity)); d.source = 'BuildGuard'; d.code = it.id;
    const key = uri.toString(); const entry = byFile.get(key) ?? { uri, diags: [] }; entry.diags.push(d); byFile.set(key, entry);
  }
  for (const { uri, diags } of byFile.values()) coll.set(uri, diags);
}
