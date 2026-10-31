import * as vscode from 'vscode';
import * as path from 'path';
import { realpath } from 'node:fs/promises';
import type { Report, ReportItem, Severity } from './types';

function toSeverity(severity: Severity): vscode.DiagnosticSeverity {
  if (severity === 'CRITICAL' || severity === 'HIGH') return vscode.DiagnosticSeverity.Error;
  if (severity === 'MEDIUM') return vscode.DiagnosticSeverity.Warning;
  if (severity === 'LOW') return vscode.DiagnosticSeverity.Information;
  return vscode.DiagnosticSeverity.Hint;
}

function guessFile(item: ReportItem): string | undefined {
  const ecosystem = String(item.subject?.ecosystem ?? '').toLowerCase();
  if (ecosystem === 'npm') return 'package.json';
  if (ecosystem === 'pypi') return 'requirements.txt';
  return undefined;
}

function isInside(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

export async function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  report: Report,
  root: vscode.Uri
): Promise<void> {
  collection.clear();
  const byFile = new Map<string, { uri: vscode.Uri; diagnostics: vscode.Diagnostic[] }>();
  const canonicalRoot = await realpath(root.fsPath).catch(() => path.resolve(root.fsPath));

  for (const item of report.items ?? []) {
    if (item.category === 'NO_KNOWN_ISSUES') continue;
    const hint = item.file_hint ?? guessFile(item);
    if (!hint) continue;

    const uri = path.isAbsolute(hint)
      ? vscode.Uri.file(hint)
      : vscode.Uri.joinPath(root, hint);
    if (uri.scheme !== 'file') continue;

    // Resolve symlinks as well as '..' segments so hints cannot open files outside the workspace.
    const canonicalFile = await realpath(uri.fsPath).catch(() => undefined);
    if (!canonicalFile || !isInside(canonicalRoot, canonicalFile)) continue;

    let document: vscode.TextDocument;
    try {
      document = await vscode.workspace.openTextDocument(vscode.Uri.file(canonicalFile));
    } catch {
      continue;
    }
    if (document.lineCount === 0) continue;

    let line = Number.isInteger(item.line_hint) && (item.line_hint ?? 0) > 0
      ? (item.line_hint as number) - 1
      : 0;
    if (!Number.isInteger(item.line_hint) || (item.line_hint ?? 0) <= 0) {
      const name = String(item.subject?.name ?? '');
      if (name) {
        for (let index = 0; index < document.lineCount; index++) {
          if (document.lineAt(index).text.includes(name)) {
            line = index;
            break;
          }
        }
      }
    }

    line = Math.min(Math.max(line, 0), document.lineCount - 1);
    const diagnostic = new vscode.Diagnostic(
      document.lineAt(line).range,
      `[${item.category}] ${item.title} (${item.severity}, confidence ${item.confidence})`,
      toSeverity(item.severity)
    );
    diagnostic.source = 'BuildGuard';
    diagnostic.code = item.id;

    const key = document.uri.toString();
    const entry = byFile.get(key) ?? { uri: document.uri, diagnostics: [] };
    entry.diagnostics.push(diagnostic);
    byFile.set(key, entry);
  }

  for (const { uri, diagnostics } of byFile.values()) collection.set(uri, diagnostics);
}
