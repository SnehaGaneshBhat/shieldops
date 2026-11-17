'use strict';

const vscode = require('./vscode-mock.cjs');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { applyDiagnostics } = require('../dist/diagnostics.js');

test('applyDiagnostics maps severity levels correctly and skips NO_KNOWN_ISSUES', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-diag-test-'));
  const pkgJsonPath = path.join(tmpDir, 'package.json');
  fs.writeFileSync(pkgJsonPath, '{\n  "name": "my-app",\n  "version": "1.0.0"\n}\n');

  const rootUri = vscode.Uri.file(tmpDir);
  const collection = vscode.languages.createDiagnosticCollection('test-buildguard');

  const report = {
    scan_id: 'scan-diag-1',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Diagnostics severity test',
    items: [
      {
        id: 'D-001',
        module: 'dependency',
        category: 'KNOWN_MALICIOUS_ADVISORY',
        severity: 'CRITICAL',
        confidence: 'CONFIRMED',
        title: 'Critical malicious package',
        file_hint: 'package.json',
        line_hint: 1
      },
      {
        id: 'D-002',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'High vulnerability',
        file_hint: 'package.json',
        line_hint: 2
      },
      {
        id: 'D-003',
        module: 'compiler',
        category: 'COMPILER_ANOMALY',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        title: 'Medium compiler anomaly',
        file_hint: 'package.json',
        line_hint: 2
      },
      {
        id: 'D-004',
        module: 'dependency',
        category: 'SUSPICIOUS_INDICATOR',
        severity: 'LOW',
        confidence: 'LOW',
        title: 'Low indicator',
        file_hint: 'package.json',
        line_hint: 3
      },
      {
        id: 'D-005',
        module: 'dependency',
        category: 'UNRESOLVED',
        severity: 'UNKNOWN',
        confidence: 'LOW',
        title: 'Unknown severity check',
        file_hint: 'package.json',
        line_hint: 3
      },
      {
        id: 'D-006',
        module: 'dependency',
        category: 'NO_KNOWN_ISSUES',
        severity: 'INFO',
        confidence: 'HIGH',
        title: 'Clean check result',
        file_hint: 'package.json',
        line_hint: 1
      }
    ]
  };

  try {
    await applyDiagnostics(collection, report, rootUri);
    const diags = collection.get(vscode.Uri.file(pkgJsonPath));
    assert.ok(diags, 'diagnostics must be set for package.json');
    assert.equal(diags.length, 5, 'NO_KNOWN_ISSUES must be skipped, leaving 5 diagnostics');

    // Severity mapping check
    assert.equal(diags[0].code, 'D-001');
    assert.equal(diags[0].severity, vscode.DiagnosticSeverity.Error); // CRITICAL -> Error
    assert.equal(diags[1].code, 'D-002');
    assert.equal(diags[1].severity, vscode.DiagnosticSeverity.Error); // HIGH -> Error
    assert.equal(diags[2].code, 'D-003');
    assert.equal(diags[2].severity, vscode.DiagnosticSeverity.Warning); // MEDIUM -> Warning
    assert.equal(diags[3].code, 'D-004');
    assert.equal(diags[3].severity, vscode.DiagnosticSeverity.Information); // LOW -> Information
    assert.equal(diags[4].code, 'D-005');
    assert.equal(diags[4].severity, vscode.DiagnosticSeverity.Hint); // UNKNOWN -> Hint

    // Source and format
    assert.equal(diags[0].source, 'BuildGuard');
    assert.match(diags[0].message, /\[KNOWN_MALICIOUS_ADVISORY\] Critical malicious package \(CRITICAL, confidence CONFIRMED\)/);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('applyDiagnostics blocks path traversal, symlink escapes, and outside files', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-diag-sec-'));
  const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-diag-outside-'));

  const insideFile = path.join(tmpDir, 'inside.txt');
  fs.writeFileSync(insideFile, 'inside workspace');

  const outsideFile = path.join(outsideDir, 'secret.txt');
  fs.writeFileSync(outsideFile, 'outside workspace');

  // Symlink pointing outside workspace
  const badSymlink = path.join(tmpDir, 'symlink-outside');
  try { fs.symlinkSync(outsideDir, badSymlink, 'dir'); } catch {}

  const rootUri = vscode.Uri.file(tmpDir);
  const collection = vscode.languages.createDiagnosticCollection('test-security');

  const report = {
    scan_id: 'scan-sec-1',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Security containment test',
    items: [
      {
        id: 'SEC-1',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Traverse up out of workspace',
        file_hint: '../../secret.txt'
      },
      {
        id: 'SEC-2',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Absolute outside file',
        file_hint: outsideFile
      },
      {
        id: 'SEC-3',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Inside file via symlink escaping root',
        file_hint: 'symlink-outside/secret.txt'
      },
      {
        id: 'SEC-4',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Legitimate inside file',
        file_hint: 'inside.txt'
      }
    ]
  };

  try {
    await applyDiagnostics(collection, report, rootUri);

    // Ensure outside file did NOT get diagnostics
    assert.equal(collection.get(vscode.Uri.file(outsideFile)), undefined);

    // Ensure inside file got diagnostics
    const insideDiags = collection.get(vscode.Uri.file(insideFile));
    assert.ok(insideDiags, 'inside.txt should receive diagnostics');
    assert.equal(insideDiags.length, 1);
    assert.equal(insideDiags[0].code, 'SEC-4');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
    fs.rmSync(outsideDir, { recursive: true, force: true });
  }
});

test('applyDiagnostics resolves line hints and searches text when line_hint is missing', async () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bg-diag-lines-'));
  const testFile = path.join(tmpDir, 'requirements.txt');
  fs.writeFileSync(testFile, 'flask==2.0.0\nrequests==2.25.1\nurllib3==1.26.5\n');

  const rootUri = vscode.Uri.file(tmpDir);
  const collection = vscode.languages.createDiagnosticCollection('test-lines');

  const report = {
    scan_id: 'scan-lines-1',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Line hint test',
    items: [
      {
        id: 'L-1',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        title: 'Explicit line hint',
        file_hint: 'requirements.txt',
        line_hint: 3 // urllib3 (0-based line 2)
      },
      {
        id: 'L-2',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        title: 'Missing line hint searched by subject name',
        file_hint: 'requirements.txt',
        line_hint: null,
        subject: { name: 'requests' } // should match line 1
      },
      {
        id: 'L-3',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        title: 'Guess file from ecosystem pypi',
        line_hint: 1, // flask line 0
        subject: { ecosystem: 'pypi', name: 'flask' }
      }
    ]
  };

  try {
    await applyDiagnostics(collection, report, rootUri);
    const diags = collection.get(vscode.Uri.file(testFile));
    assert.ok(diags);
    assert.equal(diags.length, 3);

    // L-1: line_hint 3 -> 0-based line 2
    assert.equal(diags[0].range.start.line, 2);
    // L-2: found "requests" on line 1
    assert.equal(diags[1].range.start.line, 1);
    // L-3: guessed requirements.txt and line 0
    assert.equal(diags[2].range.start.line, 0);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});
