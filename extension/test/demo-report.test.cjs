'use strict';

require('./vscode-mock.cjs');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { renderStandaloneReport } = require('../dist/panel.js');

const root = path.resolve(__dirname, '..');
const report = JSON.parse(fs.readFileSync(path.join(root, 'media', 'demo-report.json'), 'utf8'));
const packageJson = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
const extensionSource = fs.readFileSync(path.join(root, 'src', 'extension.ts'), 'utf8');

test('demo report is clearly fictional and covers every report category', () => {
  assert.match(report.overall_summary, /DEMO DATA/);
  assert.match(report.overall_summary, /No workspace files were scanned/);

  const categories = new Set(report.items.map((item) => item.category));
  assert.deepEqual([...categories].sort(), [
    'BUILD_MISMATCH',
    'COMPILER_ANOMALY',
    'KNOWN_MALICIOUS_ADVISORY',
    'KNOWN_VULNERABILITY',
    'NO_KNOWN_ISSUES',
    'SUSPICIOUS_INDICATOR',
    'UNRESOLVED'
  ]);

  for (const item of report.items) {
    assert.match(item.title, /^DEMO · /);
    assert.ok(item.evidence.some((entry) => entry.data?.simulation === true), `${item.id} must be marked as simulated`);
  }
});

test('demo command is registered and its report is included in the extension package', () => {
  const command = packageJson.contributes.commands.find((entry) => entry.command === 'buildguard.showDemoReport');
  assert.ok(command, 'demo command must be contributed to VS Code');
  assert.ok(packageJson.files.includes('media/demo-report.json'), 'bundled demo report must be included in the VSIX');
  assert.match(extensionSource, /registerCommand\('buildguard\.showDemoReport', showDemoReport\)/);
  assert.match(extensionSource, /'media', 'demo-report\.json'/);
});

test('demo report renders standalone HTML with all 7 categories and simulation badges', () => {
  const html = renderStandaloneReport(report);
  assert.ok(html.startsWith('<!doctype html>'), 'must be standard HTML document');
  assert.match(html, /DEMO DATA/);
  assert.match(html, /<span class="pill sim">SIMULATION<\/span>/);
  assert.doesNotMatch(html, /<script/, 'standalone HTML must not contain script tags');
  assert.doesNotMatch(html, /<button id="export">/, 'standalone HTML must omit export button');

  // Verify all 7 categories are rendered in headings/labels
  assert.match(html, /Malicious advisory/);
  assert.match(html, /Known vulnerability/);
  assert.match(html, /Build mismatch/);
  assert.match(html, /Compiler anomaly/);
  assert.match(html, /Suspicious indicator/);
  assert.match(html, /Unresolved check/);
  assert.match(html, /No known issues detected/);
});
