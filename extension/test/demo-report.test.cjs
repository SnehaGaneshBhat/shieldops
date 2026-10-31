'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

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
