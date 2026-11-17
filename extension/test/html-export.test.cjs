'use strict';

require('./vscode-mock.cjs');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { renderStandaloneReport } = require('../dist/panel.js');

const fixturePath = path.resolve(__dirname, 'fixtures', 'report.sample.json');
const sampleReport = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));

test('renderStandaloneReport produces valid HTML with strict CSP and no scripts', () => {
  const html = renderStandaloneReport(sampleReport);

  assert.ok(html.startsWith('<!doctype html>'), 'must start with doctype');
  assert.match(html, /<meta charset="UTF-8">/);
  assert.match(html, /<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'nonce-[a-f0-9]{32}';">/);
  assert.doesNotMatch(html, /script-src/, 'CSP must not allow scripts in standalone export');
  assert.doesNotMatch(html, /<script/, 'standalone report must contain no script tags');
  assert.doesNotMatch(html, /<button id="export">/, 'standalone export button must be omitted');
  assert.match(html, /--vscode-editor-background:#101d2c/, 'standalone export must include embedded dark theme');
});

test('renderStandaloneReport renders all 7 categories from sample report', () => {
  const html = renderStandaloneReport(sampleReport);

  const expectedLabels = [
    'Malicious advisory',
    'Known vulnerability',
    'Build mismatch',
    'Compiler anomaly',
    'Suspicious indicator',
    'Unresolved check',
    'No known issues detected'
  ];

  for (const label of expectedLabels) {
    assert.match(html, new RegExp(label), `category label "${label}" must be rendered`);
  }

  // Check finding titles
  assert.match(html, /lodash 4\.17\.20 has a published advisory/);
  assert.match(html, /The distributed file differs from the trusted build/);
  assert.match(html, /Binary contains a function absent from source/);
});

test('renderStandaloneReport properly escapes untrusted input and prevents XSS', () => {
  const xssReport = {
    scan_id: 'scan-xss<script>alert(1)</script>',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Overall <img src=x onerror=alert(2)> summary',
    module_status: { '<test>': 'status <script>' },
    limitations: ['Limit with <script>evil()</script> and & " \' characters'],
    items: [
      {
        id: 'X-001',
        module: 'dependency<script>',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        subject: { name: '<marquee>bad-pkg</marquee>', version: '1.0.0"><script>' },
        title: 'Title with <script>alert("title")</script> & bad characters',
        plain_explanation: 'Explanation with <script>alert("plain")</script>',
        why_it_matters: 'Why with <b>unsafe</b> <script>',
        recommended_actions: ['Action <script>alert("action")</script>'],
        limitations: 'Limit <script>'
      }
    ]
  };

  const html = renderStandaloneReport(xssReport);

  assert.doesNotMatch(html, /<script>/, 'raw <script> tags must not exist');
  assert.doesNotMatch(html, /<marquee>/, 'raw HTML tags from subjects must not exist');
  assert.doesNotMatch(html, /<img src=x/, 'injected image tags must be escaped');
  assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
  assert.match(html, /&lt;marquee&gt;bad-pkg&lt;\/marquee&gt;/);
  assert.match(html, /&lt;script&gt;alert\(&quot;title&quot;\)&lt;\/script&gt;/);
});

test('renderStandaloneReport handles flattened backend items as well as nested explanation objects', () => {
  const flattenedReport = {
    scan_id: 'scan-flat',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Flat report test',
    items: [
      {
        id: 'FLAT-1',
        module: 'build',
        category: 'BUILD_MISMATCH',
        severity: 'CRITICAL',
        confidence: 'HIGH',
        title: 'Flat finding title',
        plain_explanation: 'Direct plain explanation on finding',
        why_it_matters: 'Direct why it matters text',
        recommended_actions: ['Action 1', 'Action 2'],
        limitations: 'Direct limitation note',
        explanation_source: 'llm_validated'
      }
    ]
  };

  const html = renderStandaloneReport(flattenedReport);
  assert.match(html, /Flat finding title/);
  assert.match(html, /Direct plain explanation on finding/);
  assert.match(html, /Direct why it matters text/);
  assert.match(html, /<li>Action 1<\/li>/);
  assert.match(html, /<li>Action 2<\/li>/);
  assert.match(html, /Direct limitation note/);
  assert.match(html, /AI explanation · checked against findings/);
});

test('renderStandaloneReport marks simulations correctly', () => {
  const simReport = {
    scan_id: 'scan-sim',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'Simulation test',
    items: [
      {
        id: 'SIM-1',
        module: 'compiler',
        category: 'COMPILER_ANOMALY',
        severity: 'MEDIUM',
        confidence: 'HIGH',
        title: 'Simulated finding via top-level flag',
        simulated: true
      },
      {
        id: 'SIM-2',
        module: 'dependency',
        category: 'SUSPICIOUS_INDICATOR',
        severity: 'HIGH',
        confidence: 'HIGH',
        title: 'Simulated finding via evidence data',
        evidence: [{ type: 'rule_hit', data: { simulation: true } }]
      },
      {
        id: 'REAL-1',
        module: 'dependency',
        category: 'KNOWN_VULNERABILITY',
        severity: 'HIGH',
        confidence: 'CONFIRMED',
        title: 'Real finding without simulation',
        evidence: [{ type: 'osv_advisory', data: { id: 'GHSA-1234' } }]
      }
    ]
  };

  const html = renderStandaloneReport(simReport);
  const simMatches = html.match(/<span class="pill sim">SIMULATION<\/span>/g);
  assert.equal(simMatches?.length, 2, 'exactly two findings must have the SIMULATION badge');
});

test('renderStandaloneReport handles empty findings and global limitations', () => {
  const emptyReport = {
    scan_id: 'scan-empty',
    generated_at: '2026-11-01T00:00:00Z',
    overall_summary: 'No checks executed',
    items: [],
    global_limitations: ['First global limit', 'Second global limit']
  };

  const html = renderStandaloneReport(emptyReport);
  assert.match(html, /No findings were returned/);
  assert.match(html, /First global limit/);
  assert.match(html, /Second global limit/);
  assert.match(html, /0<\/strong><span>Needs review<\/span>/);
});
