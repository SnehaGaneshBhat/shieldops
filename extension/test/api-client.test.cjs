'use strict';

const assert = require('node:assert/strict');
const http = require('node:http');
const test = require('node:test');
const { BuildGuardClient, ApiError } = require('../dist/api.js');

test('endpoint validates loopback URLs and rejects non-loopback or unsafe configurations', () => {
  const invalidUrls = [
    'http://example.com:8787',
    'http://192.168.1.1:8787',
    'http://10.0.0.1:8787',
    'http://172.16.0.1:8787',
    'http://user:secret@127.0.0.1:8787',
    'http://127.0.0.1:8787/api',
    'http://127.0.0.1:8787?filter=all',
    'http://127.0.0.1:8787#section',
    'ftp://127.0.0.1:8787',
    'not_a_valid_url',
    'http://127.0.0.300:8787'
  ];

  for (const url of invalidUrls) {
    const client = new BuildGuardClient(() => ({ url, token: 'test-token' }));
    assert.rejects(
      async () => client.health(),
      (err) => err instanceof ApiError && err.status === -1,
      `URL "${url}" should have been rejected with ApiError(-1)`
    );
  }

  const validUrls = [
    'http://127.0.0.1:8787',
    'http://127.0.0.2:8787',
    'http://localhost:8787',
    'http://[::1]:8787'
  ];

  for (const url of validUrls) {
    const client = new BuildGuardClient(() => ({ url, token: 'test-token' }));
    // Access endpoint private method or trigger request to verify URL parses without loopback error
    // If it reaches connection failure (status 0), it passed loopback validation!
    assert.rejects(
      async () => client.health(),
      (err) => err instanceof ApiError && err.status === 0,
      `Valid loopback URL "${url}" should pass loopback check (failing only on connection)`
    );
  }
});

test('BuildGuardClient executes health, startScan, getScan, getReport, and cancel against HTTP server', async () => {
  let receivedHeaders = {};
  let lastRequestBody = null;

  const server = http.createServer((req, res) => {
    receivedHeaders = req.headers;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');

    if (req.headers['x-buildguard-token'] !== 'secret-test-token') {
      res.writeHead(401);
      return res.end(JSON.stringify({ detail: 'unauthorized token' }));
    }

    if (req.method === 'GET' && req.url === '/v1/health') {
      res.writeHead(200);
      return res.end(JSON.stringify({ status: 'ok', version: '0.1.0' }));
    }

    if (req.method === 'POST' && req.url === '/v1/scans') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        lastRequestBody = JSON.parse(body);
        res.writeHead(202);
        res.end(JSON.stringify({ scan_id: 'test-scan-001' }));
      });
      return;
    }

    if (req.method === 'GET' && req.url === '/v1/scans/test-scan-001') {
      res.writeHead(200);
      return res.end(JSON.stringify({
        scan_id: 'test-scan-001',
        state: 'running',
        modules: { dependency: 'completed', build: 'running', compiler: 'queued' },
        errors: [],
        started_at: '2026-11-01T06:00:00Z'
      }));
    }

    if (req.method === 'GET' && req.url === '/v1/scans/test-scan-001/report') {
      res.writeHead(200);
      return res.end(JSON.stringify({
        scan_id: 'test-scan-001',
        generated_at: '2026-11-01T06:05:00Z',
        overall_summary: 'Test summary from real mock server',
        summary_counts: { total: 1 },
        items: [
          {
            id: 'F-100',
            module: 'dependency',
            category: 'KNOWN_VULNERABILITY',
            severity: 'HIGH',
            confidence: 'CONFIRMED',
            title: 'Sample vuln',
            evidence: []
          }
        ],
        module_status: { dependency: 'ok' },
        limitations: []
      }));
    }

    if (req.method === 'POST' && req.url === '/v1/scans/test-scan-001/cancel') {
      res.writeHead(200);
      return res.end(JSON.stringify({ scan_id: 'test-scan-001', state: 'cancelled' }));
    }

    res.writeHead(404);
    res.end(JSON.stringify({ detail: 'not found' }));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const client = new BuildGuardClient(() => ({
    url: `http://127.0.0.1:${port}`,
    token: 'secret-test-token'
  }));

  try {
    // 1. health
    const health = await client.health();
    assert.equal(health.status, 'ok');
    assert.equal(receivedHeaders['x-buildguard-token'], 'secret-test-token');
    assert.equal(receivedHeaders['accept'], 'application/json');

    // 2. startScan
    const scanReq = {
      project_path: '/home/miumiu/test-project',
      modules: ['dependency', 'build', 'compiler'],
      options: {
        use_llm: true,
        recipe_path: 'buildguard.yml',
        manifest_path: null,
        distributed_artifact: null,
        compiler_sample: 'sample',
        run_sandbox: false
      }
    };
    const { scan_id } = await client.startScan(scanReq);
    assert.equal(scan_id, 'test-scan-001');
    assert.deepEqual(lastRequestBody, scanReq);

    // 3. getScan
    const status = await client.getScan('test-scan-001');
    assert.equal(status.scan_id, 'test-scan-001');
    assert.equal(status.state, 'running');
    assert.equal(status.modules.dependency, 'completed');

    // 4. getReport
    const report = await client.getReport('test-scan-001');
    assert.equal(report.scan_id, 'test-scan-001');
    assert.equal(report.items.length, 1);
    assert.equal(report.items[0].id, 'F-100');

    // 5. cancel
    const cancelRes = await client.cancel('test-scan-001');
    assert.equal(cancelRes.state, 'cancelled');
  } finally {
    server.close();
  }
});

test('BuildGuardClient correctly handles HTTP errors, token mismatch, and response truncation', async () => {
  const longErrorMsg = 'E'.repeat(500);
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/v1/health') {
      res.writeHead(401);
      return res.end(JSON.stringify({ detail: 'bad token' }));
    }
    if (req.url === '/v1/scans/missing') {
      res.writeHead(404);
      return res.end(JSON.stringify({ detail: 'scan not found' }));
    }
    if (req.url === '/v1/scans/long-error') {
      res.writeHead(500);
      return res.end(JSON.stringify({ detail: longErrorMsg }));
    }
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const client = new BuildGuardClient(() => ({
    url: `http://127.0.0.1:${port}`,
    token: 'wrong-token'
  }));

  try {
    // 401 error
    await assert.rejects(
      async () => client.health(),
      (err) => err instanceof ApiError && err.status === 401 && err.message.includes('bad token')
    );

    // 404 error
    await assert.rejects(
      async () => client.getScan('missing'),
      (err) => err instanceof ApiError && err.status === 404 && err.message.includes('scan not found')
    );

    // 500 error with truncation to 300 characters
    await assert.rejects(
      async () => client.getScan('long-error'),
      (err) => {
        assert.ok(err instanceof ApiError);
        assert.equal(err.status, 500);
        assert.ok(err.message.length <= 360, 'error message must cap detail to 300 chars');
        return true;
      }
    );
  } finally {
    server.close();
  }
});

test('BuildGuardClient enforces 10 MB payload limit', async () => {
  const server = http.createServer((req, res) => {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Content-Length': String(11 * 1024 * 1024)
    });
    res.write('{"scan_id":"test",');
    // Write chunks exceeding 10MB
    const chunk = 'a'.repeat(64 * 1024);
    for (let i = 0; i < 180; i++) res.write(chunk);
    res.end('}');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const client = new BuildGuardClient(() => ({
    url: `http://127.0.0.1:${port}`,
    token: 'test-token'
  }));

  try {
    await assert.rejects(
      async () => client.health(),
      (err) => err instanceof ApiError && err.message.includes('10 MB size limit')
    );
  } finally {
    server.close();
  }
});

test('BuildGuardClient validates response shape for scan_id, status, and report', async () => {
  let responseData = {};
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(200);
    res.end(JSON.stringify(responseData));
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const client = new BuildGuardClient(() => ({
    url: `http://127.0.0.1:${port}`,
    token: 'test-token'
  }));

  try {
    // Malformed startScan response (missing scan_id)
    responseData = { invalid: true };
    await assert.rejects(
      async () => client.startScan({ project_path: '.', modules: [], options: {} }),
      (err) => err instanceof ApiError && err.message.includes('valid scan ID')
    );

    // Malformed getScan response (invalid state)
    responseData = { scan_id: 's-1', state: 'unknown_state', modules: {} };
    await assert.rejects(
      async () => client.getScan('s-1'),
      (err) => err instanceof ApiError && err.message.includes('invalid scan status')
    );

    // Malformed getReport response (items not an array)
    responseData = { scan_id: 'r-1', overall_summary: 'summary', items: 'not-array' };
    await assert.rejects(
      async () => client.getReport('r-1'),
      (err) => err instanceof ApiError && err.message.includes('invalid shape')
    );
  } finally {
    server.close();
  }
});
