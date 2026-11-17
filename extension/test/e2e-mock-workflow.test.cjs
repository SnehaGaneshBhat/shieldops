'use strict';

const assert = require('node:assert/strict');
const cp = require('node:child_process');
const path = require('node:path');
const test = require('node:test');
const { BuildGuardClient, ApiError } = require('../dist/api.js');

test('complete end-to-end scan workflow against mock-server.cjs', async () => {
  const token = 'mock-integration-token-456';
  const mockServerPath = path.resolve(__dirname, 'mock-server.cjs');

  const serverProc = cp.spawn(process.execPath, [mockServerPath], {
    env: {
      ...process.env,
      BUILDGUARD_MOCK_PORT: '0',
      BUILDGUARD_TOKEN: token
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  let port = null;

  try {
    // Wait for mock server listening message with dynamically assigned port
    await new Promise((resolve, reject) => {
      let output = '';
      serverProc.stdout.on('data', (d) => {
        output += d.toString();
        const match = output.match(/BuildGuard mock listening at http:\/\/127\.0\.0\.1:(\d+)/);
        if (match) {
          port = Number(match[1]);
          resolve();
        }
      });
      serverProc.stderr.on('data', (d) => {
        output += d.toString();
      });
      serverProc.on('exit', (code) => {
        reject(new Error(`Mock server exited prematurely with code ${code}: ${output}`));
      });
      setTimeout(() => reject(new Error(`Mock server startup timed out: ${output}`)), 5000);
    });

    assert.ok(port && port > 0, `port must be assigned, got ${port}`);

    const client = new BuildGuardClient(() => ({
      url: `http://127.0.0.1:${port}`,
      token
    }));

    // 1. Health check
    const health = await client.health();
    assert.equal(health.status, 'ok');
    assert.equal(health.mock, true);

    // 2. Start scan with options matching backend schemas.py
    const scanRequest = {
      project_path: '/home/miumiu/shieldops',
      modules: ['dependency', 'build', 'compiler'],
      options: {
        use_llm: true,
        recipe_path: 'buildguard.yml',
        manifest_path: null,
        distributed_artifact: null,
        compiler_sample: 'test_samples/compiler_hello',
        run_sandbox: false
      }
    };

    const { scan_id } = await client.startScan(scanRequest);
    assert.ok(typeof scan_id === 'string' && scan_id.startsWith('mock-'), `valid scan_id expected: ${scan_id}`);

    // 3. Poll scan status through state transitions
    const statesObserved = [];
    for (let i = 0; i < 10; i++) {
      const status = await client.getScan(scan_id);
      statesObserved.push(status.state);
      assert.equal(status.scan_id, scan_id);
      assert.ok(status.modules, 'modules dictionary must exist');
      if (status.state === 'completed') break;
    }

    assert.ok(statesObserved.includes('queued'), 'scan must start in queued state');
    assert.ok(statesObserved.includes('running'), 'scan must transition through running');
    assert.equal(statesObserved[statesObserved.length - 1], 'completed', 'scan must finish in completed state');

    // 4. Retrieve complete report
    const report = await client.getReport(scan_id);
    assert.equal(report.scan_id, scan_id);
    assert.match(report.overall_summary, /MOCK DATA/);
    assert.equal(report.items.length, 7, 'mock report must contain 7 items');

    const categories = new Set(report.items.map((it) => it.category));
    assert.equal(categories.size, 7, 'all 7 categories must be present in items');

    // 5. Test cancellation with a second scan
    const { scan_id: secondScanId } = await client.startScan(scanRequest);
    const cancelRes = await client.cancel(secondScanId);
    assert.equal(cancelRes.state, 'cancelled');

    // 6. Test unauthorized token rejection
    const badClient = new BuildGuardClient(() => ({
      url: `http://127.0.0.1:${port}`,
      token: 'wrong-token'
    }));

    await assert.rejects(
      async () => badClient.health(),
      (err) => err instanceof ApiError && err.status === 401 && err.message.includes('invalid token')
    );
  } finally {
    serverProc.kill();
  }
});
