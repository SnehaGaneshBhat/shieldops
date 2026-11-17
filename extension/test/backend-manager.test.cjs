'use strict';

const vscode = require('./vscode-mock.cjs');
const assert = require('node:assert/strict');
const test = require('node:test');
const { BackendManager } = require('../dist/backend.js');
const { ApiError } = require('../dist/api.js');

test('BackendManager.config normalizes URLs and generates token when unconfigured', () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  // Default configuration
  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1:8787/',
    'buildguard.token': '',
    'buildguard.autoStartBackend': true,
    'buildguard.backendCwd': '/path/to/shieldops'
  });

  const cfg = manager.config();
  assert.equal(cfg.url, 'http://127.0.0.1:8787');
  assert.equal(typeof cfg.token, 'string');
  assert.equal(cfg.token.length, 48, 'generated token should be 24 bytes hex (48 characters)');
  assert.equal(cfg.autoStart, true);
  assert.equal(cfg.cwd, '/path/to/shieldops');

  // Explicit token and URL without port
  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1',
    'buildguard.token': 'custom-token-xyz'
  });

  const cfg2 = manager.config();
  assert.equal(cfg2.url, 'http://127.0.0.1:8787');
  assert.equal(cfg2.token, 'custom-token-xyz');
});

test('BackendManager.ensure succeeds immediately when health check passes', async () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  let healthCalls = 0;
  const mockHealth = async () => {
    healthCalls++;
    return { status: 'ok' };
  };

  await manager.ensure(mockHealth);
  assert.equal(healthCalls, 1);
  assert.ok(out.logs.some((l) => l.includes('Backend health check passed')));
});

test('BackendManager.ensure throws directly on invalid URL or token mismatch without auto-starting', async () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1:8787',
    'buildguard.autoStartBackend': true,
    'buildguard.backendCwd': '/some/repo'
  });

  // 1. Invalid URL (ApiError status < 0)
  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(-1, 'Invalid loopback URL'); }),
    /Invalid loopback URL/
  );

  // 2. Token rejected (ApiError 401)
  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(401, 'Unauthorized'); }),
    /The backend rejected the token/
  );

  // 3. HTTP 500 error on health
  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(500, 'Server error'); }),
    /BuildGuard backend responded with HTTP 500/
  );
});

test('BackendManager.ensure throws helpful instructions when autoStart is disabled or backendCwd is empty', async () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  // Connection refused (status 0) but autoStart is false
  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1:8787',
    'buildguard.autoStartBackend': false,
    'buildguard.backendCwd': '/some/repo'
  });

  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(0, 'Connection refused'); }),
    /Start it with "make run-backend" in the backend environment, or set buildguard.backendCwd/
  );

  // Connection refused but backendCwd is empty
  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1:8787',
    'buildguard.autoStartBackend': true,
    'buildguard.backendCwd': ''
  });

  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(0, 'Connection refused'); }),
    /Start it with "make run-backend" in the backend environment, or set buildguard.backendCwd/
  );
});

test('BackendManager.ensure rejects auto-start for HTTPS URLs', async () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  vscode._setMockConfig({
    'buildguard.backendUrl': 'https://127.0.0.1:8787',
    'buildguard.autoStartBackend': true,
    'buildguard.backendCwd': '/some/repo'
  });

  await assert.rejects(
    async () => manager.ensure(async () => { throw new ApiError(0, 'Connection refused'); }),
    /Automatic backend startup supports HTTP loopback URLs only/
  );
});

test('BackendManager.ensure retries health check and succeeds during startup', async () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);

  vscode._setMockConfig({
    'buildguard.backendUrl': 'http://127.0.0.1:8787',
    'buildguard.autoStartBackend': true,
    'buildguard.backendCwd': '/path/to/shieldops'
  });

  // Mock manager.start so it doesn't actually try to spawn python
  manager.start = () => {
    out.appendLine('Mock process started');
  };

  let attempts = 0;
  const mockHealth = async () => {
    attempts++;
    if (attempts <= 2) throw new ApiError(0, 'Connection refused');
    return { status: 'ok' };
  };

  await manager.ensure(mockHealth);
  assert.equal(attempts, 3);
});

test('BackendManager.dispose terminates child process', () => {
  const out = vscode.window.createOutputChannel('BuildGuard');
  const manager = new BackendManager(out);
  // Calling dispose when child is undefined should not throw
  assert.doesNotThrow(() => manager.dispose());
});
