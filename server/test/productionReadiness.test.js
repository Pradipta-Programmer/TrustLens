// server/test/productionReadiness.test.js
// Tests for Priority 4.1 - 4.4 Production Readiness & Reliability
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const app = require('../src/app');
const config = require('../src/config');
const feedScheduler = require('../src/services/feedScheduler');
const { asyncLocalStorage } = require('../src/utils/logger');

test('Priority 4.1–4.4 Production Readiness Test Suite', async (t) => {
  let srv;
  let baseUrl;

  await new Promise((resolve) => {
    srv = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${srv.address().port}`;
      resolve();
    });
  });

  t.after(() => {
    srv.close();
    feedScheduler.stopScheduledSync();
  });

  const get = async (path, headers = {}) => {
    const res = await fetch(`${baseUrl}${path}`, { headers });
    const json = await res.json().catch(() => null);
    return { status: res.status, headers: res.headers, json };
  };

  await t.test('Health /api/health/ready returns unready (503) when DB is down', async () => {
    const res = await get('/api/health/ready');
    assert.equal(res.status, 503);
    assert.equal(res.json.ok, false);
    assert.equal(res.json.status, 'unready');
    assert.equal(res.json.dependencies.database, 'unavailable');
  });

  await t.test('Health /api/health preserves legacy status reporting', async () => {
    const res = await get('/api/health');
    assert.equal(res.status, 503);
    assert.equal(res.json.ok, false);
    assert.equal(res.json.data.service, 'trustlens-server');
    assert.equal(res.json.data.database, 'unavailable');
  });

  await t.test('Request ID middleware generates UUID when missing', async () => {
    const res = await get('/api/health');
    const reqId = res.headers.get('x-request-id');
    assert.ok(reqId, 'X-Request-Id header must be present');
    assert.match(reqId, /^[0-9a-f-]{36}$/);
  });

  await t.test('Request ID middleware validates and echoes valid incoming ID', async () => {
    const custom = 'client-trace-id-12345';
    const res = await get('/api/health', { 'x-request-id': custom });
    assert.equal(res.headers.get('x-request-id'), custom);
  });

  await t.test('Request ID middleware sanitizes invalid or malicious IDs', async () => {
    const evil = 'bad/id;drop table users--<script>';
    const res = await get('/api/health', { 'x-request-id': evil });
    const reqId = res.headers.get('x-request-id');
    assert.notEqual(reqId, evil);
    assert.match(reqId, /^[0-9a-f-]{36}$/);
  });

  await t.test('Logger AsyncLocalStorage context captures request ID', () => {
    let captured = null;
    asyncLocalStorage.run({ reqId: 'test-req-123' }, () => {
      captured = asyncLocalStorage.getStore()?.reqId;
    });
    assert.equal(captured, 'test-req-123');
  });

  await t.test('Trust proxy config parser parses booleans, numbers, and strings', () => {
    const { parseTrustProxy } = require('../src/config');
    assert.equal(parseTrustProxy('true'), true);
    assert.equal(parseTrustProxy('false'), false);
    assert.equal(parseTrustProxy('0'), false);
    assert.equal(parseTrustProxy('1'), 1);
    assert.equal(parseTrustProxy('3'), 3);
    assert.equal(parseTrustProxy('loopback'), 'loopback');
    assert.equal(parseTrustProxy('10.0.0.0/8'), '10.0.0.0/8');
    assert.equal(parseTrustProxy(undefined), false);
  });

  await t.test('validateProductionConfig fails fast in production if variables are invalid', () => {
    const { validateProductionConfig } = require('../src/config');
    const res1 = validateProductionConfig({
      nodeEnv: 'production',
      jwtSecret: 'short',
      mongoUri: 'mongodb://srv',
      port: 4000,
    });
    assert.equal(res1.valid, false);
    assert.ok(res1.errors.some(e => e.includes('JWT_SECRET')));

    const res2 = validateProductionConfig({
      nodeEnv: 'production',
      jwtSecret: 'a'.repeat(32),
      mongoUri: '',
      port: 4000,
    });
    assert.equal(res2.valid, false);
    assert.ok(res2.errors.some(e => e.includes('MONGODB_URI')));

    const res3 = validateProductionConfig({
      nodeEnv: 'production',
      jwtSecret: 'a'.repeat(32),
      mongoUri: 'mongodb://srv',
      port: 4000,
    });
    assert.equal(res3.valid, true);

    // Non-production passes gracefully
    const res4 = validateProductionConfig({
      nodeEnv: 'development',
      jwtSecret: '',
      mongoUri: '',
      port: 4000,
    });
    assert.equal(res4.valid, true);
  });

  await t.test('Background feed sync is disabled by default', () => {
    assert.equal(config.enableBackgroundFeedSync, false);
    assert.equal(feedScheduler.isScheduledSyncRunning(), false);
  });

  await t.test('Background feed scheduler can be started and stopped cleanly', () => {
    feedScheduler.startScheduledSync(60000);
    assert.equal(feedScheduler.isScheduledSyncRunning(), true);
    feedScheduler.stopScheduledSync();
    assert.equal(feedScheduler.isScheduledSyncRunning(), false);
  });

  await t.test('Background feed sync executeSync skips when database is unavailable', async () => {
    const result = await feedScheduler.executeSync('test_caller');
    assert.equal(result, null);
  });

  await t.test('POST /api/auth/guest operates independently from /login rate limiter', async () => {
    const res = await fetch(`${baseUrl}/api/auth/guest`, { method: 'POST' });
    const json = await res.json().catch(() => null);
    assert.equal(res.status, 201);
    assert.equal(json.ok, true);
    assert.equal(json.data.role, 'guest');
    assert.ok(json.data.token);
  });
});
