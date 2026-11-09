// server/test/dashboard.test.js
// Priority 3.6 — Dashboard Metrics & Statistics API Integration Tests
// Tests GET /api/dashboard/stats across authenticated, unauthenticated,
// guest, forged token, DB-unavailable, and privacy constraints.
'use strict';
require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const config = require('../src/config');
const { connectDb, dbReady, closeDb, assertTestDatabase } = require('../src/config/db');

test('Dashboard API Integration Suite', async (t) => {
  let srv;
  let baseUrl;

  // Setup: start Express on a random port
  await new Promise((resolve) => {
    srv = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${srv.address().port}`;
      resolve();
    });
  });

  // Connect to MongoDB Atlas (must target trustlens_test)
  const connected = await connectDb();
  assert.ok(connected, 'MongoDB Atlas should connect for integration testing');
  assert.ok(dbReady(), 'Database should be marked ready');
  assertTestDatabase();

  // Helper
  const get = async (path, headers = {}) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json', ...headers },
    });
    const json = await res.json().catch(() => null);
    return [res.status, json];
  };

  const makeUserToken = (role = 'user') =>
    jwt.sign({ role }, config.jwtSecret, {
      subject: new mongoose.Types.ObjectId().toString(),
      expiresIn: '1h',
    });

  try {
    // ── Test 1: Unauthenticated public access succeeds (200) ──────────────────
    await t.test('GET /api/dashboard/stats allows unauthenticated public access (200)', async () => {
      const [s, j] = await get('/api/dashboard/stats');
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      const d = j.data;
      assert.equal(typeof d.scans, 'number');
      assert.equal(typeof d.highRiskScans, 'number');
      assert.equal(typeof d.criticalScans, 'number');
      assert.equal(typeof d.reports, 'number');
      assert.equal(typeof d.verifiedReports, 'number');
      assert.equal(typeof d.pendingReports, 'number');
      assert.ok(d.riskDistribution);
      assert.equal(typeof d.riskDistribution.low, 'number');
      assert.equal(typeof d.riskDistribution.moderate, 'number');
      assert.equal(typeof d.riskDistribution.high, 'number');
      assert.equal(typeof d.riskDistribution.critical, 'number');
      assert.ok(typeof d.categories === 'object');
      assert.ok(Array.isArray(d.recentScans));
      assert.ok(Array.isArray(d.recentReports));
      assert.equal(d.userScans, undefined, 'unauthenticated caller should not have userScans');
    });

    // ── Test 2: Authenticated user access returns userScans (200) ─────────────
    await t.test('GET /api/dashboard/stats with valid user token returns user metrics (200)', async () => {
      const userToken = makeUserToken('user');
      const [s, j] = await get('/api/dashboard/stats', { Authorization: 'Bearer ' + userToken });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.equal(typeof j.data.userScans, 'number');
    });

    // ── Test 3: Authenticated guest token succeeds (200) ──────────────────────
    await t.test('GET /api/dashboard/stats with valid guest token succeeds (200)', async () => {
      const guestToken = makeUserToken('guest');
      const [s, j] = await get('/api/dashboard/stats', { Authorization: 'Bearer ' + guestToken });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.equal(typeof j.data.scans, 'number');
    });

    // ── Test 4: Forged token rejected (401) ───────────────────────────────────
    await t.test('GET /api/dashboard/stats with forged token returns 401 UNAUTHENTICATED', async () => {
      const [s, j] = await get('/api/dashboard/stats', { Authorization: 'Bearer invalid.forged.jwt' });
      assert.equal(s, 401);
      assert.equal(j.error.code, 'UNAUTHENTICATED');
    });

    // ── Test 5: Privacy check: no private reporter or user data exposed ───────
    await t.test('GET /api/dashboard/stats never exposes reporter or user identities', async () => {
      const [s, j] = await get('/api/dashboard/stats');
      assert.equal(s, 200);
      for (const scan of j.data.recentScans) {
        assert.equal(scan.requestedBy, undefined, 'scan requestedBy must not be exposed');
      }
      for (const report of j.data.recentReports) {
        assert.equal(report.reporter, undefined, 'report reporter must not be exposed');
        assert.equal(report.reviewedBy, undefined, 'report reviewedBy must not be exposed');
      }
    });

    // ── Test 6: DB disconnected returns 503 DB_UNAVAILABLE ────────────────────
    await t.test('GET /api/dashboard/stats returns 503 DB_UNAVAILABLE when database is disconnected', async () => {
      const originalState = mongoose.connection.readyState;
      try {
        Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });
        const [s, j] = await get('/api/dashboard/stats');
        assert.equal(s, 503);
        assert.equal(j.error.code, 'DB_UNAVAILABLE');
      } finally {
        Object.defineProperty(mongoose.connection, 'readyState', { value: originalState, configurable: true });
      }
    });

  } finally {
    // Teardown
    await new Promise((resolve) => { srv.closeAllConnections?.(); srv.close(resolve); });
    await closeDb();
  }
});
