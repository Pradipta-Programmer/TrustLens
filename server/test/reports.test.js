// server/test/reports.test.js
// Priority 3.4 — Community Reporting Flow Integration Tests
// Tests POST /api/reports, GET /api/reports/mine, POST /api/auth/guest,
// and all associated auth/validation/duplicate/DB-unavailable paths.
// Requires live MongoDB Atlas connection for integration subtests.
'use strict';
require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const config = require('../src/config');
const { connectDb, dbReady, closeDb } = require('../src/config/db');
const Report = require('../src/models/CommunityReport');

// ─── Constants ────────────────────────────────────────────────────────────────
const TEST_DOMAIN = `report-test-${Date.now()}.example`;
const TEST_URL = `https://${TEST_DOMAIN}/`;
// A valid backend category value
const TEST_CATEGORY = 'phishing';

test('Reports API Integration Suite', async (t) => {
  let srv;
  let baseUrl;

  // ── Setup ──────────────────────────────────────────────────────────────────
  // Start Express on a random port
  await new Promise((resolve) => {
    srv = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${srv.address().port}`;
      resolve();
    });
  });

  // Connect to MongoDB Atlas
  const connected = await connectDb();
  assert.ok(connected, 'MongoDB Atlas should connect for integration testing');
  assert.ok(dbReady(), 'Database should be marked ready');

  // ── Helpers ────────────────────────────────────────────────────────────────
  const req = async (method, path, body, headers = {}) => {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(`${baseUrl}${path}`, opts);
    const json = await res.json().catch(() => null);
    return [res.status, json];
  };
  const post = (path, body, hdrs) => req('POST', path, body, hdrs);
  const get  = (path, hdrs) => req('GET', path, undefined, hdrs);

  // Helper: obtain a guest token via POST /api/auth/guest
  const getGuestToken = async () => {
    const [s, j] = await post('/api/auth/guest', {});
    assert.equal(s, 201, 'guest token endpoint should return 201');
    assert.ok(j && j.ok && j.data && j.data.token, 'guest token response should contain token');
    return j.data.token;
  };

  // Helper: sign a full user JWT directly (for owned-report tests)
  const makeUserToken = (role = 'user') =>
    jwt.sign({ role }, config.jwtSecret, {
      subject: new mongoose.Types.ObjectId().toString(),
      expiresIn: '1h',
    });

  try {
    // ── Test 1: POST /api/auth/guest returns a valid JWT ──────────────────────
    await t.test('POST /api/auth/guest issues a signed JWT without DB access', async () => {
      const [s, j] = await post('/api/auth/guest', {});
      assert.equal(s, 201);
      assert.ok(j && j.ok);
      assert.ok(typeof j.data.token === 'string');
      assert.equal(j.data.role, 'guest');
      // Verify it decodes correctly
      const decoded = jwt.verify(j.data.token, config.jwtSecret);
      assert.equal(decoded.role, 'guest');
      assert.ok(decoded.sub, 'subject should be a generated ID');
    });

    // ── Test 2: POST /api/reports with valid guest token creates report ────────
    let createdReportId = null;
    let guestToken = null;
    await t.test('POST /api/reports with valid guest token creates report (201)', async () => {
      guestToken = await getGuestToken();
      const [s, j] = await post(
        '/api/reports',
        { url: TEST_URL, category: TEST_CATEGORY, description: 'Integration test — automated.' },
        { Authorization: 'Bearer ' + guestToken }
      );
      assert.equal(s, 201, `expected 201, got ${s}: ${JSON.stringify(j)}`);
      assert.ok(j && j.ok);
      assert.equal(j.data.domain, TEST_DOMAIN);
      assert.equal(j.data.category, TEST_CATEGORY);
      assert.equal(j.data.status, 'pending_review');
      assert.ok(j.data.id, 'response must include id');
      assert.ok(!j.data.reporter, 'reporter field must NOT be exposed publicly');
      createdReportId = String(j.data.id);
    });

    // ── Test 3: Duplicate report (same token = same reporter sub) → 409 ──────
    await t.test('POST /api/reports duplicate (same guest, same domain+category) returns 409 DUPLICATE_REPORT', async () => {
      assert.ok(guestToken, 'need guest token from previous test');
      const [s, j] = await post(
        '/api/reports',
        { url: TEST_URL, category: TEST_CATEGORY },
        { Authorization: 'Bearer ' + guestToken }
      );
      assert.equal(s, 409);
      assert.equal(j.error.code, 'DUPLICATE_REPORT');
    });

    // ── Test 4: Different category from same guest is allowed ─────────────────
    await t.test('POST /api/reports different category from same guest is accepted (201)', async () => {
      const [s, j] = await post(
        '/api/reports',
        { url: TEST_URL, category: 'fake_banking' },
        { Authorization: 'Bearer ' + guestToken }
      );
      assert.equal(s, 201, `expected 201, got ${s}`);
      assert.equal(j.data.category, 'fake_banking');
    });

    // ── Test 5: No token → 401 UNAUTHENTICATED ────────────────────────────────
    await t.test('POST /api/reports without token returns 401 UNAUTHENTICATED', async () => {
      const [s, j] = await post('/api/reports', { url: TEST_URL, category: TEST_CATEGORY });
      assert.equal(s, 401);
      assert.equal(j.error.code, 'UNAUTHENTICATED');
    });

    // ── Test 6: Invalid URL → 400 ─────────────────────────────────────────────
    await t.test('POST /api/reports with invalid URL returns 400 INVALID_URL', async () => {
      const tok = await getGuestToken();
      // ftp: scheme blocked
      const [s1, j1] = await post(
        '/api/reports',
        { url: 'ftp://example.com', category: TEST_CATEGORY },
        { Authorization: 'Bearer ' + tok }
      );
      assert.equal(s1, 400);
      assert.equal(j1.error.code, 'INVALID_URL');
    });

    // ── Test 7: SSRF-blocked URL → 400 SSRF_BLOCKED ───────────────────────────
    await t.test('POST /api/reports with private IP URL returns 400 SSRF_BLOCKED', async () => {
      const tok = await getGuestToken();
      // localhost is SSRF_BLOCKED by urlGuard
      const [s, j] = await post(
        '/api/reports',
        { url: 'http://localhost/evil', category: TEST_CATEGORY },
        { Authorization: 'Bearer ' + tok }
      );
      assert.equal(s, 400);
      // urlGuard returns SSRF_BLOCKED or INVALID_URL for localhost — both are correct rejections
      assert.ok(
        j.error.code === 'SSRF_BLOCKED' || j.error.code === 'INVALID_URL',
        `expected SSRF_BLOCKED or INVALID_URL, got ${j.error.code}`
      );
    });

    // ── Test 8: Invalid category → 400 VALIDATION_ERROR ──────────────────────
    await t.test('POST /api/reports with unknown category returns 400 VALIDATION_ERROR', async () => {
      const tok = await getGuestToken();
      const [s, j] = await post(
        '/api/reports',
        { url: TEST_URL, category: 'not_a_real_category' },
        { Authorization: 'Bearer ' + tok }
      );
      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── Test 9: Missing URL field → 400 VALIDATION_ERROR ─────────────────────
    await t.test('POST /api/reports with missing url returns 400 VALIDATION_ERROR', async () => {
      const tok = await getGuestToken();
      const [s, j] = await post(
        '/api/reports',
        { category: TEST_CATEGORY },
        { Authorization: 'Bearer ' + tok }
      );
      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── Test 10: reporter field is never in public response ───────────────────
    await t.test('POST /api/reports response never exposes reporter identity', async () => {
      assert.ok(createdReportId, 'need a created report from earlier test');
      // Verify persisted record via Mongoose: reporter should exist in DB but select:false
      const dbRecord = await Report.findById(createdReportId);
      // With select:false, reporter is not returned unless explicitly selected
      assert.ok(!dbRecord.reporter, 'reporter should not be returned without +reporter select');
      // Verify via full record
      const dbRecordWithReporter = await Report.findById(createdReportId).select('+reporter');
      assert.ok(dbRecordWithReporter.reporter, 'reporter should be stored in DB');
      // But the API response had no reporter field
      // (already asserted in test 2 above — this confirms the DB side is correct)
    });

    // ── Test 11: DB unavailable → 503 DB_UNAVAILABLE ──────────────────────────
    await t.test('POST /api/reports returns 503 DB_UNAVAILABLE when database is disconnected', async () => {
      const tok = await getGuestToken();
      const originalState = mongoose.connection.readyState;
      try {
        Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });
        const [s, j] = await post(
          '/api/reports',
          { url: TEST_URL, category: TEST_CATEGORY },
          { Authorization: 'Bearer ' + tok }
        );
        assert.equal(s, 503);
        assert.equal(j.error.code, 'DB_UNAVAILABLE');
      } finally {
        Object.defineProperty(mongoose.connection, 'readyState', { value: originalState, configurable: true });
      }
    });

    // ── Test 12: GET /api/reports/mine with valid user token ──────────────────
    await t.test('GET /api/reports/mine returns reports for authenticated user', async () => {
      // Use guestToken — the guest's reports are in the DB
      const [s, j] = await get('/api/reports/mine', { Authorization: 'Bearer ' + guestToken });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data));
      // Should contain at least the two reports created in tests 2 and 4
      assert.ok(j.data.length >= 2, `expected ≥2 reports, got ${j.data.length}`);
      // No reporter field in any item
      for (const item of j.data) {
        assert.ok(!item.reporter, 'reporter must not be in /mine response');
      }
    });

    // ── Test 13: GET /api/reports/mine without token → 401 ───────────────────
    await t.test('GET /api/reports/mine without token returns 401 UNAUTHENTICATED', async () => {
      const [s, j] = await get('/api/reports/mine');
      assert.equal(s, 401);
      assert.equal(j.error.code, 'UNAUTHENTICATED');
    });

    // ── Test 14: Admin can list reports via GET /api/admin/reports ────────────
    await t.test('GET /api/admin/reports with admin token returns report list (200)', async () => {
      const adminToken = jwt.sign(
        { role: 'admin' },
        config.jwtSecret,
        { subject: new mongoose.Types.ObjectId().toString(), expiresIn: '1h' }
      );
      const [s, j] = await get('/api/admin/reports', { Authorization: 'Bearer ' + adminToken });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data));
    });

    // ── Test 15: Forged token rejected ────────────────────────────────────────
    await t.test('POST /api/reports with forged token returns 401 UNAUTHENTICATED', async () => {
      const [s, j] = await post(
        '/api/reports',
        { url: TEST_URL, category: TEST_CATEGORY },
        { Authorization: 'Bearer forged.token.value' }
      );
      assert.equal(s, 401);
      assert.equal(j.error.code, 'UNAUTHENTICATED');
    });

    // ── Test 16: GET /api/reports returns public threat report list (200) ─────
    await t.test('GET /api/reports returns public reports with pagination', async () => {
      const [s, j] = await get('/api/reports');
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(j.data && Array.isArray(j.data.reports));
      assert.ok(j.data.pagination);
      assert.equal(typeof j.data.pagination.page, 'number');
      assert.equal(typeof j.data.pagination.total, 'number');
      assert.equal(typeof j.data.pagination.totalPages, 'number');
    });

    // ── Test 17: GET /api/reports privacy: reporter and reviewer never exposed
    await t.test('GET /api/reports never exposes reporter or reviewer identities', async () => {
      const [s, j] = await get(`/api/reports?q=${TEST_DOMAIN}`);
      assert.equal(s, 200);
      assert.ok(j.data.reports.length >= 1);
      for (const item of j.data.reports) {
        assert.equal(item.reporter, undefined, 'reporter must be undefined in public feed');
        assert.equal(item.reviewedBy, undefined, 'reviewedBy must be undefined in public feed');
        assert.ok(item.id, 'item must have public id');
        assert.ok(item.domain, 'item must have domain');
        assert.ok(item.category, 'item must have category');
        assert.ok(item.status, 'item must have status');
      }
    });

    // ── Test 18: GET /api/reports filters by domain search query ──────────────
    await t.test('GET /api/reports filters by domain search query', async () => {
      const [s, j] = await get(`/api/reports?q=${TEST_DOMAIN.slice(0, 15)}`);
      assert.equal(s, 200);
      assert.ok(j.data.reports.length >= 1);
      for (const item of j.data.reports) {
        assert.ok(item.domain.includes(TEST_DOMAIN.slice(0, 15).toLowerCase()));
      }
    });

    // ── Test 19: GET /api/reports filters by category ─────────────────────────
    await t.test('GET /api/reports filters by category', async () => {
      const [s, j] = await get('/api/reports?category=phishing');
      assert.equal(s, 200);
      for (const item of j.data.reports) {
        assert.equal(item.category, 'phishing');
      }
    });

    // ── Test 20: GET /api/reports rejects invalid category with 400 ───────────
    await t.test('GET /api/reports with invalid category returns 400 VALIDATION_ERROR', async () => {
      const [s, j] = await get('/api/reports?category=non_existent_category');
      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── Test 21: GET /api/reports filters by status ───────────────────────────
    await t.test('GET /api/reports filters by status', async () => {
      const [s, j] = await get('/api/reports?status=pending_review');
      assert.equal(s, 200);
      for (const item of j.data.reports) {
        assert.equal(item.status, 'pending_review');
      }
    });

    // ── Test 22: GET /api/reports rejects invalid status with 400 ─────────────
    await t.test('GET /api/reports with invalid status returns 400 VALIDATION_ERROR', async () => {
      const [s, j] = await get('/api/reports?status=bogus_status');
      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── Test 23: GET /api/reports pagination parameters ───────────────────────
    await t.test('GET /api/reports supports pagination limit and page', async () => {
      const [s, j] = await get('/api/reports?limit=5&page=1');
      assert.equal(s, 200);
      assert.equal(j.data.pagination.limit, 5);
      assert.equal(j.data.pagination.page, 1);
      assert.ok(j.data.reports.length <= 5);
    });

    // ── Test 24: GET /api/reports returns 503 when DB is offline ──────────────
    await t.test('GET /api/reports returns 503 DB_UNAVAILABLE when database is disconnected', async () => {
      const originalState = mongoose.connection.readyState;
      try {
        Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });
        const [s, j] = await get('/api/reports');
        assert.equal(s, 503);
        assert.equal(j.error.code, 'DB_UNAVAILABLE');
      } finally {
        Object.defineProperty(mongoose.connection, 'readyState', { value: originalState, configurable: true });
      }
    });

    // ── Test 25: GET /api/threats alias routes properly ───────────────────────
    await t.test('GET /api/threats alias returns 200 for public threat exploration', async () => {
      const [s, j] = await get('/api/threats');
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data.reports));
    });

  } finally {
    // ── Cleanup ────────────────────────────────────────────────────────────────
    // Remove test-created reports from MongoDB Atlas
    await Report.deleteMany({ domainName: TEST_DOMAIN }).catch(() => {});

    // Close HTTP server (awaited)
    await new Promise((resolve) => { srv.closeAllConnections?.(); srv.close(resolve); });

    // Close MongoDB connections cleanly (no forced exit needed)
    await closeDb();
  }
});
