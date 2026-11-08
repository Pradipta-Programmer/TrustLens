// server/test/certificates.test.js
// Priority 3.7 — Live Certificate Intelligence Integration Tests
// Tests GET /api/certificates/:domain and GET /api/certificates across
// public, authenticated, expired, fallback, DB-unavailable, and privacy constraints.
'use strict';
require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const config = require('../src/config');
const CertificateRecord = require('../src/models/CertificateRecord');
const Scan = require('../src/models/Scan');
const { connectDb, dbReady, closeDb } = require('../src/config/db');

test('Certificates API Integration Suite', async (t) => {
  let srv;
  let baseUrl;

  // Setup: start Express on a random port
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

  const uniqueSuffix = Date.now();
  const testValidDomain = `cert-valid-${uniqueSuffix}.example`;
  const testExpiredDomain = `cert-expired-${uniqueSuffix}.example`;
  const testExpiringSoonDomain = `cert-soon-${uniqueSuffix}.example`;
  const testScanOnlyDomain = `cert-scanonly-${uniqueSuffix}.example`;

  // Seed test certificate records
  await CertificateRecord.create([
    {
      domainName: testValidDomain,
      issuer: 'DigiCert Global Root G2',
      subject: testValidDomain,
      san: [testValidDomain, `www.${testValidDomain}`],
      validFrom: new Date(Date.now() - 30 * 86400000),
      validTo: new Date(Date.now() + 180 * 86400000),
      hostnameMatch: true,
      chainValid: true,
      mode: 'live',
      observedAt: new Date(),
    },
    {
      domainName: testExpiredDomain,
      issuer: 'Let\'s Encrypt Authority X3',
      subject: testExpiredDomain,
      san: [testExpiredDomain],
      validFrom: new Date(Date.now() - 120 * 86400000),
      validTo: new Date(Date.now() - 10 * 86400000), // Expired 10 days ago
      hostnameMatch: true,
      chainValid: true,
      mode: 'live',
      observedAt: new Date(),
    },
    {
      domainName: testExpiringSoonDomain,
      issuer: 'Sectigo RSA Domain Validation Secure Server CA',
      subject: testExpiringSoonDomain,
      san: [testExpiringSoonDomain],
      validFrom: new Date(Date.now() - 85 * 86400000),
      validTo: new Date(Date.now() + 5 * 86400000), // Expires in 5 days
      hostnameMatch: true,
      chainValid: true,
      mode: 'live',
      observedAt: new Date(),
    },
  ]);

  // Seed test scan document (for fallback retrieval test)
  await Scan.create({
    submittedUrl: `https://${testScanOnlyDomain}/`,
    domainName: testScanOnlyDomain,
    mode: 'live',
    status: 'completed',
    riskScore: 10,
    confidence: 85,
    classification: 'Low Risk',
    modules: {
      threat: { status: 'live', score: 0, findings: [] },
      security: { status: 'live', score: 10, findings: [] },
      certificate: {
        status: 'live',
        score: 0,
        findings: [{ name: 'Certificate Valid', severity: 'Info', explanation: 'Valid certificate' }],
      },
      community: { status: 'live', score: 0, findings: [] },
      impersonation: { status: 'live', score: 0, findings: [] },
    },
  });

  try {
    // ── Test 1: GET /api/certificates/:domain returns 200 with full certificate record ──
    await t.test('GET /api/certificates/:domain returns 200 with verified certificate details', async () => {
      const [s, j] = await get(`/api/certificates/${testValidDomain}`);
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      const d = j.data;
      assert.equal(d.domain, testValidDomain);
      assert.equal(d.domainName, testValidDomain);
      assert.equal(d.issuer, 'DigiCert Global Root G2');
      assert.equal(d.subject, testValidDomain);
      assert.ok(Array.isArray(d.san) && d.san.includes(testValidDomain));
      assert.ok(d.validFrom);
      assert.ok(d.validTo);
      assert.equal(typeof d.daysRemaining, 'number');
      assert.ok(d.daysRemaining > 100);
      assert.equal(d.hostnameMatch, true);
      assert.equal(d.chainValid, true);
      assert.equal(d.status, 'valid');
      assert.ok(d.ct);
      assert.ok(d.observedAt);
      assert.equal(j.meta.mode, 'live');
    });

    // ── Test 2: Input normalization (protocol, path, slashes, uppercase) ─────────
    await t.test('GET /api/certificates/:domain normalizes domain input formats', async () => {
      const [s, j] = await get(`/api/certificates/https%3A%2F%2F${testValidDomain.toUpperCase()}%2Fpath%2Fsub`);
      assert.equal(s, 200);
      assert.equal(j.data.domain, testValidDomain);
    });

    // ── Test 3: Expired certificate status computation ─────────────────────────
    await t.test('GET /api/certificates/:domain detects and labels expired certificates', async () => {
      const [s, j] = await get(`/api/certificates/${testExpiredDomain}`);
      assert.equal(s, 200);
      assert.equal(j.data.status, 'expired');
      assert.ok(j.data.daysRemaining < 0);
    });

    // ── Test 4: Expiring soon certificate status computation ───────────────────
    await t.test('GET /api/certificates/:domain detects certificates expiring soon (< 14 days)', async () => {
      const [s, j] = await get(`/api/certificates/${testExpiringSoonDomain}`);
      assert.equal(s, 200);
      assert.equal(j.data.status, 'expiring_soon');
      assert.ok(j.data.daysRemaining >= 0 && j.data.daysRemaining < 14);
    });

    // ── Test 5: Fallback to Scan record when CertificateRecord is not pre-populated
    await t.test('GET /api/certificates/:domain falls back to live Scan document if available', async () => {
      const [s, j] = await get(`/api/certificates/${testScanOnlyDomain}`);
      assert.equal(s, 200);
      assert.equal(j.data.domain, testScanOnlyDomain);
      assert.equal(j.data.hostnameMatch, true);
      assert.equal(j.data.chainValid, true);
    });

    // ── Test 6: 404 NOT_FOUND for unscanned domain ─────────────────────────────
    await t.test('GET /api/certificates/:domain returns 404 NOT_FOUND for unscanned domain', async () => {
      const [s, j] = await get(`/api/certificates/unscanned-${uniqueSuffix}.example`);
      assert.equal(s, 404);
      assert.equal(j.error.code, 'NOT_FOUND');
      assert.ok(j.error.message.includes('Run a website scan first'));
    });

    // ── Test 7: 400 INVALID_DOMAIN for malformed input ─────────────────────────
    await t.test('GET /api/certificates/:domain rejects invalid domain parameter format (400)', async () => {
      const [s, j] = await get('/api/certificates/invalid%20domain%20name');
      assert.equal(s, 400);
      assert.equal(j.error.code, 'INVALID_DOMAIN');
    });

    // ── Test 8: GET /api/certificates listing & pagination ─────────────────────
    await t.test('GET /api/certificates returns paginated certificate records', async () => {
      const [s, j] = await get('/api/certificates?limit=10&page=1');
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data.certificates));
      assert.ok(j.data.pagination);
      assert.equal(j.data.pagination.page, 1);
      assert.equal(j.data.pagination.limit, 10);
      assert.ok(typeof j.data.pagination.total === 'number');
    });

    // ── Test 9: GET /api/certificates search query ─────────────────────────────
    await t.test('GET /api/certificates filters by search query parameter q', async () => {
      const [s, j] = await get(`/api/certificates?q=${uniqueSuffix}`);
      assert.equal(s, 200);
      assert.ok(j.data.certificates.length >= 3);
      for (const cert of j.data.certificates) {
        assert.ok(cert.domain.includes(String(uniqueSuffix)));
      }
    });

    // ── Test 10: GET /api/certificates rejects invalid pagination ──────────────
    await t.test('GET /api/certificates rejects invalid pagination query params (400)', async () => {
      const [s, j] = await get('/api/certificates?page=-1');
      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── Test 11: Privacy check: never exposes user/reporter metadata ───────────
    await t.test('Certificates API never exposes user IDs, reporter data, or internal secrets', async () => {
      const [s, j] = await get(`/api/certificates/${testValidDomain}`);
      assert.equal(s, 200);
      const d = j.data;
      assert.equal(d.reporter, undefined, 'Must not expose reporter');
      assert.equal(d.requestedBy, undefined, 'Must not expose requestedBy');
      assert.equal(d.userId, undefined, 'Must not expose userId');
      assert.equal(d.email, undefined, 'Must not expose email');
      assert.equal(d.__v, undefined, 'Must not expose Mongoose version key');
    });

    // ── Test 12: Optional authentication (public, authenticated, forged token) ──
    await t.test('Certificates API allows valid tokens and rejects forged tokens', async () => {
      const userToken = makeUserToken('user');
      const [sValid] = await get(`/api/certificates/${testValidDomain}`, {
        Authorization: `Bearer ${userToken}`,
      });
      assert.equal(sValid, 200);

      const [sForged, jForged] = await get(`/api/certificates/${testValidDomain}`, {
        Authorization: 'Bearer invalid.forged.jwt',
      });
      assert.equal(sForged, 401);
      assert.equal(jForged.error.code, 'UNAUTHENTICATED');
    });

    // ── Test 13: DB disconnected returns 503 DB_UNAVAILABLE ────────────────────
    await t.test('GET /api/certificates/:domain returns 503 DB_UNAVAILABLE when database is down', async () => {
      const originalState = mongoose.connection.readyState;
      try {
        Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });
        const [s, j] = await get(`/api/certificates/${testValidDomain}`);
        assert.equal(s, 503);
        assert.equal(j.error.code, 'DB_UNAVAILABLE');
      } finally {
        Object.defineProperty(mongoose.connection, 'readyState', { value: originalState, configurable: true });
      }
    });

  } finally {
    // Cleanup seeded test records
    await CertificateRecord.deleteMany({ domainName: new RegExp(String(uniqueSuffix)) }).catch(() => {});
    await Scan.deleteMany({ domainName: testScanOnlyDomain }).catch(() => {});

    // Teardown
    await new Promise((resolve) => { srv.closeAllConnections?.(); srv.close(resolve); });
    await closeDb();
  }
});
