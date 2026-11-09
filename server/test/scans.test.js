require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const app = require('../src/app');
const config = require('../src/config');
const { connectDb, dbReady, closeDb, assertTestDatabase } = require('../src/config/db');
const Scan = require('../src/models/Scan');
const Domain = require('../src/models/Domain');

test('Scans API Integration Suite', async (t) => {
  let srv;
  let baseUrl;
  let testHttpServer;
  let testHttpPort;

  const testDomain = `test-target-${Date.now()}.example`;
  const userAId = new mongoose.Types.ObjectId().toString();
  const userBId = new mongoose.Types.ObjectId().toString();

  const tokenUserA = jwt.sign({ sub: userAId, role: 'user' }, config.jwtSecret);
  const tokenUserB = jwt.sign({ sub: userBId, role: 'user' }, config.jwtSecret);

  // Setup local controlled test HTTP server as target fixture
  await new Promise((resolve) => {
    testHttpServer = http.createServer((req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'X-Frame-Options': 'SAMEORIGIN',
      });
      res.end('<!DOCTYPE html><html><body><h1>TRUSTLENS INTEGRATION TARGET</h1></body></html>');
    });
    testHttpServer.listen(0, '127.0.0.1', () => {
      testHttpPort = testHttpServer.address().port;
      resolve();
    });
  });

  // Setup Express server instance
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

  let createdScanId = null;

  try {
    // Helper for JSON requests
    const postJson = async (path, body, headers = {}) => {
      const res = await fetch(`${baseUrl}${path}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
      const data = await res.json().catch(() => null);
      return [res.status, data];
    };

    const getJson = async (path, headers = {}) => {
      const res = await fetch(`${baseUrl}${path}`, {
        method: 'GET',
        headers,
      });
      const data = await res.json().catch(() => null);
      return [res.status, data];
    };

    // Test 1: Valid scan request
    await t.test('POST /api/scans with valid URL creates assessment and returns 201', async () => {
      // Point assessment to our local fixture using mock resolver to map testDomain to 127.0.0.1
      const [status, json] = await postJson(
        '/api/scans',
        { url: `http://${testDomain}:${testHttpPort}/` },
        { authorization: `Bearer ${tokenUserA}` }
      );

      assert.equal(status, 201);
      assert.equal(json.ok, true);
      assert.ok(json.data.id, 'Scan response must contain id');
      assert.equal(json.data.domain, testDomain);
      assert.ok(typeof json.data.score === 'number');
      assert.ok(['low', 'medium', 'high', 'critical'].includes(json.data.riskLevel));
      assert.ok(json.data.confidence >= 0);
      assert.ok(json.data.coverage >= 0);
      assert.ok(Array.isArray(json.data.findings));
      assert.ok(Array.isArray(json.data.recommendations));
      assert.ok(json.data.m, 'Must include frontend compatibility m object');
      assert.ok(json.data.a, 'Must include frontend compatibility a object');

      createdScanId = json.data.id;
    });

    // Test 2: Invalid URL handling
    await t.test('POST /api/scans with invalid URL rejects with 400 INVALID_URL', async () => {
      const [status, json] = await postJson('/api/scans', { url: 'ftp://not-supported-scheme.com' });
      assert.equal(status, 400);
      assert.equal(json.ok, false);
      assert.equal(json.error.code, 'INVALID_URL');

      const [statusEmpty, jsonEmpty] = await postJson('/api/scans', { url: '' });
      assert.equal(statusEmpty, 400);
      assert.equal(jsonEmpty.error.code, 'VALIDATION_ERROR');
    });

    // Test 3: SSRF-blocked target rejection
    await t.test('POST /api/scans with loopback or metadata IP rejects with 400 SSRF_BLOCKED', async () => {
      const blockedTargets = [
        'http://127.0.0.1:8080',
        'http://localhost',
        'http://169.254.169.254/latest/meta-data',
        'http://server.internal',
      ];

      for (const target of blockedTargets) {
        const [status, json] = await postJson('/api/scans', { url: target });
        assert.equal(status, 400, `Expected 400 for ${target}`);
        assert.equal(json.ok, false);
        assert.equal(json.error.code, 'SSRF_BLOCKED', `Expected SSRF_BLOCKED for ${target}`);
      }
    });

    // Test 4: Successful scan persistence in MongoDB
    await t.test('verifies scan document and domain record are persisted in MongoDB', async () => {
      assert.ok(createdScanId, 'Scan ID must be present from Test 1');

      const persistedScan = await Scan.findById(createdScanId).lean();
      assert.ok(persistedScan, 'Scan record must exist in MongoDB');
      assert.equal(persistedScan.domainName, testDomain);
      assert.equal(persistedScan.mode, 'live');
      assert.equal(persistedScan.status, 'completed');
      assert.equal(persistedScan.requestedBy.toString(), userAId);
      assert.ok(persistedScan.modules.threat);
      assert.ok(persistedScan.modules.security);

      const persistedDomain = await Domain.findOne({ name: testDomain }).lean();
      assert.ok(persistedDomain, 'Domain record must exist in MongoDB');
      assert.equal(persistedDomain.name, testDomain);
      assert.ok(persistedDomain.lastScannedAt instanceof Date);
    });

    // Test 5: Database unavailable handling
    await t.test('returns 503 DB_UNAVAILABLE when database is disconnected', async () => {
      const originalReadyState = mongoose.connection.readyState;
      try {
        // Temporarily simulate disconnected state
        Object.defineProperty(mongoose.connection, 'readyState', { value: 0, configurable: true });

        const [status, json] = await postJson('/api/scans', { url: 'https://example.com' });
        assert.equal(status, 503);
        assert.equal(json.error.code, 'DB_UNAVAILABLE');

        const [histStatus, histJson] = await getJson('/api/scans', { authorization: `Bearer ${tokenUserA}` });
        assert.equal(histStatus, 503);
        assert.equal(histJson.error.code, 'DB_UNAVAILABLE');
      } finally {
        Object.defineProperty(mongoose.connection, 'readyState', { value: originalReadyState, configurable: true });
      }
    });

    // Test 6: Scan history retrieval
    await t.test('GET /api/scans retrieves authenticated user history with pagination', async () => {
      const [status, json] = await getJson('/api/scans?page=1&limit=10', {
        authorization: `Bearer ${tokenUserA}`,
      });

      assert.equal(status, 200);
      assert.equal(json.ok, true);
      assert.ok(Array.isArray(json.data.scans));
      assert.ok(json.data.scans.length >= 1);
      assert.equal(json.data.scans[0].domain, testDomain);
      assert.ok(json.data.pagination);
      assert.equal(json.data.pagination.page, 1);
      assert.ok(json.data.pagination.total >= 1);
    });

    // Test 7: Empty scan history for user without scans
    await t.test('GET /api/scans returns empty array for user with no scans', async () => {
      const [status, json] = await getJson('/api/scans', {
        authorization: `Bearer ${tokenUserB}`,
      });

      assert.equal(status, 200);
      assert.equal(json.ok, true);
      assert.deepEqual(json.data.scans, []);
      assert.equal(json.data.pagination.total, 0);
    });

    // Test 8: Scan detail retrieval
    await t.test('GET /api/scans/:id retrieves full details for valid scan', async () => {
      const [status, json] = await getJson(`/api/scans/${createdScanId}`, {
        authorization: `Bearer ${tokenUserA}`,
      });

      assert.equal(status, 200);
      assert.equal(json.ok, true);
      assert.equal(json.data.id, createdScanId);
      assert.equal(json.data.domain, testDomain);
      assert.ok(json.data.modules.threat);
      assert.ok(json.data.modules.security);
      assert.ok(Array.isArray(json.data.recommendations));
    });

    // Test 9: Invalid scan ID format
    await t.test('GET /api/scans/:id with invalid ID format returns 400 INVALID_ID', async () => {
      const [status, json] = await getJson('/api/scans/invalid-non-hex-id', {
        authorization: `Bearer ${tokenUserA}`,
      });

      assert.equal(status, 400);
      assert.equal(json.error.code, 'INVALID_ID');
    });

    // Test 10: Nonexistent scan ID
    await t.test('GET /api/scans/:id with nonexistent ID returns 404 NOT_FOUND', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();
      const [status, json] = await getJson(`/api/scans/${fakeId}`, {
        authorization: `Bearer ${tokenUserA}`,
      });

      assert.equal(status, 404);
      assert.equal(json.error.code, 'NOT_FOUND');
    });

    // Test 11: Unauthorized access to history
    await t.test('GET /api/scans without token returns 401 UNAUTHENTICATED', async () => {
      const [status, json] = await getJson('/api/scans');
      assert.equal(status, 401);
      assert.equal(json.error.code, 'UNAUTHENTICATED');
    });

    // Test 12: Cross-user scan access restrictions
    await t.test('GET /api/scans/:id by a different user returns 403 FORBIDDEN', async () => {
      // User B attempts to access User A's private scan
      const [status, json] = await getJson(`/api/scans/${createdScanId}`, {
        authorization: `Bearer ${tokenUserB}`,
      });

      assert.equal(status, 403);
      assert.equal(json.error.code, 'FORBIDDEN');
    });

    // Test 13: Admin user can access cross-user scans
    await t.test('GET /api/scans/:id by admin user succeeds', async () => {
      const adminToken = jwt.sign({ sub: new mongoose.Types.ObjectId().toString(), role: 'admin' }, config.jwtSecret);
      const [status, json] = await getJson(`/api/scans/${createdScanId}`, {
        authorization: `Bearer ${adminToken}`,
      });

      assert.equal(status, 200);
      assert.equal(json.data.id, createdScanId);
    });

  } finally {
    // Cleanup test artifacts from MongoDB Atlas
    if (createdScanId) {
      await Scan.deleteMany({ domainName: testDomain }).catch(() => {});
      await Domain.deleteOne({ name: testDomain }).catch(() => {});
    }

    // Close HTTP servers, awaiting full socket drain so no handles remain.
    await new Promise(resolve => { testHttpServer.closeAllConnections?.(); testHttpServer.close(resolve); });
    await new Promise(resolve => { srv.closeAllConnections?.(); srv.close(resolve); });

    // Close the underlying MongoClient connection pool before closing Mongoose.
    // mongoose.connection.close() alone does not drain driver TLS sockets on v6+;
    // closeDb() calls client.close(true) first to ensure all pooled sockets are
    // destroyed so no active handles remain in the event loop.
    await closeDb();
  }
});
