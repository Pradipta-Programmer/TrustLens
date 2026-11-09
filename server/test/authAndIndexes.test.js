// server/test/authAndIndexes.test.js
// Priority 6.3 Stage 2 — Integration tests for:
// Area 1: Registration, Login, Logout & Authentication Persistence
// Area 12: MongoDB Indexes & Query Behavior
'use strict';
require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const config = require('../src/config');
const { connectDb, dbReady, closeDb, assertTestDatabase } = require('../src/config/db');
const User = require('../src/models/User');
const CommunityReport = require('../src/models/CommunityReport');
const Scan = require('../src/models/Scan');

test('Auth & MongoDB Indexes Integration Suite', async (t) => {
  let srv;
  let baseUrl;

  // Start Express on random port
  await new Promise((resolve) => {
    srv = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${srv.address().port}`;
      resolve();
    });
  });

  // Connect to isolated test database (trustlens_test)
  const connected = await connectDb();
  assert.ok(connected, 'MongoDB Atlas should connect for integration testing');
  assert.ok(dbReady(), 'Database should be marked ready');
  assertTestDatabase();

  const testSuffix = Date.now();
  const testEmail = `user-${testSuffix}@example.com`;
  const testPassword = 'Password123!Secure';
  let registeredUserId = null;
  let userAuthToken = null;

  const post = async (path, body, headers = {}) => {
    const res = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: JSON.stringify(body),
    });
    const json = await res.json().catch(() => null);
    return [res.status, json];
  };

  try {
    // ── AREA 1: Authentication & User Lifecycle ──────────────────────────────
    await t.test('POST /api/auth/register succeeds with valid payload', async () => {
      const [status, json] = await post('/api/auth/register', {
        name: 'Integration Test User',
        email: testEmail,
        password: testPassword,
      });

      assert.equal(status, 201);
      assert.ok(json && json.ok);
      assert.ok(json.data.token, 'Should return signed JWT token');
      assert.equal(json.data.user.name, 'Integration Test User');
      assert.equal(json.data.user.role, 'user', 'Role must default to user, not admin');

      registeredUserId = json.data.user.id;
      userAuthToken = json.data.token;

      // Verify token is valid and decodable
      const decoded = jwt.verify(userAuthToken, config.jwtSecret);
      assert.equal(decoded.sub, registeredUserId);
      assert.equal(decoded.role, 'user');
    });

    await t.test('POST /api/auth/register rejects duplicate email (409)', async () => {
      const [status, json] = await post('/api/auth/register', {
        name: 'Duplicate Attempt',
        email: testEmail,
        password: testPassword,
      });

      assert.equal(status, 409);
      assert.equal(json.error.code, 'EMAIL_IN_USE');
    });

    await t.test('POST /api/auth/register validates short password and bad email (400)', async () => {
      const [sShort, jShort] = await post('/api/auth/register', {
        name: 'Short Pass',
        email: `short-${testSuffix}@example.com`,
        password: 'short',
      });
      assert.equal(sShort, 400);

      const [sEmail, jEmail] = await post('/api/auth/register', {
        name: 'Bad Email',
        email: 'not-an-email',
        password: testPassword,
      });
      assert.equal(sEmail, 400);
    });

    await t.test('POST /api/auth/login succeeds with correct credentials', async () => {
      const [status, json] = await post('/api/auth/login', {
        email: testEmail,
        password: testPassword,
      });

      assert.equal(status, 200);
      assert.ok(json && json.ok);
      assert.ok(json.data.token);
      assert.equal(json.data.user.id, registeredUserId);
    });

    await t.test('POST /api/auth/login rejects incorrect password (401)', async () => {
      const [status, json] = await post('/api/auth/login', {
        email: testEmail,
        password: 'WrongPassword!',
      });

      assert.equal(status, 401);
      assert.equal(json.error.code, 'BAD_CREDENTIALS');
    });

    await t.test('POST /api/auth/login rejects non-existent email (401)', async () => {
      const [status, json] = await post('/api/auth/login', {
        email: `nonexistent-${testSuffix}@example.com`,
        password: testPassword,
      });

      assert.equal(status, 401);
      assert.equal(json.error.code, 'BAD_CREDENTIALS');
    });

    await t.test('POST /api/auth/guest issues valid anonymous guest token', async () => {
      const [status, json] = await post('/api/auth/guest', {});
      assert.equal(status, 201);
      assert.ok(json && json.ok);
      assert.equal(json.data.role, 'guest');
      const decoded = jwt.verify(json.data.token, config.jwtSecret);
      assert.equal(decoded.role, 'guest');
    });

    // ── AREA 12: MongoDB Indexes & Query Behavior ────────────────────────────
    await t.test('User collection enforces unique email index', async () => {
      assertTestDatabase();
      const indexes = await User.collection.indexes();
      const emailIdx = indexes.find(idx => idx.key && idx.key.email === 1);
      assert.ok(emailIdx, 'Email index must exist');
      assert.equal(emailIdx.unique, true, 'Email index must be unique');
    });

    await t.test('CommunityReport enforces compound unique index { domainName, category, reporter }', async () => {
      assertTestDatabase();
      const indexes = await CommunityReport.collection.indexes();
      const compoundIdx = indexes.find(
        idx => idx.key && idx.key.domainName === 1 && idx.key.category === 1 && idx.key.reporter === 1
      );
      assert.ok(compoundIdx, 'Compound report index must exist');
      assert.equal(compoundIdx.unique, true, 'Compound report index must be unique');

      // Verify Mongoose rejects duplicate insert with E11000
      const repDomain = `idx-test-${testSuffix}.example`;
      const repUser = new mongoose.Types.ObjectId();
      await CommunityReport.create({
        url: `https://${repDomain}/`,
        domainName: repDomain,
        category: 'phishing',
        reporter: repUser,
      });

      await assert.rejects(
        async () => {
          await CommunityReport.create({
            url: `https://${repDomain}/`,
            domainName: repDomain,
            category: 'phishing',
            reporter: repUser,
          });
        },
        (err) => {
          assert.equal(err.code, 11000, 'Must throw duplicate key error code 11000');
          return true;
        }
      );
    });

    await t.test('Scan collection maintains compound query indexes', async () => {
      assertTestDatabase();
      const indexes = await Scan.collection.indexes();
      const domainIdx = indexes.find(idx => idx.key && idx.key.domainName === 1 && idx.key.createdAt === -1);
      const userIdx = indexes.find(idx => idx.key && idx.key.requestedBy === 1 && idx.key.createdAt === -1);
      assert.ok(domainIdx, 'Scan domainName + createdAt index must exist');
      assert.ok(userIdx, 'Scan requestedBy + createdAt index must exist');
    });

  } finally {
    // Teardown: cleanup test-created rows strictly using testSuffix
    await User.deleteMany({ email: new RegExp(String(testSuffix)) }).catch(() => {});
    await CommunityReport.deleteMany({ domainName: new RegExp(String(testSuffix)) }).catch(() => {});

    await new Promise((resolve) => { srv.closeAllConnections?.(); srv.close(resolve); });
    await closeDb();
  }
});
