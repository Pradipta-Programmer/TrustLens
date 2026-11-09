// server/test/admin.test.js
// Priority 3.8 — Admin Authentication, Moderation, Audit Logging & External Threat Intelligence Tests
'use strict';
require('dotenv').config();
const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const app = require('../src/app');
const config = require('../src/config');
const User = require('../src/models/User');
const CommunityReport = require('../src/models/CommunityReport');
const AuditLog = require('../src/models/AuditLog');
const VerifiedThreat = require('../src/models/VerifiedThreat');
const ThreatIntel = require('../src/models/ThreatIntel');
const threatModule = require('../src/modules/threat');
const threatFeedService = require('../src/services/threatFeedService');
const { connectDb, dbReady, closeDb, assertTestDatabase } = require('../src/config/db');

test('Admin & Threat Intelligence Integration Suite', async (t) => {
  let srv;
  let baseUrl;

  // Setup Express server on random port
  await new Promise((resolve) => {
    srv = app.listen(0, () => {
      baseUrl = `http://127.0.0.1:${srv.address().port}`;
      resolve();
    });
  });

  // Connect to MongoDB Atlas (must target trustlens_test)
  const connected = await connectDb();
  assert.ok(connected, 'MongoDB Atlas should connect');
  assert.ok(dbReady(), 'Database should be marked ready');
  assertTestDatabase();

  // Request helpers
  const request = async (path, method = 'GET', body = null, headers = {}) => {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json', ...headers },
    };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`${baseUrl}${path}`, opts);
    const json = await res.json().catch(() => null);
    return [res.status, json];
  };

  const makeToken = (role = 'admin', id = new mongoose.Types.ObjectId().toString()) =>
    jwt.sign({ role }, config.jwtSecret, { subject: id, expiresIn: '1h' });

  const adminId = new mongoose.Types.ObjectId().toString();
  const userId = new mongoose.Types.ObjectId().toString();
  const adminToken = makeToken('admin', adminId);
  const userToken = makeToken('user', userId);

  const testSuffix = Date.now();
  const testDomain = `admin-test-${testSuffix}.example`;
  let testReportId = null;

  // Seed admin user for populate tests
  await User.findOneAndUpdate(
    { email: `admin-${testSuffix}@trustlens.internal` },
    {
      $set: {
        name: 'SecOps Analyst',
        email: `admin-${testSuffix}@trustlens.internal`,
        passwordHash: '$2a$12$dummyhashfordeterministicintegrationtests000000000',
        role: 'admin',
      },
    },
    { upsert: true, new: true }
  );

  // Seed sample report for moderation tests
  const reportDoc = await CommunityReport.create({
    url: `https://${testDomain}/login`,
    domainName: testDomain,
    category: 'phishing',
    description: 'Suspicious credential harvesting page',
    reporter: new mongoose.Types.ObjectId(),
    status: 'pending_review',
  });
  testReportId = String(reportDoc._id);

  try {
    // ── 1. Admin RBAC & Route Access Control ──────────────────────────────────
    await t.test('GET /api/admin/reports rejects unauthenticated callers (401)', async () => {
      const [s, j] = await request('/api/admin/reports');
      assert.equal(s, 401);
      assert.equal(j.error.code, 'UNAUTHENTICATED');
    });

    await t.test('GET /api/admin/reports rejects non-admin users (403 FORBIDDEN)', async () => {
      const [s, j] = await request('/api/admin/reports', 'GET', null, { Authorization: `Bearer ${userToken}` });
      assert.equal(s, 403);
      assert.equal(j.error.code, 'FORBIDDEN');
    });

    await t.test('GET /api/admin/reports succeeds for admin role (200)', async () => {
      const [s, j] = await request('/api/admin/reports', 'GET', null, { Authorization: `Bearer ${adminToken}` });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data));
      assert.ok(j.meta?.pagination || j.data);
    });

    // ── 2. Report Moderation & Status Transitions ─────────────────────────────
    await t.test('PATCH /api/admin/reports/:id moves status to under_verification', async () => {
      const [s, j] = await request(`/api/admin/reports/${testReportId}`, 'PATCH', {
        status: 'under_verification',
        notes: 'Investigating WHOIS and server headers',
      }, { Authorization: `Bearer ${adminToken}` });

      assert.equal(s, 200);
      assert.equal(j.data.status, 'under_verification');

      const updated = await CommunityReport.findById(testReportId).select('+reviewedBy');
      assert.equal(updated.status, 'under_verification');
      assert.equal(String(updated.reviewedBy), adminId);
    });

    await t.test('PATCH /api/admin/reports/:id rejects invalid status enum (400)', async () => {
      const [s, j] = await request(`/api/admin/reports/${testReportId}`, 'PATCH', {
        status: 'bogus_status',
      }, { Authorization: `Bearer ${adminToken}` });

      assert.equal(s, 400);
      assert.equal(j.error.code, 'VALIDATION_ERROR');
    });

    // ── 3. VerifiedThreat Lifecycle Synchronization ───────────────────────────
    await t.test('Verifying report synchronizes and creates VerifiedThreat record', async () => {
      const [s, j] = await request(`/api/admin/reports/${testReportId}`, 'PATCH', {
        status: 'verified',
        notes: 'Confirmed phishing form mimicking bank login',
      }, { Authorization: `Bearer ${adminToken}` });

      assert.equal(s, 200);
      assert.equal(j.data.status, 'verified');

      const vt = await VerifiedThreat.findOne({ domainName: testDomain });
      assert.ok(vt, 'VerifiedThreat record should be created');
      assert.equal(vt.domainName, testDomain);
      assert.equal(vt.category, 'phishing');
      assert.ok(vt.sourceReports.some(id => id.toString() === testReportId));
    });

    await t.test('Rejecting previously verified report revokes VerifiedThreat record', async () => {
      const [s, j] = await request(`/api/admin/reports/${testReportId}`, 'PATCH', {
        status: 'rejected',
        notes: 'False positive confirmed on second review',
      }, { Authorization: `Bearer ${adminToken}` });

      assert.equal(s, 200);
      assert.equal(j.data.status, 'rejected');

      const vt = await VerifiedThreat.findOne({ domainName: testDomain });
      assert.equal(vt, null, 'VerifiedThreat record should be removed when no verified reports remain');
    });

    // ── 4. AuditLog Recording & Query API ─────────────────────────────────────
    await t.test('GET /api/admin/audit retrieves paginated moderation audit entries', async () => {
      const [s, j] = await request('/api/admin/audit?limit=10', 'GET', null, { Authorization: `Bearer ${adminToken}` });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(Array.isArray(j.data.auditLogs));
      assert.ok(j.data.pagination);

      const matchingAudit = j.data.auditLogs.find(a => a.targetId === testReportId);
      assert.ok(matchingAudit, 'AuditLog should contain entry for modified report');
      assert.equal(matchingAudit.action, 'report.status_changed');
      assert.equal(matchingAudit.detail.newStatus, 'rejected');
    });

    await t.test('GET /api/admin/audit rejects non-admin callers (403)', async () => {
      const [s, j] = await request('/api/admin/audit', 'GET', null, { Authorization: `Bearer ${userToken}` });
      assert.equal(s, 403);
    });

    // ── 5. Admin Platform Stats ───────────────────────────────────────────────
    await t.test('GET /api/admin/stats returns platform moderation totals and threat metrics', async () => {
      const [s, j] = await request('/api/admin/stats', 'GET', null, { Authorization: `Bearer ${adminToken}` });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      const d = j.data;
      assert.equal(typeof d.reports.pending, 'number');
      assert.equal(typeof d.reports.verified, 'number');
      assert.equal(typeof d.threats.verifiedThreats, 'number');
      assert.equal(typeof d.threats.externalThreatIntel, 'number');
      assert.ok(Array.isArray(d.recentAudits));
    });

    // ── 6. Threat Feed Ingestion Service Unit Tests ───────────────────────────
    await t.test('threatFeedService allowlist rejects unapproved feed URLs', () => {
      assert.equal(threatFeedService.isApprovedFeedUrl('https://urlhaus-api.abuse.ch/v1/urls/recent/'), true);
      assert.equal(threatFeedService.isApprovedFeedUrl('https://openphish.com/feed.txt'), true);
      assert.equal(threatFeedService.isApprovedFeedUrl('http://urlhaus-api.abuse.ch/'), false, 'Must reject HTTP');
      assert.equal(threatFeedService.isApprovedFeedUrl('https://evil.example.com/feed'), false);
    });

    await t.test('threatFeedService sanitizes URLs and rejects private/loopback IPs', () => {
      const validItem = threatFeedService.sanitizeThreatItem('https://malware-drop.example/payload.exe', 'urlhaus', 'malware');
      assert.ok(validItem);
      assert.equal(validItem.domainName, 'malware-drop.example');

      const loopbackItem = threatFeedService.sanitizeThreatItem('http://127.0.0.1/malware.exe', 'urlhaus', 'malware');
      assert.equal(loopbackItem, null, 'Must reject loopback IP');

      const privateItem = threatFeedService.sanitizeThreatItem('http://10.0.0.5/phish', 'openphish', 'phishing');
      assert.equal(privateItem, null, 'Must reject RFC 1918 private IP');
    });

    await t.test('threatFeedService.syncFeeds with mock feed ingests and deduplicates ThreatIntel', async () => {
      const mockDomain = `feed-malware-${testSuffix}.example`;
      const mockUrl = `https://${mockDomain}/trojan.bin`;
      const mockFeeds = {
        urlhaus: {
          query_status: 'ok',
          urls: [
            { id: '101', url: mockUrl, threat: 'malware_download', date_added: new Date().toISOString() },
            { id: '101', url: mockUrl, threat: 'malware_download', date_added: new Date().toISOString() }, // duplicate
          ],
        },
      };

      const syncResult = await threatFeedService.syncFeeds({
        source: 'urlhaus',
        mockFeeds,
      });

      assert.equal(syncResult.totalIngested >= 1, true);

      const records = await ThreatIntel.find({ domainName: mockDomain });
      assert.equal(records.length, 1, 'Duplicate feed entries must be deduplicated into a single document');
      assert.equal(records[0].source, 'urlhaus');
    });

    // ── 7. Admin Threat Intel Sync Endpoints ──────────────────────────────────
    await t.test('POST /api/admin/threat-intel/sync ingests mock feed and records audit log', async () => {
      const mockDomain = `phish-feed-${testSuffix}.example`;
      const mockFeeds = {
        openphish: `https://${mockDomain}/login.php\n`,
      };

      const [s, j] = await request('/api/admin/threat-intel/sync', 'POST', {
        source: 'openphish',
        mockFeeds,
      }, { Authorization: `Bearer ${adminToken}` });

      assert.equal(s, 200);
      assert.ok(j.data.totalIngested >= 1);

      // Verify audit log entry was created
      const auditEntry = await AuditLog.findOne({ action: 'threat_intel.feed_sync' }).sort('-createdAt');
      assert.ok(auditEntry);
      assert.equal(String(auditEntry.actor), adminId);
    });

    await t.test('GET /api/admin/threat-intel/status returns feed configuration and counts', async () => {
      const [s, j] = await request('/api/admin/threat-intel/status', 'GET', null, { Authorization: `Bearer ${adminToken}` });
      assert.equal(s, 200);
      assert.ok(j && j.ok);
      assert.ok(j.data.sourcesConfig.length >= 2);
      assert.ok(typeof j.data.databaseTotal === 'number');
    });

    // ── 8. Threat Assessment Module Correlation ───────────────────────────────
    await t.test('threat.js detects ThreatIntel feed match and escalates risk score', async () => {
      const feedTarget = `feed-target-${testSuffix}.example`;
      await ThreatIntel.create({
        domainName: feedTarget,
        url: `https://${feedTarget}/bank-login`,
        source: 'urlhaus',
        category: 'malware',
        observedAt: new Date(),
      });

      const res = await threatModule.analyze({ url: `https://${feedTarget}/` });
      assert.ok(res.score >= 50, `Expected elevated score >= 50, got ${res.score}`);
      assert.ok(res.findings.some(f => f.name.includes('Known Malicious Feed Match')));
      assert.ok(res.evidence.some(e => e.includes('URLhaus')));
    });

    await t.test('threat.js detects VerifiedThreat and escalates to critical score', async () => {
      const verifiedTarget = `verified-target-${testSuffix}.example`;
      await VerifiedThreat.create({
        domainName: verifiedTarget,
        category: 'phishing',
        verifiedAt: new Date(),
      });

      const res = await threatModule.analyze({ url: `https://${verifiedTarget}/` });
      assert.ok(res.score >= 60, `Expected critical score >= 60, got ${res.score}`);
      assert.ok(res.findings.some(f => f.name === 'Verified Malicious Domain'));
      assert.ok(res.evidence.some(e => e.includes('Confirmed malicious')));
    });

  } finally {
    // Cleanup seeded test records
    await CommunityReport.deleteMany({ domainName: new RegExp(String(testSuffix)) }).catch(() => {});
    await VerifiedThreat.deleteMany({ domainName: new RegExp(String(testSuffix)) }).catch(() => {});
    await ThreatIntel.deleteMany({ domainName: new RegExp(String(testSuffix)) }).catch(() => {});
    await AuditLog.deleteMany({ 'detail.domainName': new RegExp(String(testSuffix)) }).catch(() => {});
    await User.deleteMany({ email: new RegExp(String(testSuffix)) }).catch(() => {});

    // Teardown server and DB connection cleanly
    await new Promise((resolve) => { srv.closeAllConnections?.(); srv.close(resolve); });
    await closeDb();
  }
});
