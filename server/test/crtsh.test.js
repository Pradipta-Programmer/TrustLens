// server/test/crtsh.test.js
// Priority 3.9 — Certificate Transparency Intelligence Client Unit & Integration Tests
// Tests domain validation, response parsing, malformed payloads, timeout, oversized payloads,
// cache hits/expiry, failed refresh preservation, and empty results.
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  queryCT,
  validateDomain,
  analyzeCT,
  isCacheFresh,
  CRTSH_HOST,
  TIMEOUT_MS,
  MAX_BYTES,
  CACHE_TTL_MS,
} = require('../src/services/crtshClient');
const certificateModule = require('../src/modules/certificate');
const threatModule = require('../src/modules/threat');
const { correlate } = require('../src/modules/correlation');
const { assessWebsite } = require('../src/modules');

test('Certificate Transparency (crtshClient) Suite', async (t) => {

  const sampleValidEntry = [
    {
      id: 987654321,
      issuer_ca_id: 16418,
      issuer_name: "C=US, O=Let's Encrypt, CN=R3",
      common_name: "example.com",
      name_value: "example.com\nwww.example.com\nmail.example.com",
      entry_timestamp: "2024-03-01T12:00:00",
      not_before: "2024-03-01T12:00:00",
      not_after: "2024-05-30T12:00:00",
      serial_number: "04a1b2c3d4e5f6",
    },
    {
      id: 987654320,
      issuer_ca_id: 7395,
      issuer_name: "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1",
      common_name: "example.com",
      name_value: "example.com\nwww.example.com",
      entry_timestamp: "2023-01-10T08:00:00",
      not_before: "2023-01-10T08:00:00",
      not_after: "2024-01-10T08:00:00",
      serial_number: "03b2c1d0e9f8a7",
    },
  ];

  // ── 1. Domain Validation ───────────────────────────────────────────────────
  await t.test('Domain validation: accepts valid domains and normalizes format', () => {
    assert.equal(validateDomain('example.com'), 'example.com');
    assert.equal(validateDomain('  EXAMPLE.COM  '), 'example.com');
    assert.equal(validateDomain('https://sub.domain.co.uk/path?arg=1#hash'), 'sub.domain.co.uk');
    assert.equal(validateDomain('http://api.service.net:8080/'), 'api.service.net');
    assert.equal(validateDomain('my-site_123.org'), 'my-site_123.org');
  });

  await t.test('Domain validation: rejects malformed and invalid domain inputs', () => {
    assert.equal(validateDomain(''), null);
    assert.equal(validateDomain(null), null);
    assert.equal(validateDomain(undefined), null);
    assert.equal(validateDomain(123), null);
    assert.equal(validateDomain('invalid domain name with spaces'), null);
    assert.equal(validateDomain('..invalid..'), null);
    assert.equal(validateDomain('http://'), null);
    assert.equal(validateDomain('a'.repeat(254) + '.com'), null);
  });

  await t.test('queryCT: returns structured unavailable on invalid domain input', async () => {
    const res = await queryCT('invalid domain name');
    assert.equal(res.status, 'unavailable');
    assert.ok(res.note.includes('Invalid domain format'));
    assert.deepEqual(res.records, []);
    assert.equal(res.summary, null);
  });

  // ── 2. Successful Response Parsing ─────────────────────────────────────────
  await t.test('Successful response parsing: normalizes crt.sh entries and computes summary', async () => {
    let savedRecords = null;
    let savedFetchedAt = null;

    const res = await queryCT('example.com', {
      mockResponse: JSON.stringify(sampleValidEntry),
      saveFn: async (records, fetchedAt) => {
        savedRecords = records;
        savedFetchedAt = fetchedAt;
      },
    });

    assert.equal(res.status, 'available');
    assert.equal(res.source, 'crt.sh');
    assert.equal(res.note, null);
    assert.equal(res.records.length, 2);

    // Verify normalized record fields
    const r0 = res.records[0];
    assert.equal(r0.id, 987654321);
    assert.equal(r0.commonName, 'example.com');
    assert.equal(r0.issuerName, "C=US, O=Let's Encrypt, CN=R3");
    assert.deepEqual(r0.sans, ['example.com', 'www.example.com', 'mail.example.com']);
    assert.ok(r0.entryTimestamp);
    assert.ok(r0.notBefore);
    assert.ok(r0.notAfter);

    // Verify summary heuristics
    const s = res.summary;
    assert.ok(s);
    assert.equal(s.totalCerts, 2);
    assert.ok(s.uniqueSANs.includes('example.com'));
    assert.ok(s.uniqueSANs.includes('www.example.com'));
    assert.ok(s.uniqueSANs.includes('mail.example.com'));
    assert.ok(s.earliest);
    assert.ok(s.latest);
    assert.equal(typeof s.youngCert, 'boolean');
    assert.equal(typeof s.highVelocity, 'boolean');

    // Verify persistence callback was called
    assert.ok(Array.isArray(savedRecords));
    assert.equal(savedRecords.length, 2);
    assert.ok(savedFetchedAt instanceof Date);
  });

  // ── 3. Malformed Responses ─────────────────────────────────────────────────
  await t.test('Malformed response: handles HTML error pages gracefully without throwing', async () => {
    const res = await queryCT('example.com', {
      mockResponse: '<html><head><title>502 Bad Gateway</title></head><body>502 Bad Gateway</body></html>',
    });

    assert.equal(res.status, 'unavailable');
    assert.ok(res.note.includes('Malformed response from crt.sh'));
    assert.deepEqual(res.records, []);
    assert.equal(res.summary, null);
  });

  await t.test('Malformed response: handles non-array JSON payload gracefully', async () => {
    const res = await queryCT('example.com', {
      mockResponse: JSON.stringify({ error: 'Internal server error', code: 500 }),
    });

    assert.equal(res.status, 'unavailable');
    assert.ok(res.note.includes('Unexpected response format from crt.sh'));
    assert.deepEqual(res.records, []);
    assert.equal(res.summary, null);
  });

  // ── 4. Timeout Handling ────────────────────────────────────────────────────
  await t.test('Timeout handling: enforces 3500ms timeout and returns structured failure', async () => {
    const res = await queryCT('example.com', {
      mockTimeout: true,
    });

    assert.equal(res.status, 'unavailable');
    assert.ok(res.note.includes('timed out'));
    assert.deepEqual(res.records, []);
    assert.equal(res.summary, null);
  });

  // ── 5. Oversized Response Capping ──────────────────────────────────────────
  await t.test('Oversized responses: rejects responses exceeding 1 MB limit', async () => {
    const hugePayload = 'A'.repeat(MAX_BYTES + 2048);
    const res = await queryCT('example.com', {
      mockResponse: hugePayload,
    });

    assert.equal(res.status, 'unavailable');
    assert.ok(res.note.includes('1 MB size limit'));
    assert.deepEqual(res.records, []);
    assert.equal(res.summary, null);
  });

  // ── 6. Cache Hit & Expiry (12h TTL) ────────────────────────────────────────
  await t.test('Cache handling: fresh cache (< 12h) returns cached data without fetching', async () => {
    const cachedObservations = [
      {
        id: 111,
        issuerName: 'Test CA',
        commonName: 'cached.example',
        sans: ['cached.example'],
        entryTimestamp: new Date().toISOString(),
      },
    ];

    const cachedDoc = {
      ctObservations: cachedObservations,
      ctFetchedAt: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago (< 12h)
    };

    assert.equal(isCacheFresh(cachedDoc.ctFetchedAt), true);

    const res = await queryCT('cached.example', {
      cachedDoc,
      mockResponse: 'SHOULD_NOT_BE_READ', // If fetch is called, this would cause parse error
    });

    assert.equal(res.status, 'cached');
    assert.ok(res.note.includes('within 12h TTL'));
    assert.equal(res.records.length, 1);
    assert.equal(res.records[0].id, 111);
    assert.ok(res.cachedAt);
  });

  await t.test('Cache handling: expired cache (> 12h) initiates fresh query', async () => {
    const expiredDoc = {
      ctObservations: [{ id: 100, commonName: 'old.example', sans: ['old.example'] }],
      ctFetchedAt: new Date(Date.now() - 14 * 60 * 60 * 1000), // 14 hours ago (> 12h TTL)
    };

    assert.equal(isCacheFresh(expiredDoc.ctFetchedAt), false);

    const freshEntry = [
      {
        id: 200,
        issuer_name: 'Fresh CA',
        common_name: 'fresh.example',
        name_value: 'fresh.example',
        entry_timestamp: new Date().toISOString(),
      },
    ];

    const res = await queryCT('fresh.example', {
      cachedDoc: expiredDoc,
      mockResponse: JSON.stringify(freshEntry),
    });

    assert.equal(res.status, 'available');
    assert.equal(res.records.length, 1);
    assert.equal(res.records[0].id, 200);
  });

  // ── 7. Failed Refresh Preserving Valid Cached Data ──────────────────────────
  await t.test('Failed refresh: preserves valid cached observations when live query fails', async () => {
    const validCached = [
      {
        id: 300,
        issuerName: 'Preserved CA',
        commonName: 'preserve.example',
        sans: ['preserve.example'],
        entryTimestamp: new Date(Date.now() - 86400000).toISOString(),
      },
    ];

    const expiredDoc = {
      ctObservations: validCached,
      ctFetchedAt: new Date(Date.now() - 15 * 60 * 60 * 1000), // expired
    };

    // Case A: Live query times out
    const timeoutRes = await queryCT('preserve.example', {
      cachedDoc: expiredDoc,
      mockTimeout: true,
    });

    assert.equal(timeoutRes.status, 'cached');
    assert.equal(timeoutRes.preservedCache, true);
    assert.ok(timeoutRes.note.includes('preserved valid cached data'));
    assert.equal(timeoutRes.records.length, 1);
    assert.equal(timeoutRes.records[0].id, 300);

    // Case B: Live query returns malformed response
    const malformedRes = await queryCT('preserve.example', {
      cachedDoc: expiredDoc,
      mockResponse: 'ERROR 500 Server Error',
    });

    assert.equal(malformedRes.status, 'cached');
    assert.equal(malformedRes.preservedCache, true);
    assert.equal(malformedRes.records.length, 1);
    assert.equal(malformedRes.records[0].id, 300);

    // Case C: Live query returns empty array [] when valid cached data exists
    const emptyLiveRes = await queryCT('preserve.example', {
      cachedDoc: expiredDoc,
      mockResponse: '[]',
    });

    assert.equal(emptyLiveRes.status, 'cached');
    assert.equal(emptyLiveRes.preservedCache, true);
    assert.ok(emptyLiveRes.note.includes('preserved existing valid cached observations'));
    assert.equal(emptyLiveRes.records.length, 1);
    assert.equal(emptyLiveRes.records[0].id, 300);
  });

  // ── 8. Empty CT Results ────────────────────────────────────────────────────
  await t.test('Empty CT results: handles domain with no CT logs honestly', async () => {
    let savedRecords = null;
    let savedFetchedAt = null;

    const res = await queryCT('brand-new-domain.example', {
      mockResponse: '[]',
      saveFn: async (records, fetchedAt) => {
        savedRecords = records;
        savedFetchedAt = fetchedAt;
      },
    });

    assert.equal(res.status, 'available');
    assert.deepEqual(res.records, []);
    assert.ok(res.summary);
    assert.equal(res.summary.totalCerts, 0);
    assert.deepEqual(res.summary.uniqueSANs, []);
    assert.equal(res.summary.youngCert, false);
    assert.equal(res.summary.highVelocity, false);

    assert.deepEqual(savedRecords, []);
    assert.ok(savedFetchedAt instanceof Date);
  });

  // ── 9. Heuristic Analysis Signals ──────────────────────────────────────────
  await t.test('Heuristic analysis: detects brand-in-SAN and young certificate age', () => {
    const now = Date.now();
    const records = [
      {
        id: 1,
        sans: ['paypal-security-update.attacker.com', 'login.attacker.com'],
        entryTimestamp: new Date(now - 2 * 86400000).toISOString(), // 2 days ago
      },
    ];

    const analysis = analyzeCT('attacker.com', records);
    assert.equal(analysis.youngCert, true);
    assert.equal(analysis.brandInSAN, 'PayPal');
    assert.equal(analysis.totalCerts, 1);
  });

  await t.test('Heuristic analysis: detects high issuance velocity (> 5 certs in 7 days)', () => {
    const now = Date.now();
    const records = Array.from({ length: 7 }, (_, i) => ({
      id: i + 1,
      sans: [`sub${i}.rapid.example`],
      entryTimestamp: new Date(now - (i + 1) * 3600000).toISOString(), // within last 7 hours
    }));

    const analysis = analyzeCT('rapid.example', records);
    assert.equal(analysis.highVelocity, true);
    assert.equal(analysis.recentCount, 7);
  });

  // ── 10. Phase 2: Certificate Module CT Integration ─────────────────────────
  await t.test('certificate.analyze combines TLS peer certificate with historical CT observations', async () => {
    const mockFetch = {
      tls: {
        authorized: true,
        authorizationError: null,
        peerCertificate: {
          subject: { CN: 'app.example.com' },
          issuer: { O: 'GlobalSign Root CA', CN: 'GlobalSign' },
          validFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
          validTo: new Date(Date.now() + 150 * 86400000).toISOString(),
          subjectaltname: 'DNS:app.example.com, DNS:www.app.example.com',
          fingerprint: 'AA:BB:CC:DD:EE',
        },
      },
    };

    const ctData = {
      status: 'available',
      source: 'crt.sh',
      records: [
        {
          id: 501,
          commonName: 'app.example.com',
          sans: ['app.example.com', 'api.app.example.com'],
          entryTimestamp: '2023-01-01T00:00:00Z',
          notBefore: '2023-01-01T00:00:00Z',
          notAfter: '2024-01-01T00:00:00Z',
        },
        {
          id: 502,
          commonName: 'app.example.com',
          sans: ['app.example.com', 'admin.app.example.com'],
          entryTimestamp: '2024-01-01T00:00:00Z',
          notBefore: '2024-01-01T00:00:00Z',
          notAfter: '2025-01-01T00:00:00Z',
        },
      ],
      summary: {
        totalCerts: 2,
        earliest: '2023-01-01T00:00:00.000Z',
        latest: '2024-01-01T00:00:00.000Z',
        uniqueSANs: ['app.example.com', 'api.app.example.com', 'admin.app.example.com'],
        youngCert: false,
        highVelocity: false,
      },
    };

    const res = await certificateModule.analyze({
      url: 'https://app.example.com/',
      fetchResult: mockFetch,
      ct: ctData,
    });

    assert.equal(res.status, 'live');
    // Valid TLS + benign CT does not add risk points (score must remain 0)
    assert.equal(res.score, 0);

    // Current direct peer certificate is preserved
    assert.equal(res.cert.issuer, 'GlobalSign Root CA');
    assert.equal(res.cert.subject, 'app.example.com');
    assert.equal(res.cert.match, true);
    assert.equal(res.cert.chain, true);

    // CT historical data is populated and clearly distinguished
    assert.equal(res.cert.ct.status, 'available');
    assert.equal(res.cert.ct.totalLogged, 2);
    assert.equal(res.cert.ct.earliest, '2023-01-01T00:00:00.000Z');
    assert.equal(res.cert.ct.latest, '2024-01-01T00:00:00.000Z');
    assert.ok(res.cert.ct.discoveredSANs.includes('api.app.example.com'));

    assert.ok(res.cert.history);
    assert.equal(res.cert.history.totalLogged, 2);
    assert.equal(res.cert.history.youngCert, false);

    // Evidence & positive findings
    assert.ok(res.positiveFindings.some(f => f.includes('Certificate Transparency log history observed')));
    assert.ok(res.evidence.some(e => e.includes('CT log history: 2 cert(s) recorded')));
  });

  await t.test('certificate.analyze handles missing or unavailable CT data honestly', async () => {
    const mockFetch = {
      tls: {
        authorized: true,
        authorizationError: null,
        peerCertificate: {
          subject: { CN: 'no-ct.example.com' },
          issuer: { O: 'Demo CA' },
          validFrom: new Date(Date.now() - 10 * 86400000).toISOString(),
          validTo: new Date(Date.now() + 100 * 86400000).toISOString(),
          subjectaltname: 'DNS:no-ct.example.com',
        },
      },
    };

    // Case A: Missing CT data (not assessed)
    const resA = await certificateModule.analyze({
      url: 'https://no-ct.example.com/',
      fetchResult: mockFetch,
    });
    assert.equal(resA.status, 'live');
    assert.equal(resA.score, 0);
    assert.equal(resA.cert.ct.status, 'not_assessed');

    // Case B: Explicitly unavailable CT
    const resB = await certificateModule.analyze({
      url: 'https://no-ct.example.com/',
      fetchResult: mockFetch,
      ct: { status: 'unavailable', note: 'crt.sh timed out' },
    });
    assert.equal(resB.status, 'live');
    assert.equal(resB.score, 0);
    assert.equal(resB.cert.ct.status, 'unavailable');
    assert.equal(resB.cert.ct.note, 'crt.sh timed out');
  });

  await t.test('certificate.analyze does not classify certificates as malicious based on age or velocity alone', async () => {
    const mockFetch = {
      tls: {
        authorized: true,
        authorizationError: null,
        peerCertificate: {
          subject: { CN: 'young-site.example.com' },
          issuer: { O: 'ZeroSSL' },
          validFrom: new Date(Date.now() - 2 * 86400000).toISOString(),
          validTo: new Date(Date.now() + 88 * 86400000).toISOString(),
          subjectaltname: 'DNS:young-site.example.com',
        },
      },
    };

    const ctData = {
      status: 'available',
      summary: {
        totalCerts: 8,
        earliest: new Date(Date.now() - 5 * 86400000).toISOString(), // 5 days ago (young)
        latest: new Date().toISOString(),
        uniqueSANs: ['young-site.example.com'],
        youngCert: true,
        highVelocity: true,
        recentCount: 8,
      },
    };

    const res = await certificateModule.analyze({
      url: 'https://young-site.example.com/',
      fetchResult: mockFetch,
      ct: ctData,
    });

    // Score must NEVER be elevated from CT signals alone
    assert.equal(res.score, 0, 'Risk score must remain 0 for valid certificate despite young cert and high velocity');
    assert.ok(res.findings.some(f => f.name === 'Recently Logged Certificate History' && f.severity === 'Info'));
    assert.ok(res.findings.some(f => f.name === 'Elevated Issuance Velocity' && f.severity === 'Info'));
  });

  // ── 11. Phase 3: Threat Intelligence CT Correlation ────────────────────────
  await t.test('threat.analyze true positive: CT SAN brand target with suspicious keywords adds supporting points', async () => {
    // Domain with sensitive keywords + CT SAN brand reference
    const ctData = {
      status: 'available',
      summary: {
        totalCerts: 3,
        brandInSAN: 'PayPal',
        youngCert: true,
      },
    };

    const res = await threatModule.analyze({
      url: 'https://security-verify-portal.attacker.com/login',
      ct: ctData,
    });

    assert.equal(res.status, 'live');
    // Finds keyword finding + CT brand finding
    assert.ok(res.findings.some(f => f.name === 'Sensitive Keywords'));
    assert.ok(res.findings.some(f => f.name === 'Brand Target in Certificate SANs (PayPal)' && f.severity === 'Medium'));
    assert.ok(res.impersonation);
    assert.equal(res.impersonation.brand, 'PayPal');
    assert.ok(res.evidence.some(e => e.includes('CT SAN references PayPal')));
    assert.ok(res.evidence.some(e => e.includes('CT context: Domain certificates first recorded within the last 30 days')));
  });

  await t.test('threat.analyze benign case: legitimate brand domain never triggers brand-in-SAN alert', async () => {
    // google.com is the registered brand domain itself
    const ctData = {
      status: 'available',
      summary: {
        totalCerts: 50,
        brandInSAN: 'Google',
        youngCert: false,
      },
    };

    const res = await threatModule.analyze({
      url: 'https://mail.google.com/',
      ct: ctData,
    });

    assert.equal(res.status, 'live');
    assert.equal(res.score, 0);
    assert.equal(res.impersonation, null);
    assert.ok(!res.findings.some(f => f.name.includes('Brand Target in Certificate SANs')));
  });

  await t.test('threat.analyze false-positive prevention: isolated CT brand mention without corroborating threat indicators does not escalate score', async () => {
    // Plain, short URL on a standard domain with 0 heuristic flags
    const ctData = {
      status: 'available',
      summary: {
        totalCerts: 2,
        brandInSAN: 'Amazon',
        youngCert: false,
      },
    };

    const res = await threatModule.analyze({
      url: 'https://service-relay.org/',
      ct: ctData,
    });

    assert.equal(res.status, 'live');
    // Without any other threat indicators, points must be 0 (Info severity)
    assert.equal(res.score, 0, 'Isolated CT brand mention must not add risk points (CT alone never establishes malicious verdict)');
    const ctFinding = res.findings.find(f => f.name.includes('Brand Target in Certificate SANs'));
    assert.ok(ctFinding);
    assert.equal(ctFinding.severity, 'Info');
    assert.equal(ctFinding.points, 0);
  });

  await t.test('threat.analyze deduplication: corroborates existing impersonation without double-counting points', async () => {
    // Domain already resembles PayPal in hostname (triggers 35-point impersonation)
    const ctData = {
      status: 'available',
      summary: {
        totalCerts: 4,
        brandInSAN: 'PayPal',
        youngCert: true,
      },
    };

    const res = await threatModule.analyze({
      url: 'https://paypal-portal.security.example.com/',
      ct: ctData,
    });

    // Impersonation was already flagged by hostname; CT corroborates evidence
    assert.ok(res.impersonation);
    assert.equal(res.impersonation.brand, 'PayPal');
    assert.ok(res.impersonation.evidence.some(e => e.includes('Certificate Transparency logs corroborate')));
    assert.ok(res.evidence.some(e => e.includes('corroborate PayPal impersonation')));

    // Should NOT have an extra "Brand Target in Certificate SANs" finding (prevents double-counting)
    assert.equal(res.findings.filter(f => f.name.includes('PayPal')).length, 1);
  });

  // ── 12. Phase 4: Correlation Engine Integration ────────────────────────────
  await t.test('correlate: preserves separate risk and confidence when CT data is present', () => {
    const moduleResults = {
      threat: { status: 'live', score: 0, findings: [], positiveFindings: [] },
      security: { status: 'live', score: 10, findings: [], positiveFindings: [], checks: [] },
      certificate: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: ['Certificate Transparency log history observed: 15 certs recorded.'],
        cert: {
          chain: true,
          ct: { status: 'available', totalLogged: 15 },
        },
      },
      community: { status: 'live', score: 0, findings: [], positiveFindings: [], rep: { n: 0, uniq: 0, ver: 0 } },
    };

    const report = correlate(moduleResults, { hostname: 'ct-verified.example' });

    // Risk score should reflect weighted sum (0*0.4 + 10*0.15 + 0*0.2 + 0*0.25) / 1.0 = 2 => Low Risk
    assert.equal(report.score, 2);
    assert.equal(report.riskLevel, 'low');
    assert.equal(report.coverage, 100);

    // Verified CT data (+5) and verified chain (+10) boost confidence
    // base (25) + 4*12 (48) + chain (10) + CT (5) = 88
    assert.equal(report.confidence, 88);
    assert.equal(report.confidenceLevel, 'High');

    // Positive CT finding should be deduplicated and synthesized in positiveFindings
    assert.ok(report.positiveFindings.some(f => f.includes('Certificate Transparency log history observed')));
  });

  await t.test('correlate: unavailable CT data is kept separate from negative evidence and does not penalize score', () => {
    const moduleResults = {
      threat: { status: 'live', score: 0, findings: [], positiveFindings: [] },
      security: { status: 'live', score: 0, findings: [], positiveFindings: [], checks: [] },
      certificate: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: [],
        evidence: ['Certificate Transparency logs unavailable'],
        cert: {
          chain: true,
          ct: { status: 'unavailable', note: 'crt.sh timed out' },
        },
      },
      community: { status: 'live', score: 0, findings: [], positiveFindings: [], rep: { n: 0, uniq: 0, ver: 0 } },
    };

    const report = correlate(moduleResults, { hostname: 'ct-unavail.example' });

    // Risk score remains 0 - unavailable CT is not penalizing
    assert.equal(report.score, 0);
    assert.equal(report.riskLevel, 'low');
    // Negative findings must not treat unavailable CT as a vulnerability/risk
    assert.equal(report.negativeFindings.length, 0);
  });

  await t.test('correlate: generates actionable recommendations when CT corroborates impersonation', () => {
    const moduleResults = {
      threat: {
        status: 'live',
        score: 45,
        impersonation: { brand: 'PayPal' },
        findings: [{ name: 'Brand Target in Certificate SANs (PayPal)', severity: 'Medium', explanation: 'CT SAN references PayPal' }],
        positiveFindings: [],
        evidence: ['CT SAN references PayPal'],
      },
      security: { status: 'live', score: 0, findings: [], positiveFindings: [], checks: [] },
      certificate: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: [],
        cert: { chain: true, ct: { status: 'available' } },
      },
      community: { status: 'live', score: 0, findings: [], positiveFindings: [], rep: { n: 0, uniq: 0, ver: 0 } },
    };

    const report = correlate(moduleResults, { hostname: 'paypal-login.phish.example' });

    assert.ok(report.recommendations.some(r => r.includes('Certificate Transparency logs corroborate brand resemblance (PayPal)')));
  });

  // ── 13. Phase 5: Scan Pipeline & Persistence Integration ───────────────────
  await t.test('assessWebsite end-to-end pipeline incorporates CT observations into report', async () => {
    const mockTls = {
      authorized: true,
      authorizationError: null,
      peerCertificate: {
        subject: { CN: 'pipeline-ct.example.com' },
        issuer: { O: 'Verified Trust CA' },
        validFrom: new Date(Date.now() - 60 * 86400000).toISOString(),
        validTo: new Date(Date.now() + 120 * 86400000).toISOString(),
        subjectaltname: 'DNS:pipeline-ct.example.com',
      },
    };

    const ctData = {
      status: 'available',
      records: [
        {
          id: 701,
          commonName: 'pipeline-ct.example.com',
          sans: ['pipeline-ct.example.com'],
          entryTimestamp: '2023-06-01T00:00:00Z',
        },
      ],
      summary: {
        totalCerts: 1,
        earliest: '2023-06-01T00:00:00Z',
        latest: '2023-06-01T00:00:00Z',
        uniqueSANs: ['pipeline-ct.example.com'],
        youngCert: false,
        highVelocity: false,
      },
    };

    const report = await assessWebsite('https://pipeline-ct.example.com/', {
      skipFetch: true,
      fetchResult: {
        url: 'https://pipeline-ct.example.com/',
        status: 200,
        headers: {
          'strict-transport-security': 'max-age=31536000; includeSubDomains',
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
        },
        body: '',
        tls: mockTls,
      },
      ct: ctData,
    });

    assert.equal(report.score, 0);
    assert.ok(report.modules.certificate);
    assert.equal(report.modules.certificate.cert.ct.status, 'available');
    assert.equal(report.modules.certificate.cert.ct.totalLogged, 1);
    assert.ok(report.positiveFindings.some(f => f.includes('Certificate Transparency log history observed')));
  });

  await t.test('assessWebsite pipeline completes successfully when CT is unavailable', async () => {
    const report = await assessWebsite('https://fallback-ct.example.com/', {
      skipFetch: true,
      fetchResult: {
        url: 'https://fallback-ct.example.com/',
        status: 200,
        headers: {
          'strict-transport-security': 'max-age=31536000; includeSubDomains',
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
          'x-frame-options': 'DENY',
          'referrer-policy': 'strict-origin-when-cross-origin',
        },
        body: '',
        tls: {
          authorized: true,
          peerCertificate: {
            subject: { CN: 'fallback-ct.example.com' },
            issuer: { O: 'CA' },
            validTo: new Date(Date.now() + 50 * 86400000).toISOString(),
            subjectaltname: 'DNS:fallback-ct.example.com',
          },
        },
      },
      ct: { status: 'unavailable', note: 'Service down' },
    });

    // Assessment completes normally despite unavailable CT
    assert.equal(report.score, 0);
    assert.ok(report.modules.certificate);
    assert.equal(report.modules.certificate.cert.ct.status, 'unavailable');
  });

  await t.test('in-flight deduplication: concurrent requests for same domain share promise', async () => {
    const inFlightMap = new Map();
    let queryCount = 0;

    const mockQuery = (domain) => {
      let p = inFlightMap.get(domain);
      if (!p) {
        queryCount++;
        p = queryCT(domain, { mockResponse: '[]' }).finally(() => inFlightMap.delete(domain));
        inFlightMap.set(domain, p);
      }
      return p;
    };

    // 5 simultaneous requests for the exact same domain
    const results = await Promise.all([
      mockQuery('dedup.example.com'),
      mockQuery('dedup.example.com'),
      mockQuery('dedup.example.com'),
      mockQuery('dedup.example.com'),
      mockQuery('dedup.example.com'),
    ]);

    // All 5 calls receive the same result, and only 1 outbound query was launched
    assert.equal(queryCount, 1);
    assert.equal(results.length, 5);
    for (const r of results) {
      assert.equal(r.status, 'available');
    }
    assert.equal(inFlightMap.size, 0);
  });

  // ── Regression Tests: CT SAN False-Positive Impersonation Prevention ───────
  await t.test('Regression: example.com with unrelated Example Bank SAN must not become Example Bank impersonation', async () => {
    // Multi-tenant certificate bundles example.com with an unrelated domain containing "Example Bank"
    const records = [
      {
        id: 101,
        sans: ['example.com', 'example-bank-login.othertenant.org'],
        entryTimestamp: new Date().toISOString(),
      },
    ];

    const analysis = analyzeCT('example.com', records);
    // Unrelated SAN on shared certificate must not trigger brandInSAN for target domain
    assert.equal(analysis.brandInSAN, null);

    const res = await threatModule.analyze({
      url: 'https://example.com/',
      ct: { status: 'available', summary: analysis },
    });

    assert.equal(res.status, 'live');
    assert.equal(res.score, 0);
    assert.equal(res.impersonation, null, 'Unrelated Example Bank SAN must not create an impersonation finding');
    assert.ok(!res.findings.some(f => f.name.includes('Example Bank')));
  });

  await t.test('Regression: Unrelated PayPal SAN on a shared certificate must not trigger PayPal impersonation', async () => {
    // CDN certificate bundles clean domain my-site.com with an unrelated third-party PayPal checkout SAN
    const records = [
      {
        id: 102,
        sans: ['my-site.com', 'cdn.my-site.com', 'paypal-checkout.thirdparty-merchant.net'],
        entryTimestamp: new Date().toISOString(),
      },
    ];

    const analysis = analyzeCT('my-site.com', records);
    assert.equal(analysis.brandInSAN, null);

    const res = await threatModule.analyze({
      url: 'https://my-site.com/',
      ct: { status: 'available', summary: analysis },
    });

    assert.equal(res.status, 'live');
    assert.equal(res.score, 0);
    assert.equal(res.impersonation, null, 'Unrelated PayPal SAN on shared cert must not trigger PayPal impersonation');
    assert.ok(!res.findings.some(f => f.name.includes('PayPal')));
  });

  await t.test('Regression: A genuinely suspicious lookalike domain with independent evidence retains detection', async () => {
    // Lookalike domain that directly contains PayPal and sensitive keywords in URL structure
    const records = [
      {
        id: 103,
        sans: ['paypal-portal.security-update.attacker.com'],
        entryTimestamp: new Date().toISOString(),
      },
    ];

    const analysis = analyzeCT('paypal-portal.security-update.attacker.com', records);
    assert.equal(analysis.brandInSAN, 'PayPal');

    const res = await threatModule.analyze({
      url: 'https://paypal-portal.security-update.attacker.com/login',
      ct: { status: 'available', summary: analysis },
    });

    assert.equal(res.status, 'live');
    assert.ok(res.score >= 35, 'Genuinely suspicious lookalike domain must retain high score');
    assert.ok(res.impersonation, 'Genuinely suspicious lookalike must retain impersonation finding');
    assert.equal(res.impersonation.brand, 'PayPal');
  });
});
