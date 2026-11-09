const test = require('node:test');
const assert = require('node:assert');
const threatModule = require('../src/modules/threat');
const securityModule = require('../src/modules/security');
const certificateModule = require('../src/modules/certificate');
const communityModule = require('../src/modules/community');
const { correlate, classifyRisk, WEIGHTS, THRESHOLDS } = require('../src/modules/correlation');
const { assessWebsite, registry } = require('../src/modules/index');

test('Core Assessment Engine test suite', async (t) => {

  // Test 1: Threat heuristics findings
  await t.test('detects suspicious URL heuristics and returns structured findings', async () => {
    // URL with multiple red flags: raw IP, keywords, length, hyphens, and @
    const suspiciousUrl = 'http://198.51.100.1/login-verify-account-security-update-billing-confirm-wallet-credentials-user?ref=@portal';
    const res = await threatModule.analyze({ url: suspiciousUrl });

    assert.equal(res.status, 'live');
    assert.ok(res.score > 50, `Expected high threat score, got ${res.score}`);
    assert.ok(res.findings.length >= 4, `Expected at least 4 findings, got ${res.findings.length}`);

    const findingNames = res.findings.map(f => f.name);
    assert.ok(findingNames.includes('Raw IP Address'));
    assert.ok(findingNames.includes('Excessive URL Length'));
    assert.ok(findingNames.includes('Insecure Protocol (HTTP)'));
    assert.ok(findingNames.includes('Sensitive Keywords'));
    assert.ok(findingNames.includes('Embedded Credential Symbol (@)'));

    // Check structure of each finding
    for (const f of res.findings) {
      assert.ok(f.name, 'Finding must have a name');
      assert.ok(['Low', 'Medium', 'High', 'Critical'].includes(f.severity), 'Finding must have valid severity');
      assert.ok(f.explanation, 'Finding must have an explanation');
      assert.ok(f.evidence !== undefined, 'Finding must have evidence');
    }
  });

  // Test 1b: Punycode and brand similarity
  await t.test('detects punycode domains and brand similarity patterns', async () => {
    const punycodeRes = await threatModule.analyze({ url: 'https://xn--pple-43d.com' });
    assert.ok(punycodeRes.findings.some(f => f.name === 'Punycode Domain'));

    const brandRes = await threatModule.analyze({ url: 'https://paypal-security-check.example.com/login' });
    assert.ok(brandRes.impersonation, 'Expected impersonation alert for paypal');
    assert.equal(brandRes.impersonation.brand, 'PayPal');
  });

  // Test 2: Benign URL handling
  await t.test('handles benign URLs without false-positive inflation', async () => {
    const benignUrls = [
      'https://example.com',
      'https://google.com',
      'https://stateuniversity.edu/admissions',
    ];

    for (const u of benignUrls) {
      const res = await threatModule.analyze({ url: u });
      assert.equal(res.status, 'live');
      assert.equal(res.score, 0, `Expected score 0 for benign URL ${u}, got ${res.score}`);
      assert.equal(res.findings.length, 0);
      assert.ok(res.positiveFindings.length > 0);
    }
  });

  // Test 3: Security header detection
  await t.test('evaluates present security headers accurately as passed', async () => {
    const mockFetchResult = {
      url: 'https://secure.example.com/',
      status: 200,
      headers: {
        'strict-transport-security': 'max-age=31536000; includeSubDomains',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'x-frame-options': 'SAMEORIGIN',
      },
      redirects: [],
    };

    const res = await securityModule.analyze({
      url: 'https://secure.example.com/',
      fetchResult: mockFetchResult,
    });

    assert.equal(res.status, 'live');
    assert.equal(res.score, 0, `Expected security deficiency score 0, got ${res.score}`);
    assert.equal(res.findings.length, 7);

    // All 7 checks should pass
    const passedCount = res.checks.filter(c => c[1] === 'Passed').length;
    assert.equal(passedCount, 7);
  });

  // Test 4: Missing-header handling
  await t.test('identifies missing security headers and distinguishes from confirmed vulnerabilities', async () => {
    const mockInsecureHeaders = {
      url: 'http://insecure.example.com/',
      status: 200,
      headers: {}, // No security headers
      redirects: [],
    };

    const res = await securityModule.analyze({
      url: 'http://insecure.example.com/',
      fetchResult: mockInsecureHeaders,
    });

    assert.equal(res.status, 'live');
    assert.ok(res.score > 70, `Expected high deficiency score for missing headers, got ${res.score}`);

    // Verify explanations and remediation instructions
    const failedChecks = res.checks.filter(c => c[1] === 'Failed' || c[1] === 'Warning');
    assert.ok(failedChecks.length >= 6);
    for (const c of failedChecks) {
      assert.ok(c[3], 'Must provide an explanation');
      assert.ok(c[4], 'Must provide a remediation fix instruction');
    }
  });

  // Test 5: TLS certificate information
  await t.test('extracts and verifies valid TLS certificate metadata', async () => {
    const mockFetchWithTls = {
      url: 'https://valid.example.com/',
      status: 200,
      tls: {
        authorized: true,
        authorizationError: null,
        peerCertificate: {
          subject: { CN: 'valid.example.com', O: 'Example Corp' },
          issuer: { CN: 'Trusted Root CA', O: 'Trust Authority Inc' },
          validFrom: new Date(Date.now() - 30 * 86400000).toISOString(),
          validTo: new Date(Date.now() + 180 * 86400000).toISOString(),
          subjectaltname: 'DNS:valid.example.com, DNS:www.valid.example.com',
          fingerprint: 'AA:BB:CC:DD:EE:FF',
        },
      },
    };

    const res = await certificateModule.analyze({
      url: 'https://valid.example.com/',
      fetchResult: mockFetchWithTls,
    });

    assert.equal(res.status, 'live');
    assert.equal(res.score, 0, `Expected cert risk score 0 for valid cert, got ${res.score}`);
    assert.ok(res.cert);
    assert.equal(res.cert.match, true);
    assert.equal(res.cert.chain, true);
    assert.ok(res.cert.days > 100);
    assert.ok(res.positiveFindings.length >= 3);
  });

  // Test 6: Invalid or unavailable certificate data
  await t.test('detects expired certificates, hostname mismatches, and untrusted chains honestly', async () => {
    // 6a: Expired certificate
    const expiredFetch = {
      url: 'https://expired.example.com/',
      tls: {
        authorized: true,
        peerCertificate: {
          subject: { CN: 'expired.example.com' },
          issuer: { O: 'Demo CA' },
          validTo: new Date(Date.now() - 15 * 86400000).toISOString(), // Expired 15 days ago
          subjectaltname: 'DNS:expired.example.com',
        },
      },
    };
    const expiredRes = await certificateModule.analyze({ url: 'https://expired.example.com/', fetchResult: expiredFetch });
    assert.ok(expiredRes.score >= 50);
    assert.ok(expiredRes.findings.some(f => f.name === 'Certificate Expired'));

    // 6b: Hostname mismatch
    const mismatchFetch = {
      url: 'https://phishing-site.example.com/',
      tls: {
        authorized: true,
        peerCertificate: {
          subject: { CN: 'different-domain.example' },
          issuer: { O: 'Demo CA' },
          validTo: new Date(Date.now() + 90 * 86400000).toISOString(),
          subjectaltname: 'DNS:different-domain.example',
        },
      },
    };
    const mismatchRes = await certificateModule.analyze({ url: 'https://phishing-site.example.com/', fetchResult: mismatchFetch });
    assert.ok(mismatchRes.score >= 30);
    assert.ok(mismatchRes.findings.some(f => f.name === 'Certificate Hostname Mismatch'));

    // 6c: Plain HTTP (not assessed)
    const httpRes = await certificateModule.analyze({ url: 'http://plain-http.example.com/', fetchResult: null });
    assert.equal(httpRes.status, 'not_assessed');
    assert.equal(httpRes.score, null);

    // 6d: Missing/unavailable certificate on HTTPS endpoint
    const unavailFetch = {
      url: 'https://no-cert.example.com/',
      tls: { authorized: true, peerCertificate: null },
    };
    const unavailRes = await certificateModule.analyze({ url: 'https://no-cert.example.com/', fetchResult: unavailFetch });
    assert.equal(unavailRes.status, 'unavailable');
    assert.equal(unavailRes.score, null);
    assert.ok(unavailRes.findings.some(f => f.name === 'TLS Certificate Unavailable'));
  });

  // Test 7: Community intelligence unavailable state and verified report scaling
  await t.test('handles community intelligence unavailable state without fabricating data', async () => {
    // Offline state (no DB, no injected reports)
    const offlineRes = await communityModule.analyze({
      domainName: 'unknown-domain.example',
      models: { CommunityReport: null },
    });
    assert.equal(offlineRes.status, 'not_assessed');
    assert.equal(offlineRes.score, null);

    // Empty community state (0 reports)
    const emptyRes = await communityModule.analyze({
      domainName: 'clean-domain.example',
      reports: [],
    });
    assert.equal(emptyRes.status, 'live');
    assert.equal(emptyRes.score, 0);
    assert.equal(emptyRes.rep.n, 0);

    // Verified reports scaling
    const reportedRes = await communityModule.analyze({
      domainName: 'bad-actor.example',
      reports: [
        { domainName: 'bad-actor.example', status: 'verified', reporter: 'u1' },
        { domainName: 'bad-actor.example', status: 'verified', reporter: 'u2' },
        { domainName: 'bad-actor.example', status: 'pending_review', reporter: 'u3' },
      ],
    });
    assert.equal(reportedRes.status, 'live');
    assert.equal(reportedRes.score, 100); // 2 * 50 = 100
    assert.equal(reportedRes.rep.ver, 2);
    assert.equal(reportedRes.rep.uniq, 3);
  });

  // Test 8: Risk-score normalization across assessed modules only
  await t.test('normalizes risk score across assessed modules only without penalty for missing modules', () => {
    // Only Threat heuristic is assessed (score = 50). Other 3 are not_assessed.
    const partialResults = {
      threat: { status: 'live', score: 50, findings: [], positiveFindings: [] },
      security: { status: 'not_assessed', score: null },
      certificate: { status: 'not_assessed', score: null },
      community: { status: 'not_assessed', score: null },
    };

    const report = correlate(partialResults, { hostname: 'partial.example' });
    // Since only threat is assessed: 50 * 0.40 / 0.40 = 50
    assert.equal(report.score, 50, `Expected normalized score 50, got ${report.score}`);
    assert.equal(report.assessedModules, 1);
    assert.equal(report.coverage, 25); // 1 out of 4 modules

    // Multi-module weighted calculation:
    // Threat = 80 (wt 0.40), Security = 20 (wt 0.15)
    // Total weight = 0.55
    // Weighted sum = (80 * 0.40) + (20 * 0.15) = 32 + 3 = 35
    // Normalized = Math.round(35 / 0.55) = Math.round(63.63) = 64
    const twoModules = {
      threat: { status: 'live', score: 80, findings: [], positiveFindings: [] },
      security: { status: 'live', score: 20, findings: [], positiveFindings: [] },
      certificate: { status: 'unavailable', score: null },
      community: { status: 'not_assessed', score: null },
    };
    const reportTwo = correlate(twoModules, { hostname: 'two.example' });
    assert.equal(reportTwo.score, 64);
    assert.equal(reportTwo.coverage, 50);
  });

  // Test 9: Confidence and coverage separation
  await t.test('keeps risk score separate from confidence and coverage', () => {
    // Case A: High risk, low coverage/confidence (only 1 module assessed, threat=90)
    const lowConfReport = correlate({
      threat: { status: 'live', score: 90, findings: [], positiveFindings: [] },
      security: { status: 'not_assessed', score: null },
      certificate: { status: 'not_assessed', score: null },
      community: { status: 'not_assessed', score: null },
    }, { hostname: 'low-conf.example' });

    assert.equal(lowConfReport.score, 90);
    assert.ok(lowConfReport.confidence < 50);
    assert.equal(lowConfReport.confidenceLevel, 'Low');
    assert.equal(lowConfReport.coverage, 25);

    // Case B: Low risk, high coverage/confidence (all 4 modules assessed with clean score 0)
    const highConfReport = correlate({
      threat: { status: 'live', score: 0, findings: [], positiveFindings: [] },
      security: { status: 'live', score: 0, findings: [], positiveFindings: [] },
      certificate: { status: 'live', score: 0, cert: { chain: true }, findings: [], positiveFindings: [] },
      community: { status: 'live', score: 0, rep: { n: 5, ver: 0 }, findings: [], positiveFindings: [] },
    }, { hostname: 'high-conf.example' });

    assert.equal(highConfReport.score, 0);
    assert.ok(highConfReport.confidence >= 70);
    assert.equal(highConfReport.confidenceLevel, 'High');
    assert.equal(highConfReport.coverage, 100);
  });

  // Test 10: Duplicate evidence handling
  await t.test('deduplicates repetitive findings across modules', () => {
    const duplicateEvidenceInput = {
      threat: {
        status: 'live',
        score: 30,
        findings: [{ name: 'Insecure Protocol', explanation: 'Site uses HTTP.' }],
        positiveFindings: ['Valid domain syntax.'],
      },
      security: {
        status: 'live',
        score: 30,
        findings: [{ name: 'Insecure Protocol', explanation: 'Site uses HTTP.' }], // duplicate string
        positiveFindings: ['Valid domain syntax.'], // duplicate string
      },
    };

    const report = correlate(duplicateEvidenceInput, { hostname: 'dup.example' });
    const posMatches = report.positiveFindings.filter(p => p === 'Valid domain syntax.');
    const negMatches = report.negativeFindings.filter(n => n === 'Site uses HTTP.');

    assert.equal(posMatches.length, 1, 'Positive findings must be deduplicated');
    assert.equal(negMatches.length, 1, 'Negative findings must be deduplicated');
  });

  // Test 11: Missing assessment modules handled gracefully
  await t.test('handles empty or missing assessment modules gracefully without NaN', () => {
    const emptyReport = correlate({}, { hostname: 'empty.example' });
    assert.equal(emptyReport.score, 0);
    assert.equal(emptyReport.coverage, 0);
    assert.equal(emptyReport.assessedModules, 0);
    assert.ok(emptyReport.explanation.includes('No modules were assessed'));
  });

  // Test 12: Risk-level classification thresholds
  await t.test('classifies risk levels accurately based on documented thresholds', () => {
    assert.equal(classifyRisk(0).level, 'low');
    assert.equal(classifyRisk(24).level, 'low');
    assert.equal(classifyRisk(25).level, 'medium');
    assert.equal(classifyRisk(49).level, 'medium');
    assert.equal(classifyRisk(50).level, 'high');
    assert.equal(classifyRisk(74).level, 'high');
    assert.equal(classifyRisk(75).level, 'critical');
    assert.equal(classifyRisk(100).level, 'critical');
  });

  // Test 13: Full pipeline execution via assessWebsite
  await t.test('executes end-to-end assessWebsite pipeline with mock network fixtures', async () => {
    const report = await assessWebsite('https://test-pipeline.example/login', {
      skipFetch: true,
      fetchResult: {
        url: 'https://test-pipeline.example/login',
        status: 200,
        headers: {
          'strict-transport-security': 'max-age=31536000',
          'content-security-policy': "default-src 'self'",
          'x-content-type-options': 'nosniff',
        },
        tls: {
          authorized: true,
          peerCertificate: {
            subject: { CN: 'test-pipeline.example' },
            issuer: { O: 'Demo Authority' },
            validTo: new Date(Date.now() + 60 * 86400000).toISOString(),
            subjectaltname: 'DNS:test-pipeline.example',
          },
        },
      },
      reports: [
        { domainName: 'test-pipeline.example', status: 'verified', reporter: 'u1' },
      ],
    });

    assert.ok(typeof report.score === 'number');
    assert.ok(['low', 'medium', 'high', 'critical'].includes(report.riskLevel));
    assert.ok(typeof report.confidence === 'number');
    assert.ok(typeof report.coverage === 'number');
    assert.ok(report.modules.threat);
    assert.ok(report.modules.security);
    assert.ok(report.modules.certificate);
    assert.ok(report.modules.community);
    assert.ok(Array.isArray(report.recommendations));
    assert.ok(report.m, 'Must provide frontend compatibility m object');
    assert.ok(report.a, 'Must provide frontend compatibility a object');
  });

  // Test 14: Negative findings classification ensures passed checks do not appear as adverse findings
  await t.test('negativeFindings excludes passed checks while retaining failed and warning checks', () => {
    const correlationInput = {
      threat: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: ['No malicious threat intelligence matches found.'],
      },
      security: {
        status: 'live',
        score: 35,
        checks: [
          ['HTTPS available', 'Passed', 'High', 'Site is served over encrypted HTTPS.'],
          ['HTTP→HTTPS redirect', 'Passed', 'Medium', 'Initial connection initiated over HTTPS.'],
          ['HSTS', 'Failed', 'Medium', 'Strict-Transport-Security header is missing.'],
          ['Content-Security-Policy', 'Failed', 'Medium', 'No Content-Security-Policy header found.'],
          ['X-Content-Type-Options', 'Warning', 'Low', 'X-Content-Type-Options header is missing.'],
        ],
        findings: [
          { name: 'HTTPS available', status: 'Passed', severity: 'High', explanation: 'Site is served over encrypted HTTPS.' },
          { name: 'HTTP→HTTPS redirect', status: 'Passed', severity: 'Medium', explanation: 'Initial connection initiated over HTTPS.' },
          { name: 'HSTS', status: 'Failed', severity: 'Medium', explanation: 'Strict-Transport-Security header is missing.' },
          { name: 'Content-Security-Policy', status: 'Failed', severity: 'Medium', explanation: 'No Content-Security-Policy header found.' },
          { name: 'X-Content-Type-Options', status: 'Warning', severity: 'Low', explanation: 'X-Content-Type-Options header is missing.' },
        ],
        positiveFindings: [
          'Site is served over encrypted HTTPS.',
          'Initial connection initiated over HTTPS.',
        ],
      },
      certificate: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: ['Certificate is valid and active.'],
      },
      community: {
        status: 'live',
        score: 0,
        findings: [],
        positiveFindings: [],
      },
    };

    const report = correlate(correlationInput, { hostname: 'sec-findings.example' });

    // Positive findings must retain passed security checks
    assert.ok(report.positiveFindings.includes('Site is served over encrypted HTTPS.'));
    assert.ok(report.positiveFindings.includes('Initial connection initiated over HTTPS.'));

    // Negative findings MUST NOT contain passed checks
    assert.ok(!report.negativeFindings.includes('Site is served over encrypted HTTPS.'), 'Passed HTTPS check must not be in negativeFindings');
    assert.ok(!report.negativeFindings.includes('Initial connection initiated over HTTPS.'), 'Passed redirect check must not be in negativeFindings');

    // Negative findings MUST retain failed and warning checks
    assert.ok(report.negativeFindings.includes('Strict-Transport-Security header is missing.'), 'Failed HSTS must be in negativeFindings');
    assert.ok(report.negativeFindings.includes('No Content-Security-Policy header found.'), 'Failed CSP must be in negativeFindings');
    assert.ok(report.negativeFindings.includes('X-Content-Type-Options header is missing.'), 'Warning X-Content-Type-Options must be in negativeFindings');
  });
});
