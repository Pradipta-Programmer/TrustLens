const test = require('node:test'), assert = require('node:assert');
const app = require('../src/app');
const { isBlockedIp, validateUrlSyntax, resolveAndValidate } = require('../src/security/urlGuard');
let srv, base;
test.before(() => new Promise(r => { srv = app.listen(0, () => { base = `http://127.0.0.1:${srv.address().port}`; r(); }); }));
test.after(() => srv.close());
const get = async (p, o) => { const r = await fetch(base + p, o); return [r.status, await r.json()]; };
test('GET / serves the frontend application', async () => {
  const res = await fetch(base + '/');
  assert.equal(res.status, 200);
  assert.ok(res.headers.get('content-type')?.includes('text/html'));
  const html = await res.text();
  assert.ok(html.includes('TRUSTLENS – Website Trust Intelligence'));
  assert.ok(html.includes('Threat intelligence explorer'));
});
test('health reports DB unavailable honestly (no DB in test)', async () => { const [s, j] = await get('/api/health'); assert.equal(s, 503); assert.equal(j.data.database, 'unavailable'); });
test('health/ready reports 503 when DB is unavailable', async () => {
  const [s, j] = await get('/api/health/ready');
  assert.equal(s, 503);
  assert.equal(j.ok, false);
  assert.equal(j.status, 'unready');
  assert.equal(j.dependencies.database, 'unavailable');
});
test('trustProxy configuration parser handles booleans, hops, and cidrs', () => {
  const { parseTrustProxy } = require('../src/config');
  assert.equal(parseTrustProxy('false'), false);
  assert.equal(parseTrustProxy('0'), false);
  assert.equal(parseTrustProxy(undefined), false);
  assert.equal(parseTrustProxy('true'), true);
  assert.equal(parseTrustProxy('1'), 1);
  assert.equal(parseTrustProxy('2'), 2);
  assert.equal(parseTrustProxy('loopback'), 'loopback');
  assert.equal(parseTrustProxy('10.0.0.0/8'), '10.0.0.0/8');
});
test('validateProductionConfig enforces strict security checks in production', () => {
  const { validateProductionConfig } = require('../src/config');
  // Non-production allows empty for tests
  assert.equal(validateProductionConfig({ nodeEnv: 'test', jwtSecret: '', mongoUri: '', port: 4000 }).valid, true);

  // Production missing JWT_SECRET fails
  const missingSecret = validateProductionConfig({ nodeEnv: 'production', jwtSecret: 'short', mongoUri: 'mongodb://srv', port: 4000 });
  assert.equal(missingSecret.valid, false);
  assert.ok(missingSecret.errors.some(e => e.includes('JWT_SECRET')));

  // Production missing MONGODB_URI fails
  const missingMongo = validateProductionConfig({ nodeEnv: 'production', jwtSecret: '12345678901234567890123456789012', mongoUri: '', port: 4000 });
  assert.equal(missingMongo.valid, false);
  assert.ok(missingMongo.errors.some(e => e.includes('MONGODB_URI')));

  // Valid production configuration passes
  const validProd = validateProductionConfig({ nodeEnv: 'production', jwtSecret: '12345678901234567890123456789012', mongoUri: 'mongodb://srv', port: 4000 });
  assert.equal(validProd.valid, true);
});
test('correlationId middleware generates X-Request-Id when missing and echoes valid incoming ID', async () => {
  // Test generated ID
  const res1 = await fetch(base + '/api/health');
  const reqId1 = res1.headers.get('x-request-id');
  assert.ok(reqId1, 'X-Request-Id header should be returned');
  assert.match(reqId1, /^[0-9a-f-]{36}$/);

  // Test preserving valid incoming ID
  const customId = 'req-prod-test-998811';
  const res2 = await fetch(base + '/api/health', {
    headers: { 'x-request-id': customId },
  });
  assert.equal(res2.headers.get('x-request-id'), customId);

  // Test invalid/malicious incoming ID replaced with secure UUID
  const evilId = '<script>alert(1)</script>';
  const res3 = await fetch(base + '/api/health', {
    headers: { 'x-request-id': evilId },
  });
  const sanitizedId = res3.headers.get('x-request-id');
  assert.notEqual(sanitizedId, evilId);
  assert.match(sanitizedId, /^[0-9a-f-]{36}$/);
});
test('scans endpoint reports DB unavailable honestly (no DB in test)', async () => { const [s, j] = await get('/api/scans'); assert.equal(s, 503); assert.equal(j.error.code, 'DB_UNAVAILABLE'); });
test('admin route rejects anonymous', async () => { const [s] = await get('/api/admin/reports'); assert.equal(s, 401); });
test('admin route rejects forged token', async () => { const [s] = await get('/api/admin/reports', { headers: { authorization: 'Bearer abc.def.ghi' } }); assert.equal(s, 401); });
test('unknown route 404', async () => { const [s] = await get('/api/nope'); assert.equal(s, 404); });
test('urlGuard blocks private/reserved/metadata IPs', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254', '0.0.0.0', '100.64.0.1', '::1', 'fe80::1', 'fd00::1', '::ffff:127.0.0.1']) assert.ok(isBlockedIp(ip), ip);
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '2606:4700:4700::1111']) assert.ok(!isBlockedIp(ip), ip);
});
test('urlGuard syntax rules', () => {
  for (const u of ['ftp://a.com', 'file:///etc/passwd', 'http://localhost', 'http://127.0.0.1', 'http://[::1]/', 'http://user:pw@a.com', 'http://x.internal', 'http://intranet', 'javascript:alert(1)', '']) assert.equal(validateUrlSyntax(u).ok, false, u);
  assert.equal(validateUrlSyntax('example.com/x').ok, true);
});
test('urlGuard rejects hostnames resolving to private IPs (injected resolver)', async () => {
  assert.equal((await resolveAndValidate('https://evil.example', async () => [{ address: '10.0.0.5' }])).ok, false);
  assert.equal((await resolveAndValidate('https://ok.example', async () => [{ address: '93.184.216.34' }])).ok, true);
});
