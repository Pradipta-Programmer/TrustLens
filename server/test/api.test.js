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
