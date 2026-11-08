const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const tls = require('node:tls');
const { safeFetch, SafeFetchError } = require('../src/security/safeFetcher');

function derLength(len) {
  if (len < 128) return Buffer.from([len]);
  const bytes = [];
  let temp = len;
  while (temp > 0) { bytes.unshift(temp & 0xff); temp >>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
function derSeq(items) {
  const body = Buffer.concat(items);
  return Buffer.concat([Buffer.from([0x30]), derLength(body.length), body]);
}
function derInt(num) {
  const b = Buffer.isBuffer(num) ? num : Buffer.from([num]);
  return Buffer.concat([Buffer.from([0x02]), derLength(b.length), b]);
}
function derUtf8(str) {
  const b = Buffer.from(str, 'utf8');
  return Buffer.concat([Buffer.from([0x0c]), derLength(b.length), b]);
}
function derUtcTime(date) {
  const pad = n => String(n).padStart(2, '0');
  const str = String(date.getUTCFullYear()).slice(-2) +
    pad(date.getUTCMonth() + 1) + pad(date.getUTCDate()) +
    pad(date.getUTCHours()) + pad(date.getUTCMinutes()) + pad(date.getUTCSeconds()) + 'Z';
  return Buffer.concat([Buffer.from([0x17]), derLength(str.length), Buffer.from(str, 'ascii')]);
}
const sha256WithRsa = Buffer.from('300d06092a864886f70d01010b0500', 'hex');
function createName(cn) {
  const cnOid = Buffer.from('0603550403', 'hex');
  const attr = derSeq([cnOid, derUtf8(cn)]);
  const set = Buffer.concat([Buffer.from([0x31]), derLength(attr.length), attr]);
  return derSeq([set]);
}

function generateTestCert(hostname) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const serial = derInt(Buffer.from([Date.now() % 100000]));
  const sigAlg = sha256WithRsa;
  const issuer = createName(hostname);
  const notBefore = derUtcTime(new Date(Date.now() - 100000));
  const notAfter = derUtcTime(new Date(Date.now() + 86400000 * 365));
  const validity = derSeq([notBefore, notAfter]);
  const subject = createName(hostname);
  const spki = publicKey;
  const v3 = Buffer.from('a003020102', 'hex');

  const sanVal = Buffer.concat([Buffer.from([0x82]), derLength(Buffer.byteLength(hostname)), Buffer.from(hostname, 'ascii')]);
  const sanSeq = derSeq([sanVal]);
  const sanExt = derSeq([Buffer.from('0603551d11', 'hex'), Buffer.concat([Buffer.from([0x04]), derLength(sanSeq.length), sanSeq])]);
  const exts = Buffer.concat([Buffer.from([0xa3]), derLength(derSeq([sanExt]).length), derSeq([sanExt])]);

  const tbs = derSeq([v3, serial, sigAlg, issuer, validity, subject, spki, exts]);
  const signature = crypto.sign('sha256', tbs, privateKey);
  const sigBitString = Buffer.concat([Buffer.from([0x03]), derLength(signature.length + 1), Buffer.from([0x00]), signature]);
  const certDer = derSeq([tbs, sigAlg, sigBitString]);
  const certPem = '-----BEGIN CERTIFICATE-----\n' + certDer.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
  return { key: privateKey, cert: certPem };
}

test('safeFetcher test suite', async (t) => {

  // Test 1: Rejection of private and reserved addresses without connecting
  await t.test('rejects private, reserved and loopback addresses directly', async () => {
    const blockedUrls = [
      'http://127.0.0.1',
      'http://127.0.0.1:8080/test',
      'http://10.0.0.1',
      'http://192.168.1.1',
      'http://172.16.0.5',
      'http://169.254.169.254',
      'http://[::1]',
      'http://localhost',
      'http://server.internal',
    ];

    for (const u of blockedUrls) {
      await assert.rejects(
        () => safeFetch(u),
        (err) => {
          assert.ok(err instanceof SafeFetchError, `Expected SafeFetchError for ${u}`);
          assert.ok(
            ['SSRF_BLOCKED', 'INVALID_URL'].includes(err.code),
            `Expected SSRF_BLOCKED or INVALID_URL for ${u}, got ${err.code}`
          );
          return true;
        }
      );
    }
  });

  // Test 2: DNS rebinding protection (DNS resolves to private IP)
  await t.test('rejects hostnames that resolve to private/reserved IPs (DNS rebinding prevention)', async () => {
    const mockResolver = async () => [{ address: '127.0.0.1', family: 4 }];
    await assert.rejects(
      () => safeFetch('http://rebind-attack.example/test', { resolver: mockResolver }),
      (err) => {
        assert.ok(err instanceof SafeFetchError);
        assert.equal(err.code, 'SSRF_BLOCKED');
        return true;
      }
    );

    const mockCloudResolver = async () => [{ address: '169.254.169.254', family: 4 }];
    await assert.rejects(
      () => safeFetch('http://metadata-attack.example/latest', { resolver: mockCloudResolver }),
      (err) => {
        assert.ok(err instanceof SafeFetchError);
        assert.equal(err.code, 'SSRF_BLOCKED');
        return true;
      }
    );

    // Multiple IPs test: if ANY resolved IP is in a blocked range, it must be rejected
    const mockMultiIpResolver = async () => [
      { address: '93.184.216.34', family: 4 },
      { address: '10.0.0.1', family: 4 },
    ];
    await assert.rejects(
      () => safeFetch('http://dual-ip-attack.example', { resolver: mockMultiIpResolver }),
      (err) => {
        assert.ok(err instanceof SafeFetchError);
        assert.equal(err.code, 'SSRF_BLOCKED');
        return true;
      }
    );
  });

  // Test 3: DNS resolution failure handling
  await t.test('handles DNS resolution failure gracefully', async () => {
    const failingResolver = async () => {
      const err = new Error('getaddrinfo ENOTFOUND non-existent-domain.example');
      err.code = 'ENOTFOUND';
      throw err;
    };

    await assert.rejects(
      () => safeFetch('http://non-existent-domain.example', { resolver: failingResolver }),
      (err) => {
        assert.ok(err instanceof SafeFetchError);
        assert.equal(err.code, 'DNS_ERROR');
        return true;
      }
    );
  });

  // Test 4: Rejection of non-http/https protocols and credentials
  await t.test('rejects non-http/https schemes and credentials in URL', async () => {
    const invalidUrls = [
      'ftp://example.com/file',
      'file:///etc/passwd',
      'javascript:alert(1)',
      'http://user:password@example.com',
      'gopher://example.com',
    ];

    for (const u of invalidUrls) {
      await assert.rejects(
        () => safeFetch(u),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'INVALID_URL');
          return true;
        }
      );
    }
  });

  // Test 5: Rejection of non-allowed HTTP methods
  await t.test('rejects non-passive HTTP methods (e.g. POST, PUT, DELETE)', async () => {
    for (const m of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      await assert.rejects(
        () => safeFetch('http://example.com', { method: m }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'METHOD_NOT_ALLOWED');
          return true;
        }
      );
    }
  });

  // Setup local fixture server for HTTP verification tests
  let server;
  let serverPort;

  await new Promise((resolve) => {
    server = http.createServer((req, res) => {
      const url = new URL(req.url, `http://${req.headers.host}`);

      if (url.pathname === '/ok') {
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
          'X-Content-Type-Options': 'nosniff',
          'X-Test-Header': 'trustlens-ok',
        });
        return res.end('<!DOCTYPE html><html><body>TRUSTLENS TEST PAGE</body></html>');
      }

      if (url.pathname === '/redirect-1') {
        res.writeHead(302, { 'Location': '/ok' });
        return res.end();
      }

      if (url.pathname === '/redirect-chain') {
        res.writeHead(301, { 'Location': '/redirect-1' });
        return res.end();
      }

      if (url.pathname === '/redirect-loop') {
        const step = Number(url.searchParams.get('step') || 0);
        res.writeHead(302, { 'Location': `/redirect-loop?step=${step + 1}` });
        return res.end();
      }

      if (url.pathname === '/redirect-to-ssrf') {
        res.writeHead(302, { 'Location': 'http://169.254.169.254/latest/meta-data/' });
        return res.end();
      }

      if (url.pathname === '/slow') {
        // Deliberately delay response past timeout
        setTimeout(() => {
          if (!res.writableEnded) {
            res.writeHead(200);
            res.end('late');
          }
        }, 800);
        return;
      }

      if (url.pathname === '/large-body') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        // Stream 1.2 MB in chunks (exceeds 1 MB cap)
        const chunk = Buffer.alloc(100 * 1024, 'A'); // 100 KB
        let sent = 0;
        const interval = setInterval(() => {
          if (sent >= 1200 * 1024 || res.destroyed) {
            clearInterval(interval);
            if (!res.destroyed) res.end();
            return;
          }
          res.write(chunk);
          sent += chunk.length;
        }, 10);
        return;
      }

      res.writeHead(404);
      res.end('Not found');
    });

    server.listen(0, '127.0.0.1', () => {
      serverPort = server.address().port;
      resolve();
    });
  });

  const testOptions = {
    resolveAndValidate: async (u) => ({
      ok: true,
      url: new URL(u),
      addresses: ['127.0.0.1'],
    }),
    isBlockedIp: () => false, // isolated fixture authorization
  };

  try {
    // Test 6: Valid HTTP GET request and header inspection
    await t.test('fetches valid HTTP endpoint and extracts headers and body', async () => {
      const res = await safeFetch(`http://test-site.example:${serverPort}/ok`, testOptions);
      assert.equal(res.status, 200);
      assert.equal(res.headers['x-test-header'], 'trustlens-ok');
      assert.equal(res.headers['x-content-type-options'], 'nosniff');
      assert.ok(res.body.includes('TRUSTLENS TEST PAGE'));
      assert.ok(res.bytesRead > 0);
      assert.equal(res.ip, '127.0.0.1');
    });

    // Test 7: Valid HTTP HEAD request (headers without body)
    await t.test('fetches valid HTTP endpoint using HEAD method', async () => {
      const res = await safeFetch(`http://test-site.example:${serverPort}/ok`, {
        ...testOptions,
        method: 'HEAD',
      });
      assert.equal(res.status, 200);
      assert.equal(res.headers['x-test-header'], 'trustlens-ok');
      assert.equal(res.body, '');
      assert.equal(res.bytesRead, 0);
    });

    // Test 8: Redirect following and history recording
    await t.test('follows up to allowed redirects and records redirect history', async () => {
      const res = await safeFetch(`http://test-site.example:${serverPort}/redirect-chain`, testOptions);
      assert.equal(res.status, 200);
      assert.equal(res.redirects.length, 2);
      assert.ok(res.redirects[0].from.includes('/redirect-chain'));
      assert.ok(res.redirects[0].to.includes('/redirect-1'));
      assert.ok(res.redirects[1].from.includes('/redirect-1'));
      assert.ok(res.redirects[1].to.includes('/ok'));
      assert.ok(res.body.includes('TRUSTLENS TEST PAGE'));
    });

    // Test 9: Redirect limit enforcement (exceeding 3 redirects)
    await t.test('enforces maximum 3 redirect limit', async () => {
      await assert.rejects(
        () => safeFetch(`http://test-site.example:${serverPort}/redirect-loop?step=0`, {
          ...testOptions,
          maxRedirects: 3,
        }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'TOO_MANY_REDIRECTS');
          return true;
        }
      );
    });

    // Test 10: Redirect destination revalidation (blocking SSRF in redirect location)
    await t.test('re-validates every redirect destination against SSRF rules', async () => {
      // In this test, initial hop is permitted by testOptions, but the redirect targets 169.254.169.254
      // We pass an isBlockedIp function that recognizes 169.254.169.254 as blocked
      const redirectSsrfOptions = {
        resolveAndValidate: async (u) => {
          const parsed = new URL(u);
          if (parsed.hostname === '169.254.169.254') {
            return { ok: false, reason: 'Private or reserved address' };
          }
          return { ok: true, url: parsed, addresses: ['127.0.0.1'] };
        },
        isBlockedIp: (ip) => ip === '169.254.169.254',
      };

      await assert.rejects(
        () => safeFetch(`http://test-site.example:${serverPort}/redirect-to-ssrf`, redirectSsrfOptions),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'SSRF_BLOCKED');
          return true;
        }
      );
    });

    // Test 11: Request timeout enforcement
    await t.test('enforces request timeout', async () => {
      await assert.rejects(
        () => safeFetch(`http://test-site.example:${serverPort}/slow`, {
          ...testOptions,
          timeoutMs: 150, // short timeout
        }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'TIMEOUT');
          return true;
        }
      );
    });

    // Test 12: Streaming response size enforcement (> 1 MB cap)
    await t.test('enforces streaming body size limit (destroys stream if > maxBodyBytes)', async () => {
      await assert.rejects(
        () => safeFetch(`http://test-site.example:${serverPort}/large-body`, {
          ...testOptions,
          maxBodyBytes: 50 * 1024, // 50 KB test threshold
        }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'BODY_SIZE_EXCEEDED');
          return true;
        }
      );
    });

    // Test 13: Connection failure handling (connection refused)
    await t.test('handles connection refused gracefully', async () => {
      // Connect to a closed port on 127.0.0.1 (e.g. serverPort + 999)
      const closedPort = (serverPort + 999) % 65535;
      await assert.rejects(
        () => safeFetch(`http://test-site.example:${closedPort}/ok`, testOptions),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.ok(['CONNECTION_REFUSED', 'FETCH_FAILED'].includes(err.code));
          return true;
        }
      );
    });

  } finally {
    server.close();
  }

  // Setup local HTTPS fixture server for TLS runtime verification
  let httpsServer;
  let httpsServerPort;
  const validHostname = 'valid-site.example';
  const testCert = generateTestCert(validHostname);

  await new Promise((resolve) => {
    httpsServer = https.createServer({ key: testCert.key, cert: testCert.cert }, (req, res) => {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'X-Content-Type-Options': 'nosniff',
      });
      res.end('<!DOCTYPE html><html><body>SECURE TRUSTLENS TEST PAGE</body></html>');
    });
    httpsServer.listen(0, '127.0.0.1', () => {
      httpsServerPort = httpsServer.address().port;
      resolve();
    });
  });

  try {
    // Test 14: Valid HTTPS request with IP pinning, TLS SNI, and cert extraction
    await t.test('connects to HTTPS server with IP pinning, valid SNI, and active cert verification', async () => {
      const res = await safeFetch(`https://${validHostname}:${httpsServerPort}/secure`, {
        resolveAndValidate: async () => ({
          ok: true,
          url: new URL(`https://${validHostname}:${httpsServerPort}/secure`),
          addresses: ['127.0.0.1'],
        }),
        isBlockedIp: () => false,
        ca: [testCert.cert], // Test fixture CA, keeping rejectUnauthorized: true
      });
      assert.equal(res.status, 200);
      assert.ok(res.body.includes('SECURE TRUSTLENS TEST PAGE'));
      assert.ok(res.tls, 'TLS metadata should be present');
      assert.equal(res.tls.authorized, true);
      assert.ok(res.tls.peerCertificate, 'Peer certificate should be extracted');
      assert.ok(res.tls.peerCertificate.subject.CN.includes(validHostname));
    });

    // Test 15: Hostname mismatch rejection
    await t.test('rejects HTTPS connection when hostname does not match certificate (TLS mismatch)', async () => {
      const mismatchedHost = 'mismatched-host.example';
      await assert.rejects(
        () => safeFetch(`https://${mismatchedHost}:${httpsServerPort}/secure`, {
          resolveAndValidate: async () => ({
            ok: true,
            url: new URL(`https://${mismatchedHost}:${httpsServerPort}/secure`),
            addresses: ['127.0.0.1'],
          }),
          isBlockedIp: () => false,
          ca: [testCert.cert], // Even with CA trusted, hostname mismatch must fail
        }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'TLS_ERROR');
          return true;
        }
      );
    });

    // Test 16: Untrusted certificate rejection when default TLS verification is active
    await t.test('rejects untrusted certificate when default TLS verification is active', async () => {
      await assert.rejects(
        () => safeFetch(`https://${validHostname}:${httpsServerPort}/secure`, {
          resolveAndValidate: async () => ({
            ok: true,
            url: new URL(`https://${validHostname}:${httpsServerPort}/secure`),
            addresses: ['127.0.0.1'],
          }),
          isBlockedIp: () => false,
          // No custom CA passed -> default Node trust store rejects self-signed cert
        }),
        (err) => {
          assert.ok(err instanceof SafeFetchError);
          assert.equal(err.code, 'TLS_ERROR');
          return true;
        }
      );
    });
  } finally {
    httpsServer.close();
  }
});
