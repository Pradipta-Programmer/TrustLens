// Secure network fetcher for TRUSTLENS.
// Enforces strict SSRF defense, socket-level IP pinning, redirect validation,
// streaming response body limits, and overall request timeouts.
// Uses Node.js standard library (http, https, net, dns, tls) with zero external dependencies.

const http = require('http');
const https = require('https');
const dns = require('dns').promises;
const net = require('net');
const { LIMITS, isBlockedIp, validateUrlSyntax, resolveAndValidate } = require('./urlGuard');

class SafeFetchError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'SafeFetchError';
    this.code = code;
    this.details = details;
  }
}

/**
 * Safely fetches an HTTP or HTTPS endpoint with strict defensive controls:
 * 1. Syntax & scheme validation (http/https only, no embedded credentials).
 * 2. Pre-connection DNS resolution validating against private/reserved/cloud metadata CIDRs.
 * 3. Connection pinning directly to the validated IP address (prevents DNS rebinding TOCTOU).
 * 4. Preservation of original hostname for HTTP 'Host' header and TLS SNI ('servername').
 * 5. Independent validation of each redirect destination (maximum 3 redirects).
 * 6. Hard 8-second total request timeout across all hops.
 * 7. Hard 1 MB streaming response body limit with immediate stream destruction.
 * 8. Passive only: supports GET and HEAD; never executes scripts or payloads.
 *
 * @param {string} targetUrl - The initial URL to fetch.
 * @param {object} options - Fetch options (method, headers, timeoutMs, maxRedirects, maxBodyBytes, resolver, rejectUnauthorized).
 * @returns {Promise<object>} Structured response object.
 */
async function safeFetch(targetUrl, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method)) {
    throw new SafeFetchError('METHOD_NOT_ALLOWED', `Method ${method} is not permitted. Only GET and HEAD are allowed.`);
  }

  const overallTimeoutMs = options.timeoutMs ?? LIMITS.timeoutMs;
  const maxRedirects = options.maxRedirects ?? LIMITS.maxRedirects;
  const maxBodyBytes = options.maxBodyBytes ?? LIMITS.maxBodyBytes;
  const resolver = options.resolver || dns.lookup.bind(dns);
  const resolveAndValidateFn = options.resolveAndValidate || resolveAndValidate;
  const isBlockedFn = options.isBlockedIp || isBlockedIp;
  const rejectUnauthorized = options.rejectUnauthorized !== false;

  const deadline = Date.now() + overallTimeoutMs;
  const redirects = [];
  let currentUrlStr = targetUrl;
  let redirectCount = 0;

  while (true) {
    const remainingTimeMs = deadline - Date.now();
    if (remainingTimeMs <= 0) {
      throw new SafeFetchError('TIMEOUT', `Request timed out after ${overallTimeoutMs}ms total execution.`);
    }

    // Step 1: Validate URL syntax and protocol
    const syntax = validateUrlSyntax(currentUrlStr);
    if (!syntax.ok) {
      const code = syntax.code || (['Private or reserved address', 'Blocked hostname'].includes(syntax.reason) ? 'SSRF_BLOCKED' : 'INVALID_URL');
      throw new SafeFetchError(code, syntax.reason);
    }
    const currentUrl = syntax.url;

    // Step 2: Resolve DNS and validate destination IP
    let resolved;
    try {
      resolved = await resolveAndValidateFn(currentUrl.href, resolver);
    } catch (e) {
      throw new SafeFetchError('DNS_ERROR', `DNS resolution error: ${e.message}`, { cause: e });
    }

    if (!resolved.ok) {
      const code = resolved.code || (resolved.reason === 'DNS resolution failed' ? 'DNS_ERROR' : 'SSRF_BLOCKED');
      throw new SafeFetchError(code, resolved.reason);
    }

    if (!resolved.addresses || !resolved.addresses.length) {
      throw new SafeFetchError('DNS_ERROR', `No IP addresses found for host ${currentUrl.hostname}`);
    }

    // Validate every candidate IP address independently
    for (const ip of resolved.addresses) {
      if (isBlockedFn(ip)) {
        throw new SafeFetchError('SSRF_BLOCKED', `Destination IP ${ip} is in a blocked range.`);
      }
    }

    const pinnedIp = resolved.addresses[0];

    // Step 3: Execute single hop with pinned IP
    const hopResult = await executeHop({
      url: currentUrl,
      pinnedIp,
      method,
      timeoutMs: remainingTimeMs,
      maxBodyBytes,
      headers: options.headers || {},
      userAgent: options.userAgent,
      rejectUnauthorized,
      ca: options.ca,
    });

    // Check for HTTP redirect status codes (301, 302, 303, 307, 308)
    const statusCode = hopResult.status;
    const isRedirect = [301, 302, 303, 307, 308].includes(statusCode);

    if (isRedirect && options.followRedirects !== false) {
      const location = hopResult.headers.location;
      if (!location) {
        // Redirect without Location header is treated as a terminal response
        return {
          url: currentUrl.href,
          status: hopResult.status,
          statusText: hopResult.statusText,
          headers: hopResult.headers,
          body: hopResult.body,
          bytesRead: hopResult.bytesRead,
          ip: pinnedIp,
          redirects,
          tls: hopResult.tls,
        };
      }

      if (redirectCount >= maxRedirects) {
        throw new SafeFetchError('TOO_MANY_REDIRECTS', `Exceeded maximum redirect limit of ${maxRedirects}.`);
      }

      let nextUrl;
      try {
        nextUrl = new URL(location, currentUrl.href);
      } catch {
        throw new SafeFetchError('INVALID_URL', `Invalid redirect destination URL: ${location}`);
      }

      redirects.push({
        from: currentUrl.href,
        to: nextUrl.href,
        status: statusCode,
        ip: pinnedIp,
      });

      redirectCount++;
      currentUrlStr = nextUrl.href;
      continue;
    }

    // Terminal response reached
    return {
      url: currentUrl.href,
      status: hopResult.status,
      statusText: hopResult.statusText,
      headers: hopResult.headers,
      body: hopResult.body,
      bytesRead: hopResult.bytesRead,
      ip: pinnedIp,
      redirects,
      tls: hopResult.tls,
    };
  }
}

/**
 * Executes a single HTTP/HTTPS request pinned directly to a validated IP.
 */
function executeHop({ url, pinnedIp, method, timeoutMs, maxBodyBytes, headers, userAgent, rejectUnauthorized, ca }) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;
    const isIpHost = net.isIP(url.hostname) !== 0;

    const abortController = new AbortController();
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      abortController.abort();
    }, Math.max(1, timeoutMs));

    // Custom lookup function that returns the pre-validated IP
    // Bypasses secondary OS DNS resolution and prevents DNS rebinding
    const customLookup = (hostname, opts, cb) => {
      if (typeof opts === 'function') {
        cb = opts;
        opts = {};
      }
      const family = net.isIPv4(pinnedIp) ? 4 : 6;
      if (opts && opts.all) {
        return cb(null, [{ address: pinnedIp, family }]);
      }
      return cb(null, pinnedIp, family);
    };

    const requestHeaders = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'User-Agent': userAgent || 'TrustLens-Scanner/1.0 (Passive Website Trust Intelligence)',
      'Connection': 'close',
      ...headers,
      'Host': url.host, // Preserves original hostname and non-standard port
    };

    const reqOptions = {
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || (isHttps ? 443 : 80),
      path: (url.pathname || '/') + (url.search || ''),
      method,
      headers: requestHeaders,
      lookup: customLookup,
      signal: abortController.signal,
      timeout: Math.max(1, timeoutMs),
    };

    if (isHttps) {
      reqOptions.rejectUnauthorized = rejectUnauthorized;
      if (ca) {
        reqOptions.ca = ca;
      }
      if (!isIpHost) {
        reqOptions.servername = url.hostname; // TLS SNI
      }
    }

    let req;
    try {
      req = client.request(reqOptions);
    } catch (err) {
      clearTimeout(timer);
      return reject(new SafeFetchError('REQUEST_INIT_FAILED', `Failed to initialize request: ${err.message}`));
    }

    let bytesRead = 0;
    const chunks = [];
    let limitExceeded = false;

    req.on('response', (res) => {
      let tls = null;
      if (isHttps && res.socket && typeof res.socket.getPeerCertificate === 'function') {
        try {
          const cert = res.socket.getPeerCertificate(false);
          tls = {
            authorized: res.socket.authorized,
            authorizationError: res.socket.authorizationError || null,
            protocol: res.socket.getProtocol ? res.socket.getProtocol() : null,
            cipher: res.socket.getCipher ? res.socket.getCipher() : null,
            peerCertificate: cert && Object.keys(cert).length > 0 ? {
              subject: cert.subject,
              issuer: cert.issuer,
              validFrom: cert.valid_from,
              validTo: cert.valid_to,
              subjectaltname: cert.subjectaltname,
              fingerprint: cert.fingerprint256 || cert.fingerprint,
            } : null,
          };
        } catch {
          tls = null;
        }
      }

      if (method === 'HEAD') {
        clearTimeout(timer);
        res.resume(); // drain
        return resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          body: '',
          bytesRead: 0,
          tls,
        });
      }

      res.on('data', (chunk) => {
        bytesRead += chunk.length;
        if (bytesRead > maxBodyBytes) {
          limitExceeded = true;
          clearTimeout(timer);
          req.destroy();
          res.destroy();
          return reject(new SafeFetchError('BODY_SIZE_EXCEEDED', `Response body exceeded limit of ${maxBodyBytes} bytes.`));
        }
        chunks.push(chunk);
      });

      res.on('end', () => {
        if (limitExceeded) return;
        clearTimeout(timer);
        const bodyBuffer = Buffer.concat(chunks);
        resolve({
          status: res.statusCode,
          statusText: res.statusMessage,
          headers: res.headers,
          body: bodyBuffer.toString('utf-8'),
          bytesRead,
          tls,
        });
      });

      res.on('error', (err) => {
        if (limitExceeded) return;
        clearTimeout(timer);
        reject(new SafeFetchError('STREAM_ERROR', `Response stream error: ${err.message}`));
      });
    });

    req.on('error', (err) => {
      clearTimeout(timer);
      if (limitExceeded) return;

      if (timedOut || err.name === 'AbortError' || err.code === 'ABORT_ERR') {
        return reject(new SafeFetchError('TIMEOUT', `Request timed out after ${timeoutMs}ms.`));
      }

      if (err.code === 'ECONNREFUSED') {
        return reject(new SafeFetchError('CONNECTION_REFUSED', `Connection refused by ${pinnedIp}.`));
      }

      if (err.code === 'ECONNRESET') {
        return reject(new SafeFetchError('CONNECTION_RESET', `Connection reset by peer.`));
      }

      if (err.code === 'ETIMEDOUT') {
        return reject(new SafeFetchError('TIMEOUT', `Connection to ${pinnedIp} timed out.`));
      }

      if (err.code && (err.code.startsWith('ERR_TLS_') || err.code === 'CERT_HAS_EXPIRED' || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' || err.code === 'CERT_UNTRUSTED')) {
        return reject(new SafeFetchError('TLS_ERROR', `TLS handshake failure: ${err.message}`, { code: err.code }));
      }

      return reject(new SafeFetchError('FETCH_FAILED', err.message, { code: err.code }));
    });

    req.end();
  });
}

module.exports = {
  safeFetch,
  SafeFetchError,
};
