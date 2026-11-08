// Certificate Transparency client for TRUSTLENS.
// Queries crt.sh to retrieve CT log data for a domain.
// crt.sh is the ONLY allowed external endpoint; no arbitrary URL is ever accepted.
// CT failures NEVER affect scan results or API responses for other routes.
// CT evidence alone NEVER classifies a domain as malicious.

'use strict';

const https = require('https');
const { BRAND_TARGETS } = require('../modules/threat');

// Strict allowlist: only crt.sh is ever contacted.
const CRTSH_HOST = 'crt.sh';
const CRTSH_PATH_PREFIX = '/?q=';
const CRTSH_QUERY_SUFFIX = '&output=json';

// Operational limits
const TIMEOUT_MS = 3500;
const MAX_BYTES = 1 * 1024 * 1024; // 1 MB
const CACHE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

/**
 * Validates a domain string for use in a crt.sh query.
 * Returns a cleaned, lowercase domain string, or null if invalid.
 *
 * @param {string} raw
 * @returns {string|null}
 */
function validateDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  // Strip protocol, path, query, fragment, port
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.split('/')[0].split('?')[0].split('#')[0].split(':')[0];
  if (!d || d.length > 253) return null;
  if (/\s/.test(d)) return null;
  if (!/^[a-z0-9]([a-z0-9\-_.]*[a-z0-9])?$/i.test(d)) return null;
  return d;
}

/**
 * Fetches raw data from crt.sh using native Node https module.
 * Uses AbortController-equivalent via setTimeout + socket destroy.
 * Rejects if response exceeds MAX_BYTES.
 * Returns the raw string body, or throws on error/timeout/oversize.
 *
 * @param {string} domain - Already-validated domain string.
 * @param {object} [opts]
 * @param {string} [opts.mockResponse] - If provided, bypass fetch and return this string.
 * @returns {Promise<string>}
 */
function fetchCrtsh(domain, opts = {}) {
  if (opts.mockTimeout) {
    return Promise.reject(new Error('Request timed out after 3500ms'));
  }
  if (opts.mockError) {
    return Promise.reject(opts.mockError instanceof Error ? opts.mockError : new Error(String(opts.mockError)));
  }
  if (opts.mockResponse !== undefined) {
    if (Buffer.byteLength(opts.mockResponse) > MAX_BYTES) {
      return Promise.reject(new Error('Response exceeded 1 MB size limit'));
    }
    return Promise.resolve(opts.mockResponse);
  }

  return new Promise((resolve, reject) => {
    const path = CRTSH_PATH_PREFIX + encodeURIComponent(domain) + CRTSH_QUERY_SUFFIX;

    const req = https.get(
      {
        hostname: CRTSH_HOST,
        path,
        headers: {
          'User-Agent': 'TrustLens-CT-Client/1.0',
          Accept: 'application/json',
        },
        timeout: TIMEOUT_MS,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          return reject(new Error(`HTTP ${res.statusCode}`));
        }

        let body = '';
        let totalBytes = 0;

        res.on('data', (chunk) => {
          totalBytes += chunk.length;
          if (totalBytes > MAX_BYTES) {
            res.destroy();
            return reject(new Error('Response exceeded 1 MB size limit'));
          }
          body += chunk;
        });

        res.on('end', () => resolve(body));
        res.on('error', reject);
      }
    );

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out after 3500ms'));
    });

    req.on('error', reject);
  });
}

/**
 * Parses raw SANs string from crt.sh (newline-delimited) into an array.
 *
 * @param {string} nameValue
 * @returns {string[]}
 */
function parseSANs(nameValue) {
  if (!nameValue || typeof nameValue !== 'string') return [];
  return nameValue
    .split('\n')
    .map((s) => s.trim().toLowerCase())
    .filter(Boolean);
}

/**
 * Normalizes a raw crt.sh entry into a consistent structure.
 *
 * @param {object} entry
 * @returns {object}
 */
function normalizeEntry(entry) {
  return {
    id: entry.id ?? null,
    issuerName: (entry.issuer_name || '').trim(),
    commonName: (entry.common_name || '').trim(),
    sans: parseSANs(entry.name_value),
    entryTimestamp: entry.entry_timestamp ? new Date(entry.entry_timestamp).toISOString() : null,
    notBefore: entry.not_before ? new Date(entry.not_before).toISOString() : null,
    notAfter: entry.not_after ? new Date(entry.not_after).toISOString() : null,
  };
}

/**
 * Analyzes a list of normalized CT records for security-supporting signals.
 * CT signals are informational only; they NEVER produce a risk score on their own.
 *
 * @param {string} domain
 * @param {object[]} records - Normalized CT records.
 * @returns {object} CT analysis result.
 */
function analyzeCT(domain, records) {
  if (!Array.isArray(records) || records.length === 0) {
    return {
      youngCert: false,
      highVelocity: false,
      brandInSAN: null,
      totalCerts: 0,
      uniqueSANs: [],
      earliest: null,
      latest: null,
    };
  }

  const now = Date.now();
  const sevenDaysAgo = now - 7 * 24 * 60 * 60 * 1000;

  // Collect all timestamps (entryTimestamp preferred; fallback to notBefore)
  const timestamps = records
    .map((r) => r.entryTimestamp || r.notBefore)
    .filter(Boolean)
    .map((t) => new Date(t).getTime())
    .filter((t) => !isNaN(t));

  const earliest = timestamps.length > 0 ? Math.min(...timestamps) : null;
  const latest = timestamps.length > 0 ? Math.max(...timestamps) : null;

  // Young cert: domain first appeared in CT less than 30 days ago
  const youngCert = earliest !== null && now - earliest < 30 * 24 * 60 * 60 * 1000;

  // High velocity: more than 5 certs issued in the last 7 days
  const recentCount = timestamps.filter((t) => t > sevenDaysAgo).length;
  const highVelocity = recentCount > 5;

  // Unique SANs across all records
  const sanSet = new Set();
  for (const r of records) {
    for (const san of r.sans) {
      sanSet.add(san);
    }
  }
  const uniqueSANs = Array.from(sanSet);

  // Detect brand keyword presence in SANs (supporting signal only)
  let brandInSAN = null;
  const sanText = uniqueSANs.join(' ');
  for (const brand of Object.keys(BRAND_TARGETS)) {
    const keyword = brand.split(' ')[0].toLowerCase(); // e.g. 'paypal', 'google', 'amazon'
    if (sanText.includes(keyword) && !sanText.includes(BRAND_TARGETS[brand])) {
      brandInSAN = brand;
      break;
    }
  }

  return {
    youngCert,
    highVelocity,
    brandInSAN,
    totalCerts: records.length,
    uniqueSANs,
    earliest: earliest ? new Date(earliest).toISOString() : null,
    latest: latest ? new Date(latest).toISOString() : null,
    recentCount,
  };
}

/**
 * Checks whether a cached CT observation is still fresh (within 12h TTL).
 *
 * @param {Date|string|null} ctFetchedAt
 * @returns {boolean}
 */
function isCacheFresh(ctFetchedAt) {
  if (!ctFetchedAt) return false;
  const fetchedTime = new Date(ctFetchedAt).getTime();
  if (isNaN(fetchedTime)) return false;
  return Date.now() - fetchedTime < CACHE_TTL_MS;
}

/**
 * Main entry point. Queries CT transparency logs for a domain via crt.sh.
 *
 * Returns a structured result that is ALWAYS defined (never throws).
 * On any failure, returns `{ status: 'unavailable', ... }` with a descriptive note.
 *
 * Cache behavior:
 *   - If a CertificateRecord exists with ctFetchedAt within the last 12h, returns cached data.
 *   - Otherwise fetches live from crt.sh and stores result back via options.saveFn.
 *
 * @param {string} domain - Domain to query (will be validated internally).
 * @param {object} [opts]
 * @param {string} [opts.mockResponse] - Mock response body for testing (bypasses fetch).
 * @param {object} [opts.cachedDoc] - Existing CertificateRecord (optional, for cache check).
 * @param {Function} [opts.saveFn] - Async function(ctObservations, ctFetchedAt) to persist results.
 * @returns {Promise<object>}
 */
async function queryCT(domain, opts = {}) {
  const cleanDomain = validateDomain(domain);
  if (!cleanDomain) {
    return {
      status: 'unavailable',
      note: 'Invalid domain format; CT lookup skipped.',
      records: [],
      summary: null,
    };
  }

  // Extract cached records if available
  const cachedRecords = (opts.cachedDoc && Array.isArray(opts.cachedDoc.ctObservations))
    ? opts.cachedDoc.ctObservations
    : [];
  const normalizedCached = cachedRecords.filter((r) => r && typeof r === 'object' && r.id !== undefined);
  const hasCachedData = normalizedCached.length > 0;

  // Check cache freshness (within 12h TTL)
  if (opts.cachedDoc && isCacheFresh(opts.cachedDoc.ctFetchedAt)) {
    if (hasCachedData || opts.cachedDoc.ctFetchedAt) {
      const summary = analyzeCT(cleanDomain, normalizedCached);
      return {
        status: 'cached',
        note: 'Returned from cache (within 12h TTL).',
        records: normalizedCached,
        summary,
        cachedAt: new Date(opts.cachedDoc.ctFetchedAt).toISOString(),
      };
    }
  }

  // Fetch from crt.sh
  let rawBody;
  try {
    rawBody = await fetchCrtsh(cleanDomain, opts);
  } catch (err) {
    // If live refresh failed but we have valid cached data, preserve it!
    if (hasCachedData) {
      const summary = analyzeCT(cleanDomain, normalizedCached);
      return {
        status: 'cached',
        note: `Live CT refresh failed (${err.message}); preserved valid cached data.`,
        records: normalizedCached,
        summary,
        cachedAt: opts.cachedDoc.ctFetchedAt ? new Date(opts.cachedDoc.ctFetchedAt).toISOString() : null,
        preservedCache: true,
      };
    }
    return {
      status: 'unavailable',
      note: `CT fetch failed: ${err.message}`,
      records: [],
      summary: null,
    };
  }

  // Parse JSON safely
  let rawEntries;
  try {
    rawEntries = JSON.parse(rawBody);
  } catch {
    if (hasCachedData) {
      const summary = analyzeCT(cleanDomain, normalizedCached);
      return {
        status: 'cached',
        note: 'Malformed response from crt.sh (JSON parse error); preserved valid cached data.',
        records: normalizedCached,
        summary,
        cachedAt: opts.cachedDoc.ctFetchedAt ? new Date(opts.cachedDoc.ctFetchedAt).toISOString() : null,
        preservedCache: true,
      };
    }
    return {
      status: 'unavailable',
      note: 'Malformed response from crt.sh (JSON parse error).',
      records: [],
      summary: null,
    };
  }

  if (!Array.isArray(rawEntries)) {
    if (hasCachedData) {
      const summary = analyzeCT(cleanDomain, normalizedCached);
      return {
        status: 'cached',
        note: 'Unexpected response format from crt.sh; preserved valid cached data.',
        records: normalizedCached,
        summary,
        cachedAt: opts.cachedDoc.ctFetchedAt ? new Date(opts.cachedDoc.ctFetchedAt).toISOString() : null,
        preservedCache: true,
      };
    }
    return {
      status: 'unavailable',
      note: 'Unexpected response format from crt.sh.',
      records: [],
      summary: null,
    };
  }

  // If live query returned empty results but we already have valid cached data, do NOT overwrite with empty.
  if (rawEntries.length === 0 && hasCachedData) {
    const summary = analyzeCT(cleanDomain, normalizedCached);
    if (typeof opts.saveFn === 'function') {
      try {
        await opts.saveFn(normalizedCached, new Date());
      } catch {}
    }
    return {
      status: 'cached',
      note: 'Live query returned empty results; preserved existing valid cached observations.',
      records: normalizedCached,
      summary,
      cachedAt: opts.cachedDoc.ctFetchedAt ? new Date(opts.cachedDoc.ctFetchedAt).toISOString() : new Date().toISOString(),
      preservedCache: true,
    };
  }

  // Normalize entries
  const records = rawEntries.map(normalizeEntry);
  const summary = analyzeCT(cleanDomain, records);

  // Persist CT observations if a save function was provided
  if (typeof opts.saveFn === 'function') {
    try {
      await opts.saveFn(records, new Date());
    } catch {
      // Persistence failure must NEVER surface to the caller
    }
  }

  return {
    status: 'available',
    note: null,
    records,
    summary,
    source: 'crt.sh',
  };
}

module.exports = {
  queryCT,
  validateDomain,
  analyzeCT,
  isCacheFresh,
  CRTSH_HOST,
  TIMEOUT_MS,
  MAX_BYTES,
  CACHE_TTL_MS,
};
