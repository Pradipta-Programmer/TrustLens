// Threat feed ingestion service for TRUSTLENS.
// Securely ingests, normalizes, deduplicates, and persists external threat intelligence
// from reputable open feeds (URLhaus and OpenPhish).
// Enforces strict allowlisted HTTPS endpoints, timeouts, body size limits, and SSRF defenses.

const net = require('net');
const { validateUrlSyntax, isBlockedIp } = require('../security/urlGuard');
const ThreatIntel = require('../models/ThreatIntel');
const logger = require('../utils/logger');

const ALLOWED_FEEDS = {
  urlhaus: {
    id: 'urlhaus',
    name: 'URLhaus (abuse.ch)',
    url: 'https://urlhaus-api.abuse.ch/v1/urls/recent/',
    category: 'malware',
    format: 'json',
    license: 'Creative Commons CC0 (Public Domain)',
  },
  openphish: {
    id: 'openphish',
    name: 'OpenPhish Community Feed',
    url: 'https://openphish.com/feed.txt',
    category: 'phishing',
    format: 'text',
    license: 'OpenPhish Community (Non-commercial security use)',
  },
};

// In-memory synchronization status
const syncState = {
  lastSyncAt: null,
  status: 'idle',
  sources: {
    urlhaus: { count: 0, status: 'not_run', lastError: null },
    openphish: { count: 0, status: 'not_run', lastError: null },
  },
  lastSummary: null,
};

/**
 * Validates that a feed URL belongs strictly to approved external endpoints.
 */
function isApprovedFeedUrl(urlStr) {
  try {
    const u = new URL(urlStr);
    if (u.protocol !== 'https:') return false;
    const allowedHosts = ['urlhaus-api.abuse.ch', 'openphish.com'];
    return allowedHosts.includes(u.hostname.toLowerCase());
  } catch {
    return false;
  }
}

/**
 * Safely fetches an approved external feed with timeouts and streaming size caps.
 */
async function fetchFeedContent(feedConfig, options = {}) {
  const feedUrl = feedConfig.url;
  if (!isApprovedFeedUrl(feedUrl)) {
    throw new Error(`Feed URL "${feedUrl}" is not on the approved feed allowlist.`);
  }

  const timeoutMs = options.timeoutMs || 8000;
  const maxBytes = options.maxBytes || 2 * 1024 * 1024; // 2MB max response
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(feedUrl, {
      method: 'GET',
      headers: {
        'User-Agent': 'TRUSTLENS-ThreatIntel-Ingestion/1.0 (+https://trustlens.internal)',
        'Accept': feedConfig.format === 'json' ? 'application/json' : 'text/plain',
      },
      signal: controller.signal,
    });

    if (!res.ok) {
      throw new Error(`Feed endpoint returned HTTP ${res.status} (${res.statusText})`);
    }

    const text = await res.text();
    if (Buffer.byteLength(text, 'utf8') > maxBytes) {
      throw new Error(`Feed response exceeded maximum allowed size of ${maxBytes} bytes.`);
    }

    return text;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Normalizes and sanitizes a raw threat URL entry into a validated indicator.
 */
function sanitizeThreatItem(rawUrl, source, category, rawMeta = {}) {
  if (!rawUrl || typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.startsWith('#')) return null;

  const syntax = validateUrlSyntax(trimmed);
  if (!syntax.ok) return null;

  const parsed = syntax.url;
  const hostname = parsed.hostname.toLowerCase();

  // Reject blocked/private/loopback/metadata IP addresses
  if (net.isIP(hostname) && isBlockedIp(hostname)) return null;

  return {
    domainName: hostname,
    url: parsed.href,
    source,
    category: category || 'malware',
    observedAt: rawMeta.observedAt ? new Date(rawMeta.observedAt) : new Date(),
    raw: rawMeta,
  };
}

/**
 * Ingests and persists an array of sanitized threat items into MongoDB via bulk upsert.
 */
async function persistThreatItems(items) {
  if (!items || items.length === 0) return { processed: 0, upserted: 0 };

  const ops = [];
  const seenKeys = new Set();

  for (const item of items) {
    // In-batch deduplication
    const key = `${item.domainName}|${item.source}|${item.url}`;
    if (seenKeys.has(key)) continue;
    seenKeys.add(key);

    ops.push({
      updateOne: {
        filter: { domainName: item.domainName, source: item.source, url: item.url },
        update: {
          $set: {
            domainName: item.domainName,
            url: item.url,
            source: item.source,
            category: item.category,
            observedAt: item.observedAt,
            raw: item.raw,
          },
        },
        upsert: true,
      },
    });
  }

  if (ops.length === 0) return { processed: items.length, upserted: 0 };

  const bulkRes = await ThreatIntel.bulkWrite(ops, { ordered: false });
  return {
    processed: items.length,
    upserted: (bulkRes.upsertedCount || 0) + (bulkRes.modifiedCount || 0),
  };
}

/**
 * Parses raw feed content based on format.
 */
function parseFeedContent(content, feedConfig) {
  const items = [];
  if (feedConfig.format === 'json') {
    let json;
    try {
      json = typeof content === 'string' ? JSON.parse(content) : content;
    } catch (err) {
      throw new Error(`Failed to parse JSON feed from ${feedConfig.id}: ${err.message}`);
    }

    const rawUrls = Array.isArray(json.urls) ? json.urls : (Array.isArray(json) ? json : []);
    for (const u of rawUrls) {
      const urlStr = typeof u === 'string' ? u : u.url;
      const rawMeta = typeof u === 'object' ? {
        id: u.id,
        threat: u.threat,
        tags: u.tags,
        urlhaus_reference: u.urlhaus_reference,
        observedAt: u.date_added,
      } : {};

      const sanitized = sanitizeThreatItem(urlStr, feedConfig.id, u.threat || feedConfig.category, rawMeta);
      if (sanitized) items.push(sanitized);
    }
  } else {
    // Plain text line-delimited URLs
    const lines = content.split(/\r?\n/);
    for (const line of lines) {
      const sanitized = sanitizeThreatItem(line, feedConfig.id, feedConfig.category, { feed: feedConfig.id });
      if (sanitized) items.push(sanitized);
    }
  }
  return items;
}

/**
 * Executes a full or partial threat feed synchronization.
 * Supports mock items override for deterministic test suites without outbound network calls.
 *
 * @param {object} options - Configuration options (e.g. source, mockFeeds, limit).
 * @returns {Promise<object>} Synchronization summary.
 */
async function syncFeeds(options = {}) {
  syncState.status = 'syncing';
  const now = new Date();
  const results = {
    startedAt: now.toISOString(),
    completedAt: null,
    totalIngested: 0,
    sources: {},
    errors: [],
  };

  const targetSources = options.source && options.source !== 'all'
    ? [options.source]
    : Object.keys(ALLOWED_FEEDS);

  for (const sourceId of targetSources) {
    const feedConfig = ALLOWED_FEEDS[sourceId];
    if (!feedConfig) {
      results.errors.push(`Unknown source: ${sourceId}`);
      continue;
    }

    try {
      let items = [];

      // 1. Check for mock fixture overrides (used in test suite)
      if (options.mockFeeds && options.mockFeeds[sourceId]) {
        const mockData = options.mockFeeds[sourceId];
        items = parseFeedContent(mockData, feedConfig);
      } else {
        // 2. Fetch live feed from allowlisted external HTTPS endpoint
        const content = await fetchFeedContent(feedConfig, options);
        items = parseFeedContent(content, feedConfig);
      }

      // Cap ingestion size if specified
      if (options.limit && items.length > options.limit) {
        items = items.slice(0, options.limit);
      }

      // 3. Persist into MongoDB with deduplication
      const persistStats = await persistThreatItems(items);

      results.sources[sourceId] = {
        status: 'success',
        processed: persistStats.processed,
        upserted: persistStats.upserted,
      };
      results.totalIngested += persistStats.upserted;

      syncState.sources[sourceId] = {
        count: persistStats.upserted,
        status: 'success',
        lastError: null,
      };
    } catch (err) {
      logger.warn({ msg: `Feed sync failed for ${sourceId}`, err: err.message });
      results.errors.push(`${sourceId}: ${err.message}`);
      results.sources[sourceId] = {
        status: 'failed',
        error: err.message,
      };
      syncState.sources[sourceId] = {
        status: 'failed',
        lastError: err.message,
      };
    }
  }

  results.completedAt = new Date().toISOString();
  syncState.lastSyncAt = results.completedAt;
  syncState.status = results.errors.length === 0 ? 'idle' : 'partial_error';
  syncState.lastSummary = results;

  return results;
}

/**
 * Returns current feed synchronization metrics and stored database counts.
 */
async function getFeedStatus() {
  let dbCounts = { total: 0, bySource: {} };
  try {
    const agg = await ThreatIntel.aggregate([
      { $group: { _id: '$source', count: { $sum: 1 } } },
    ]);
    for (const item of agg) {
      dbCounts.bySource[item._id] = item.count;
      dbCounts.total += item.count;
    }
  } catch (err) {
    logger.warn({ msg: 'Failed to aggregate ThreatIntel counts', err: err.message });
  }

  return {
    state: syncState.status,
    lastSyncAt: syncState.lastSyncAt,
    databaseTotal: dbCounts.total,
    bySource: dbCounts.bySource,
    sourcesConfig: Object.values(ALLOWED_FEEDS).map(f => ({
      id: f.id,
      name: f.name,
      category: f.category,
      license: f.license,
      lastStatus: syncState.sources[f.id]?.status || 'not_run',
      lastError: syncState.sources[f.id]?.lastError || null,
    })),
    lastSummary: syncState.lastSummary,
  };
}

module.exports = {
  ALLOWED_FEEDS,
  isApprovedFeedUrl,
  sanitizeThreatItem,
  parseFeedContent,
  persistThreatItems,
  syncFeeds,
  getFeedStatus,
};
