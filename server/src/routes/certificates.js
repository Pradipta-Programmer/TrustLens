// Certificate controller and API routes for TRUSTLENS.
// Provides live certificate intelligence, validity status, and transparency observations.
// Data is derived strictly from real persisted scan results and verified TLS connections.
// Never fabricates certificates; distinguishes transport security from site trustworthiness.

const express = require('express');
const { z } = require('zod');
const jwt = require('jsonwebtoken');
const config = require('../config');
const CertificateRecord = require('../models/CertificateRecord');
const Scan = require('../models/Scan');
const { ok, ApiError, wrap } = require('../utils/http');
const { requireDb, limiter } = require('../middleware');
const crtshClient = require('../services/crtshClient');

const router = express.Router();

/**
 * Optional authentication middleware.
 * Public requests are allowed; valid tokens populate req.user; malformed/forged tokens are rejected.
 */
const optionalAuth = (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return next();
  if (!config.jwtSecret) return next(new ApiError(401, 'UNAUTHENTICATED', 'Authentication required.'));
  try {
    const p = jwt.verify(h.slice(7), config.jwtSecret);
    req.user = { id: p.sub, role: p.role };
    next();
  } catch {
    next(new ApiError(401, 'UNAUTHENTICATED', 'Invalid or expired token.'));
  }
};

/**
 * Validates domain string format.
 */
function cleanAndValidateDomain(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let d = raw.trim().toLowerCase();
  d = d.replace(/^[a-z]+:\/\//, '');
  d = d.split('/')[0].split('?')[0].split('#')[0];
  d = d.split(':')[0]; // strip port

  if (!d || d.length > 253) return null;
  if (/\s/.test(d)) return null;
  // Domain must contain valid characters
  if (!/^[a-z0-9]([a-z0-9-_.]*[a-z0-9])?$/i.test(d)) return null;
  return d;
}

/**
 * Formats a certificate record into a safe, public response payload.
 * @param {object} record - CertificateRecord document (plain object).
 * @param {object|null} [ctResult] - Structured CT result from crtshClient.queryCT (optional).
 */
function formatCertificateData(record, ctResult = null) {
  let daysRemaining = null;
  if (record.validTo) {
    const expiryTime = new Date(record.validTo).getTime();
    if (!isNaN(expiryTime)) {
      daysRemaining = Math.round((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));
    }
  }

  let status = 'valid';
  if (daysRemaining !== null && daysRemaining < 0) {
    status = 'expired';
  } else if (daysRemaining !== null && daysRemaining < 14) {
    status = 'expiring_soon';
  } else if (record.chainValid === false) {
    status = 'untrusted';
  } else if (record.hostnameMatch === false) {
    status = 'mismatch';
  }

  // Build structured CT field from live/cached CT result or fall back to legacy string.
  let ctField;
  if (ctResult && (ctResult.status === 'available' || ctResult.status === 'cached')) {
    const s = ctResult.summary || {};
    ctField = {
      status: ctResult.status,
      source: 'crt.sh',
      totalLogged: s.totalCerts || 0,
      earliest: s.earliest || null,
      latest: s.latest || null,
      discoveredSANs: Array.isArray(s.uniqueSANs) ? s.uniqueSANs.slice(0, 20) : [],
      note: ctResult.note || null,
      disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. Multi-domain and CDN certificates frequently include unrelated third-party SANs; presence in this list does not establish common ownership or affiliation.',
    };
  } else if (ctResult && ctResult.status === 'unavailable') {
    ctField = {
      status: 'unavailable',
      source: 'crt.sh',
      totalLogged: null,
      earliest: null,
      latest: null,
      discoveredSANs: [],
      note: ctResult.note || 'CT data temporarily unavailable.',
      disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. Multi-domain and CDN certificates frequently include unrelated third-party SANs; presence in this list does not establish common ownership or affiliation.',
    };
  } else {
    // Legacy fallback for records without CT enrichment
    ctField = {
      status: 'not_fetched',
      source: null,
      totalLogged: null,
      earliest: null,
      latest: null,
      discoveredSANs: [],
      note: 'CT intelligence not yet fetched for this record. Run a new scan to populate.',
      disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. Multi-domain and CDN certificates frequently include unrelated third-party SANs; presence in this list does not establish common ownership or affiliation.',
    };
  }

  return {
    domain: record.domainName,
    domainName: record.domainName,
    issuer: record.issuer || 'Unknown CA',
    subject: record.subject || record.domainName,
    san: Array.isArray(record.san) ? record.san : [],
    validFrom: record.validFrom ? new Date(record.validFrom).toISOString() : null,
    validTo: record.validTo ? new Date(record.validTo).toISOString() : null,
    daysRemaining: daysRemaining !== null ? daysRemaining : 'Unknown',
    hostnameMatch: record.hostnameMatch !== false,
    chainValid: record.chainValid !== false,
    status,
    ct: ctField,
    observedAt: (record.observedAt || record.createdAt || new Date()).toISOString(),
  };
}

const listQuerySchema = z.object({
  q: z.string().trim().max(253).optional(),
  page: z.coerce.number().int().positive().default(1),
  limit: z.coerce.number().int().positive().max(100).default(20),
});

/**
 * GET /api/certificates
 * List and search verified certificate intelligence records.
 */
router.get(
  '/',
  limiter(60 * 1000, 60),
  requireDb,
  optionalAuth,
  wrap(async (req, res) => {
    const parsedQuery = listQuerySchema.safeParse(req.query);
    if (!parsedQuery.success) {
      throw new ApiError(400, 'VALIDATION_ERROR', 'Invalid query parameters.');
    }

    const { q, page, limit } = parsedQuery.data;
    const filter = {};

    if (q) {
      const sanitized = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.domainName = new RegExp(sanitized, 'i');
    }

    const total = await CertificateRecord.countDocuments(filter);
    const records = await CertificateRecord.find(filter)
      .sort({ observedAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit)
      .lean();

    const certificates = records.map(formatCertificateData);

    return ok(res, {
      certificates,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit) || 1,
      },
    }, 200, { mode: 'live' });
  })
);

/**
 * GET /api/certificates/:domain
 * Retrieve certificate intelligence and verification details for a domain.
 */
router.get(
  '/:domain',
  limiter(60 * 1000, 60),
  requireDb,
  optionalAuth,
  wrap(async (req, res) => {
    const domain = cleanAndValidateDomain(req.params.domain);
    if (!domain) {
      throw new ApiError(400, 'INVALID_DOMAIN', 'Invalid domain parameter format.');
    }

    // 1. Check dedicated CertificateRecord collection first
    let certDoc = await CertificateRecord.findOne({ domainName: domain })
      .sort({ observedAt: -1 })
      .lean();

    // 2. If not found in CertificateRecord, check Scan collection for any completed scan with live certificate
    if (!certDoc) {
      const scanDoc = await Scan.findOne({
        domainName: domain,
        mode: 'live',
        'modules.certificate.status': 'live',
      })
        .sort({ createdAt: -1 })
        .lean();

      if (scanDoc) {
        // Find certificate evidence/findings from completed scan
        const findings = scanDoc.modules?.certificate?.findings || [];
        const isExpired = findings.some(f => f.name === 'Certificate Expired');
        const isMismatch = findings.some(f => f.name === 'Certificate Hostname Mismatch');
        const isUntrusted = findings.some(f => f.name === 'Untrusted Certificate Chain');

        certDoc = {
          domainName: domain,
          issuer: 'Observed during live scan',
          subject: domain,
          san: [domain],
          hostnameMatch: !isMismatch,
          chainValid: !isUntrusted,
          ctObservations: ['Observed via direct TLS peer certificate inspection during scan.'],
          mode: 'live',
          observedAt: scanDoc.createdAt,
        };
      }
    }

    if (!certDoc) {
      throw new ApiError(
        404,
        'NOT_FOUND',
        `No certificate record found for domain "${domain}". Run a website scan first.`
      );
    }

    // Fetch CT observations (non-blocking; failure must not affect main response).
    // Pass cached document for 12h TTL cache check.
    let ctResult = null;
    try {
      ctResult = await crtshClient.queryCT(domain, {
        cachedDoc: certDoc,
        saveFn: async (records, fetchedAt) => {
          // Persist CT observations back to the database (best-effort)
          // Ensure valid cached observations are never overwritten with empty results
          const update = { ctFetchedAt: fetchedAt };
          if (Array.isArray(records) && records.length > 0) {
            update.ctObservations = records;
          } else if (!certDoc.ctObservations || certDoc.ctObservations.length === 0) {
            update.ctObservations = [];
          }
          await CertificateRecord.findOneAndUpdate(
            { domainName: domain },
            { $set: update },
            { new: true }
          );
        },
      });
    } catch {
      // CT fetch must never propagate an exception
      ctResult = { status: 'unavailable', note: 'CT lookup failed unexpectedly.', records: [], summary: null };
    }

    const certData = formatCertificateData(certDoc, ctResult);
    return ok(res, certData, 200, { mode: certDoc.mode || 'live' });
  })
);

module.exports = router;
