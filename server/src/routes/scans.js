// Scan controller and API routes for TRUSTLENS.
// Handles scan submissions, scan history queries, and scan detail retrieval.
// Enforces URL validation, SSRF defense, rate limiting, and access authorization.

const express = require('express');
const { z } = require('zod');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const config = require('../config');
const Scan = require('../models/Scan');
const Domain = require('../models/Domain');
const CertificateRecord = require('../models/CertificateRecord');
const { assessWebsite } = require('../modules');
const { safeFetch } = require('../security/safeFetcher');
const { validateUrlSyntax } = require('../security/urlGuard');
const { ok, ApiError, wrap } = require('../utils/http');
const { requireDb, authenticate, validate, limiter } = require('../middleware');
const crtshClient = require('../services/crtshClient');

const router = express.Router();
const inFlightCT = new Map();

const scanSchema = z.object({
  url: z.string().trim().min(1, 'URL is required').max(2048, 'URL must not exceed 2048 characters'),
});

/**
 * Optional authentication middleware.
 * If Authorization header is provided, validates the Bearer JWT token;
 * otherwise proceeds as an anonymous request.
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
 * POST /api/scans
 * Submit a website URL for security assessment.
 */
router.post(
  '/',
  limiter(60 * 1000, 30),
  requireDb,
  optionalAuth,
  validate(scanSchema),
  wrap(async (req, res) => {
    const targetUrl = req.body.url;

    // Validate URL syntax and SSRF protections
    const syntax = validateUrlSyntax(targetUrl);
    if (!syntax.ok) {
      const isSsrf = ['Private or reserved address', 'Blocked hostname'].includes(syntax.reason) || syntax.code === 'SSRF_BLOCKED';
      throw new ApiError(400, isSsrf ? 'SSRF_BLOCKED' : 'INVALID_URL', syntax.reason);
    }

    const parsedUrl = syntax.url;
    const hostname = parsedUrl.hostname.toLowerCase();

    // Concurrently execute CT intelligence query and network safeFetch
    const ctPromise = (async () => {
      try {
        let existingCert = null;
        try {
          existingCert = await CertificateRecord.findOne({ domainName: hostname }).lean();
        } catch {}

        if (existingCert && crtshClient.isCacheFresh(existingCert.ctFetchedAt)) {
          return await crtshClient.queryCT(hostname, { cachedDoc: existingCert });
        }

        let p = inFlightCT.get(hostname);
        if (!p) {
          p = crtshClient.queryCT(hostname, {
            cachedDoc: existingCert,
          }).finally(() => {
            inFlightCT.delete(hostname);
          });
          inFlightCT.set(hostname, p);
        }

        // Strict bounded wait (max 2500ms): CT failures or timeouts must never block or fail the scan
        return await Promise.race([
          p,
          new Promise((resolve) => setTimeout(() => resolve(null), 2500)),
        ]);
      } catch {
        return null;
      }
    })();

    const fetchPromise = (async () => {
      try {
        const res = await safeFetch(parsedUrl.href);
        return { fetchResult: res, fetchError: null };
      } catch (err) {
        return { fetchResult: null, fetchError: err };
      }
    })();

    const [ctResult, fetchOutcome] = await Promise.all([ctPromise, fetchPromise]);

    if (fetchOutcome.fetchError && fetchOutcome.fetchError.name === 'SafeFetchError' && fetchOutcome.fetchError.code === 'SSRF_BLOCKED') {
      throw new ApiError(400, 'SSRF_BLOCKED', fetchOutcome.fetchError.message);
    }

    // Execute multi-layer assessment pipeline with pre-fetched assets
    let assessment;
    try {
      assessment = await assessWebsite(parsedUrl.href, {
        ct: ctResult,
        skipFetch: true,
        fetchResult: fetchOutcome.fetchResult,
        fetchError: fetchOutcome.fetchError,
      });
    } catch (err) {
      if (err.name === 'SafeFetchError' && err.code === 'SSRF_BLOCKED') {
        throw new ApiError(400, 'SSRF_BLOCKED', err.message);
      }
      throw err;
    }

    // Upsert Domain record
    const domainDoc = await Domain.findOneAndUpdate(
      { name: hostname },
      {
        $setOnInsert: {
          name: hostname,
          firstSeenAt: new Date(),
        },
        $set: {
          lastScannedAt: new Date(),
          'reputation.classification': assessment.riskLevel,
        },
      },
      { upsert: true, new: true }
    );

    // Save completed assessment in Scan collection
    const scanDoc = await Scan.create({
      submittedUrl: parsedUrl.href,
      domain: domainDoc._id,
      domainName: hostname,
      requestedBy: req.user ? req.user.id : undefined,
      mode: 'live',
      status: 'completed',
      riskScore: assessment.score,
      confidence: assessment.confidence,
      classification: assessment.classification,
      modules: {
        threat: {
          status: assessment.modules.threat.status,
          score: assessment.modules.threat.score,
          findings: assessment.modules.threat.findings,
        },
        security: {
          status: assessment.modules.security.status,
          score: assessment.modules.security.score,
          findings: assessment.modules.security.findings,
        },
        certificate: {
          status: assessment.modules.certificate.status,
          score: assessment.modules.certificate.score,
          findings: assessment.modules.certificate.findings,
        },
        community: {
          status: assessment.modules.community.status,
          score: assessment.modules.community.score,
          findings: assessment.modules.community.findings,
        },
        impersonation: {
          status: assessment.modules.threat.status,
          score: assessment.a?.imp ? 35 : 0,
          findings: assessment.a?.imp ? [assessment.a.imp] : [],
        },
      },
      evidence: assessment.findings,
      recommendations: assessment.recommendations,
    });

    // Upsert CertificateRecord if live certificate metadata was observed
    const certData = assessment.modules?.certificate?.cert;
    if (certData) {
      const vFrom = certData.validFrom ? new Date(certData.validFrom) : null;
      const vTo = certData.validTo ? new Date(certData.validTo) : null;

      const certUpdate = {
        domainName: hostname,
        issuer: certData.issuer || 'Unknown CA',
        subject: certData.subject || hostname,
        san: Array.isArray(certData.san) ? certData.san : [hostname],
        validFrom: vFrom && !isNaN(vFrom.getTime()) ? vFrom : undefined,
        validTo: vTo && !isNaN(vTo.getTime()) ? vTo : undefined,
        hostnameMatch: certData.match === true,
        chainValid: certData.chain === true,
        mode: 'live',
        observedAt: new Date(),
      };

      // Safely persist CT observations if available; never overwrite valid observations with empty
      if (ctResult && (ctResult.status === 'available' || ctResult.status === 'cached')) {
        certUpdate.ctFetchedAt = new Date();
        if (Array.isArray(ctResult.records) && ctResult.records.length > 0) {
          certUpdate.ctObservations = ctResult.records;
        }
      }

      await CertificateRecord.findOneAndUpdate(
        { domainName: hostname },
        { $set: certUpdate },
        { upsert: true, new: true }
      ).catch(() => {});
    }

    const responseData = {
      id: scanDoc._id,
      url: scanDoc.submittedUrl,
      domain: scanDoc.domainName,
      host: scanDoc.domainName,
      score: scanDoc.riskScore,
      riskLevel: assessment.riskLevel,
      classification: scanDoc.classification,
      confidence: scanDoc.confidence,
      confidenceLevel: assessment.confidenceLevel,
      coverage: assessment.coverage,
      modules: assessment.modules,
      findings: assessment.findings,
      positiveFindings: assessment.positiveFindings,
      negativeFindings: assessment.negativeFindings,
      recommendations: scanDoc.recommendations,
      createdAt: scanDoc.createdAt,
      time: scanDoc.createdAt.toISOString(),
      // Frontend backward compatibility fields
      m: assessment.m,
      a: assessment.a,
      rep: assessment.rep,
      conf: scanDoc.confidence,
      confL: assessment.confidenceLevel,
    };

    return ok(res, responseData, 201, { mode: 'live' });
  })
);

/**
 * GET /api/scans
 * Retrieve scan history with pagination.
 */
router.get(
  '/',
  requireDb,
  authenticate,
  wrap(async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const skip = (page - 1) * limit;

    const filter = {};
    if (req.user.role !== 'admin') {
      filter.requestedBy = req.user.id;
    } else if (req.query.userId) {
      filter.requestedBy = req.query.userId;
    }

    if (req.query.domain) {
      filter.domainName = req.query.domain.toLowerCase().trim();
    }

    const [scans, total] = await Promise.all([
      Scan.find(filter)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit)
        .lean(),
      Scan.countDocuments(filter),
    ]);

    const formattedScans = scans.map(s => ({
      id: s._id,
      url: s.submittedUrl,
      domain: s.domainName,
      host: s.domainName,
      score: s.riskScore,
      classification: s.classification,
      confidence: s.confidence,
      status: s.status,
      createdAt: s.createdAt,
    }));

    return ok(
      res,
      {
        scans: formattedScans,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit) || 0,
        },
      },
      200,
      { mode: 'live' }
    );
  })
);

/**
 * GET /api/scans/:id
 * Retrieve detailed findings of a completed scan.
 */
router.get(
  '/:id',
  requireDb,
  optionalAuth,
  wrap(async (req, res) => {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) {
      throw new ApiError(400, 'INVALID_ID', 'Invalid scan ID format.');
    }

    const scan = await Scan.findById(req.params.id).lean();
    if (!scan) {
      throw new ApiError(404, 'NOT_FOUND', 'Scan record not found.');
    }

    // Ownership and authorization check:
    // If the scan was associated with a user, enforce ownership
    if (scan.requestedBy) {
      if (!req.user) {
        throw new ApiError(401, 'UNAUTHENTICATED', 'Authentication required to view this scan.');
      }
      if (req.user.role !== 'admin' && scan.requestedBy.toString() !== req.user.id) {
        throw new ApiError(403, 'FORBIDDEN', 'You do not have permission to access this scan.');
      }
    }

    const m = {
      threat: scan.modules?.threat?.score ?? null,
      sec: scan.modules?.security?.score ?? null,
      cert: scan.modules?.certificate?.score ?? null,
      comm: scan.modules?.community?.score ?? null,
    };

    const evidenceList = Array.isArray(scan.evidence) ? scan.evidence : [];

    const responseData = {
      id: scan._id,
      url: scan.submittedUrl,
      domain: scan.domainName,
      host: scan.domainName,
      score: scan.riskScore,
      classification: scan.classification,
      confidence: scan.confidence,
      status: scan.status,
      mode: scan.mode,
      modules: scan.modules,
      findings: evidenceList,
      recommendations: scan.recommendations || [],
      createdAt: scan.createdAt,
      time: scan.createdAt ? scan.createdAt.toISOString() : new Date().toISOString(),
      // Frontend compatibility fields
      m,
      a: {
        t: m.threat || 0,
        f: evidenceList.map(e => [10, typeof e === 'string' ? e : (e.explanation || e.name || 'Finding')]),
        pos: [],
        neg: evidenceList.map(e => typeof e === 'string' ? e : (e.explanation || e.name || 'Finding')),
        imp: scan.modules?.impersonation?.findings?.[0] || null,
        fx: {
          sec: [],
          cert: null,
        },
      },
      rep: {
        n: 0,
        uniq: 0,
        ver: 0,
        risk: m.comm,
      },
    };

    return ok(res, responseData, 200, { mode: 'live' });
  })
);

module.exports = router;
