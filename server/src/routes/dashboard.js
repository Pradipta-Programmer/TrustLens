const express = require('express');
const jwt = require('jsonwebtoken');
const config = require('../config');
const Scan = require('../models/Scan');
const Report = require('../models/CommunityReport');
const { ok, ApiError, wrap } = require('../utils/http');
const { requireDb, limiter } = require('../middleware');

const router = express.Router();

/**
 * Optional authentication middleware.
 * Proceeds anonymously if no Authorization header is present.
 * Validates token if present; rejects malformed/forged tokens with 401 UNAUTHENTICATED.
 */
const optionalAuth = (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return next();
  try {
    const token = h.slice(7);
    const p = jwt.verify(token, config.jwtSecret);
    req.user = { id: p.sub, role: p.role };
    next();
  } catch {
    return next(new ApiError(401, 'UNAUTHENTICATED', 'Invalid or expired token.'));
  }
};

/**
 * GET /api/dashboard/stats
 * Aggregates live system-wide platform statistics from MongoDB.
 * Supports both unauthenticated public access and authenticated access.
 * Returns safe public metrics, risk distribution, category breakdown, and recent activity.
 */
router.get('/stats', limiter(60 * 1000, 60), optionalAuth, requireDb, wrap(async (req, res) => {
  const [
    totalScans,
    lowRisk,
    modRisk,
    highRiskOnly,
    criticalRisk,
    totalReports,
    verifiedReports,
    pendingReports,
    categoryAgg,
    recentScans,
    recentReports,
  ] = await Promise.all([
    Scan.countDocuments({ mode: 'live' }),
    Scan.countDocuments({ mode: 'live', riskScore: { $lt: 25 } }),
    Scan.countDocuments({ mode: 'live', riskScore: { $gte: 25, $lt: 50 } }),
    Scan.countDocuments({ mode: 'live', riskScore: { $gte: 50, $lt: 75 } }),
    Scan.countDocuments({ mode: 'live', riskScore: { $gte: 75 } }),
    Report.countDocuments(),
    Report.countDocuments({ status: 'verified' }),
    Report.countDocuments({ status: 'pending_review' }),
    Report.aggregate([{ $group: { _id: '$category', count: { $sum: 1 } } }]),
    Scan.find({ mode: 'live' })
      .sort('-createdAt')
      .limit(5)
      .select('domainName submittedUrl riskScore classification createdAt')
      .lean(),
    Report.find()
      .sort('-createdAt')
      .limit(5)
      .select('domainName category status createdAt')
      .lean(),
  ]);

  const highRiskTotal = highRiskOnly + criticalRisk;

  const categories = {};
  for (const item of categoryAgg) {
    if (item._id) categories[item._id] = item.count;
  }

  const data = {
    // Top-level backward-compatible fields
    scans: totalScans,
    highRiskScans: highRiskTotal,
    criticalScans: criticalRisk,
    reports: totalReports,
    verifiedReports,
    pendingReports,
    // Enriched platform metrics
    riskDistribution: {
      low: lowRisk,
      moderate: modRisk,
      high: highRiskOnly,
      critical: criticalRisk,
    },
    categories,
    recentScans: recentScans.map(s => ({
      id: s._id,
      domain: s.domainName,
      domainName: s.domainName,
      url: s.submittedUrl,
      riskScore: s.riskScore,
      classification: s.classification,
      createdAt: s.createdAt,
    })),
    recentReports: recentReports.map(r => ({
      id: r._id,
      domain: r.domainName,
      domainName: r.domainName,
      category: r.category,
      status: r.status,
      createdAt: r.createdAt,
    })),
  };

  // Optional user-specific scan count for authenticated non-guest users
  if (req.user && req.user.role !== 'guest') {
    data.userScans = await Scan.countDocuments({ requestedBy: req.user.id });
  }

  ok(res, data, 200, { mode: 'live' });
}));

module.exports = router;
