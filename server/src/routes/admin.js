// Admin controller and API routes for TRUSTLENS.
// Enforces strict authentication and administrator role checks on every endpoint.
// Manages community report moderation, VerifiedThreat synchronization, immutable audit logging,
// and external threat intelligence feed operations.

const r = require('express').Router();
const { z } = require('zod');
const mongoose = require('mongoose');

const Report = require('../models/CommunityReport');
const Audit = require('../models/AuditLog');
const VerifiedThreat = require('../models/VerifiedThreat');
const ThreatIntel = require('../models/ThreatIntel');
const { syncFeeds, getFeedStatus } = require('../services/threatFeedService');
const { ok, ApiError, wrap } = require('../utils/http');
const { authenticate, requireRole, requireDb, validate, limiter } = require('../middleware');

// Strict server-side access control: Every route requires valid JWT, admin role, and active DB
r.use(limiter(60 * 1000, 60), authenticate, requireRole('admin'), requireDb);

const reportsQuerySchema = z.object({
  q: z.string().trim().max(200).optional(),
  status: z.preprocess(v => (v === '' ? undefined : v), z.enum(['pending_review', 'under_verification', 'verified', 'rejected']).optional()),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const patchReportSchema = z.object({
  status: z.enum(['under_verification', 'verified', 'rejected']),
  notes: z.string().trim().max(500).optional(),
});

const auditQuerySchema = z.object({
  action: z.string().trim().max(100).optional(),
  targetType: z.string().trim().max(50).optional(),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

/**
 * GET /api/admin/reports
 * Lists community reports for administrative moderation with pagination and filtering.
 */
r.get('/reports', validate(reportsQuerySchema, 'query'), wrap(async (req, res) => {
  const { q, status, page, limit } = req.query;
  const filter = {};

  if (status) filter.status = status;
  if (q) {
    const escaped = q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.domainName = { $regex: escaped, $options: 'i' };
  }

  const skip = (page - 1) * limit;
  const [docs, total] = await Promise.all([
    Report.find(filter).sort('-createdAt').skip(skip).limit(limit).lean(),
    Report.countDocuments(filter),
  ]);

  const reports = docs.map(d => ({
    id: d._id,
    domain: d.domainName,
    domainName: d.domainName,
    url: d.url,
    category: d.category,
    status: d.status,
    description: d.description || '',
    createdAt: d.createdAt,
    reviewedAt: d.reviewedAt || null,
  }));

  ok(res, reports, 200, {
    mode: 'live',
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit) || 1,
    },
  });
}));

/**
 * PATCH /api/admin/reports/:id
 * Updates moderation status of a report, records an audit log entry, and synchronizes VerifiedThreat.
 */
r.patch('/reports/:id', validate(patchReportSchema), wrap(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) {
    throw new ApiError(400, 'INVALID_ID', 'Invalid report id format.');
  }

  const report = await Report.findById(req.params.id);
  if (!report) {
    throw new ApiError(404, 'NOT_FOUND', 'Report not found.');
  }

  const oldStatus = report.status;
  const newStatus = req.body.status;
  const notes = req.body.notes || '';

  report.status = newStatus;
  report.reviewedBy = req.user.id;
  report.reviewedAt = new Date();
  await report.save();

  // Synchronize VerifiedThreat collection:
  if (newStatus === 'verified') {
    // Upsert into VerifiedThreat
    await VerifiedThreat.findOneAndUpdate(
      { domainName: report.domainName },
      {
        $set: {
          domainName: report.domainName,
          category: report.category,
          verifiedBy: req.user.id,
          verifiedAt: new Date(),
        },
        $addToSet: { sourceReports: report._id },
      },
      { upsert: true, new: true }
    );
  } else if (oldStatus === 'verified' && newStatus !== 'verified') {
    // If no longer verified, remove this report from VerifiedThreat
    const vt = await VerifiedThreat.findOne({ domainName: report.domainName });
    if (vt) {
      vt.sourceReports = vt.sourceReports.filter(id => id.toString() !== report._id.toString());
      if (vt.sourceReports.length === 0) {
        await VerifiedThreat.deleteOne({ _id: vt._id });
      } else {
        await vt.save();
      }
    }
  }

  // Record immutable AuditLog entry
  await Audit.create({
    actor: req.user.id,
    action: 'report.status_changed',
    targetType: 'CommunityReport',
    targetId: String(report._id),
    detail: {
      domainName: report.domainName,
      oldStatus,
      newStatus,
      notes: notes || undefined,
    },
  });

  ok(res, {
    id: report._id,
    domain: report.domainName,
    status: report.status,
    reviewedAt: report.reviewedAt,
  });
}));

/**
 * GET /api/admin/audit
 * Retrieves historical audit log entries with pagination.
 */
r.get('/audit', validate(auditQuerySchema, 'query'), wrap(async (req, res) => {
  const { action, targetType, page, limit } = req.query;
  const filter = {};

  if (action) filter.action = action;
  if (targetType) filter.targetType = targetType;

  const skip = (page - 1) * limit;
  const [docs, total] = await Promise.all([
    Audit.find(filter)
      .sort('-createdAt')
      .skip(skip)
      .limit(limit)
      .populate('actor', 'name email role')
      .lean(),
    Audit.countDocuments(filter),
  ]);

  const auditLogs = docs.map(a => ({
    id: a._id,
    actor: a.actor ? { id: a.actor._id, name: a.actor.name, role: a.actor.role } : null,
    action: a.action,
    targetType: a.targetType,
    targetId: a.targetId,
    detail: a.detail || null,
    createdAt: a.createdAt,
  }));

  ok(res, {
    auditLogs,
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit) || 1,
    },
  }, 200, { mode: 'live' });
}));

/**
 * GET /api/admin/stats
 * Aggregates moderation statistics, threat indicator totals, and recent audit activity.
 */
r.get('/stats', wrap(async (req, res) => {
  const [pending, underVerification, verified, rejected, totalVerifiedThreats, totalThreatIntel, recentAudits] = await Promise.all([
    Report.countDocuments({ status: 'pending_review' }),
    Report.countDocuments({ status: 'under_verification' }),
    Report.countDocuments({ status: 'verified' }),
    Report.countDocuments({ status: 'rejected' }),
    VerifiedThreat.countDocuments(),
    ThreatIntel.countDocuments(),
    Audit.find().sort('-createdAt').limit(5).populate('actor', 'name role').lean(),
  ]);

  ok(res, {
    reports: {
      pending,
      underVerification,
      verified,
      rejected,
      total: pending + underVerification + verified + rejected,
    },
    threats: {
      verifiedThreats: totalVerifiedThreats,
      externalThreatIntel: totalThreatIntel,
    },
    recentAudits: recentAudits.map(a => ({
      id: a._id,
      action: a.action,
      actor: a.actor ? a.actor.name : 'System',
      targetId: a.targetId,
      createdAt: a.createdAt,
    })),
  }, 200, { mode: 'live' });
}));

/**
 * POST /api/admin/threat-intel/sync
 * Triggers external threat intelligence feed synchronization.
 */
r.post('/threat-intel/sync', wrap(async (req, res) => {
  const options = {
    source: req.body?.source || 'all',
    mockFeeds: req.body?.mockFeeds || null,
    limit: req.body?.limit || undefined,
  };

  const syncResult = await syncFeeds(options);

  // Record audit log entry
  await Audit.create({
    actor: req.user.id,
    action: 'threat_intel.feed_sync',
    targetType: 'ThreatIntel',
    detail: {
      source: options.source,
      totalIngested: syncResult.totalIngested,
      errors: syncResult.errors,
    },
  });

  ok(res, syncResult, 200, { mode: 'live' });
}));

/**
 * GET /api/admin/threat-intel/status
 * Retrieves status and counts of external threat intelligence feeds.
 */
r.get('/threat-intel/status', wrap(async (req, res) => {
  const status = await getFeedStatus();
  ok(res, status, 200, { mode: 'live' });
}));

module.exports = r;
