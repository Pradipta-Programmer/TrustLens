const r = require('express').Router();
const { z } = require('zod');
const Report = require('../models/CommunityReport');
const { validateUrlSyntax } = require('../security/urlGuard');
const { ok, ApiError, wrap } = require('../utils/http');
const { authenticate, requireDb, validate, limiter } = require('../middleware');

const body = z.object({
  url: z.string().max(2048),
  category: z.enum(Report.CATEGORIES),
  description: z.string().trim().max(1000).optional(),
});

const querySchema = z.object({
  q: z.string().trim().max(200).optional(),
  domain: z.string().trim().max(253).optional(),
  category: z.preprocess(v => (v === '' ? undefined : v), z.enum(Report.CATEGORIES).optional()),
  status: z.preprocess(v => (v === '' ? undefined : v), z.enum(['pending_review', 'under_verification', 'verified', 'rejected']).optional()),
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
});

const pub = d => ({
  id: d._id,
  domain: d.domainName,
  category: d.category,
  status: d.status,
  ...(d.description ? { description: d.description } : {}),
  createdAt: d.createdAt,
}); // reporter is strictly excluded

/**
 * GET /api/reports
 * Public endpoint for searching and exploring community threat intelligence reports.
 * Returns safe public fields only (id, domain, category, status, description, createdAt).
 * Never exposes reporter identity, reviewer identity, or internal tokens.
 */
r.get('/', limiter(60 * 1000, 60), requireDb, validate(querySchema, 'query'), wrap(async (req, res) => {
  const { q, domain, category, status, page = 1, limit = 20 } = req.query;
  const filter = {};

  const searchDomain = (q || domain || '').trim().toLowerCase();
  if (searchDomain) {
    let cleanTerm = searchDomain;
    try {
      if (cleanTerm.includes('://')) cleanTerm = new URL(cleanTerm).hostname.toLowerCase();
    } catch {}
    const escaped = cleanTerm.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    filter.domainName = { $regex: escaped, $options: 'i' };
  }

  if (category) filter.category = category;
  if (status) filter.status = status;

  const skip = (page - 1) * limit;
  const [docs, total] = await Promise.all([
    Report.find(filter).sort('-createdAt').skip(skip).limit(limit).lean(),
    Report.countDocuments(filter),
  ]);

  ok(res, {
    reports: docs.map(pub),
    pagination: {
      page,
      limit,
      total,
      totalPages: Math.ceil(total / limit) || 1,
    },
  }, 200, { mode: 'live' });
}));

r.post('/', limiter(60 * 60 * 1000, 20), authenticate, requireDb, validate(body), wrap(async (req, res) => {
  const v = validateUrlSyntax(req.body.url); if (!v.ok) throw new ApiError(400, 'INVALID_URL', v.reason);
  try {
    const d = await Report.create({ url: v.url.href, domainName: v.url.hostname.toLowerCase(), category: req.body.category, description: req.body.description, reporter: req.user.id });
    ok(res, pub(d), 201, { mode: 'live' });
  } catch (e) { if (e.code === 11000) throw new ApiError(409, 'DUPLICATE_REPORT', 'You already reported this domain in this category.'); throw e; }
}));

r.get('/mine', authenticate, requireDb, wrap(async (req, res) => ok(res, (await Report.find({ reporter: req.user.id }).sort('-createdAt').limit(50)).map(pub), 200, { mode: 'live' })));

module.exports = r;
