const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const config = require('../config');
const { dbReady } = require('../config/db');
const { ApiError } = require('../utils/http');
const logger = require('../utils/logger');
const requireDb = (req, res, next) => dbReady() ? next() : next(new ApiError(503, 'DB_UNAVAILABLE', 'Database is unavailable.'));
const authenticate = (req, res, next) => {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ') || !config.jwtSecret) return next(new ApiError(401, 'UNAUTHENTICATED', 'Authentication required.'));
  try { const p = jwt.verify(h.slice(7), config.jwtSecret); req.user = { id: p.sub, role: p.role }; next(); }
  catch { next(new ApiError(401, 'UNAUTHENTICATED', 'Invalid or expired token.')); }
};
const requireRole = (role) => (req, res, next) => req.user?.role === role ? next() : next(new ApiError(403, 'FORBIDDEN', 'Insufficient permissions.'));
const validate = (schema, part = 'body') => (req, res, next) => {
  const r = schema.safeParse(req[part]);
  if (!r.success) return next(new ApiError(400, 'VALIDATION_ERROR', 'Invalid input.', r.error.issues.map(i => ({ path: i.path.join('.'), message: i.message }))));
  req[part] = r.data; next();
};
const limiter = (windowMs, max) => rateLimit({ windowMs, max, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ ok: false, error: { code: 'RATE_LIMITED', message: 'Too many requests. Try again later.' } }) });
const notFound = (req, res) => res.status(404).json({ ok: false, error: { code: 'NOT_FOUND', message: 'Route not found.' } });
// eslint-disable-next-line no-unused-vars
const errorHandler = (err, req, res, next) => {
  if (err.type === 'entity.parse.failed') err = new ApiError(400, 'BAD_JSON', 'Malformed JSON body.');
  const known = err instanceof ApiError;
  const status = err.status || 500;
  if (!known) logger.error('Unhandled error', { path: req.path, reason: err.message });
  res.status(status).json({ ok: false, error: { code: err.code || 'INTERNAL_ERROR', message: known ? err.message : (status >= 500 ? 'Internal server error.' : err.message), ...(err.details && { details: err.details }) } });
};
module.exports = { requireDb, authenticate, requireRole, validate, limiter, notFound, errorHandler };
