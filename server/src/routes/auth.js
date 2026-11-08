const r = require('express').Router();
const { z } = require('zod');
const bcrypt = require('bcryptjs'), jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const config = require('../config'), User = require('../models/User');
const { ok, ApiError, wrap } = require('../utils/http');
const { validate, requireDb, limiter } = require('../middleware');
const sign = u => jwt.sign({ role: u.role }, config.jwtSecret, { subject: String(u._id), expiresIn: config.jwtExpiresIn });
const cfg = (req, res, next) => config.jwtSecret.length >= 32 ? next() : next(new ApiError(503, 'AUTH_NOT_CONFIGURED', 'JWT_SECRET is missing or shorter than 32 characters.'));

// Decoupled rate limiters: strict for credentials, dedicated for anonymous guest sessions
const authBruteForceLimiter = limiter(15 * 60 * 1000, 15);
const guestLimiter = limiter(15 * 60 * 1000, 60);

r.use(cfg);

r.post('/register', authBruteForceLimiter, requireDb, validate(z.object({ name: z.string().trim().min(1).max(80), email: z.string().email().max(254), password: z.string().min(10).max(128) })), wrap(async (req, res) => {
  const { name, email, password } = req.body;
  if (await User.exists({ email: email.toLowerCase() })) throw new ApiError(409, 'EMAIL_IN_USE', 'Email already registered.');
  const u = await User.create({ name, email, passwordHash: await bcrypt.hash(password, 12), role: 'user' }); // role is never client-controlled
  ok(res, { token: sign(u), user: { id: u._id, name: u.name, role: u.role } }, 201);
}));

r.post('/login', authBruteForceLimiter, requireDb, validate(z.object({ email: z.string().email(), password: z.string().min(1).max(128) })), wrap(async (req, res) => {
  const u = await User.findOne({ email: req.body.email.toLowerCase() }).select('+passwordHash');
  if (!u || !(await bcrypt.compare(req.body.password, u.passwordHash))) throw new ApiError(401, 'BAD_CREDENTIALS', 'Incorrect email or password.');
  ok(res, { token: sign(u), user: { id: u._id, name: u.name, role: u.role } });
}));

/**
 * POST /api/auth/guest
 * Issues a short-lived JWT (24h) for anonymous browser sessions so they can
 * submit community reports without creating a full user account. The subject is
 * a randomly generated ObjectId — it is never stored in the User collection and
 * carries role:'guest'. The CommunityReport unique index (domainName+category+reporter)
 * still deduplicates by this stable per-session ID.
 * No database access is required; requireDb is intentionally omitted.
 */
r.post('/guest', guestLimiter, wrap((req, res) => {
  const guestId = new mongoose.Types.ObjectId().toString();
  const token = jwt.sign({ role: 'guest' }, config.jwtSecret, { subject: guestId, expiresIn: '24h' });
  ok(res, { token, role: 'guest' }, 201);
}));
module.exports = r;
