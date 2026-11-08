const r = require('express').Router();
const User = require('../models/User');
const { ok, ApiError, wrap } = require('../utils/http');
const { authenticate, requireDb } = require('../middleware');
r.get('/me', authenticate, requireDb, wrap(async (req, res) => {
  const u = await User.findById(req.user.id); if (!u) throw new ApiError(404, 'NOT_FOUND', 'User not found.');
  ok(res, { id: u._id, name: u.name, email: u.email, role: u.role, createdAt: u.createdAt });
}));
module.exports = r;
