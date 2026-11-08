const r = require('express').Router();
const { dbReady, state } = require('../config/db');
r.get('/', (req, res) => res.status(dbReady() ? 200 : 503).json({ ok: dbReady(), data: { service: 'trustlens-server', uptimeSec: Math.round(process.uptime()), database: dbReady() ? 'connected' : 'unavailable', databaseNote: dbReady() ? undefined : state.lastError } }));
module.exports = r;
