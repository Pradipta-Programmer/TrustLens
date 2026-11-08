const r = require('express').Router();
const { dbReady, state } = require('../config/db');

// Liveness probe — returns 200 or 503 depending on db status, preserving existing contract
r.get('/', (req, res) => {
  const ready = dbReady();
  const safeNote = ready
    ? undefined
    : (state.lastError ? String(state.lastError).replace(/(mongodb(?:\+srv)?:\/\/)[^@]+@/i, '$1***:***@') : undefined);

  res.status(ready ? 200 : 503).json({
    ok: ready,
    data: {
      service: 'trustlens-server',
      uptimeSec: Math.round(process.uptime()),
      database: ready ? 'connected' : 'unavailable',
      databaseNote: safeNote,
    },
  });
});

// Dedicated Kubernetes / Docker readiness probe
r.get('/ready', (req, res) => {
  const ready = dbReady();
  if (ready) {
    return res.status(200).json({
      ok: true,
      status: 'ready',
      dependencies: {
        database: 'connected',
      },
      uptimeSec: Math.round(process.uptime()),
    });
  }

  return res.status(503).json({
    ok: false,
    status: 'unready',
    error: {
      code: 'DEPENDENCY_UNAVAILABLE',
      message: 'Required database dependency is not ready.',
    },
    dependencies: {
      database: 'unavailable',
    },
  });
});

module.exports = r;
