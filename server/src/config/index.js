require('dotenv').config();
const env = process.env;

const parseTrustProxy = (val) => {
  if (!val || val === 'false' || val === '0') return false;
  if (val === 'true') return true;
  const num = Number(val);
  if (!isNaN(num) && num > 0) return num;
  return val; // e.g., 'loopback', '10.0.0.0/8', or specific IP list
};

const config = {
  port: Number(env.PORT) || 4000,
  nodeEnv: env.NODE_ENV || 'development',
  mongoUri: env.MONGODB_URI || '',
  jwtSecret: env.JWT_SECRET || '',
  jwtExpiresIn: env.JWT_EXPIRES_IN || '2h',
  corsOrigin: (env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean),
  trustProxy: parseTrustProxy(env.TRUST_PROXY),
  enableBackgroundFeedSync: env.ENABLE_BACKGROUND_FEED_SYNC === 'true',
  feedSyncIntervalMs: (() => {
    const rawHours = Number(env.FEED_SYNC_INTERVAL_HOURS);
    if (!isNaN(rawHours) && rawHours > 0) return rawHours * 60 * 60 * 1000;
    const rawMs = Number(env.FEED_SYNC_INTERVAL_MS);
    if (!isNaN(rawMs) && rawMs > 0) return rawMs;
    return 6 * 60 * 60 * 1000; // default 6 hours
  })(),
};

function validateProductionConfig(cfg = config) {
  if (cfg.nodeEnv !== 'production') return { valid: true };

  const errors = [];
  if (!cfg.jwtSecret || typeof cfg.jwtSecret !== 'string' || cfg.jwtSecret.trim().length < 32) {
    errors.push('JWT_SECRET must be configured with at least 32 characters in production.');
  }
  if (!cfg.mongoUri || typeof cfg.mongoUri !== 'string' || !cfg.mongoUri.trim()) {
    errors.push('MONGODB_URI must be configured in production.');
  }
  if (!cfg.port || isNaN(cfg.port) || cfg.port < 1 || cfg.port > 65535) {
    errors.push('PORT must be a valid number between 1 and 65535.');
  }

  if (errors.length > 0) {
    const msg = `[CRITICAL CONFIG ERROR] Production startup aborted:\n  - ${errors.join('\n  - ')}`;
    return { valid: false, errors, message: msg };
  }
  return { valid: true };
}

module.exports = {
  ...config,
  parseTrustProxy,
  validateProductionConfig,
};
