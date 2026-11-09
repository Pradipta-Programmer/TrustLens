const mongoose = require('mongoose');
const config = require('./index');
const logger = require('../utils/logger');
mongoose.set('bufferCommands', false); // fail fast when DB is down instead of hanging
const state = { lastError: null };

function detectTestEnv() {
  if (process.env.NODE_TEST_CONTEXT) return true;
  if (process.env.NODE_ENV === 'test') return true;
  if (process.env.USE_TEST_DB === 'true') return true;
  if (process.execArgv && process.execArgv.some(a => a === '--test' || a.startsWith('--test'))) return true;
  if (process.argv && process.argv.some(a => a === '--test' || a.includes('node:test'))) return true;
  return false;
}

const isTestEnv = detectTestEnv();

function extractDbName(rawUri) {
  if (!rawUri || typeof rawUri !== 'string') return '';
  try {
    const u = new URL(rawUri);
    return (u.pathname || '').replace(/^\/+/, '').split('/')[0].split('?')[0];
  } catch (_) {
    const match = rawUri.match(/\/([a-zA-Z0-9_-]+)(?:\?|$)/);
    return match ? match[1] : '';
  }
}

function enforceTestDbUri(rawUri) {
  if (!rawUri || typeof rawUri !== 'string') return '';
  const currentDb = extractDbName(rawUri);
  if (currentDb === 'trustlens_test') return rawUri;
  if (currentDb) {
    return rawUri.replace(new RegExp(`/${currentDb}(?:(\\?|$))`), '/trustlens_test$1');
  }
  try {
    const u = new URL(rawUri);
    u.pathname = '/trustlens_test';
    return u.toString();
  } catch (_) {
    return rawUri.replace(/\/?(\?|$)/, '/trustlens_test$1');
  }
}

const getDbUri = () => {
  if (!config.mongoUri) return '';
  if (isTestEnv) {
    const candidate = process.env.MONGODB_TEST_URI || config.mongoUri;
    return enforceTestDbUri(candidate);
  }
  return config.mongoUri;
};

async function connectDb(customUri) {
  let targetUri;
  if (isTestEnv) {
    if (customUri) {
      const customDb = extractDbName(customUri);
      if (customDb && customDb !== 'trustlens_test') {
        const err = `[CRITICAL TEST SAFETY GUARD] Custom URI targeted "${customDb}". Tests must strictly target "trustlens_test". Connection rejected.`;
        state.lastError = err;
        logger.error(err);
        throw new Error(err);
      }
      targetUri = enforceTestDbUri(customUri);
    } else {
      targetUri = getDbUri();
    }
  } else {
    targetUri = customUri || getDbUri();
  }

  if (!targetUri) {
    state.lastError = 'MONGODB_URI not set';
    logger.warn('Database not configured; API runs in degraded mode');
    return false;
  }

  try {
    await mongoose.connect(targetUri, { serverSelectionTimeoutMS: 5000 });
    const dbName = mongoose.connection.name;

    // Strict safety guard: In any test execution, block immediately if not trustlens_test
    if (isTestEnv && dbName !== 'trustlens_test') {
      await mongoose.disconnect();
      const guardErr = `[CRITICAL TEST SAFETY GUARD] Connected database is "${dbName}". Tests MUST use "trustlens_test" to prevent mutating production data.`;
      state.lastError = guardErr;
      logger.error(guardErr);
      throw new Error(guardErr);
    }

    logger.info('MongoDB connected', { dbName, isTest: isTestEnv });
    state.lastError = null;
    return true;
  } catch (e) {
    state.lastError = e.message;
    logger.error('MongoDB connection failed; API runs in degraded mode', { reason: e.message });
    if (isTestEnv && e.message && e.message.includes('CRITICAL TEST SAFETY GUARD')) {
      throw e;
    }
    return false;
  }
}

const dbReady = () => mongoose.connection.readyState === 1;

function assertTestDatabase() {
  const name = mongoose.connection.name;
  if (name !== 'trustlens_test') {
    throw new Error(`[CRITICAL TEST SAFETY GUARD] Mutation rejected: current database is "${name}", expected "trustlens_test".`);
  }
}

/**
 * Fully closes all database connections, including the underlying MongoClient connection pool.
 * Calling mongoose.connection.close() alone does not drain the driver's TLS socket pool on
 * MongoDB Node.js driver v6+, leaving active handles in the event loop that prevent natural
 * process exit. This helper closes the MongoClient first to destroy all pooled sockets, then
 * calls mongoose.connection.close() to tear down the Mongoose layer cleanly.
 */
async function closeDb() {
  try {
    const client = mongoose.connection.readyState !== 0
      ? mongoose.connection.getClient()
      : null;
    if (client) await client.close(true);
  } catch (_) { /* ignore – connection may already be closing */ }
  await mongoose.connection.close(true).catch(() => {});
}
module.exports = {
  connectDb,
  dbReady,
  closeDb,
  assertTestDatabase,
  isTestEnv,
  detectTestEnv,
  extractDbName,
  enforceTestDbUri,
  getDbUri,
  state,
};
