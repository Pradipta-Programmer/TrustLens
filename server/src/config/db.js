const mongoose = require('mongoose');
const config = require('./index');
const logger = require('../utils/logger');
mongoose.set('bufferCommands', false); // fail fast when DB is down instead of hanging
const state = { lastError: null };
async function connectDb() {
  if (!config.mongoUri) { state.lastError = 'MONGODB_URI not set'; logger.warn('Database not configured; API runs in degraded mode'); return false; }
  try { await mongoose.connect(config.mongoUri, { serverSelectionTimeoutMS: 5000 }); logger.info('MongoDB connected'); state.lastError = null; return true; }
  catch (e) { state.lastError = e.message; logger.error('MongoDB connection failed; API runs in degraded mode', { reason: e.message }); return false; }
}
const dbReady = () => mongoose.connection.readyState === 1;
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
module.exports = { connectDb, dbReady, closeDb, state };
