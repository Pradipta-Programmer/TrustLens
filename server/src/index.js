const config = require('./config'), app = require('./app'), logger = require('./utils/logger');
const { connectDb, closeDb } = require('./config/db');
const feedScheduler = require('./services/feedScheduler');

(async () => {
  const check = config.validateProductionConfig();
  if (!check.valid) {
    logger.error(check.message);
    process.exit(1);
  }
  await connectDb(); // server still starts when the DB is down; DB routes return 503
  if (config.jwtSecret.length < 32) logger.warn('JWT_SECRET missing/short: auth endpoints disabled');

  if (config.enableBackgroundFeedSync) {
    feedScheduler.startScheduledSync();
  }

  const server = app.listen(config.port, () => logger.info(`TrustLens API listening on :${config.port}`));

  const shutdown = async (signal) => {
    logger.info(`Received ${signal}. Shutting down gracefully...`);
    feedScheduler.stopScheduledSync();
    await closeDb();
    server.close(() => {
      logger.info('HTTP server closed cleanly.');
      process.exit(0);
    });
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
})();
