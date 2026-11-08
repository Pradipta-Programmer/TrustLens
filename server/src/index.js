const config = require('./config'), app = require('./app'), logger = require('./utils/logger');
const { connectDb } = require('./config/db');
(async () => {
  await connectDb(); // server still starts when the DB is down; DB routes return 503
  if (config.jwtSecret.length < 32) logger.warn('JWT_SECRET missing/short: auth endpoints disabled');
  app.listen(config.port, () => logger.info(`TrustLens API listening on :${config.port}`));
})();
