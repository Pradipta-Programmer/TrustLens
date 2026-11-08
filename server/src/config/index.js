require('dotenv').config();
const env = process.env;
module.exports = {
  port: Number(env.PORT) || 4000,
  nodeEnv: env.NODE_ENV || 'development',
  mongoUri: env.MONGODB_URI || '',
  jwtSecret: env.JWT_SECRET || '',
  jwtExpiresIn: env.JWT_EXPIRES_IN || '2h',
  corsOrigin: (env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean),
};
