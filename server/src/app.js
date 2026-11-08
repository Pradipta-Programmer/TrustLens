const path = require('path');
const express = require('express'), helmet = require('helmet'), cors = require('cors');
const config = require('./config');
const { limiter, notFound, errorHandler } = require('./middleware');
const app = express();
app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
    },
  },
}));
app.use(cors({ origin: config.corsOrigin.length ? config.corsOrigin : false })); // no origins allowed unless configured
app.use(express.json({ limit: '20kb' }));
app.use('/api', limiter(60 * 1000, 120), require('./routes'));
app.use(express.static(path.resolve(__dirname, '../../frontend'), { index: 'index.html', dotfiles: 'ignore' }));
app.use(notFound); app.use(errorHandler);
module.exports = app;
