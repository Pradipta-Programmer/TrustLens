const { AsyncLocalStorage } = require('node:async_hooks');
const asyncLocalStorage = new AsyncLocalStorage();

const log = (level, msg, meta = {}) => {
  const store = asyncLocalStorage.getStore();
  const reqId = store?.reqId;
  const payload = {
    t: new Date().toISOString(),
    level,
    msg,
    ...(reqId ? { reqId } : {}),
    ...meta,
  };
  console[level === 'error' ? 'error' : 'log'](JSON.stringify(payload));
};

module.exports = {
  info: (m, x) => log('info', m, x),
  warn: (m, x) => log('warn', m, x),
  error: (m, x) => log('error', m, x),
  asyncLocalStorage,
};
