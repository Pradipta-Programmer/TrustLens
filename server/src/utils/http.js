// Response convention: { ok, data?, error?: {code,message,details?}, meta?: {mode} }
class ApiError extends Error { constructor(status, code, message, details) { super(message); this.status = status; this.code = code; this.details = details; } }
const ok = (res, data, status = 200, meta) => res.status(status).json({ ok: true, data, ...(meta && { meta }) });
const planned = (name) => (req, res) => res.status(501).json({ ok: false, error: { code: 'NOT_IMPLEMENTED', message: `${name} is planned and not implemented yet.` }, meta: { mode: 'not_implemented' } });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
module.exports = { ApiError, ok, planned, wrap };
