// SSRF foundation. Pure functions; resolveAndValidate does DNS only (no HTTP).
// The future scanner MUST call it before any fetch and again for every redirect hop.
const net = require('net');
const dns = require('dns').promises;
const LIMITS = Object.freeze({ maxRedirects: 3, timeoutMs: 8000, maxBodyBytes: 1000000, maxUrlLength: 2048 });
const BLOCKED_HOSTS = new Set(['localhost', 'metadata.google.internal']);
const toInt = ip => ip.split('.').reduce((a, o) => a * 256 + Number(o), 0);
const V4 = [['0.0.0.0',8],['10.0.0.0',8],['100.64.0.0',10],['127.0.0.0',8],['169.254.0.0',16],['172.16.0.0',12],['192.0.0.0',24],['192.168.0.0',16],['198.18.0.0',15],['224.0.0.0',4],['240.0.0.0',4]]
  .map(([b, n]) => [toInt(b), 2 ** (32 - n)]); // [start, size]
function isBlockedIp(ip) {
  if (net.isIPv4(ip)) { const v = toInt(ip); return V4.some(([s, size]) => v >= s && v < s + size); }
  if (net.isIPv6(ip)) { const l = ip.toLowerCase(); if (l === '::' || l === '::1') return true;
    const m = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (m) return isBlockedIp(m[1]);
    return /^f[cd]/.test(l) || /^fe[89ab]/.test(l) || l.startsWith('ff'); }
  return true;
}
function validateUrlSyntax(input) {
  if (typeof input !== 'string' || !input.trim() || input.length > LIMITS.maxUrlLength) return { ok: false, code: 'INVALID_URL', reason: 'URL missing or too long' };
  let u; try { u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(input.trim()) ? input.trim() : 'https://' + input.trim()); } catch { return { ok: false, code: 'INVALID_URL', reason: 'Malformed URL' }; }
  if (!['http:', 'https:'].includes(u.protocol)) return { ok: false, code: 'INVALID_URL', reason: 'Only http and https are allowed' };
  if (u.username || u.password) return { ok: false, code: 'INVALID_URL', reason: 'Credentials in URL are not allowed' };
  const h = u.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (BLOCKED_HOSTS.has(h) || h.endsWith('.localhost') || h.endsWith('.internal')) return { ok: false, code: 'SSRF_BLOCKED', reason: 'Blocked hostname' };
  if (net.isIP(h) && isBlockedIp(h)) return { ok: false, code: 'SSRF_BLOCKED', reason: 'Private or reserved address' };
  if (!net.isIP(h) && !h.includes('.')) return { ok: false, code: 'INVALID_URL', reason: 'Hostname must be a public domain' };
  return { ok: true, url: u };
}
async function resolveAndValidate(input, resolver = dns.lookup.bind(dns)) {
  const s = validateUrlSyntax(input); if (!s.ok) return s;
  const h = s.url.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(h)) return { ok: true, url: s.url, addresses: [h] };
  let addrs; try { addrs = await resolver(h, { all: true }); } catch { return { ok: false, code: 'DNS_ERROR', reason: 'DNS resolution failed' }; }
  if (!addrs.length || addrs.some(a => isBlockedIp(a.address))) return { ok: false, code: 'SSRF_BLOCKED', reason: 'Resolves to a private or reserved address' };
  return { ok: true, url: s.url, addresses: addrs.map(a => a.address) };
}
module.exports = { LIMITS, isBlockedIp, validateUrlSyntax, resolveAndValidate };
