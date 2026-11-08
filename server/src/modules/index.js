// Module registry and assessment pipeline orchestrator for TRUSTLENS.
// Coordinates threat heuristics, security headers, TLS certificate intelligence,
// and community reports, followed by evidence correlation and risk scoring.

const threatModule = require('./threat');
const securityModule = require('./security');
const certificateModule = require('./certificate');
const communityModule = require('./community');
const { correlate, WEIGHTS, THRESHOLDS, classifyRisk } = require('./correlation');
const { safeFetch, SafeFetchError } = require('../security/safeFetcher');
const { validateUrlSyntax } = require('../security/urlGuard');

const names = ['threat', 'security', 'certificate', 'community', 'impersonation'];

const registry = {
  threat: {
    implemented: true,
    analyze: threatModule.analyze,
  },
  security: {
    implemented: true,
    analyze: securityModule.analyze,
  },
  certificate: {
    implemented: true,
    analyze: certificateModule.analyze,
  },
  community: {
    implemented: true,
    analyze: communityModule.analyze,
  },
  impersonation: {
    implemented: true,
    analyze: async (ctx) => {
      const res = await threatModule.analyze(ctx);
      return {
        status: res.status,
        score: res.impersonation ? 35 : 0,
        impersonation: res.impersonation,
        findings: res.impersonation ? [{
          name: 'Possible Brand Impersonation',
          severity: 'High',
          explanation: res.impersonation.evidence[0] || 'Brand resemblance detected.',
          evidence: res.impersonation.brand,
        }] : [],
        evidence: res.impersonation ? res.impersonation.evidence : [],
      };
    },
  },
};

/**
 * Executes a full multi-module assessment pipeline for a submitted URL.
 *
 * @param {string} targetUrl - URL to assess.
 * @param {object} options - Options (fetcher overrides, report overrides, timeout, etc.)
 * @returns {Promise<object>} Complete correlated assessment report.
 */
async function assessWebsite(targetUrl, options = {}) {
  const syntax = validateUrlSyntax(targetUrl);
  if (!syntax.ok) {
    const errorRes = {
      status: 'failed',
      score: null,
      findings: [{
        name: 'Invalid URL',
        severity: 'High',
        explanation: syntax.reason,
        evidence: targetUrl,
      }],
      evidence: [syntax.reason],
    };
    return correlate({
      threat: errorRes,
      security: { status: 'not_assessed', score: null },
      certificate: { status: 'not_assessed', score: null },
      community: { status: 'not_assessed', score: null },
    }, { url: targetUrl, hostname: '', time: new Date().toISOString() });
  }

  const parsedUrl = syntax.url;
  const hostname = parsedUrl.hostname.toLowerCase();
  const baseCtx = {
    url: targetUrl,
    parsedUrl,
    domainName: hostname,
    ct: options.ct,
    models: options.models,
    verifiedThreat: options.verifiedThreat,
    threatIntel: options.threatIntel,
  };

  // Step 1: Run threat heuristics
  const threatResult = await threatModule.analyze(baseCtx);

  // Step 2: Attempt safe network fetch if not explicitly disabled
  let fetchResult = null;
  let fetchError = null;

  if (options.skipFetch) {
    fetchResult = options.fetchResult || null;
    fetchError = options.fetchError || null;
  } else {
    try {
      fetchResult = await safeFetch(parsedUrl.href, {
        timeoutMs: options.timeoutMs,
        maxRedirects: options.maxRedirects,
        maxBodyBytes: options.maxBodyBytes,
        ca: options.ca,
        resolver: options.resolver,
        resolveAndValidate: options.resolveAndValidate,
        isBlockedIp: options.isBlockedIp,
      });
    } catch (err) {
      fetchError = err;
    }
  }

  // Step 3: Run security configuration assessment
  let secResult;
  if (fetchResult) {
    secResult = await securityModule.analyze({ ...baseCtx, fetchResult });
  } else if (fetchError) {
    secResult = {
      status: 'unavailable',
      score: null,
      findings: [{
        name: 'Connection Failed',
        severity: 'Medium',
        explanation: `Unable to inspect security configuration: ${fetchError.message}`,
        evidence: fetchError.code || 'FETCH_FAILED',
      }],
      checks: [],
      evidence: [`Fetch error: ${fetchError.message}`],
      note: `Security checks unavailable: ${fetchError.message}`,
    };
  } else {
    secResult = { status: 'not_assessed', score: null, findings: [], checks: [], evidence: [] };
  }

  // Step 4: Run TLS certificate assessment
  let certResult;
  if (fetchResult && fetchResult.tls) {
    certResult = await certificateModule.analyze({ ...baseCtx, fetchResult });
  } else if (fetchError && fetchError.code === 'TLS_ERROR') {
    certResult = {
      status: 'live',
      score: 85,
      findings: [{
        name: 'TLS Handshake Failed',
        severity: 'High',
        explanation: fetchError.message,
        evidence: fetchError.code,
      }],
      positiveFindings: [],
      evidence: [fetchError.message],
      cert: null,
      note: 'TLS verification failed during connection handshake.',
    };
  } else if (parsedUrl.protocol === 'http:') {
    certResult = await certificateModule.analyze({ ...baseCtx, fetchResult: null });
  } else {
    certResult = {
      status: 'unavailable',
      score: null,
      findings: [],
      evidence: [],
      cert: null,
      note: fetchError ? `Certificate unavailable: ${fetchError.message}` : 'Certificate not assessed.',
    };
  }

  // Step 5: Run community intelligence assessment
  const commResult = await communityModule.analyze({
    ...baseCtx,
    reports: options.reports,
    models: options.models,
  });

  // Step 6: Evidence correlation & risk scoring
  const correlated = correlate({
    threat: threatResult,
    security: secResult,
    certificate: certResult,
    community: commResult,
  }, {
    url: parsedUrl.href,
    hostname,
    time: new Date().toISOString(),
  });

  return correlated;
}

module.exports = {
  names,
  registry,
  assessWebsite,
  correlate,
  WEIGHTS,
  THRESHOLDS,
  classifyRisk,
};
