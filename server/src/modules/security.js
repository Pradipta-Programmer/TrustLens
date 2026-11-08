// Website security configuration assessment module for TRUSTLENS.
// Evaluates observable HTTP response headers and transport security settings.
// Checks: HTTPS, HTTP->HTTPS redirect, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, X-Frame-Options.
// Distinguishes missing security headers from confirmed vulnerabilities.

/**
 * Assesses website security configuration from safeFetch response and optional redirect info.
 *
 * @param {object} ctx - Context object containing `fetchResult` (from safeFetch) and `targetUrl`.
 * @returns {Promise<object>} Structured security module assessment.
 */
async function analyze(ctx = {}) {
  const fetchResult = ctx.fetchResult;
  const initialUrlStr = ctx.url || (ctx.parsedUrl ? ctx.parsedUrl.href : '');

  // If no fetch result was provided, the check cannot be completed
  if (!fetchResult) {
    return {
      status: 'not_assessed',
      score: null,
      findings: [],
      evidence: [],
      checks: [],
      note: 'Website security checks not assessed (no fetch response available).',
    };
  }

  const headers = fetchResult.headers || {};
  const finalUrlStr = fetchResult.url || initialUrlStr;
  let finalUrl;
  try {
    finalUrl = new URL(finalUrlStr);
  } catch {
    finalUrl = { protocol: 'http:' };
  }

  let initialUrl;
  try {
    initialUrl = new URL(initialUrlStr);
  } catch {
    initialUrl = finalUrl;
  }

  const checks = [];
  const findings = [];
  const positiveFindings = [];
  const evidence = [];

  const addCheck = (name, status, severity, explanation, fix = '') => {
    // Array format matching frontend fx.sec: [name, status, severity, explanation, fix]
    checks.push([name, status, severity, explanation, fix]);
    findings.push({ name, status, severity, explanation, fix });
    evidence.push(`${name}: ${status}`);
    if (status === 'Passed') {
      positiveFindings.push(explanation);
    }
  };

  // 1. HTTPS availability
  const isHttps = finalUrl.protocol === 'https:';
  if (isHttps) {
    addCheck(
      'HTTPS available',
      'Passed',
      'High',
      'Site is served over encrypted HTTPS.'
    );
  } else {
    addCheck(
      'HTTPS available',
      'Failed',
      'High',
      'Site is served over unencrypted plain HTTP. Traffic can be intercepted or modified.',
      'Enable HTTPS with a valid TLS certificate.'
    );
  }

  // 2. HTTP-to-HTTPS redirect behavior
  const redirects = fetchResult.redirects || [];
  const redirectedToHttps = redirects.some(r => {
    try {
      return new URL(r.to).protocol === 'https:';
    } catch {
      return false;
    }
  });

  if (initialUrl.protocol === 'https:') {
    addCheck(
      'HTTP→HTTPS redirect',
      'Passed',
      'Medium',
      'Initial connection initiated over HTTPS.'
    );
  } else if (redirectedToHttps) {
    addCheck(
      'HTTP→HTTPS redirect',
      'Passed',
      'Medium',
      'Plain HTTP connection is automatically redirected to HTTPS.'
    );
  } else if (ctx.httpRedirectResult && ctx.httpRedirectResult.redirectsToHttps) {
    addCheck(
      'HTTP→HTTPS redirect',
      'Passed',
      'Medium',
      'Plain HTTP requests redirect to HTTPS.'
    );
  } else {
    addCheck(
      'HTTP→HTTPS redirect',
      'Failed',
      'Medium',
      'Plain HTTP requests do not redirect to HTTPS.',
      'Configure a permanent (301) redirect from HTTP to HTTPS.'
    );
  }

  // 3. Strict-Transport-Security (HSTS)
  const hsts = headers['strict-transport-security'];
  if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
    const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
    if (maxAge >= 10886400) { // >= 18 weeks
      addCheck(
        'HSTS',
        'Passed',
        'Medium',
        `Browsers are forced onto HTTPS (max-age=${maxAge}s).`
      );
    } else {
      addCheck(
        'HSTS',
        'Warning',
        'Medium',
        `HSTS is configured but max-age (${maxAge}s) is shorter than recommended 1 year.`,
        'Set max-age to at least 31536000 with includeSubDomains.'
      );
    }
  } else {
    addCheck(
      'HSTS',
      'Failed',
      'Medium',
      'Strict-Transport-Security header is missing. Browsers are not forced to use HTTPS on subsequent visits.',
      'Add Strict-Transport-Security: max-age=31536000; includeSubDomains.'
    );
  }

  // 4. Content-Security-Policy (CSP)
  const csp = headers['content-security-policy'];
  if (csp) {
    addCheck(
      'Content-Security-Policy',
      'Passed',
      'Medium',
      'Content-Security-Policy is defined to restrict script and resource execution.'
    );
  } else {
    addCheck(
      'Content-Security-Policy',
      'Failed',
      'Medium',
      'No Content-Security-Policy header found. The site does not restrict sources for scripts or styles.',
      'Define a Content-Security-Policy header restricting script sources.'
    );
  }

  // 5. X-Content-Type-Options
  const xcto = headers['x-content-type-options'];
  if (xcto && xcto.toLowerCase().includes('nosniff')) {
    addCheck(
      'X-Content-Type-Options',
      'Passed',
      'Low',
      'MIME sniffing is disabled (nosniff).'
    );
  } else {
    addCheck(
      'X-Content-Type-Options',
      'Warning',
      'Low',
      'X-Content-Type-Options header is missing or not set to nosniff.',
      'Add X-Content-Type-Options: nosniff.'
    );
  }

  // 6. Referrer-Policy
  const refPolicy = headers['referrer-policy'];
  if (refPolicy) {
    addCheck(
      'Referrer-Policy',
      'Passed',
      'Low',
      `Referrer information is controlled (${refPolicy}).`
    );
  } else {
    addCheck(
      'Referrer-Policy',
      'Warning',
      'Low',
      'Referrer-Policy header is missing; browser defaults will be used.',
      'Add Referrer-Policy: strict-origin-when-cross-origin.'
    );
  }

  // 7. Clickjacking Protection (X-Frame-Options or CSP frame-ancestors)
  const xfo = headers['x-frame-options'];
  const hasFrameAncestors = csp && csp.includes('frame-ancestors');
  if (xfo || hasFrameAncestors) {
    addCheck(
      'X-Frame-Options',
      'Passed',
      'Medium',
      'Frame embedding / clickjacking defenses are in place.'
    );
  } else {
    addCheck(
      'X-Frame-Options',
      'Warning',
      'Low',
      'X-Frame-Options and CSP frame-ancestors are missing. Site may be embeddable in external iframes.',
      'Add X-Frame-Options: SAMEORIGIN or DENY.'
    );
  }

  // Weighted scoring calculation (Passed=0, Warning=0.5, Failed=1.0)
  // Severity weights: High=3, Medium=2, Low=1
  const statusWeight = { Passed: 0.0, Warning: 0.5, Failed: 1.0 };
  const severityWeight = { High: 3, Medium: 2, Low: 1 };

  let totalWeight = 0;
  let penaltySum = 0;

  for (const [, status, severity] of checks) {
    if (status === 'Not assessed') continue;
    const w = severityWeight[severity] || 1;
    const penalty = statusWeight[status] !== undefined ? statusWeight[status] : 1.0;
    totalWeight += w;
    penaltySum += w * penalty;
  }

  const score = totalWeight > 0 ? Math.round((penaltySum / totalWeight) * 100) : null;

  return {
    status: 'live',
    score,
    checks,
    findings,
    positiveFindings,
    evidence,
  };
}

module.exports = {
  analyze,
};
