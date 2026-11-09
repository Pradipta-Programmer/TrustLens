// Threat heuristics analysis module for TRUSTLENS.
// Performs lightweight, transparent URL-based heuristic checks.
// Evaluates raw IP usage, URL length, subdomain depth, suspicious punctuation,
// punycode, embedded credentials, brand similarity patterns, and pressure keywords.

const net = require('net');

const BRAND_TARGETS = {
  'Example Bank': 'examplebank.com',
  'PayPal': 'paypal.com',
  'Google': 'google.com',
  'Microsoft': 'microsoft.com',
  'Amazon': 'amazon.com',
  'Apple': 'apple.com',
  'State University': 'stateuniversity.edu',
};

const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'verify', 'verification', 'secure',
  'account', 'update', 'banking', 'confirm', 'wallet',
  'password', 'credential', 'recover', 'security', 'billing',
];

/**
 * Computes Levenshtein distance between two strings.
 */
function levenshtein(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return d[a.length][b.length];
}

/**
 * Normalizes look-alike characters (leetspeak/homoglyphs).
 */
function normalizeSubstitutions(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's')
    .replace(/vv/g, 'w');
}

/**
 * Analyzes target URL using explainable heuristics.
 *
 * @param {object} ctx - Context object with `url` (string) or `parsedUrl` (URL).
 * @returns {Promise<object>} Structured threat module assessment.
 */
async function analyze(ctx = {}) {
  const inputUrl = ctx.url || (ctx.parsedUrl ? ctx.parsedUrl.href : '');
  if (!inputUrl) {
    return {
      status: 'failed',
      score: null,
      findings: [],
      evidence: [],
      note: 'No URL provided for threat heuristic analysis',
    };
  }

  let parsed;
  try {
    parsed = ctx.parsedUrl || new URL(inputUrl);
  } catch {
    return {
      status: 'failed',
      score: null,
      findings: [{
        name: 'Malformed URL',
        severity: 'High',
        explanation: 'The provided URL could not be parsed by the standard URL parser.',
        evidence: inputUrl,
        points: 40,
      }],
      evidence: ['Malformed URL structure'],
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const rawHref = parsed.href;
  const findings = [];
  const positiveFindings = [];
  const evidence = [];
  let threatPoints = 0;

  const addFinding = (name, severity, points, explanation, itemEvidence) => {
    threatPoints += points;
    findings.push({ name, severity, points, explanation, evidence: itemEvidence });
    evidence.push(`${name}: ${itemEvidence}`);
  };

  // 1. Raw IP address usage check
  if (net.isIP(hostname) !== 0) {
    addFinding(
      'Raw IP Address',
      'Medium',
      35,
      'Destination uses a raw IP address instead of a domain name, often used in phishing campaigns.',
      hostname
    );
  }

  // 2. Unusually long URL check (> 75 chars)
  if (rawHref.length > 75) {
    addFinding(
      'Excessive URL Length',
      'Low',
      10,
      `Unusually long URL (${rawHref.length} characters), which can be used to hide real destinations.`,
      `${rawHref.length} characters`
    );
  }

  // 3. Excessive subdomain depth (> 4 labels)
  const labels = hostname.split('.').filter(Boolean);
  if (labels.length > 4) {
    addFinding(
      'Excessive Subdomain Depth',
      'Medium',
      15,
      `Domain contains ${labels.length - 2} subdomain levels, which can be used to disguise destinations.`,
      hostname
    );
  }

  // 4. Suspicious URL punctuation & patterns (multiple hyphens in hostname)
  const hyphenCount = (hostname.match(/-/g) || []).length;
  if (hyphenCount >= 2) {
    addFinding(
      'Multiple Hyphens in Domain',
      'Low',
      10,
      `Domain contains ${hyphenCount} hyphens, a common pattern in counterfeit domains.`,
      `${hyphenCount} hyphens`
    );
  }

  // 5. Presence of @ in URL structure
  if (rawHref.includes('@')) {
    addFinding(
      'Embedded Credential Symbol (@)',
      'High',
      25,
      'URL contains "@", which can cause browsers to discard earlier parts of the URL.',
      '@ in URL'
    );
  }

  // 6. Punycode (internationalized look-alike) domain
  if (hostname.includes('xn--')) {
    addFinding(
      'Punycode Domain',
      'Medium',
      25,
      'Domain uses Punycode (xn--), which can be used in homograph attacks to impersonate characters.',
      hostname
    );
  }

  // 7. Plain HTTP protocol check
  if (parsed.protocol === 'http:') {
    addFinding(
      'Insecure Protocol (HTTP)',
      'Low',
      15,
      'Website is addressed over unencrypted HTTP rather than HTTPS.',
      'http://'
    );
  }

  // 8. Suspicious keywords in hostname and path
  const checkString = `${hostname}${parsed.pathname}`.toLowerCase();
  const matchedKeywords = SUSPICIOUS_KEYWORDS.filter(kw => checkString.includes(kw));
  if (matchedKeywords.length > 0) {
    const kwPoints = Math.min(25, matchedKeywords.length * 8);
    addFinding(
      'Sensitive Keywords',
      'Low',
      kwPoints,
      `URL contains sensitive account or security keywords: ${matchedKeywords.join(', ')}.`,
      matchedKeywords.join(', ')
    );
  }

  // 9. Potential brand impersonation / similarity checks
  let impersonation = null;
  const normalizedHost = normalizeSubstitutions(hostname);
  const hostBase = labels.slice(-2).join('.');

  for (const [brandName, brandDomain] of Object.entries(BRAND_TARGETS)) {
    if (hostBase === brandDomain) {
      positiveFindings.push(`Domain matches registered domain for ${brandName} (${brandDomain}).`);
      break;
    }

    const brandLabel = brandDomain.split('.')[0];
    const hostLabel = labels[0];

    // Contains brand name with extra subdomains or words
    if (normalizedHost.includes(brandLabel) && hostBase !== brandDomain) {
      impersonation = {
        brand: brandName,
        targetDomain: brandDomain,
        evidence: [
          `Domain contains brand keyword "${brandLabel}" but is not hosted on ${brandDomain}.`,
          'Website identity requires verification before entering credentials.',
        ],
      };
      addFinding(
        `Possible Impersonation of ${brandName}`,
        'High',
        35,
        `Domain structure closely resembles ${brandName} (${brandDomain}).`,
        brandName
      );
      break;
    }

    // Levenshtein edit distance similarity
    if (levenshtein(hostLabel, brandLabel) <= 2 && hostLabel !== brandLabel && hostLabel.length >= 4) {
      impersonation = {
        brand: brandName,
        targetDomain: brandDomain,
        evidence: [
          `Domain name is visually similar to ${brandDomain} (possible character substitutions).`,
          'Review the spelling carefully.',
        ],
      };
      addFinding(
        `Possible Typo Impersonation of ${brandName}`,
        'High',
        30,
        `Domain label "${hostLabel}" is very close in spelling to "${brandLabel}".`,
        `${hostLabel} ~ ${brandLabel}`
      );
      break;
    }
  }

  // 10. External Threat Intelligence & Verified Threat indicators
  let verifiedThreat = null;
  let threatIntelMatches = [];

  // Allow injected fixtures in ctx for isolated unit testing
  if (ctx.verifiedThreat) {
    verifiedThreat = ctx.verifiedThreat;
  } else if (ctx.models?.VerifiedThreat) {
    try {
      verifiedThreat = await ctx.models.VerifiedThreat.findOne({ domainName: hostname }).lean();
    } catch {}
  } else {
    try {
      const mongoose = require('mongoose');
      if (mongoose.connection?.readyState === 1) {
        const VerifiedThreat = require('../models/VerifiedThreat');
        verifiedThreat = await VerifiedThreat.findOne({ domainName: hostname }).lean();
      }
    } catch {}
  }

  if (Array.isArray(ctx.threatIntel)) {
    threatIntelMatches = ctx.threatIntel.filter(i => (i.domainName || '').toLowerCase() === hostname);
  } else if (ctx.models?.ThreatIntel) {
    try {
      threatIntelMatches = await ctx.models.ThreatIntel.find({ domainName: hostname }).limit(5).lean();
    } catch {}
  } else {
    try {
      const mongoose = require('mongoose');
      if (mongoose.connection?.readyState === 1) {
        const ThreatIntel = require('../models/ThreatIntel');
        threatIntelMatches = await ThreatIntel.find({ domainName: hostname }).limit(5).lean();
      }
    } catch {}
  }

  // Handle VerifiedThreat match (admin verified community threat)
  if (verifiedThreat) {
    addFinding(
      'Verified Malicious Domain',
      'Critical',
      60,
      `Domain has been investigated and confirmed as malicious by TrustLens security analysts (Category: ${verifiedThreat.category || 'Malicious'}).`,
      verifiedThreat.domainName
    );
    evidence.push(`Confirmed malicious by TrustLens review`);
  }

  // Handle ThreatIntel match (external feeds: URLhaus, OpenPhish)
  if (threatIntelMatches && threatIntelMatches.length > 0) {
    for (const match of threatIntelMatches) {
      const sourceName = match.source === 'urlhaus' ? 'URLhaus (abuse.ch)' : (match.source === 'openphish' ? 'OpenPhish' : match.source);
      addFinding(
        `Known Malicious Feed Match (${match.source.toUpperCase()})`,
        'High',
        50,
        `Domain is actively listed in ${sourceName} threat intelligence under category "${match.category || 'malware'}".`,
        match.url || match.domainName
      );
      evidence.push(`Flagged on ${sourceName} (${match.category})`);
    }
  } else if (!verifiedThreat) {
    positiveFindings.push('No matches found in active external threat intelligence feeds (URLhaus / OpenPhish).');
  }

  // 11. Certificate Transparency (CT) Supporting Threat Intelligence
  // Correlates CT observations (brand-in-SAN, young certificate age, issuance patterns).
  // CT evidence alone NEVER establishes a malicious verdict.
  let ctData = ctx.ct || ctx.ctResult || ctx.ctData || null;
  if (!ctData && Array.isArray(ctx.ctObservations) && ctx.ctObservations.length > 0) {
    const { analyzeCT } = require('../services/crtshClient');
    ctData = {
      status: 'available',
      records: ctx.ctObservations,
      summary: analyzeCT(hostname, ctx.ctObservations),
    };
  }

  if (ctData && (ctData.status === 'available' || ctData.status === 'cached')) {
    const summary = ctData.summary || {};
    const brandInSAN = summary.brandInSAN;

    // Check if domain is the legitimate brand domain itself
    const isLegitBrand = Object.values(BRAND_TARGETS).includes(hostBase);

    if (brandInSAN && !isLegitBrand) {
      const brandDomain = BRAND_TARGETS[brandInSAN] || '';
      // If brand impersonation was ALREADY detected on the hostname, corroborate without double-counting points
      if (impersonation && impersonation.brand === brandInSAN) {
        impersonation.evidence.push(
          `Certificate Transparency logs corroborate brand target: "${brandInSAN}" appears in logged SAN certificates.`
        );
        evidence.push(`CT log names corroborate ${brandInSAN} impersonation`);
      } else {
        // Discovered brand name in CT SANs not previously flagged on hostname.
        // CT observations must remain informational unless independently corroborated by relevant domain evidence.
        // A brand keyword appearing in an unrelated SAN must not establish impersonation.
        // Do not manufacture an impersonation object from CT-only evidence.
        const hasCorroboratingThreat = threatPoints > 0 || verifiedThreat || threatIntelMatches.length > 0;

        if (hasCorroboratingThreat) {
          // Domain has independent threat indicators (e.g. keywords, phishing indicators, threat intel)
          addFinding(
            `Brand Target in Certificate SANs (${brandInSAN})`,
            'Medium',
            15,
            `Certificate Transparency logs contain Subject Alternative Names referencing "${brandInSAN}", though domain is not hosted on ${brandDomain || 'the official brand domain'}.`,
            brandInSAN
          );
          evidence.push(`CT SAN references ${brandInSAN}`);

          if (!impersonation) {
            impersonation = {
              brand: brandInSAN,
              targetDomain: brandDomain,
              evidence: [
                `Domain's logged certificate SANs reference ${brandInSAN}.`,
                'Verify domain identity before entering credentials.',
              ],
            };
          }
        } else {
          // Isolated CT observation without independent domain evidence:
          // Keep informational only (0 pts) so CT alone never escalates verdict, adds 15 points, or triggers an impersonation banner
          addFinding(
            `Brand Target in Certificate SANs (${brandInSAN})`,
            'Info',
            0,
            `Certificate Transparency logs contain Subject Alternative Names referencing "${brandInSAN}". Without independent domain threat indicators, this observation is informational.`,
            brandInSAN
          );
          evidence.push(`CT SAN references ${brandInSAN} (informational; uncorroborated by domain threat indicators)`);
        }
      }
    }

    // CT age context: only supporting context when other threat indicators are present
    if (summary.youngCert && (threatPoints > 0 || verifiedThreat || threatIntelMatches.length > 0)) {
      evidence.push('CT context: Domain certificates first recorded within the last 30 days');
    }

    // Established domain positive indicator
    if (summary.totalCerts > 20 && !brandInSAN && isLegitBrand) {
      positiveFindings.push(`Established certificate history: ${summary.totalCerts} certificates logged across domain lifecycle.`);
    }
  }

  if (findings.length === 0) {
    positiveFindings.push('No suspicious URL structures or obfuscation patterns detected.');
  }

  const score = Math.min(100, threatPoints);

  return {
    status: 'live',
    score,
    findings,
    positiveFindings,
    evidence,
    impersonation,
  };
}

module.exports = {
  analyze,
  levenshtein,
  normalizeSubstitutions,
  BRAND_TARGETS,
  SUSPICIOUS_KEYWORDS,
};
