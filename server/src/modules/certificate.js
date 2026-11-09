// TLS certificate intelligence module for TRUSTLENS.
// Analyzes certificate information obtained from verified TLS connections.
// Evaluates validity dates, expiration, subject/issuer, hostname matching, and verification status.
// Never disables TLS verification to obtain certificates.
// Handles unavailable or plain-HTTP endpoints honestly.

/**
 * Evaluates TLS certificate metadata from safeFetch response.
 *
 * @param {object} ctx - Context object containing `fetchResult` (with `tls`) and target hostname.
 * @returns {Promise<object>} Structured certificate module assessment.
 */
async function analyze(ctx = {}) {
  const fetchResult = ctx.fetchResult;
  const inputUrlStr = ctx.url || (ctx.parsedUrl ? ctx.parsedUrl.href : '');

  let parsed;
  try {
    parsed = ctx.parsedUrl || new URL(inputUrlStr);
  } catch {
    parsed = null;
  }

  // If input URL is plain HTTP without TLS:
  if (parsed && parsed.protocol === 'http:' && (!fetchResult || !fetchResult.tls)) {
    return {
      status: 'not_assessed',
      score: null,
      findings: [{
        name: 'No TLS in Use',
        severity: 'Info',
        explanation: 'Website connection is unencrypted plain HTTP; no TLS certificate was presented.',
        evidence: 'http://',
      }],
      positiveFindings: [],
      evidence: ['No TLS connection established (plain HTTP).'],
      cert: null,
      note: 'Certificate intelligence not assessed for plain HTTP endpoint.',
    };
  }

  // If no TLS metadata available from fetchResult
  if (!fetchResult || !fetchResult.tls || !fetchResult.tls.peerCertificate) {
    return {
      status: 'unavailable',
      score: null,
      findings: [{
        name: 'TLS Certificate Unavailable',
        severity: 'Medium',
        explanation: 'Could not extract peer certificate metadata from the connection.',
        evidence: 'Peer certificate unavailable',
      }],
      positiveFindings: [],
      evidence: ['TLS certificate data was unavailable.'],
      cert: null,
      note: 'Certificate data could not be retrieved from the target host.',
    };
  }

  const tlsData = fetchResult.tls;
  const peerCert = tlsData.peerCertificate;
  const hostname = (parsed ? parsed.hostname : '').toLowerCase();

  const findings = [];
  const positiveFindings = [];
  const evidence = [];
  let riskPoints = 0;

  // 1. Certificate Issuer & Subject
  const issuerOrg = peerCert.issuer ? (peerCert.issuer.O || peerCert.issuer.CN || 'Unknown CA') : 'Unknown CA';
  const subjectCN = peerCert.subject ? (peerCert.subject.CN || 'Unknown') : 'Unknown';

  // 2. Expiration Date & Days Remaining
  let daysRemaining = null;
  const certExpiry = peerCert.validTo || peerCert.valid_to;
  if (certExpiry) {
    const expiryTime = new Date(certExpiry).getTime();
    if (!isNaN(expiryTime)) {
      daysRemaining = Math.round((expiryTime - Date.now()) / (1000 * 60 * 60 * 24));
    }
  }

  if (daysRemaining !== null) {
    if (daysRemaining < 0) {
      riskPoints += 50;
      findings.push({
        name: 'Certificate Expired',
        severity: 'High',
        explanation: `The TLS certificate expired ${Math.abs(daysRemaining)} day(s) ago.`,
        evidence: `Expired on ${certExpiry}`,
      });
      evidence.push(`Certificate expired on ${certExpiry}`);
    } else if (daysRemaining < 14) {
      riskPoints += 20;
      findings.push({
        name: 'Certificate Expiring Soon',
        severity: 'Medium',
        explanation: `The TLS certificate will expire in ${daysRemaining} day(s).`,
        evidence: `Expires on ${certExpiry}`,
      });
      evidence.push(`Certificate expires in ${daysRemaining} days`);
    } else {
      positiveFindings.push(`Certificate is valid and active with ${daysRemaining} days remaining.`);
      evidence.push(`Certificate valid for ${daysRemaining} more days`);
    }
  }

  // 3. Hostname Matching
  let hostnameMatch = false;
  const altNames = [];

  if (peerCert.subjectaltname) {
    // format: "DNS:example.com, DNS:*.example.com, IP Address:..."
    const parts = peerCert.subjectaltname.split(',').map(s => s.trim());
    for (const part of parts) {
      if (part.startsWith('DNS:')) {
        altNames.push(part.slice(4).toLowerCase());
      }
    }
  }
  if (subjectCN && subjectCN !== 'Unknown') {
    altNames.push(subjectCN.toLowerCase());
  }

  // Check matching including wildcard match (*.domain.com)
  hostnameMatch = altNames.some(pattern => {
    if (pattern === hostname) return true;
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(2);
      const hostParts = hostname.split('.');
      if (hostParts.length > 2) {
        return hostname.endsWith(`.${suffix}`);
      }
    }
    return false;
  });

  if (hostnameMatch) {
    positiveFindings.push(`Certificate Subject / SAN matches requested hostname (${hostname}).`);
    evidence.push(`Hostname match confirmed for ${hostname}`);
  } else {
    riskPoints += 30;
    findings.push({
      name: 'Certificate Hostname Mismatch',
      severity: 'High',
      explanation: `Certificate does not match requested host "${hostname}". SANs: ${altNames.slice(0, 3).join(', ') || 'none'}.`,
      evidence: `Requested: ${hostname}, Present: ${altNames.join(', ')}`,
    });
    evidence.push(`Hostname mismatch between ${hostname} and certificate SAN`);
  }

  // 4. Chain Verification Result
  const isChainAuthorized = tlsData.authorized === true;
  if (isChainAuthorized) {
    positiveFindings.push(`Certificate chain verified by trusted Certificate Authority (${issuerOrg}).`);
    evidence.push(`Chain verified by ${issuerOrg}`);
  } else {
    riskPoints += 35;
    const authErr = tlsData.authorizationError || 'Self-signed or untrusted certificate chain';
    findings.push({
      name: 'Untrusted Certificate Chain',
      severity: 'High',
      explanation: `TLS certificate chain verification failed: ${authErr}.`,
      evidence: authErr,
    });
    evidence.push(`Chain verification failed: ${authErr}`);
  }

  // 5. Historical Certificate Transparency (CT) Observations
  // Distinguish current direct TLS peer certificate from historical CT records.
  // Missing CT data produces an honest unavailable/not_assessed state.
  // CT age, issuer changes, or velocity alone NEVER add risk points.
  let ctInfo = null;
  if (ctx.ct && typeof ctx.ct === 'object') {
    ctInfo = ctx.ct;
  } else if (ctx.ctResult && typeof ctx.ctResult === 'object') {
    ctInfo = ctx.ctResult;
  } else if (ctx.ctData && typeof ctx.ctData === 'object') {
    ctInfo = ctx.ctData;
  } else if (Array.isArray(ctx.ctObservations) && ctx.ctObservations.length > 0) {
    const { analyzeCT } = require('../services/crtshClient');
    const summary = analyzeCT(hostname, ctx.ctObservations);
    ctInfo = {
      status: 'available',
      records: ctx.ctObservations,
      summary,
    };
  }

  let ctSummaryObj = {
    status: 'not_assessed',
    source: null,
    totalLogged: null,
    earliest: null,
    latest: null,
    discoveredSANs: [],
    note: 'Certificate Transparency logs not assessed during direct TLS connection.',
    disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. They do not establish that a website is safe or malicious.',
  };

  let ctHistory = null;

  if (ctInfo) {
    if (ctInfo.status === 'available' || ctInfo.status === 'cached') {
      const summary = ctInfo.summary || {};
      const totalLogged = typeof summary.totalCerts === 'number'
        ? summary.totalCerts
        : (Array.isArray(ctInfo.records) ? ctInfo.records.length : 0);
      const earliest = summary.earliest || null;
      const latest = summary.latest || null;
      const uniqueSANs = Array.isArray(summary.uniqueSANs) ? summary.uniqueSANs : [];
      const youngCert = summary.youngCert === true;
      const highVelocity = summary.highVelocity === true;

      ctSummaryObj = {
        status: ctInfo.status,
        source: ctInfo.source || 'crt.sh',
        totalLogged,
        earliest,
        latest,
        discoveredSANs: uniqueSANs.slice(0, 20),
        note: ctInfo.note || null,
        disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. They do not establish that a website is safe or malicious.',
      };

      ctHistory = {
        totalLogged,
        earliest,
        latest,
        uniqueSANsCount: uniqueSANs.length,
        youngCert,
        highVelocity,
      };

      if (totalLogged > 0) {
        const earliestStr = earliest ? new Date(earliest).toLocaleDateString() : 'recorded past';
        const latestStr = latest ? new Date(latest).toLocaleDateString() : 'recent';
        positiveFindings.push(`Certificate Transparency log history observed: ${totalLogged} certificate(s) publicly recorded between ${earliestStr} and ${latestStr}.`);
        evidence.push(`CT log history: ${totalLogged} cert(s) recorded`);
      }

      if (youngCert) {
        findings.push({
          name: 'Recently Logged Certificate History',
          severity: 'Info',
          points: 0,
          explanation: `Domain was first observed in Certificate Transparency records within the last 30 days (${earliest ? new Date(earliest).toLocaleDateString() : 'recent'}). Common for new projects or recently established domains.`,
          evidence: `First CT log: ${earliest || 'Within 30 days'}`,
        });
        evidence.push('First public certificate recorded within last 30 days');
      }

      if (highVelocity) {
        findings.push({
          name: 'Elevated Issuance Velocity',
          severity: 'Info',
          points: 0,
          explanation: `Observed elevated certificate issuance rate (${summary.recentCount || 'Multiple'} certificates logged in the past 7 days). This can reflect automated rotation, multi-subdomain provisioning, or frequent re-issuance.`,
          evidence: `${summary.recentCount || 'Multiple'} certificates in 7 days`,
        });
        evidence.push('Elevated certificate issuance velocity observed');
      }
    } else if (ctInfo.status === 'unavailable') {
      ctSummaryObj = {
        status: 'unavailable',
        source: 'crt.sh',
        totalLogged: null,
        earliest: null,
        latest: null,
        discoveredSANs: [],
        note: ctInfo.note || 'Historical Certificate Transparency data temporarily unavailable.',
        disclaimer: 'Certificate Transparency logs show publicly recorded certificate issuance. They do not establish that a website is safe or malicious.',
      };
      evidence.push('Certificate Transparency logs unavailable');
    }
  }

  // Honest note: TLS connection verification distinguishes transport security from website legitimacy
  const certScore = Math.min(100, riskPoints);

  const certSummary = {
    issuer: issuerOrg,
    subject: subjectCN,
    san: altNames,
    days: daysRemaining !== null ? daysRemaining : 'Unknown',
    match: hostnameMatch,
    chain: isChainAuthorized,
    validFrom: peerCert.validFrom || peerCert.valid_from || null,
    validTo: peerCert.validTo || peerCert.valid_to || null,
    fingerprint: peerCert.fingerprint,
    ct: ctSummaryObj,
    history: ctHistory,
  };

  return {
    status: 'live',
    score: certScore,
    findings,
    positiveFindings,
    evidence,
    cert: certSummary,
  };
}

module.exports = {
  analyze,
};
