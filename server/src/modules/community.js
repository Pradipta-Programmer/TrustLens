// Community intelligence module for TRUSTLENS.
// Analyzes crowdsourced and verified community reports for a scanned domain.
// Queries the CommunityReport collection when available.
// Treats community reports as supporting evidence, distinguishing verified vs unverified reports.
// If the database is disconnected or unavailable, honestly returns 'not_assessed' without fabricating data.

/**
 * Assesses community threat reports for a given domain.
 *
 * @param {object} ctx - Context object with `domainName` (string) and optional `models` or `reports` override.
 * @returns {Promise<object>} Structured community intelligence module assessment.
 */
async function analyze(ctx = {}) {
  const domainName = (ctx.domainName || (ctx.parsedUrl ? ctx.parsedUrl.hostname : '')).toLowerCase();
  if (!domainName) {
    return {
      status: 'not_assessed',
      score: null,
      findings: [],
      evidence: [],
      rep: { n: 0, uniq: 0, ver: 0, risk: 0 },
      note: 'No domain name provided for community analysis',
    };
  }

  let reports = null;

  // 1. Allow explicit report fixtures / injected data for isolated testing
  if (Array.isArray(ctx.reports)) {
    reports = ctx.reports.filter(r => (r.domainName || r.domain || '').toLowerCase() === domainName);
  } else {
    // 2. Query MongoDB via CommunityReport model if available and connected
    try {
      const CommunityReport = ctx.models?.CommunityReport || require('../models/CommunityReport');
      const mongoose = require('mongoose');

      // Check if mongoose has an active connection (readyState === 1)
      if (mongoose.connection && mongoose.connection.readyState === 1) {
        reports = await CommunityReport.find({ domainName }).lean();
      }
    } catch {
      reports = null;
    }
  }

  // If database is unavailable and no data was provided: honestly return 'not_assessed'
  if (reports === null) {
    return {
      status: 'not_assessed',
      score: null,
      findings: [],
      evidence: [],
      rep: { n: 0, uniq: 0, ver: 0, risk: null },
      note: 'Community reports database is currently offline or unconfigured.',
    };
  }

  const totalReports = reports.length;
  const verifiedReports = reports.filter(r => r.status === 'verified');
  const underVerificationReports = reports.filter(r => r.status === 'under_verification');
  const pendingReports = reports.filter(r => r.status === 'pending_review');

  // Avoid duplicate reporter counting: collect unique reporter identities
  const uniqueReporters = new Set();
  for (const r of reports) {
    const repId = r.reporter ? String(r.reporter) : (Array.isArray(r.users) ? r.users : null);
    if (Array.isArray(repId)) {
      repId.forEach(u => uniqueReporters.add(u));
    } else if (repId) {
      uniqueReporters.add(repId);
    }
  }
  const uniqueReporterCount = uniqueReporters.size || totalReports;

  const findings = [];
  const positiveFindings = [];
  const evidence = [];

  // Community risk score formula:
  // Verified reports heavily escalate risk (50 pts each, capped at 100).
  // Unverified/under-verification reports contribute moderate suspicion.
  let riskScore = 0;
  if (totalReports === 0) {
    riskScore = 0;
    positiveFindings.push('No community threat reports recorded for this domain.');
    evidence.push('0 community reports found');
  } else {
    const verRisk = verifiedReports.length * 50;
    const underVerRisk = underVerificationReports.length * 15;
    const pendingRisk = pendingReports.length * 5;
    riskScore = Math.min(100, verRisk + underVerRisk + pendingRisk);

    if (verifiedReports.length > 0) {
      findings.push({
        name: 'Verified Community Reports',
        severity: 'High',
        explanation: `${verifiedReports.length} independent community threat report(s) have been verified by administrators.`,
        evidence: `${verifiedReports.length} verified report(s)`,
      });
      evidence.push(`${verifiedReports.length} verified community report(s)`);
    }

    if (underVerificationReports.length > 0 || pendingReports.length > 0) {
      const unverifiedCount = underVerificationReports.length + pendingReports.length;
      findings.push({
        name: 'Community Submissions Under Review',
        severity: 'Low',
        explanation: `${unverifiedCount} community report(s) submitted by ${uniqueReporterCount} user(s) are awaiting verification.`,
        evidence: `${unverifiedCount} unverified report(s) from ${uniqueReporterCount} unique user(s)`,
      });
      evidence.push(`${unverifiedCount} unverified community report(s)`);
    }
  }

  const repSummary = {
    n: totalReports,
    uniq: uniqueReporterCount,
    ver: verifiedReports.length,
    risk: riskScore,
  };

  return {
    status: 'live',
    score: riskScore,
    findings,
    positiveFindings,
    evidence,
    rep: repSummary,
  };
}

module.exports = {
  analyze,
};
