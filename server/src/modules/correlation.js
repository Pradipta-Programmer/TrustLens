// Evidence correlation and risk scoring engine for TRUSTLENS.
// Aggregates findings from threat heuristics, website security, TLS certificate,
// and community intelligence modules into an explainable, normalized trust assessment.

const WEIGHTS = Object.freeze({
  threat: 0.40,
  security: 0.15,
  certificate: 0.20,
  community: 0.25,
});

const THRESHOLDS = Object.freeze({
  LOW: 25,
  MODERATE: 50,
  HIGH: 75,
});

/**
 * Classifies a 0-100 score into a standardized risk level.
 *
 * @param {number} score
 * @returns {{ label: string, level: string, color: string }}
 */
function classifyRisk(score) {
  if (score < THRESHOLDS.LOW) {
    return { label: 'Low Risk', level: 'low', color: 'ok' };
  }
  if (score < THRESHOLDS.MODERATE) {
    return { label: 'Moderate Risk', level: 'medium', color: 'warn' };
  }
  if (score < THRESHOLDS.HIGH) {
    return { label: 'High Risk', level: 'high', color: 'bad' };
  }
  return { label: 'Critical Risk', level: 'critical', color: 'bad' };
}

/**
 * Correlates outputs from individual assessment modules into a unified report.
 *
 * @param {object} moduleResults - Object containing `{ threat, security, certificate, community }`.
 * @param {object} meta - Context metadata (url, hostname, timestamp).
 * @returns {object} Correlated assessment.
 */
function correlate(moduleResults = {}, meta = {}) {
  const threatResult = moduleResults.threat || { status: 'not_assessed', score: null, findings: [], positiveFindings: [] };
  const secResult = moduleResults.security || { status: 'not_assessed', score: null, findings: [], positiveFindings: [], checks: [] };
  const certResult = moduleResults.certificate || { status: 'not_assessed', score: null, findings: [], positiveFindings: [] };
  const commResult = moduleResults.community || { status: 'not_assessed', score: null, findings: [], positiveFindings: [], rep: { n: 0, uniq: 0, ver: 0, risk: null } };

  const moduleScores = {
    threat: threatResult.status === 'live' && threatResult.score !== null ? threatResult.score : null,
    security: secResult.status === 'live' && secResult.score !== null ? secResult.score : null,
    certificate: certResult.status === 'live' && certResult.score !== null ? certResult.score : null,
    community: commResult.status === 'live' && commResult.score !== null ? commResult.score : null,
  };

  // 1. Normalized scoring across assessed modules ONLY
  // Do NOT penalize for unavailable modules (omit them from weight sum)
  let weightedSum = 0;
  let weightSum = 0;
  let assessedModuleCount = 0;
  const totalModuleCount = Object.keys(WEIGHTS).length;

  for (const [modName, weight] of Object.entries(WEIGHTS)) {
    const score = moduleScores[modName];
    if (score !== null && score !== undefined) {
      weightedSum += score * weight;
      weightSum += weight;
      assessedModuleCount++;
    }
  }

  const finalScore = weightSum > 0 ? Math.round(weightedSum / weightSum) : 0;
  const coveragePercent = Math.round((assessedModuleCount / totalModuleCount) * 100);

  // 2. Separate confidence calculation from risk score
  // Scales with assessed coverage, community corroboration, and data completeness
  let confidenceValue = 25 + (assessedModuleCount * 12);
  const repStats = commResult.rep || { n: 0, uniq: 0, ver: 0 };
  if (repStats.ver > 0) {
    confidenceValue += Math.min(25, repStats.ver * 15);
  } else if (repStats.n > 0) {
    confidenceValue += Math.min(15, repStats.n * 3);
  }
  if (certResult.cert && certResult.cert.chain) {
    confidenceValue += 10;
  }
  // Data completeness: verified Certificate Transparency history boosts assessment confidence
  if (certResult.cert?.ct?.status === 'available' || certResult.cert?.ct?.status === 'cached') {
    confidenceValue += 5;
  }
  const confidence = Math.min(95, Math.max(15, confidenceValue));
  const confidenceLevel = confidence >= 70 ? 'High' : (confidence >= 50 ? 'Medium' : 'Low');

  // 3. Risk classification
  const classification = classifyRisk(finalScore);

  // 4. Deduplicate and synthesize findings
  const positiveFindingsSet = new Set();
  const negativeFindingsSet = new Set();
  const allFindings = [];

  const addUnique = (targetSet, list, sourceName) => {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      const text = typeof item === 'string' ? item : item.explanation;
      if (text && !targetSet.has(text)) {
        targetSet.add(text);
        if (typeof item === 'object') {
          allFindings.push({ ...item, module: sourceName });
        } else {
          allFindings.push({ explanation: text, module: sourceName });
        }
      }
    }
  };

  addUnique(positiveFindingsSet, threatResult.positiveFindings, 'threat');
  addUnique(positiveFindingsSet, secResult.positiveFindings, 'security');
  addUnique(positiveFindingsSet, certResult.positiveFindings, 'certificate');
  addUnique(positiveFindingsSet, commResult.positiveFindings, 'community');

  addUnique(negativeFindingsSet, threatResult.findings, 'threat');
  addUnique(negativeFindingsSet, secResult.findings, 'security');
  addUnique(negativeFindingsSet, certResult.findings, 'certificate');
  addUnique(negativeFindingsSet, commResult.findings, 'community');

  const positiveFindings = Array.from(positiveFindingsSet);
  const negativeFindings = Array.from(negativeFindingsSet);

  // 5. Actionable recommendations based on score and specific findings
  const recommendations = [];
  if (finalScore >= THRESHOLDS.HIGH) {
    recommendations.push('Do not enter passwords, credit card numbers, or financial credentials on this website.');
    recommendations.push('Close the browser tab and verify the organization through official, independently verified channels.');
    recommendations.push('If you suspect fraudulent activity, submit a report to the community.');
  } else if (finalScore >= THRESHOLDS.LOW) {
    recommendations.push('Exercise caution: verify the exact domain spelling before providing sensitive personal information.');
    recommendations.push('Inspect the TLS certificate details and verify that the issuer matches the expected organization.');
  } else {
    recommendations.push('No critical indicators observed. Continue with standard web browsing caution.');
  }

  // Specific recommendations from findings
  if (moduleScores.security !== null && moduleScores.security > 40) {
    recommendations.push('Website administrator: configure missing security headers (HSTS, CSP, X-Content-Type-Options).');
  }
  if (certResult.cert && certResult.cert.days < 14 && certResult.cert.days >= 0) {
    recommendations.push('Website administrator: renew the TLS certificate before it expires.');
  }
  if (threatResult.impersonation && Array.isArray(threatResult.evidence) && threatResult.evidence.some(e => e.includes('CT log names corroborate') || e.includes('CT SAN references'))) {
    recommendations.push(`Exercise extreme caution: Certificate Transparency logs corroborate brand resemblance (${threatResult.impersonation.brand}) on an unverified domain.`);
  }

  // 6. Synthesis / Explanation
  let explanation = '';
  if (assessedModuleCount === 0) {
    explanation = 'No modules were assessed. Unable to generate trust intelligence.';
  } else if (finalScore < THRESHOLDS.LOW) {
    explanation = `Overall risk is low (${finalScore}/100) across ${assessedModuleCount} assessed module(s). No major security deficiencies or threat indicators detected.`;
  } else if (finalScore < THRESHOLDS.MODERATE) {
    explanation = `Moderate risk score (${finalScore}/100). The site displays minor security header omissions or unusual URL patterns that warrant caution.`;
  } else if (finalScore < THRESHOLDS.HIGH) {
    explanation = `High risk score (${finalScore}/100). Significant security risks, certificate issues, or multiple suspicious URL heuristics were detected.`;
  } else {
    explanation = `Critical risk score (${finalScore}/100). Severe risk indicators detected (verified reports, impersonation patterns, or expired/mismatched certificates).`;
  }

  // Frontend compatibility bridge:
  const compatFormat = {
    threatPoints: threatResult.score || 0,
    threatFindings: (threatResult.findings || []).map(f => [f.points || 10, f.explanation]),
    positiveList: positiveFindings,
    negativeList: negativeFindings,
    impersonation: threatResult.impersonation || null,
    fx: {
      sec: secResult.checks || [],
      cert: certResult.cert || null,
    },
  };

  return {
    score: finalScore,
    riskLevel: classification.level,
    classification: classification.label,
    confidence,
    confidenceLevel,
    coverage: coveragePercent,
    assessedModules: assessedModuleCount,
    totalModules: totalModuleCount,
    modulesAssessed: `${assessedModuleCount}/${totalModuleCount}`,
    isDemo: false,
    weights: WEIGHTS,
    explanation,
    modules: {
      threat: threatResult,
      security: secResult,
      certificate: certResult,
      community: commResult,
    },
    findings: allFindings,
    positiveFindings,
    negativeFindings,
    recommendations,
    // Frontend compatibility fields
    m: {
      threat: moduleScores.threat,
      sec: moduleScores.security,
      cert: moduleScores.certificate,
      comm: moduleScores.community,
    },
    a: {
      t: compatFormat.threatPoints,
      f: compatFormat.threatFindings,
      pos: compatFormat.positiveList,
      neg: compatFormat.negativeList,
      imp: compatFormat.impersonation,
      isDemo: false,
      fx: {
        sec: compatFormat.fx.sec,
        cert: compatFormat.fx.cert,
        isDemo: false,
      },
    },
    rep: commResult.rep || { n: 0, uniq: 0, ver: 0, risk: moduleScores.community },
    host: meta.hostname || '',
    url: meta.url || '',
    time: meta.time || new Date().toISOString(),
  };
}

module.exports = {
  WEIGHTS,
  THRESHOLDS,
  classifyRisk,
  correlate,
};
