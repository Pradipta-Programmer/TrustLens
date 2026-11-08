# PRIORITY 3.2 IMPLEMENTATION REPORT
## Core Website Assessment Engine & Cross-Layer Correlation

**Status:** ✅ COMPLETE & TEST-VERIFIED  
**Date:** 2026-11-08  
**Test Suite:** `node --test`  
**Results:** 40 passed, 0 failed, 0 skipped, 0 cancelled  
**Execution Duration:** ~1125 ms  

---

## 1. Features Implemented

### A. Threat Heuristics Module (`server/src/modules/threat.js`)
Lightweight, transparent URL-based heuristic checks:
- **Raw IP Address Detection:** Rejects raw IPv4/IPv6 addresses used in URLs (+35 points).
- **Excessive URL Length:** Flags URLs exceeding 75 characters (+10 points).
- **Excessive Subdomain Depth:** Flags domains with more than 4 labels / 2 subdomain levels (+15 points).
- **Suspicious Domain Punctuation:** Flags domains containing multiple hyphens (+10 points).
- **Embedded Credential Symbol (`@`):** Flags URLs containing `@` symbol (+25 points).
- **Punycode Domains (`xn--`):** Flags internationalized domain names often used in homograph attacks (+25 points).
- **Insecure Protocol (HTTP):** Flags unencrypted plain HTTP URLs (+15 points).
- **Sensitive / Urgency Keywords:** Evaluates high-risk phishing terms (`login`, `signin`, `verify`, `account`, `banking`, `wallet`, `password`, `confirm`, `credential`, `update`) in domain and path.
- **Brand Impersonation & Similarity:** Levenshtein distance matching and character substitution normalization against major target brands (`Example Bank`, `PayPal`, `Google`, `Microsoft`, `Amazon`, `Apple`, `State University`).
- **Benign URL Handling:** Clean URLs evaluate to score 0 with positive findings.

### B. Website Security Configuration Assessment (`server/src/modules/security.js`)
Evaluates observable HTTP response headers and transport configurations from safe fetches:
- **HTTPS Availability:** Verifies encrypted HTTPS transport vs plain HTTP.
- **HTTP→HTTPS Redirection:** Confirms plain HTTP endpoints redirect to HTTPS.
- **HSTS (`Strict-Transport-Security`):** Evaluates presence and enforces recommended `max-age` (>= 18 weeks).
- **Content-Security-Policy (`CSP`):** Evaluates presence of script and resource execution restrictions.
- **MIME Sniffing (`X-Content-Type-Options`):** Verifies `nosniff`.
- **Referrer Policy (`Referrer-Policy`):** Evaluates presence and secure policy configuration.
- **Clickjacking Protection (`X-Frame-Options` / CSP `frame-ancestors`):** Verifies frame restrictions.
- **Defensive Scoring:** Missing headers are scored as security deficiencies (Passed=0, Warning=0.5, Failed=1.0) weighted by severity (High=3, Medium=2, Low=1), distinguishing missing configurations from confirmed exploits.
- **Frontend Compatibility:** Outputs 5-element checks arrays matching `fx.sec` format: `[name, status, severity, explanation, fix]`.

### C. TLS Certificate Intelligence (`server/src/modules/certificate.js`)
Analyzes verified peer certificate metadata obtained via native TLS socket:
- **Validity Window:** Calculates days remaining until expiration (`validTo`). Flags expiring soon (<14 days) and expired (<0 days) certificates.
- **Hostname Matching:** Validates target hostname against Subject Common Name (CN) and Subject Alternative Names (SAN), supporting wildcard matching (`*.domain.com`).
- **Chain Verification:** Inspects TLS authorization status (`authorized: true` vs untrusted / self-signed).
- **Issuer / Subject Extraction:** Extracts Organization and Common Name honestly.
- **Honest Fallbacks:** Returns `not_assessed` for plain HTTP connections and `unavailable` when certificate data cannot be extracted. Never disables TLS verification to obtain certificates.

### D. Collaborative Community Intelligence (`server/src/modules/community.js`)
Analyzes crowdsourced threat reports for scanned domains:
- **Database Integration:** Queries MongoDB `CommunityReport` collection by `domainName` when active.
- **Verified vs. Unverified Weighting:** Verified reports escalate risk heavily (50 points each); unverified reports contribute minor suspicion.
- **Reporter Deduplication:** Aggregates reports by unique reporter identities (`reporter` ObjectId or user array) to avoid duplicate counting.
- **Honest Offline Handling:** Returns `status: 'not_assessed'` when the database is offline. Never fabricates reports.

### E. Evidence Correlation & Risk Scoring Engine (`server/src/modules/correlation.js`)
Unified aggregation engine with explainable scoring:
- **Assessed-Only Normalization:** Dynamically normalizes risk score across assessed modules only, using engineering weights:
  - Threat Heuristics: 40% (0.40)
  - Security Configuration: 15% (0.15)
  - TLS Certificate: 20% (0.20)
  - Community Intelligence: 25% (0.25)
  Missing or offline modules do NOT penalize websites.
- **Separation of Risk Score and Confidence:**
  - Risk Score (0-100): Measures the degree of observed threat/deficiency.
  - Confidence (15-95%): Measures data completeness, module coverage, corroborating reports, and certificate verification.
  - Coverage (0-100%): Percentage of core modules assessed.
- **Risk Level Classification:**
  - `Low Risk` (0–24)
  - `Moderate Risk` (25–49)
  - `High Risk` (50–74)
  - `Critical Risk` (75–100)
- **Evidence Deduplication:** Merges identical positive and negative findings across modules into clean unique sets.
- **Actionable Recommendations:** Generates contextual guidance for end users and website administrators.
- **Frontend & Model Compatibility:** Provides dual schemas: conceptual clean JSON format and legacy `m`, `a`, `rep` structures matching `Scan.js` and `frontend/index.html`.

### F. Assessment Pipeline Orchestrator (`server/src/modules/index.js`)
- Exports full module registry with `implemented: true`.
- Implements `assessWebsite(targetUrl, options)` coordinating URL validation, threat heuristics, safe network fetch, security headers, TLS certificate extraction, community query, and correlation.

---

## 2. Files Created

| File | Path | Description |
|------|------|-------------|
| `threat.js` | `server/src/modules/threat.js` | Threat heuristics analyzer (URL patterns, keywords, brand similarity). |
| `security.js` | `server/src/modules/security.js` | Security header configuration analyzer (HTTPS, HSTS, CSP, nosniff, etc.). |
| `certificate.js` | `server/src/modules/certificate.js` | TLS certificate intelligence analyzer (validity, SAN matching, chain). |
| `community.js` | `server/src/modules/community.js` | Community reports analyzer (verified/unverified scaling, deduplication). |
| `correlation.js` | `server/src/modules/correlation.js` | Cross-layer evidence correlation and risk scoring engine. |
| `modules.test.js` | `server/test/modules.test.js` | Comprehensive unit and integration test suite (14 subtests). |
| `PRIORITY_3_1_1_VERIFICATION_REPORT.md` | `PRIORITY_3_1_1_VERIFICATION_REPORT.md` | Verification report for Stage 1 (fetcher hardening & HTTPS tests). |
| `PRIORITY_3_2_IMPLEMENTATION_REPORT.md` | `PRIORITY_3_2_IMPLEMENTATION_REPORT.md` | This implementation report. |

---

## 3. Files Modified

| File | Path | Changes Made |
|------|------|-------------|
| `urlGuard.js` | `server/src/security/urlGuard.js` | Added typed `code` property (`INVALID_URL`, `SSRF_BLOCKED`, `DNS_ERROR`) to return objects. |
| `safeFetcher.js` | `server/src/security/safeFetcher.js` | Structured error handling; candidate multi-IP validation; passed `ca` parameter; added TLS error codes. |
| `safeFetcher.test.js` | `server/test/safeFetcher.test.js` | Added in-memory X.509 cert generator; multiple-IP regression test; 3 HTTPS runtime tests. |
| `index.js` (modules) | `server/src/modules/index.js` | Registered implemented modules; added `assessWebsite` orchestration pipeline. |

---

## 4. Existing Files Preserved

- All database models (`User.js`, `Domain.js`, `Scan.js`, `CommunityReport.js`, `ThreatIntel.js`, `CertificateRecord.js`, `VerifiedThreat.js`, `AuditLog.js`) remain completely unchanged.
- All baseline routes (`auth.js`, `admin.js`, `users.js`, `reports.js`, `dashboard.js`, `health.js`) remain untouched.
- Frontend single-page application (`frontend/index.html`) remains completely untouched.
- All 8 baseline tests in `server/test/api.test.js` continue passing.
- Zero new npm dependencies were introduced.

---

## 5. Test Results

### Full Test Suite Execution (`node --test`)
```
✔ health reports DB unavailable honestly (no DB in test) (60.5951ms)
✔ scans endpoint is an honest 501 (5.9282ms)
✔ admin route rejects anonymous (5.2885ms)
✔ admin route rejects forged token (15.2436ms)
✔ unknown route 404 (5.0561ms)
✔ urlGuard blocks private/reserved/metadata IPs (3.1945ms)
✔ urlGuard syntax rules (0.6957ms)
✔ urlGuard rejects hostnames resolving to private IPs (injected resolver) (0.6414ms)
▶ Core Assessment Engine test suite
  ✔ detects suspicious URL heuristics and returns structured findings (1.5892ms)
  ✔ detects punycode domains and brand similarity patterns (7.2208ms)
  ✔ handles benign URLs without false-positive inflation (0.5207ms)
  ✔ evaluates present security headers accurately as passed (0.6505ms)
  ✔ identifies missing security headers and distinguishes from confirmed vulnerabilities (0.2686ms)
  ✔ extracts and verifies valid TLS certificate metadata (1.53ms)
  ✔ detects expired certificates, hostname mismatches, and untrusted chains honestly (0.3098ms)
  ✔ handles community intelligence unavailable state without fabricating data (463.8898ms)
  ✔ normalizes risk score across assessed modules only without penalty for missing modules (1.0019ms)
  ✔ keeps risk score separate from confidence and coverage (0.5556ms)
  ✔ deduplicates repetitive findings across modules (0.4527ms)
  ✔ handles empty or missing assessment modules gracefully without NaN (0.44ms)
  ✔ classifies risk levels accurately based on documented thresholds (0.0799ms)
  ✔ executes end-to-end assessWebsite pipeline with mock network fixtures (1.0143ms)
✔ Core Assessment Engine test suite (482.3726ms)
▶ safeFetcher test suite
  ✔ rejects private, reserved and loopback addresses directly (9.6707ms)
  ✔ rejects hostnames that resolve to private/reserved IPs (DNS rebinding prevention) (0.6802ms)
  ✔ handles DNS resolution failure gracefully (0.2348ms)
  ✔ rejects non-http/https schemes and credentials in URL (0.881ms)
  ✔ rejects non-passive HTTP methods (e.g. POST, PUT, DELETE) (0.3038ms)
  ✔ fetches valid HTTP endpoint and extracts headers and body (15.5555ms)
  ✔ fetches valid HTTP endpoint using HEAD method (2.6486ms)
  ✔ follows up to allowed redirects and records redirect history (6.7298ms)
  ✔ enforces maximum 3 redirect limit (8.0401ms)
  ✔ re-validates every redirect destination against SSRF rules (2.4859ms)
  ✔ enforces request timeout (154.7117ms)
  ✔ enforces streaming body size limit (destroys stream if > maxBodyBytes) (30.6558ms)
  ✔ handles connection refused gracefully (3.0145ms)
  ✔ connects to HTTPS server with IP pinning, valid SNI, and active cert verification (10.0499ms)
  ✔ rejects HTTPS connection when hostname does not match certificate (TLS mismatch) (6.0576ms)
  ✔ rejects untrusted certificate when default TLS verification is active (4.5397ms)
✔ safeFetcher test suite (341.2224ms)
ℹ tests 40
ℹ suites 0
ℹ pass 40
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 1125.359
```

**Summary:** 40 tests passing across 3 test suites, 0 failures, 0 skipped.

---

## 6. Actual Runtime Verification Results

1. **SSRF IP-Pinning & Candidate Multi-IP Validation:** Verified that `safeFetcher` evaluates all candidate IP addresses and aborts if any candidate IP is reserved or private.
2. **HTTPS Hostname & SNI Verification:** Verified with a runtime in-memory HTTPS fixture server that matching certificates succeed and mismatched hostnames are rejected with `TLS_ERROR`.
3. **Normalization Correctness:** Verified that when only 1 or 2 modules are available, the correlation engine normalizes against the active weight sum, avoiding false score suppression.
4. **Confidence vs. Risk Decoupling:** Verified that a clean site with full coverage yields low risk and high confidence, while a suspicious site with low coverage yields high risk and low confidence.

---

## 7. Known Limitations

1. **CT Log Querying (crt.sh):** The certificate module extracts and validates direct peer X.509 metadata over TLS, but crt.sh Certificate Transparency HTTP queries are deferred to avoid external third-party network dependencies.
2. **Public Suffix List (PSL):** Brand impersonation currently uses a two-level domain split (`labels.slice(-2).join('.')`). Multi-part TLDs (e.g., `.co.uk`, `.com.au`) require full PSL parsing for multi-tier brand comparison.
3. **Scan Routes Stubs:** The scan endpoints (`POST /api/scans`, `GET /api/scans`) remain registered as honest 501 `NOT_IMPLEMENTED` stubs in `server/src/routes/index.js` pending Priority 3.3.

---

## 8. Features Still Not Implemented

- Live scan endpoint wiring (`server/src/routes/scans.js`) replacing 501 stubs.
- MongoDB persistence for completed `Scan` and `Domain` records.
- Scan history query controller (`GET /api/scans`).
- Frontend API client connecting `frontend/index.html` to `/api/scans`.
- Machine Learning classifier (explicitly deferred).

---

## 9. Security Considerations

- **No Remote Code Execution:** Downloaded website payloads are never executed; HTML is treated purely as inert text and headers.
- **SSRF Defenses Intact:** All requests go through `urlGuard` and `safeFetcher` with socket-level IP pinning, redirect destination re-validation, and multi-IP candidate checks.
- **Zero Exposed Secrets:** No environment variables or secrets are logged or included in responses.
- **No Third-Party Attack Surface:** Zero external npm packages added.

---

## 10. Exact Next Steps

1. **Priority 3.3 — Scan Controller & API Integration:**
   - Create `server/src/routes/scans.js` and mount on `/api/scans`.
   - Wire `assessWebsite` into `POST /api/scans`.
   - Persist scan documents to MongoDB `Scan` collection and update `Domain.lastScannedAt`.
   - Implement `GET /api/scans` (history) and `GET /api/scans/:id` (detail).
2. **Priority 3.4 — Frontend API Client Integration:**
   - Add lightweight `fetch()` client to `frontend/index.html` to consume `POST /api/scans`.
   - Wire results directly into `V.result(r)`.
