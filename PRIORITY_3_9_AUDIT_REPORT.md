# PRIORITY 3.9 AUDIT REPORT
## Certificate Transparency (CT) Intelligence Integration

**Status:** 🔍 READ-ONLY AUDIT COMPLETE (Awaiting Review Before Implementation)  
**Date:** 2026-11-09  
**Target Milestone:** Priority 3.9 (Certificate Transparency Intelligence)  
**Project Workspace:** `C:\Users\Pradipta\.gemini\antigravity\scratch\trustlens`  

---

## 1. Executive Summary

This read-only audit evaluates the enhancement of TRUSTLENS Certificate Intelligence with **Certificate Transparency (CT)** data.

Currently, TRUSTLENS evaluates TLS certificates using direct peer-certificate inspection during active TLS connection handshakes. While this provides accurate real-time data regarding the presented certificate (issuer, validity window, days remaining, hostname match, and CA chain trust), it lacks historical visibility, issuance velocity insights, subdomain enumeration through Subject Alternative Names (SANs), and detection of multi-certificate issuance patterns.

Certificate Transparency logs (governed by RFC 6962) provide an append-only, publicly auditable ledger of all certificates issued by publicly trusted Certificate Authorities (CAs). Integrating CT intelligence—specifically via **crt.sh**—will allow TRUSTLENS to surface historical issuance timelines, detect brand keywords across logged SANs, identify recently issued certificates, and provide deeper explainability.

In accordance with strict instructions, **zero source files or database records have been modified** during this audit.

---

## 2. Baseline Audit: What Certificate Information Is Already Collected

Based on inspection of [`server/src/modules/certificate.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/certificate.js), [`server/src/models/CertificateRecord.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CertificateRecord.js), and [`server/src/routes/certificates.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/certificates.js):

| Field / Attribute | Source | Current Collection Status | How It Is Evaluated |
|---|---|---|---|
| **Subject (CN / O)** | TLS Peer Certificate | Collected (`peerCert.subject`) | Checks common name and organizational identity. |
| **Issuer (O / CN)** | TLS Peer Certificate | Collected (`peerCert.issuer`) | Identifies issuing Certificate Authority. |
| **Validity Dates (`validFrom`, `validTo`)** | TLS Peer Certificate | Collected & Persisted | Determines start date and expiration date. |
| **Days Remaining** | Calculated | Collected & Computed | Flags expired (<0d), expiring soon (<14d), or active. |
| **Hostname Match** | TLS Peer Certificate | Collected (`subjectaltname` + CN) | Validates requested hostname against SAN list (including wildcards). |
| **CA Chain Verification** | TLS Handshake Socket | Collected (`tlsData.authorized`) | Confirms trusted root CA authorization or flags self-signed/untrusted. |
| **Subject Alternative Names (SAN)**| TLS Peer Certificate | Collected & Persisted | Array of DNS names listed on the presented certificate. |
| **Certificate Transparency** | Direct Socket Observation | **Stub / Generic Text Only** | Hardcoded text: `"Observed via direct TLS peer certificate inspection."` |

---

## 3. What Certificate Transparency (CT) Information Is Missing

The current inspection is restricted strictly to the **single peer certificate presented on port 443** at scan time. The following critical intelligence dimensions are currently missing:

1. **Historical Issuance Timeline:**
   - When was the first certificate ever logged for this domain?
   - How many total certificates have been issued over the domain's lifetime?
   - Has there been a sudden surge of certificate issuances within the last 24–48 hours?
2. **Subdomain Enumeration via CT SANs:**
   - Threat actors frequently create targeted subdomains (e.g. `login.paypal.verify-account.example`) that are logged in CT before users receive phishing links.
   - Currently, TRUSTLENS only sees the specific hostname requested.
3. **Brand Resemblance Across Logged SANs:**
   - A generic domain (e.g., `cloud-auth-portal.example`) might host phishing pages for specific brands (`chase-login`, `microsoft-verify`) visible only in CT log entries.
4. **CA Diversification & Anomalies:**
   - Has an established domain abruptly switched from an enterprise OV/EV CA (e.g. DigiCert) to a short-lived automated DV CA (e.g. Let's Encrypt / ZeroSSL) immediately prior to suspicious activity?

---

## 4. Evaluation of crt.sh as a CT Data Source

### 4.1 Capabilities & API Interface
- **Operator:** Sectigo.
- **Data Coverage:** Indexes all public RFC 6962 Certificate Transparency logs globally.
- **API Endpoint:**
  `GET https://crt.sh/?q=<domain>&output=json`
- **Response Format (JSON Array):**
  ```json
  [
    {
      "issuer_ca_id": 16418,
      "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
      "common_name": "example.com",
      "name_value": "example.com\nwww.example.com",
      "id": 1234567890,
      "entry_timestamp": "2026-05-01T12:00:00.000",
      "not_before": "2026-05-01T11:00:00",
      "not_after": "2026-07-30T11:00:00",
      "serial_number": "03a1b2c3d4..."
    }
  ]
  ```

### 4.2 Reliability, Availability & Rate Limits
- **Licensing & Terms:** Free public utility for the cybersecurity community. No mandatory API key.
- **Availability Challenges:**
  - `crt.sh` is known to experience periodic PostgreSQL query timeouts or HTTP 502/504 responses during high traffic or when querying domains with hundreds of thousands of certificates (e.g., `cloudflare.com`).
  - Queries for large domains can take between 2 and 10 seconds.
- **Rate Limit Policy:** Sectigo requests reasonable query pacing and discourages aggressive scraping.

### 4.3 Essential Architectural Requirements for crt.sh Integration
1. **Aggressive Timeout & Asynchronous Safety:**
   - Must enforce a strict 3500ms timeout with an `AbortController`.
   - Never allow a slow crt.sh query to stall or fail a website scan.
2. **Honest Degradation:**
   - If crt.sh times out, returns HTTP 502/504, or is unreachable, the system must cleanly record `ct: { status: 'unavailable', note: 'CT log query timed out or service unavailable.' }`.
3. **Response Body Size Limit:**
   - Must stream/cap response at 1 MB to prevent memory exhaustion from mega-domains.
4. **Local Database Caching:**
   - Cache results in `CertificateRecord.ctObservations` with a time-to-live (e.g. 12–24 hours) to minimize external requests to `crt.sh`.
5. **Deterministic Testing:**
   - Must provide offline mock fixtures for test execution so `npm test` never depends on live internet connectivity to `crt.sh`.

---

## 5. Safe Integration Architecture

```
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                                   SCANNER / CERT API                                    │
 │                    (POST /api/scans  or  GET /api/certificates/:domain)                 │
 └───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             │
                                             ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                          CERTIFICATE ASSESSMENT PIPELINE                                │
 │                                                                                         │
 │  Step 1: Direct TLS Socket Inspection (safeFetcher)                                     │
 │          Extract presented peer cert (issuer, validity, match, chain).                  │
 │                                                                                         │
 │  Step 2: Certificate Transparency Client (crtshClient.js)                               │
 │          - Check cached ctObservations in MongoDB (TTL: 12h).                           │
 │          - If cache miss: Query https://crt.sh/?q=<domain>&output=json                  │
 │            * Strict 3500ms timeout                                                      │
 │            * Allowlist check: crt.sh only                                               │
 │            * 1 MB body size cap                                                         │
 │            * If failed/timeout: Graceful fallback to 'unavailable' (never throws)       │
 │                                                                                         │
 │  Step 3: CT Heuristic Analysis                                                          │
 │          - Compute total logged certs, age of earliest cert, age of latest cert.        │
 │          - Extract unique SANs and subdomains.                                          │
 │          - Check for brand keywords in CT SANs (impersonation indicator).               │
 │          - Detect rapid issuance velocity.                                              │
 └───────────────────────────────────────────┬─────────────────────────────────────────────┘
                                             │
                                             ▼
 ┌─────────────────────────────────────────────────────────────────────────────────────────┐
 │                              MONGODB ATLAS PERSISTENCE                                  │
 │                                                                                         │
 │  CertificateRecord:                                                                     │
 │  - domainName: "example.com"                                                            │
 │  - issuer, subject, san, validFrom, validTo, hostnameMatch, chainValid                  │
 │  - ctObservations: [                                                                    │
 │      {                                                                                  │
 │        source: "crt.sh",                                                                │
 │        certId: "1234567890",                                                            │
 │        loggedAt: "2026-05-01T12:00:00Z",                                                │
 │        issuer: "Let's Encrypt",                                                         │
 │        commonName: "example.com",                                                       │
 │        sans: ["example.com", "www.example.com"]                                         │
 │      }                                                                                  │
 │    ]                                                                                    │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Database Changes Assessment

- **Schema Alterations Required:** **NONE.**
- **Existing Schema Verification:**
  Inspection of [`server/src/models/CertificateRecord.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CertificateRecord.js) confirms:
  ```javascript
  const { Schema, model } = require('mongoose');
  module.exports = model('CertificateRecord', new Schema({
    domainName: { type: String, required: true, index: true }, issuer: String, subject: String, san: [String],
    validFrom: Date, validTo: Date, hostnameMatch: Boolean, chainValid: Boolean, ctObservations: [Schema.Types.Mixed],
    mode: { type: String, enum: ['live', 'demo'], required: true }, observedAt: { type: Date, default: Date.now },
  }, { timestamps: true }));
  ```
  `ctObservations: [Schema.Types.Mixed]` is **already present** in the Mongoose schema.
  We can store structured CT logs and summary metadata directly without index migrations or breaking schema modifications.

---

## 7. How CT Evidence Can Improve Threat Intelligence

### 7.1 Correlating CT with Threat Assessment
1. **Brand-Lookalike Domain with Young Certificate:**
   - *Pattern:* Domain matches a brand typo (e.g. `examp1ebank.example`) AND the earliest CT log was created < 48 hours ago.
   - *Correlation:* High confidence indicator of active credential phishing staging.
2. **Brand Keywords in Discovered Subdomains:**
   - *Pattern:* Root domain is `generic-hosting.example`, but CT log reveals SAN `login.bankofamerica.generic-hosting.example`.
   - *Correlation:* Flags brand impersonation even if the root URL itself does not contain the brand name.
3. **High Issuance Velocity:**
   - *Pattern:* 5+ distinct certificates issued within a 7-day period from automated CAs for ephemeral subdomains.
   - *Correlation:* Typical of automated disposable phishing infrastructures.
4. **Established Domain Trust Corroboration:**
   - *Pattern:* Domain has dozens of logged certificates spanning 5+ years with consistent enterprise CAs.
   - *Correlation:* Supports established legitimacy (increases confidence metric).

### 7.2 Strict Safeguards Against Misclassification
- **Golden Rule:** **A newly issued certificate is NOT proof of malicious activity.** Every new website acquires a certificate upon launch.
- **Rule 2:** CT observations alone must **never** mark a domain as malicious or trigger a High/Critical risk verdict without corroborating indicators (such as brand impersonation, URLhaus match, or verified reports).
- **Rule 3:** The distinction between *observed transport certificates* and *verified platform verdicts* must be maintained at all times.

---

## 8. Frontend UI Enhancements

In [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) (`V.cert()`):
1. **Certificate Transparency Summary Card:**
   - **Total CT Logs Recorded:** e.g. `14 certificates logged across 3 years`.
   - **First Observed in CT:** e.g. `First logged: 2023-04-12`.
   - **Latest Issuance:** e.g. `Most recent: 3 days ago`.
2. **Discovered Subdomain / SAN List:**
   - Collapsible list showing subdomains discovered through CT logs.
3. **Honest Unavailable & Loading States:**
   - When crt.sh query is pending: *"Checking Certificate Transparency logs…"*.
   - When crt.sh is slow or unavailable: *"Certificate Transparency logs were temporarily unreachable; live peer certificate verified via TLS handshake."*
4. **Educational Disclaimer:**
   - *"Certificate Transparency logs prove that public CAs recorded certificate issuance. They do not prove that a website's content is safe or trustworthy."*

---

## 9. Security, Privacy & Reliability Risks

1. **SSRF Risk:**
   - *Risk:* Passing arbitrary hostnames into outbound HTTP requests.
   - *Mitigation:* Allowlist only `https://crt.sh/?q=...`. Validate target domain through `validateUrlSyntax`. Discard IP addresses, internal domains, and localhost.
2. **Service Availability / Denial of Service:**
   - *Risk:* `crt.sh` outages causing TRUSTLENS scanner or API requests to hang.
   - *Mitigation:* Hard timeout of 3500ms via `AbortController`. Cache results in MongoDB. Never fail the scan if CT query fails.
3. **Response Flooding:**
   - *Risk:* Huge domains (e.g. `google.com`) returning megabytes of JSON.
   - *Mitigation:* Cap response body at 1 MB. Limit parsed CT records to the most recent 50 entries.

---

## 10. Phased Implementation Roadmap

- **Phase A — CT Client Service (`server/src/services/crtshClient.js`):**
  - Allowlisted HTTPS request to `https://crt.sh/?q=<domain>&output=json`.
  - AbortController with 3500ms timeout and 1MB size limit.
  - Safe parser extracting `entry_timestamp`, `issuer_name`, `common_name`, `name_value` (SANs), and `id`.
  - Analyzer calculating age, issuance velocity, discovered subdomains, and brand-in-SAN patterns.
  - Offline mock provider for test suite.
- **Phase B — Module & Route Integration:**
  - Update [`server/src/modules/certificate.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/certificate.js) to accept CT observations.
  - Update [`server/src/routes/certificates.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/certificates.js) to retrieve CT data on demand, cache in `CertificateRecord`, and format rich CT fields.
  - Update [`server/src/routes/scans.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/scans.js) to persist CT observations.
- **Phase C — Threat Assessment Correlation:**
  - In [`server/src/modules/threat.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/threat.js), correlate brand impersonation with young certificate age / brand-in-SAN patterns.
- **Phase D — Frontend Visualization:**
  - Update `V.cert()` in [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) to render CT timeline, log counts, and discovered subdomains.
- **Phase E — Automated Verification:**
  - Add test suite in `server/test/crtsh.test.js`.
  - Ensure all 120 existing tests continue to pass (target: ~135+ tests).
  - Verify natural process termination.

---

## 11. Affected Files

| Component | File | Nature of Proposed Change |
|---|---|---|
| **CT Client Service** | `server/src/services/crtshClient.js` | NEW: Safe network fetcher, parser, analyzer, mock provider |
| **Certificates Route** | [`server/src/routes/certificates.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/certificates.js) | Fetch & format CT data, cache in `CertificateRecord` |
| **Scan Submission Route**| [`server/src/routes/scans.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/scans.js) | Save CT observations alongside peer certificate |
| **Certificate Module** | [`server/src/modules/certificate.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/certificate.js) | Correlate peer cert with CT timeline & SAN patterns |
| **Threat Module** | [`server/src/modules/threat.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/threat.js) | Detect brand keywords in CT SANs and young cert velocity |
| **Frontend UI** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) | Display CT logs, timeline, discovered SANs, disclaimer |
| **Integration Test Suite**| `server/test/crtsh.test.js` | NEW: Test timeout, allowlist, parsing, caching, correlation |
| **API Documentation** | [`API_DOCUMENTATION.md`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/API_DOCUMENTATION.md) | Document CT schema and response payloads |
| **Project Status** | [`PROJECT_STATUS.md`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/PROJECT_STATUS.md) | Update feature status and test counts |

---

## 12. Test Strategy

1. **Client Isolation & SSRF Defense:** Verify non-allowlisted hosts and plain-HTTP schemes are rejected.
2. **Timeout & Failure Handling:** Verify that simulated slow responses or HTTP 502/504 errors from crt.sh degrade gracefully to `status: 'unavailable'` within 3500ms without throwing uncaught errors.
3. **Data Parsing & Normalization:** Test extraction of SANs, duplicate removal, date parsing, and issuer identification.
4. **Heuristic Evaluation:**
   - Brand in SAN pattern test (flags suspicious keyword).
   - High issuance velocity test.
   - Long-standing domain test (corroborates confidence).
5. **Database Caching:** Verify cached CT logs in `CertificateRecord` prevent redundant external requests.
6. **Regression Guard:** Verify that all 120 existing tests across all test suites remain 100% passing.
