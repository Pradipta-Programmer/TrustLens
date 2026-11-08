# TRUSTLENS — Website Scanner Readiness Audit Report

**Date:** 2026-11-08  
**Audit Type:** Strict Read-Only Technical Readiness Audit  
**Target Subsystem:** Website Scanner, SSRF Defense, and Assessment Modules  
**Repository Path:** `C:\Users\Pradipta\.gemini\antigravity\scratch\trustlens`  

---

## 1. Executive Summary

An architectural and source-code readiness audit was conducted on the TRUSTLENS repository to prepare for the implementation of the live website security scanner. 

The audit evaluated:
1. Existing scan routes and controllers in `server/src/routes/`.
2. Database models (`Scan.js`, `Domain.js`, `CertificateRecord.js`, `ThreatIntel.js`).
3. URL validation and SSRF defenses in `server/src/security/urlGuard.js`.
4. Analysis module contracts in `server/src/modules/index.js`.
5. Outbound network request utilities.
6. Frontend analysis and result rendering logic in `frontend/index.html`.
7. Architectural and API specifications in `ARCHITECTURE.md` and `API_DOCUMENTATION.md`.

### Core Readiness Findings:
- **Database & Data Layer: READY.** The `Scan` and `Domain` schemas are robust, fully indexed, and enforce explicit module statuses (`live`, `demo`, `pending`, `not_assessed`, `unavailable`, `failed`) and isolation modes (`live` vs `demo`). MongoDB Atlas is confirmed connected.
- **SSRF Primitives: SOLID FOUNDATION, MISSING FETCHER PINNING.** `urlGuard.js` provides accurate syntax checking and comprehensive IP blocking for IPv4/IPv6 private, loopback, and cloud metadata ranges. However, it lacks a socket-level pinned network fetcher, leaving future standard HTTP requests vulnerable to Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks.
- **Module Architecture: SCAFFOLDED.** The module registry contract is defined, but all modules currently return `not_assessed`.
- **Zero-Dependency Viability: CONFIRMED.** Live website security header assessment (Module 2) and SSL/TLS certificate inspection (Module 3) can be built entirely using Node.js standard library modules (`http`, `https`, `tls`, `net`, `dns`) without installing any new third-party npm packages.
- **Frontend Compatibility: PRESERVED.** The frontend result view (`V.result`) already defines the exact data structure it expects. The backend scanner can emit this schema directly, enabling seamless integration without breaking existing UI workflows.

---

## 2. Deep-Dive Audit of Existing Implementation

### 2.1 Scan Routes and Controllers
- **Current State:**
  - `POST /api/scans`, `GET /api/scans`, and `GET /api/scans/:id` are registered in [`server/src/routes/index.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/index.js#L10-L12).
  - All three endpoints are routed to `planned(name)` from [`utils/http.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/utils/http.js), returning honest HTTP 501 `NOT_IMPLEMENTED`.
- **What is Missing:**
  - A dedicated router module `server/src/routes/scans.js`.
  - Request body validation using Zod for incoming scan URLs (`z.object({ url: z.string().url().max(2048) })`).
  - Scan execution pipeline coordinating URL validation, domain upsert, parallel module execution, and correlation scoring.
  - Scan history query controller filtering by `domainName` or `requestedBy`.
  - Scan retrieval controller fetching specific scan records by ObjectId.

### 2.2 Database Models
- **`Scan.js` ([`server/src/models/Scan.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Scan.js)):**
  - Fully implements multi-module status tracking (`threat`, `security`, `certificate`, `community`, `impersonation`).
  - Stores `submittedUrl`, `domain` (ObjectId ref), `domainName`, `mode` (`live|demo`), `status` (`queued|running|completed|failed`), `riskScore`, `confidence`, `classification`, `evidence`, and `recommendations`.
  - Compound index `{ domainName: 1, createdAt: -1 }` is already established.
- **`Domain.js` ([`server/src/models/Domain.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Domain.js)):**
  - Acts as the central intelligence anchor. Stores `name`, `reputation`, `firstSeenAt`, and `lastScannedAt`.
- **Integration Verdict:** The database schemas require **zero modifications**. They are fully equipped to support live scanner persistence immediately.

### 2.3 URL Validation & SSRF Defense (`urlGuard.js`)
- **Existing Strengths:**
  - [`LIMITS`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js#L5) constants establish safe boundaries: `maxRedirects: 3`, `timeoutMs: 8000`, `maxBodyBytes: 1000000` (1 MB), `maxUrlLength: 2048`.
  - [`isBlockedIp()`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js#L10) blocks `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `224.0.0.0/4`, `240.0.0.0/4`, IPv6 loopback (`::1`), IPv4-mapped IPv6, link-local (`fe80::/10`), unique local (`fc00::/7`), and multicast (`ff00::/8`).
  - [`validateUrlSyntax()`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js#L17) restricts protocols to `http:` and `https:`, rejects credentials in URLs, and blocks single-label hostnames and `.internal` / `.localhost`.
  - [`resolveAndValidate()`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js#L28) validates that DNS lookups do not resolve to any blocked IP.
- **Critical SSRF Deficiencies to Address in Implementation:**
  1. **DNS Rebinding Vulnerability (TOCTOU):** Performing DNS resolution with `dns.promises.lookup` and subsequently issuing a standard `fetch(url)` causes two distinct DNS lookups. An attacker can serve a public IP on lookup #1 and a private IP (`127.0.0.1` or `169.254.169.254`) on lookup #2.
  2. **Redirect Validation Engine:** While `LIMITS.maxRedirects = 3` is defined, there is no HTTP client that enforces this limit and re-checks each redirect destination IP against `urlGuard`.
  3. **Response Body Truncation:** There is no streaming response consumer that cuts off incoming payloads at 1 MB to prevent memory exhaustion.
  4. **Timeout Enforcement:** Socket connection and read timeouts must be enforced via `AbortSignal.timeout(LIMITS.timeoutMs)`.

### 2.4 Existing Assessment Modules
- **`server/src/modules/index.js`:**
  - Exports a `registry` with 5 modules: `threat`, `security`, `certificate`, `community`, `impersonation`.
  - Currently, every module returns:
    ```javascript
    { status: 'not_assessed', findings: [], evidence: [], note: `${n} module not implemented` }
    ```
- **Requirements for Scanner Phase:**
  - Implement **Module 1 (Threat Heuristics)** on the server.
  - Implement **Module 2 (Website Security)** via live HTTP header inspection.
  - Implement **Module 3 (SSL/TLS Certificate Intelligence)** via native TLS socket connection.
  - Implement **Module 4 (Community Intelligence)** querying verified reports in MongoDB.
  - Implement **Cross-Layer Correlation Engine** aggregating module findings into risk score and confidence.

### 2.5 Outbound HTTP Utilities
- Currently, `server/src/utils/http.js` only provides API response helpers (`ApiError`, `ok`, `wrap`).
- An outbound HTTP fetching service is needed.
- **Zero-Dependency Solution:** Node.js native `http` and `https` modules can create custom agents with socket-level IP pinning, or Node 18+ native `fetch` / `undici` can be configured with an IP-pinned dispatcher.

### 2.6 Frontend Compatibility
- In `frontend/index.html`:
  - `V.scan()` submits URLs.
  - `V.result(r)` expects:
    - Overall: `score`, `conf`, `confL`, `time`, `host`, `url`.
    - Modules: `m.threat`, `m.sec`, `m.cert`, `m.comm`.
    - Breakdown: `a.f` (findings), `pos` (positive list), `neg` (negative list), `imp` (impersonation), `fx.sec` (checks table), `fx.cert` (cert details), `rep` (community stats).
  - The backend `Scan` model structure and response payload can match this format directly, ensuring that when the frontend is wired to `POST /api/scans`, the existing UI renders live results without layout refactoring.

---

## 3. Prioritized Implementation Plan for Scanner Engine

The scanner engine will be constructed systematically in **four distinct steps** to ensure maximum stability and zero regressions:

### Step 1: Safe Network Fetcher Service (`server/src/security/safeFetcher.js`)
- **Objective:** Create a bulletproof outbound HTTP/HTTPS request utility with complete SSRF immunity.
- **Key Technical Controls:**
  1. **Pre-Resolution:** Resolve hostname to IP using `urlGuard.resolveAndValidate()`.
  2. **Socket-Level IP Pinning:** Connect directly to the validated IP address while transmitting the hostname in the `Host` header and TLS SNI (`servername`), preventing DNS rebinding.
  3. **Redirect Hop Tracking:** Follow up to 3 redirects (`LIMITS.maxRedirects: 3`). For each redirect hop (`301`, `302`, `307`, `308`), re-validate the target URL through `urlGuard` before opening the socket.
  4. **Timeout Enforcement:** Enforce `LIMITS.timeoutMs = 8000` via abort controllers and socket timeouts.
  5. **Response Truncation:** Stream body reading with an immediate abort if incoming byte count exceeds `LIMITS.maxBodyBytes = 1000000` (1 MB).
  6. **Passive Only:** Perform only `HEAD` or `GET` requests; never evaluate JavaScript or execute active payloads.

### Step 2: Implementation of Core Cybersecurity Modules

#### Module 2: Live Website Security Assessment (`server/src/modules/security.js`)
- Dispatches a safe request to target URL using `safeFetcher`.
- Inspects response headers and security configurations:
  - **HTTPS Availability:** Protocol is `https:`.
  - **HSTS (`Strict-Transport-Security`):** Header presence, `max-age` value, `includeSubDomains`.
  - **CSP (`Content-Security-Policy`):** Header presence, restrictions on script sources.
  - **MIME Sniffing (`X-Content-Type-Options`):** Verified set to `nosniff`.
  - **Referrer Policy (`Referrer-Policy`):** Verified set to secure policy (e.g., `strict-origin-when-cross-origin`).
  - **HTTP to HTTPS Redirect:** Tests plain HTTP endpoint and confirms 301/302 redirect to HTTPS.
  - **Clickjacking (`X-Frame-Options` / `frame-ancestors`):** Denial or origin restriction.
- Generates structured findings table with status (`Passed`, `Warning`, `Failed`), severity, and actionable remediation instructions.

#### Module 3: Live SSL/TLS Certificate Intelligence (`server/src/modules/certificate.js`)
- Uses Node.js native `tls.connect` to connect directly to the validated IP on port 443 with SNI.
- Extracts peer X.509 certificate metadata:
  - **Issuer:** Organization and Common Name.
  - **Validity Window:** `validFrom`, `validTo`, calculation of days remaining.
  - **Hostname Verification:** Validates target hostname matches Subject CN or Subject Alternative Names (SAN).
  - **Chain Status:** Verifies certificate chain authorization.
  - **Transparency Fallback:** Graceful handling when external CT log services (crt.sh) are unavailable.
- Persists certificate intelligence to `CertificateRecord` collection with `mode: 'live'`.

#### Module 1: Server-Side Threat Heuristics (`server/src/modules/threat.js`)
- Ports URL heuristic analysis from frontend to backend:
  - Raw IP host detection.
  - Excessive URL length (> 75 chars).
  - Excessive subdomain depth (> 4 subdomains).
  - Multiple hyphens in hostname.
  - Punycode detection (`xn--`).
  - Embedded credentials / `@` symbol.
  - Pressure keywords (`login`, `verify`, `account`, `wallet`, `bank`, etc.).
  - Plain HTTP usage.

#### Module 4: Collaborative Community Intelligence (`server/src/modules/community.js`)
- Queries `CommunityReport` collection for the target domain:
  - Counts total reports, unique reporters, and admin-verified reports.
  - Calculates community risk score: verified reports heavily escalate risk, while unverified reports contribute weighted suspicion.

### Step 3: Cross-Layer Correlation Engine (`server/src/modules/correlation.js`)
- Aggregates individual module findings into a unified, explainable trust assessment:
  - **Weighted Scoring:** `threat: 0.40`, `security: 0.15`, `certificate: 0.20`, `community: 0.25` (dynamically normalized across assessed modules).
  - **Coverage & Confidence Calculation:** Base confidence dynamically scales with module coverage, report corroboration, and data certainty (independent of risk score).
  - **Classification:** Categorizes final score into `Low Risk` (<25), `Moderate Risk` (25-49), `High Risk` (50-74), `Critical Risk` (75-100).
  - **Explainable Findings Synthesis:** Generates human-readable positive findings, negative findings, and prioritized defensive recommendations.

### Step 4: Scan Controller & API Integration (`server/src/routes/scans.js`)
- Replaces 501 stubs with live controllers:
  - `POST /api/scans`: Validates URL with Zod, checks rate limits, upserts `Domain`, executes scan pipeline, persists `Scan` document in MongoDB, and returns complete report.
  - `GET /api/scans`: Queries scan history by domain or user, sorted by `createdAt: -1`.
  - `GET /api/scans/:id`: Retrieves detailed findings for a completed scan.
- Ensures graceful fallback: if external networks or target sites timeout, the module status is set to `unavailable` or `failed` rather than crashing the request.

---

## 4. Scope Boundaries for Next Implementation Phase

### A. Included Functionality (Target Phase Scope):
1. **Safe Outbound HTTP/HTTPS Fetcher (`safeFetcher.js`):**
   - Socket IP-pinning (DNS rebinding prevention).
   - Up to 3 validated redirects.
   - 8-second timeout.
   - 1 MB body stream cap.
2. **Module 1 (Threat Heuristics):**
   - Server-side heuristic feature extraction.
3. **Module 2 (Website Security Assessment):**
   - Live inspection of HTTPS, HSTS, CSP, X-Content-Type-Options, Referrer-Policy, and HTTP->HTTPS redirection.
4. **Module 3 (SSL/TLS Certificate Intelligence):**
   - Live X.509 socket parsing, validity calculation, SAN matching, and chain verification via Node native `tls`.
5. **Module 4 (Collaborative Threat Intelligence):**
   - Querying existing MongoDB `CommunityReport` records for the scanned domain.
6. **Cross-Layer Correlation Engine:**
   - Server-side multi-layer risk scoring, dynamic confidence, classification, and explainable findings.
7. **Database Persistence:**
   - Upserting `Domain` records and persisting completed `Scan` records in MongoDB Atlas.
8. **Live Scan API Endpoints:**
   - Functional `POST /api/scans`, `GET /api/scans`, `GET /api/scans/:id`.
9. **Unit & Integration Test Suite:**
   - Tests for IP pinning, redirect validation, timeout handling, body truncation, and scan persistence.

### B. Excluded Functionality (Deferred to Later Phases):
1. **Machine Learning Classifier:** Training or deploying an ONNX / Python ML model (deferred until baseline heuristics are live and benchmarked).
2. **External Paid Threat Feeds:** Integration with paid APIs (deferred to future expansion).
3. **Active/Intrusive Vulnerability Scanning:** Exploit payloads, SQL injection fuzzing, port scanning, or intrusive penetration testing (strictly excluded for safety and ethics).
4. **JavaScript Execution in Target Pages:** Headless browser rendering (Puppeteer/Playwright) is excluded to eliminate remote code execution and sandbox escape risks.
5. **PDF Export Service:** Generating binary PDF reports (deferred to Polish Phase).
6. **Frontend Complete Overhaul:** The frontend will be connected via a lightweight API client without modifying its existing UI structure.

---

## 5. Architectural Integrity & Non-Regression Guarantee

To maintain the architectural stability established during Priority 1 and 2:
- **Zero Schema Breaking Changes:** The existing `Scan`, `Domain`, `User`, and `CommunityReport` Mongoose models will be used without altering any field definitions.
- **Zero Endpoint Breaking Changes:** Existing routes (`/api/health`, `/api/auth/*`, `/api/reports/*`, `/api/admin/*`, `/api/dashboard/*`) will remain completely untouched.
- **API Envelope Consistency:** `POST /api/scans` will return the established `{ ok: true, data: { ... }, meta: { mode: "live" } }` convention.
- **Fail-Safe Degradation:** If target servers are unreachable or reject connections, the scanner records `status: "unavailable"` and explains the failure without throwing unhandled server errors.
- **Zero New External Dependencies:** The entire scanner and TLS engine will be implemented using Node.js built-in standard libraries.
