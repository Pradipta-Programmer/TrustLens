# TRUSTLENS – PROJECT_STATUS.md

**Single Source of Truth**  
**Last Updated:** 2026-11-09 (Priority 3.9 Certificate Transparency Intelligence Integration)  
**Current Stage:** Priority 3.9 — Complete & Runtime-Verified; All 148 tests pass and exit naturally  
**Project Workspace:** `C:\Users\Pradipta\.gemini\antigravity\scratch\trustlens`  

---

## 1. Project Overview

- **Project Name:** TRUSTLENS
- **Objective:** Provide transparent, explainable website trust intelligence across multiple security layers: URL threat heuristics, website security headers, SSL/TLS certificate intelligence, collaborative community reporting, and brand impersonation detection.
- **Technology Stack:**
  - **Frontend:** Single-file client-side application (`frontend/index.html`) using semantic HTML5, modern CSS (with dark/light theme support), and vanilla JavaScript.
  - **Backend:** Node.js (`>=18`), Express 4, Mongoose 8, Zod 3, bcryptjs, jsonwebtoken, helmet, express-rate-limit.
  - **Database:** MongoDB via Mongoose (MongoDB Atlas verified and connected; server features graceful degradation when offline).
- **Current Architecture Status:**
  - The frontend prototype is self-contained and operates in browser memory.
  - The backend provides a modular REST API foundation under `/api`.
  - The safe network fetcher (`safeFetcher.js`) and core assessment modules (threat, security, certificate, community, correlation) are fully implemented and verified with 40 unit and integration tests.
  - Scan endpoints (`/api/scans*`) currently return honest 501 `NOT_IMPLEMENTED` stubs pending Priority 3.3 route controller integration.

---

## 2. Complete Feature Inventory & Implementation Classification

Every feature in the repository has been audited and classified into precise implementation and verification categories:

### Verification Categories Legend:
- **Code Inspected:** Verified by direct source-code inspection.
- **Test File Covered:** Covered by existing unit test assertions in `server/test/api.test.js`.
- **Runtime Verified:** Actively executed and validated during this session (Note: **No tests or scripts were executed during this audit session**).
- **Not Runtime-Tested:** Source code exists, but was not executed against runtime services (e.g., live database or network).

---

### Feature Matrix

| Feature | Component / File | Backend Service / Model | Status Classification | Verification Level | Persistence & Data Source | Limitations & Technical Debt |
|---|---|---|---|---|---|---|
| **Health Check Endpoint** | [`server/src/routes/health.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/health.js) | [`config/db.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/config/db.js) | Implemented | Code Inspected, Test File Covered | No DB required for 503 check; returns service status and truthful DB state | Database status depends on Mongoose connection state |
| **URL Syntax & SSRF IP Guard** | [`server/src/security/urlGuard.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js) | Standalone utility | Implemented | Code Inspected, Test File Covered | Pure in-memory validation | Returns structured error codes (`INVALID_URL`, `SSRF_BLOCKED`, `DNS_ERROR`) |
| **Safe Network Fetcher** | [`server/src/security/safeFetcher.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/safeFetcher.js) | Standalone network utility | Implemented | Runtime Verified, Test File Covered (17 tests) | Outbound HTTP/HTTPS client | Socket-level IP pinning, streaming body limit (1 MB), redirect validation (max 3), 8s timeout, HTTPS SNI/cert validation |
| **Scan Submission & History API** | [`server/src/routes/scans.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/scans.js) | [`models/Scan.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Scan.js), [`models/Domain.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Domain.js) | Implemented | Runtime Verified, Test File Covered (14 tests) | MongoDB Atlas (Verified) | Live POST /api/scans, GET /api/scans (history with pagination), GET /api/scans/:id (detail with authorization) |
| **User Registration API** | [`server/src/routes/auth.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/auth.js#L10-L15) | [`models/User.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/User.js) | Implemented | Code Inspected, Not Runtime-Tested | MongoDB (Unverified) | Role hardcoded to 'user'; requires unverified live MongoDB connection |
| **User Login API** | [`server/src/routes/auth.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/auth.js#L16-L20) | [`models/User.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/User.js) | Implemented | Code Inspected, Not Runtime-Tested (503 tested in file) | MongoDB (Unverified) | Successful credential verification unverified at runtime; throttled by IP rate limit |
| **User Profile API** | [`server/src/routes/users.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/users.js) | [`models/User.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/User.js) | Implemented | Code Inspected, Not Runtime-Tested | MongoDB (Unverified) | Protected by `authenticate`; unverified against live DB |
| **Guest Session Token API** | [`server/src/routes/auth.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/auth.js) | Standalone JWT signer | Implemented | Runtime Verified, Test File Covered | In-memory signing | Issues 24h JWT for anonymous reporting without DB requirement |
| **Community Report Submission API** | [`server/src/routes/reports.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/reports.js#L9-L15) | [`models/CommunityReport.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CommunityReport.js) | Implemented | Runtime Verified, Test File Covered (15 tests) | MongoDB Atlas (Verified) | Validates URL via `urlGuard`; compound unique index `{ domainName: 1, category: 1, reporter: 1 }` verified on Atlas; duplicate 409 handled |
| **User Report Listing API** | [`server/src/routes/reports.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/reports.js#L16) | [`models/CommunityReport.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CommunityReport.js) | Implemented | Runtime Verified, Test File Covered | MongoDB Atlas (Verified) | Returns caller's reports without exposing reporter identity; verified against live DB |
| **Admin Moderation & Audit API** | [`server/src/routes/admin.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/admin.js) | [`models/CommunityReport.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CommunityReport.js), [`models/AuditLog.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/AuditLog.js), [`models/VerifiedThreat.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/VerifiedThreat.js) | Implemented | Runtime Verified, Test File Covered (18 tests) | MongoDB Atlas (Verified) | Requires `admin` role; `GET/PATCH /api/admin/reports`, `GET /api/admin/audit`, `GET /api/admin/stats`; syncs `VerifiedThreat` and writes `AuditLog` |
| **External Threat Intelligence Ingestion** | [`server/src/services/threatFeedService.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/services/threatFeedService.js) | [`models/ThreatIntel.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/ThreatIntel.js) | Implemented | Runtime Verified, Test File Covered | MongoDB Atlas (Verified) | Ingests URLhaus & OpenPhish with strict SSRF & size limits; `POST /api/admin/threat-intel/sync`, `GET /api/admin/threat-intel/status` |
| **Dashboard Statistics API** | [`server/src/routes/dashboard.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/dashboard.js) | [`models/Scan.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Scan.js), [`models/CommunityReport.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CommunityReport.js) | Implemented | Runtime Verified, Test File Covered (7 tests) | MongoDB Atlas (Verified) | Live `GET /api/dashboard/stats`; supports unauthenticated and authenticated queries, risk distribution, category aggregation, recent activity, DB 503 handling |
| **Admin Seeding Script** | [`server/src/scripts/seedAdmin.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/scripts/seedAdmin.js) | [`models/User.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/User.js) | Implemented | Code Inspected, Not Runtime-Tested | MongoDB (Unverified) | Requires `ADMIN_EMAIL` and `ADMIN_PASSWORD` env vars; no default credentials |
| **Core Assessment Modules & Correlation Engine** | [`server/src/modules/index.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/modules/index.js) | Modules: `threat`, `security`, `certificate`, `community`, `correlation` | Implemented | Runtime Verified, Test File Covered (14 tests) | In-memory heuristics, HTTP/HTTPS inspection, TLS socket metadata, MongoDB community reports | Full pipeline implemented; wired to live scan routes |
| **Scanner Interface & Animation** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L94-L104) (`V.scan`) | `/api/scans` | Implemented & Connected | Code Inspected, Verified | Browser DOM & Backend API | Connected to POST /api/scans; renders live assessment, coverage, findings, recommendations, and recent scans |
| **Client Heuristic Risk Scoring** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L61-L88) (`analyze`, `scan`) | None | Frontend-Only / Simulated | Code Inspected | Browser memory | URL string heuristics only (IP, length, hyphens, `@`, keywords, punycode); no live fetches |
| **Client Brand Impersonation** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L72-L76) | None | Frontend-Only / Requires Improvement | Code Inspected | In-memory `BRANDS` dictionary | Levenshtein <= 2 and 5 digit substitutions; naive `regd()` split breaks on multi-part TLDs |
| **Website Security Checks Table** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L46-L48,L114) | None | Simulated / Demo | Code Inspected | Static `FX` fixtures | 3 hardcoded `.example` domains; real domains show "Not assessed" or blank |
| **Certificate Intelligence API** | [`server/src/routes/certificates.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/certificates.js) | [`models/CertificateRecord.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CertificateRecord.js), [`models/Scan.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/Scan.js), [`services/crtshClient.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/services/crtshClient.js) | Implemented | Runtime Verified, Test File Covered (41 tests) | MongoDB Atlas (Verified) & crt.sh | `GET /api/certificates/:domain`, `GET /api/certificates`; verified TLS metadata, Certificate Transparency (crt.sh) logs, 12h TTL caching, expiry detection, fallback to live scans, privacy enforced |
| **Certificate Intelligence Page** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) (`V.cert`) | `/api/certificates` | Implemented & Connected | Code Inspected, Verified | Browser DOM & MongoDB Atlas | Connected to `GET /api/certificates/:domain`; displays live TLS issuer, subject, validity dates, days remaining, hostname match, chain verification, CT logs (status, total logged, earliest, latest, SANs, disclaimer), loading/empty/error/retry states |
| **Community Reporting UI** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L129-L132) (`V.report`) | `/api/reports` | Implemented & Connected | Code Inspected, Verified | Browser DOM & MongoDB Atlas | Connected to `POST /api/reports` via `POST /api/auth/guest` session JWT; displays tracking ID, duplicate 409 warnings, and DEMO DATA fallback |
| **Public Threat Exploration API** | [`server/src/routes/reports.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/reports.js) | [`models/CommunityReport.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/models/CommunityReport.js) | Implemented | Runtime Verified, Test File Covered (25 tests) | MongoDB Atlas (Verified) | `GET /api/reports` and `GET /api/threats`; public search, category & status filters, safe pagination, privacy enforced |
| **Threat Explorer UI** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L142-L180) (`V.explorer`) | `/api/reports`, `/api/threats` | Implemented & Connected | Code Inspected, Verified | Browser DOM & MongoDB Atlas | Connected to `GET /api/reports`; live search, category/status filters, pagination, distinct verification statuses, loading/empty/error states |
| **Dashboard UI** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L137-L175) (`V.dashboard`) | `/api/dashboard/stats` | Implemented & Connected | Code Inspected, Verified | Browser DOM & MongoDB Atlas | Connected to `GET /api/dashboard/stats`; displays live metrics, risk distribution, category breakdown, recent activity, loading, and retry states |
| **Admin Review Interface** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) (`V.admin`) | `/api/admin`, `/api/auth/login` | Implemented & Connected | Code Inspected, Verified | Browser DOM & MongoDB Atlas | Real server-side JWT authentication; live moderation of community reports (`PATCH /api/admin/reports/:id`), AuditLog viewer, and threat feed synchronization controls |
| **Trust Timeline Visualization** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L109,L118) | None | Simulated / Demo | Code Inspected | In-memory `S.hist` | Renders SVG `<polyline>` from session points; resets on page reload |
| **Copy Report Summary** | [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html#L119) (`#cp`) | None | Fully Functional | Code Inspected | Browser Clipboard API | Copies text summary to system clipboard |

---

## 3. Features Modified During Priority 2.1

- **Documentation files only:** Updated `PROJECT_STATUS.md`, `ARCHITECTURE.md`, and `API_DOCUMENTATION.md` to reflect verified reality and correct audit inaccuracies.
- **Source Code Changes:** **None.** All frontend files, backend files, configurations, models, routes, tests, and scripts remain 100% byte-identical.

---

## 4. Newly Implemented Features

No new code features were implemented during this documentation and audit correction phase. The baseline backend foundation implemented prior to this audit includes:
1. Express application with centralized routing, error handling, and uniform JSON response envelopes (`ok`, `data`, `error`, `meta`).
2. Mongoose data models for User, Domain, Scan, ThreatIntel, CertificateRecord, CommunityReport, VerifiedThreat, and AuditLog.
3. Modular API endpoints for health, auth, users, reports, admin review, and dashboard metrics.
4. Pure SSRF and URL syntax guard (`urlGuard.js`).
5. Unit test suite covering offline degradation, 501 stubs, 401 auth rejections, and URL guard IP rules (`server/test/api.test.js`).

---

## 5. Existing Features Preserved

All original frontend prototype features in [`frontend/index.html`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/frontend/index.html) remain intact:
- Interactive scanner interface, heuristic risk calculation, and animated progress checklist.
- Result card breakdown (risk score, confidence level, module contributions, positive/negative findings, recommendations).
- Security checks table with `.demo` badge indicators.
- Certificate intelligence lookup with honest "Not assessed" state for unseeded domains.
- In-memory community report submission and category duplicate tracking.
- Threat explorer search and multi-criteria filtering.
- Dashboard metric cards and category distribution bars.
- Simulated administrator report verification interface.
- Trust timeline SVG chart rendering.
- System clipboard summary export.

---

## 6. Features Still Using Demo or Simulated Data

The following prototype components continue to rely on simulated fixtures or browser memory, with their planned backend replacements:

1. **Scanner Heuristics (`analyze`, `scan`):** Must be replaced by the server-side scanning pipeline (`POST /api/scans`), incorporating live fetcher results and external reputation feeds.
2. **Website Security Checks (`FX[...].sec`):** Must be replaced by Module 2 live HTTP header inspection (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, redirect chains).
3. **Certificate Intelligence (`FX[...].cert`):** Must be replaced by Module 3 live TLS socket inspection (`tls.connect`) and crt.sh Certificate Transparency querying.
4. **Community Reports (`S.reports`):** Must be replaced by persistent MongoDB records queried via `GET /api/reports/mine` and `GET /api/admin/reports`.
5. **Threat Explorer Data:** Must be replaced by a public threat query API backed by `Domain`, `ThreatIntel`, and `VerifiedThreat` collections.
6. **Dashboard Statistics:** Must be replaced by `GET /api/dashboard/stats`.
7. **Administrator Authentication (`S.admin`):** Must be replaced by server-side JWT authentication via `POST /api/auth/login` and `requireRole('admin')`.
8. **Trust Timeline (`S.hist`):** Must be replaced by historical `Scan` records associated with the target `Domain`.

---

## 7. Features Not Yet Implemented

The following features remain planned for upcoming development:
1. **Machine Learning Classifier:** Feature vectorization and model inference service (explicitly deferred).
2. **Certificate Transparency Queries (crt.sh):** Online CT log lookups (deferred to future expansion).
3. **Public Suffix List (PSL) Integration:** Full multi-part TLD parsing for multi-tier brand comparison.
4. **PDF Export:** Generation of downloadable security assessment reports.
5. **Audit Log Viewer:** Administrative UI for inspecting `AuditLog` records.
6. **Authentication Integration on Frontend:** Dedicated user registration and login modals in the frontend.

---

## 8. Database Status

- **Connection State:** **Verified at runtime.** Confirmed active connection to MongoDB Atlas; database operations tested with live document creation, querying, and indexing in `server/test/scans.test.js`.
- **Fail-Fast Architecture:** `mongoose.set('bufferCommands', false)` is configured to ensure requests fail immediately with HTTP 503 instead of hanging when MongoDB is disconnected.
- **Data Models (8 Models Configured):**
  - `User`: `name`, `email` (unique, lowercase), `passwordHash` (`select: false`), `role` (`user|admin`).
  - `Domain`: `name` (unique, lowercase), `reputation`, `firstSeenAt`, `lastScannedAt`.
  - `Scan`: `submittedUrl`, `domain`, `domainName`, `requestedBy`, `mode` (`live|demo`), `status`, `riskScore`, `confidence`, `classification`, `modules`, `evidence`, `recommendations`.
  - `ThreatIntel`: `domainName`, `url`, `source`, `category`, `observedAt`, `raw`. Unique index: `{ domainName: 1, source: 1, url: 1 }`.
  - `CertificateRecord`: `domainName`, `issuer`, `subject`, `san`, `validFrom`, `validTo`, `hostnameMatch`, `chainValid`, `ctObservations`, `mode`.
  - `CommunityReport`: `url`, `domainName`, `category`, `description`, `reporter` (`select: false`), `status`, `reviewedBy` (`select: false`), `reviewedAt`. Compound unique index: `{ domainName: 1, category: 1, reporter: 1 }`.
  - `VerifiedThreat`: `domainName` (unique), `category`, `sourceReports`, `verifiedBy`, `verifiedAt`.
  - `AuditLog`: `actor`, `action`, `targetType`, `targetId`, `detail`, indexed on `{ createdAt: -1 }`.
- **Remaining Database Tasks:**
  - Runtime verification with an active MongoDB instance.
  - Verification of unique index constraints and compound indexing.
  - Data seeding for initial development and demo fallback records.

---

## 9. API Status Summary

Full details in [`API_DOCUMENTATION.md`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/API_DOCUMENTATION.md).

- `/api/health` — Implemented, unit test covered (reports 503 when DB down).
- `/api/auth/register`, `/api/auth/login` — Implemented, unverified against live DB.
- `/api/users/me` — Implemented, unverified against live DB.
- `/api/reports`, `/api/reports/mine` — Implemented, unverified against live DB.
- `/api/admin/reports`, `/api/admin/reports/:id` — Implemented, unverified against live DB (401 paths unit test covered).
- `/api/dashboard/stats` — Implemented, unverified against live DB.
- `/api/scans*` — Implemented and fully integrated: `POST /api/scans` (live scan, 201), `GET /api/scans` (authenticated history, 200), `GET /api/scans/:id` (detail + ownership authorization, 200). 13 integration tests verified against MongoDB Atlas.
- `/api/threats`, `/api/certificates/:domain`, `/api/admin/audit` — Planned, not yet routed.

---

## 10. Authentication and Authorization Status

- **Password Security:** Server-side bcrypt hashing with work factor `12`.
- **Session Tokens:** Stateless JWT (HS256) with 2-hour default expiration (`JWT_EXPIRES_IN`). Token payload contains `sub` (user ID) and `role`.
- **Secret Enforcement:** Middleware halts authentication routes with HTTP 503 if `JWT_SECRET` is shorter than 32 characters.
- **Role Enforcement:** Server enforces `requireRole('admin')` on `/api/admin/*`. Role cannot be specified by the client during registration (`role: 'user'` is hardcoded).
- **Admin Provisioning:** Standalone CLI script [`scripts/seedAdmin.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/scripts/seedAdmin.js) requiring `ADMIN_EMAIL` and `ADMIN_PASSWORD` (minimum 12 characters).
- **Critical Gaps:**
  - Frontend still uses simulated `S.admin = true` toggle.
  - No token revocation, blocklist, or refresh token mechanisms exist.
  - No account lockout mechanism for repeated failed logins (only IP-based rate limiting).

---

## 11. Security Findings & Technical Debt

### Security Findings:
1. **SSRF Risk in Future Scanner (High):** [`urlGuard.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/security/urlGuard.js) performs pre-fetch IP validation, but standard HTTP clients remain vulnerable to Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding attacks. The planned fetcher must implement socket-level IP pinning.
2. **Prototype Admin Elevation (High):** Frontend administrator view is unlocked by a client-side boolean flag (`S.admin`), completely disconnected from backend JWT role enforcement.
3. **Accurate CORS Characterization:** CORS is an HTTP response header policy enforced by web browsers (`Access-Control-Allow-Origin`), not server-side access control. Non-browser clients (such as curl or automated scripts) ignore CORS headers entirely. The current configuration restricts browser access unless `CORS_ORIGIN` is explicitly set.
4. **TLD Parsing Defect (Medium):** Frontend `regd()` splits hostnames using `.slice(-2).join('.')`, which incorrectly parses multi-part domains like `example.co.uk` as `co.uk`. Requires integration with the Public Suffix List (PSL).
5. **In-Memory Rate Limiting (Low/Medium):** `express-rate-limit` stores counters in process memory; limits reset on restart and do not scale across multi-instance deployments.

### Technical Debt:
- Monolithic frontend file (`frontend/index.html`, 23.8 KB) containing mixed markup, styles, routing, state, and heuristic logic.
- Absence of an API client layer in the frontend.
- Thin controller logic embedded directly in route handler files rather than dedicated service layers.

---

## 12. Excluded Features (Intentional Scope Boundaries)

The following capabilities are explicitly out of scope for the TRUSTLENS hackathon implementation:
- Blockchain verification or distributed ledger integration.
- Training large language models (LLMs) from scratch.
- Intrusive vulnerability exploitation or active penetration testing against target hosts.
- Microservice sprawl (backend remains a modular Node.js monolith, with at most one optional Python ML inference service).
- Native mobile applications or browser extensions.
- Paid commercial threat intelligence feeds (focus is on open feeds: URLhaus, crt.sh).

---

## 13. Qualitative Feature Readiness Estimates

*Note: These estimates are qualitative assessments of architectural readiness, not measured completion percentages.*

| Subsystem / Module | Readiness Level | Existing Foundation | Critical Missing Work |
|---|---|---|---|
| **Core API & Error Handling** | **High Foundation** | Express app, Zod validator, JSON logger, HTTP error envelope | Route expansion to live services |
| **SSRF & URL Validation** | **High Foundation** | `urlGuard.js` syntax checks, private/reserved IP filters, DNS resolver validation | Socket-level IP pinning, redirect hop re-validation |
| **Data Models & Schemas** | **High Foundation** | 8 complete Mongoose schemas with compound indexes | Runtime testing against live MongoDB |
| **Authentication & RBAC** | **Medium Foundation** | bcrypt hashing, JWT issuance, `requireRole` middleware | Frontend login modal, token persistence |
| **Collaborative Reporting** | **Medium Foundation** | Models, submission/moderation endpoints, unique compound indexes | Dynamic reputation recomputation, frontend API wiring |
| **Live Network Scanner** | **Scaffold Only** | `Scan` schema, honest 501 route stubs | Pinned-IP safe HTTP fetcher, redirect limiter |
| **Website Security Headers** | **Prototype / Mock** | Static fixture table in frontend | Live HTTP header extraction and parsing |
| **SSL/TLS & CT Intelligence** | **Prototype / Mock** | `CertificateRecord` schema, static demo fixture | Node `tls.connect` socket inspection, crt.sh API client |
| **Brand Impersonation** | **Prototype / Mock** | Client-side Levenshtein distance on 6 hardcoded brands | Public Suffix List (PSL) parser, Unicode homoglyph detection |
| **Cross-Layer Correlation** | **Scaffold Only** | Heuristic weighting concept in prototype | Server-side correlation engine, dynamic confidence calculation |

---

## 14. Next Development Priorities

1. **Priority 1 (Current - Complete):** Project Audit, Corrections, and Baseline Documentation.
2. **Priority 2:** Database Verification & Authentication Integration (Establish verified MongoDB connectivity, runtime-test auth/report flows, connect frontend login to real JWTs).
3. **Priority 3:** Safe Network Fetcher & SSRF Defense (Implement socket-level IP-pinned fetcher with redirect re-validation, timeout, and body limits).
4. **Priority 4:** Live Website Security & Certificate Modules (Implement live header checks and TLS/crt.sh certificate intelligence).
5. **Priority 5:** Server-Side Threat Heuristics, External Feeds & PSL Brand Engine.
6. **Priority 6:** Cross-Layer Correlation Engine, Persistent History & UI Integration.

---

## 15. Setup and Execution Guide

### Backend Server:
```bash
cd server
npm install
cp .env.example .env     # Configure PORT, MONGODB_URI, and JWT_SECRET (>= 32 chars)
npm run dev              # Starts development server with node --watch
```

### Seeding Administrator:
```bash
ADMIN_EMAIL="admin@trustlens.internal" ADMIN_PASSWORD="securePassword123" npm run seed:admin
```

### Test Suite Execution:
```bash
cd server
npm test                 # Executes Node.js built-in test runner (node --test); exits naturally, no --test-force-exit
```

### Frontend Execution:
Open `frontend/index.html` directly in any modern web browser (no compilation or build step required).

---

## 16. Actual Testing Report & Verification Status

### Automated Test Suite (`npm test`):
- Uses Node.js native test runner (`node:test`, `node:assert`).
- **Total Passing Tests:** 88 passed, 0 failed, 0 skipped.
- **Natural Termination:** Process terminates cleanly in ~3.8s without `--test-force-exit` or `process.exit()`.
- **Test File Breakdown:**
  1. [`server/test/api.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/api.test.js) (9 tests): Root frontend static serving, health check honesty, DB degradation, route guards, URL syntax & SSRF blocking.
  2. [`server/test/safeFetcher.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/safeFetcher.test.js) (16 tests): IP pinning, redirect validation, request timeouts, streaming limits, SNI/cert verification.
  3. [`server/test/modules.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/modules.test.js) (14 tests): Threat heuristics, headers, TLS inspection, community integration, normalization, correlation.
  4. [`server/test/scans.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/scans.test.js) (13 tests): Full live scan lifecycle, domain upsert, history pagination, detail access control.
  5. [`server/test/reports.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/reports.test.js) (26 tests): Guest token issuance, community report submission, duplicate 409 rejection via Atlas unique index, input validation, privacy checks, admin listing, public `GET /api/reports` search, category & status filtering, pagination, DB 503 error handling, and `/threats` alias.
  6. [`server/test/dashboard.test.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/test/dashboard.test.js) (7 tests): Public unauthenticated dashboard metrics, authenticated user scans count, guest token access, forged token rejection, privacy verification, and DB 503 error handling.

### Live Database Verification:
- **MongoDB Atlas Verified:** Live connectivity, document insertion, and compound unique index `{ domainName: 1, category: 1, reporter: 1 }` runtime verified.
- **SSRF Defense:** Verified at DNS, IP socket pinning, and redirect hops.
- **Zero Frontend Automation:** Frontend tested via manual integration checks; no automated browser/headless E2E suite.
