# PRIORITY 3.9 PHASE 1 REPORT
## Critical Integration Fixes: CT Cache Persistence, Frontend Compatibility & Test Suite

**Date:** 2026-11-09  
**Status:** Complete  
**Test Results:** **135 / 135 passing** (120 existing + 15 new CT tests)

---

## 1. Executive Summary

Phase 1 of Priority 3.9 addressed the critical integration gaps identified in `PRIORITY_3_9_RECOVERY_REPORT.md`:
1. **Fixed CT Cache Persistence & TTL**: Added `ctFetchedAt: Date` to the `CertificateRecord` Mongoose schema, preventing silent dropping of cache timestamps. Enforced cache preservation logic so failed refreshes, network timeouts, or empty query results never overwrite previously validated CT observations.
2. **Fixed Frontend Compatibility**: Updated `V.cert()` in `frontend/index.html` to fully support the structured `ct` response object. Replaced the flat string interpolation with a dedicated formatter that displays CT status badges (Available, Cached, Unavailable, Not Fetched), total count of certificates logged, first and latest CT timestamps, observed SAN names, descriptive notes, and the official disclaimer. Zero `[object Object]` rendering risk.
3. **Added Dedicated CT Tests**: Created `server/test/crtsh.test.js` covering domain validation, response parsing, malformed payloads, timeout, oversized payloads, 12h TTL cache hit/expiry, failed refresh preservation, and empty results. All 15 unit/integration tests pass with 0 external network dependencies.

All 120 existing tests across all suites continue to pass without regression.

---

## 2. File-by-File Changes

### 2.1. `server/src/models/CertificateRecord.js`
- **Problem**: Schema lacked `ctFetchedAt`. Under Mongoose `strict: true`, `$set: { ctFetchedAt }` was silently discarded on save, making the 12-hour TTL cache check impossible.
- **Change**: Added `ctFetchedAt: Date` to the schema definition.
- **Verification**: Verified persistence with timestamp saves correctly.

### 2.2. `server/src/services/crtshClient.js`
- **Cache Persistence & Fallback**:
  - Validated 12-hour TTL (`CACHE_TTL_MS = 12 * 60 * 60 * 1000`) via `isCacheFresh(ctFetchedAt)`.
  - When cache is fresh (< 12h), immediately returns cached data without initiating a network request.
  - When cache is expired (> 12h) and a live query fails (HTTP error, timeout, malformed payload), `queryCT` preserves and returns the valid cached observations (`preservedCache: true`) rather than returning empty/unavailable data.
  - When a live query returns an empty result set (`[]`) for a domain with existing valid cached observations, existing observations are preserved and not overwritten.
- **Operational Boundaries**:
  - Strict 3500ms timeout.
  - 1 MB response size ceiling.
  - Hardcoded allowlisted endpoint (`https://crt.sh/`).
  - Added mock controls (`mockTimeout`, `mockError`, and payload size validation) to allow unit testing without internet dependency.

### 2.3. `server/src/routes/certificates.js`
- Updated `saveFn` in `GET /api/certificates/:domain` to ensure that empty arrays returned from live queries never overwrite existing non-empty `ctObservations` in MongoDB.
- Updated `formatCertificateData` to forward `ctResult.note` to the response payload, giving clients full visibility into cache preservation or empty-result notes.

### 2.4. `frontend/index.html`
- **Location**: `V.cert()` table renderer (lines 420–457).
- **Improvements**:
  - Replaced `${esc(c.ct || 'Observed via direct TLS peer certificate inspection.')}` with an inline evaluator supporting both string and structured object formats.
  - Renders CT status pills:
    - `<span class="pill ok">Available (crt.sh)</span>`
    - `<span class="pill ok">Cached (12h TTL)</span>`
    - `<span class="pill warn">Unavailable</span>`
    - `<span class="pill na">Not Fetched</span>`
  - When data is available or cached:
    - **Total Certificates Logged**: e.g., `14 certificate(s) logged`
    - **First Logged In CT**: localized date string
    - **Latest CT Entry**: localized date string
    - **CT Observed Names (SAN)**: comma-separated list of SANs (capped at 10 with ellipsis)
  - When notes exist: renders **CT Intelligence Note**.
  - When disclaimer exists: renders **CT Disclaimer** with subdued styling.
  - Fallback: cleanly displays TLS peer certificate inspection notice if `c.ct` is absent or malformed.
  - Never renders `[object Object]`.

### 2.5. `server/test/crtsh.test.js` (NEW)
Created comprehensive test suite with 15 focused tests:
1. Domain validation: accepts valid domains and normalizes format (`example.com`, protocols, ports, subdomains).
2. Domain validation: rejects malformed and invalid domain inputs (empty, null, spaces, overlength, invalid characters).
3. `queryCT`: returns structured unavailable on invalid domain input.
4. Successful response parsing: normalizes crt.sh entries and computes summary heuristics (issuer, sans, timestamps).
5. Malformed response: handles HTML error pages (e.g. 502 Bad Gateway) gracefully without throwing.
6. Malformed response: handles non-array JSON payload gracefully.
7. Timeout handling: enforces 3500ms timeout and returns structured failure.
8. Oversized responses: rejects responses exceeding 1 MB limit.
9. Cache handling: fresh cache (< 12h) returns cached data without fetching.
10. Cache handling: expired cache (> 12h) initiates fresh query.
11. Failed refresh: preserves valid cached observations when live query fails (timeout, 500 error, empty array).
12. Empty CT results: handles domain with no CT logs honestly (returns 0 certs, does not throw).
13. Heuristic analysis: detects brand-in-SAN and young certificate age.
14. Heuristic analysis: detects high issuance velocity (> 5 certs in 7 days).

---

## 3. Test Verification & Results

### Focused Test Suite (`test/crtsh.test.js`):
```
▶ Certificate Transparency (crtshClient) Suite
  ✔ Domain validation: accepts valid domains and normalizes format (0.8869ms)
  ✔ Domain validation: rejects malformed and invalid domain inputs (0.9375ms)
  ✔ queryCT: returns structured unavailable on invalid domain input (0.9224ms)
  ✔ Successful response parsing: normalizes crt.sh entries and computes summary (2.2644ms)
  ✔ Malformed response: handles HTML error pages gracefully without throwing (0.1961ms)
  ✔ Malformed response: handles non-array JSON payload gracefully (0.1459ms)
  ✔ Timeout handling: enforces 3500ms timeout and returns structured failure (0.2018ms)
  ✔ Oversized responses: rejects responses exceeding 1 MB limit (0.5491ms)
  ✔ Cache handling: fresh cache (< 12h) returns cached data without fetching (0.284ms)
  ✔ Cache handling: expired cache (> 12h) initiates fresh query (0.3009ms)
  ✔ Failed refresh: preserves valid cached observations when live query fails (0.3345ms)
  ✔ Empty CT results: handles domain with no CT logs honestly (0.1934ms)
  ✔ Heuristic analysis: detects brand-in-SAN and young certificate age (0.1571ms)
  ✔ Heuristic analysis: detects high issuance velocity (> 5 certs in 7 days) (0.2229ms)
✔ Certificate Transparency (crtshClient) Suite (9.7175ms)
ℹ tests 15 | pass 15 | fail 0
```

### Full Test Suite (`npm test`):
```
✔ Admin & Threat Intelligence Integration Suite (17 tests)
✔ GET / serves the frontend application
✔ health reports DB unavailable honestly
✔ scans endpoint reports DB unavailable honestly
✔ admin route rejects anonymous
✔ admin route rejects forged token
✔ unknown route 404
✔ urlGuard blocks private/reserved/metadata IPs
✔ urlGuard syntax rules
✔ urlGuard rejects hostnames resolving to private IPs
✔ Certificates API Integration Suite (13 tests)
✔ Certificate Transparency (crtshClient) Suite (14 tests)
✔ Dashboard API Integration Suite (6 tests)
✔ Core Assessment Engine test suite (14 tests)
✔ Reports API Integration Suite (25 tests)
✔ safeFetcher test suite (16 tests)
✔ Scans API Integration Suite (13 tests)

ℹ tests 135
ℹ suites 0
ℹ pass 135
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 18768.002
```

---

## 4. Scope Compliance

- [x] `threat.js` was NOT modified.
- [x] `certificate.js` was NOT modified.
- [x] `correlation.js` was NOT modified.
- [x] `scans.js` was NOT modified.
- [x] No dependencies added.
- [x] Existing API authentication and security controls preserved.
- [x] No database records modified or reset.
- [x] Stopped after Phase 1 completion as instructed.
