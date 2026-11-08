# PRIORITY 3.9 RECOVERY REPORT

**Generated:** 2026-11-09T02:31:00+05:30  
**Workspace:** `C:\Users\Pradipta\.gemini\antigravity\scratch\trustlens`  
**Baseline test status:** 120 / 120 passing ✅

---

## 1. Current Test Suite Status

All **120 existing tests pass** with no regressions.

```
ℹ tests 120
ℹ pass 120
ℹ fail 0
```

The Priority 3.9 changes made so far have not broken any existing functionality at the test level.

---

## 2. Files Modified by Priority 3.9

### 2.1. NEW — `server/src/services/crtshClient.js` ✅ Complete

**Status: Fully implemented and syntactically correct.**

| Feature | Status |
|---|---|
| `validateDomain(raw)` — domain validation | ✅ Implemented |
| `fetchCrtsh(domain, opts)` — HTTPS fetch with 3500ms timeout, 1MB cap | ✅ Implemented |
| `parseSANs(nameValue)` — newline-delimited SAN parser | ✅ Implemented |
| `normalizeEntry(entry)` — crt.sh JSON → normalized record | ✅ Implemented |
| `analyzeCT(domain, records)` — heuristics (youngCert, highVelocity, brandInSAN) | ✅ Implemented |
| `isCacheFresh(ctFetchedAt)` — 12h TTL check | ✅ Implemented |
| `queryCT(domain, opts)` — main entry with cache, mock, and saveFn support | ✅ Implemented |
| Strict crt.sh allowlist (never fetches arbitrary URLs) | ✅ Enforced |
| Never throws — returns `{ status: 'unavailable' }` on all errors | ✅ Enforced |
| `mockResponse` option for deterministic testing | ✅ Implemented |
| Exports: `queryCT`, `validateDomain`, `analyzeCT`, `isCacheFresh`, constants | ✅ All exported |

**Security review:**
- Hardcoded `CRTSH_HOST = 'crt.sh'` — no user-supplied hosts are ever used.
- `encodeURIComponent(domain)` on the query parameter.
- Response body capped at 1 MB with stream-level enforcement.
- Request timeout via `req.on('timeout')` + `req.destroy()`.
- JSON parse wrapped in try/catch — malformed responses return graceful error.
- No dependency on external npm packages (uses native `https`).

> [!NOTE]
> One design observation: `fetchCrtsh` uses Node's legacy `https.get` callback API rather than `fetch()`. This is acceptable since the codebase targets Node ≥18 and avoids adding dependencies. However, `timeout` in `https.get` options sets the socket idle timeout, not an overall request timeout. For extremely slow but active connections, the timeout may not trigger. This is a minor edge case given the 3500ms value is short.

---

### 2.2. MODIFIED — `server/src/routes/certificates.js` ✅ Mostly Complete

**Changes applied:**

| Change | Status |
|---|---|
| Added `require('../services/crtshClient')` import (line 14) | ✅ |
| `formatCertificateData(record, ctResult)` — now accepts optional CT result parameter | ✅ |
| `ct` field in response changed from string → structured object | ✅ |
| Structured CT object includes: `status`, `source`, `totalLogged`, `earliest`, `latest`, `discoveredSANs`, `note`, `disclaimer` | ✅ |
| `GET /api/certificates/:domain` — calls `crtshClient.queryCT()` after finding `certDoc` | ✅ |
| CT result persisted via `saveFn` → `CertificateRecord.findOneAndUpdate` | ✅ |
| CT failure wrapped in try/catch — never propagates exception | ✅ |
| `GET /api/certificates` (listing) — calls `formatCertificateData(record)` with no CT result (legacy fallback) | ✅ Correct |

> [!WARNING]
> **Breaking change in API response schema:** The `ct` field in `GET /api/certificates/:domain` response changed from a **string** to a **structured object**. The existing certificate tests only check `assert.ok(d.ct)` (truthy check), which passes for both strings and objects, so tests still pass. However, the **frontend at line 420** uses `esc(c.ct)` which will render `[object Object]` instead of meaningful text. This is a **rendering bug** that needs to be fixed in the frontend update step.

---

### 2.3. NOT MODIFIED — `server/src/modules/certificate.js` ❌ Pending

**No changes have been applied.** Line 179 still contains:
```javascript
ct: 'Observed via direct TLS peer certificate inspection.',
```

**Required changes (per plan):**
- Accept optional `ctx.ctData` for CT analysis results.
- Add informational findings (not risk score) when CT signals + other indicators coincide.
- Increase confidence when `ctData.totalCerts > 20` over multiple years.

---

### 2.4. NOT MODIFIED — `server/src/modules/threat.js` ❌ Pending

**No changes have been applied.** The file is unchanged from Priority 3.8.

**Required changes (per plan):**
- Accept optional `ctx.ctData`.
- If `ctData.brandInSAN` detected AND impersonation already flagged → add supporting evidence.
- If `ctData.youngCert` AND other suspicious indicators → add low-weight informational finding.
- **Critical constraint:** Never add risk points from CT evidence in isolation.

---

### 2.5. NOT MODIFIED — `server/src/modules/correlation.js` ❌ No Changes Planned

The context summary mentioned CT could boost confidence in `correlation.js`, but the actual plan routes confidence improvements through `certificate.js`. No direct changes to `correlation.js` are required.

---

### 2.6. NOT MODIFIED — `server/src/routes/scans.js` ❌ Pending

**No changes have been applied.**

**Required changes (per plan):**
- After the `CertificateRecord.findOneAndUpdate()` at lines 139–156, attempt an async (non-blocking) `crtshClient.queryCT(hostname)`.
- If CT data is available, merge into `CertificateRecord` with `ctFetchedAt`.
- Must be wrapped in try/catch — CT failure must never affect scan response.

---

### 2.7. NOT MODIFIED — `frontend/index.html` ❌ Pending

**No changes have been applied.**

**Required changes (per plan):**
- Update `V.cert()` (line 341–440) to render the new structured `ct` object with:
  - CT Logs Status (available/unavailable/cached)
  - Total CT Records
  - First Observed / Latest CT Entry timestamps
  - Certificate-Observed Names (from CT logs)
  - Disclaimer text
- Handle `ct.status === 'unavailable'` gracefully.

> [!CAUTION]
> **Active rendering bug:** The current frontend at line 420 uses `esc(c.ct)` which expects a string. Since the `GET /api/certificates/:domain` endpoint now returns `ct` as an object, the "Transparency Observations" row will display `[object Object]`. This must be fixed in the frontend update.

---

## 3. Missing Deliverables

| Deliverable | Status |
|---|---|
| `server/test/crtsh.test.js` | ❌ Not created |
| `PRIORITY_3_9_IMPLEMENTATION_REPORT.md` | ❌ Not created |
| `API_DOCUMENTATION.md` updates | ❌ Not applied |
| `PROJECT_STATUS.md` updates | ❌ Not applied |

---

## 4. Schema Issue — `ctFetchedAt`

The `CertificateRecord` model schema is:

```javascript
const { Schema, model } = require('mongoose');
module.exports = model('CertificateRecord', new Schema({
  domainName: { ... }, issuer: String, subject: String, san: [String],
  validFrom: Date, validTo: Date, hostnameMatch: Boolean, chainValid: Boolean,
  ctObservations: [Schema.Types.Mixed],
  mode: { ... }, observedAt: { ... },
}, { timestamps: true }));
```

**`ctFetchedAt` is NOT defined in the schema.** The `crtshClient.js` cache logic reads `opts.cachedDoc.ctFetchedAt`, and the `saveFn` in `certificates.js` writes `{ ctFetchedAt: fetchedAt }` via `$set`. Because Mongoose has `strict: true` by default, fields not in the schema are **silently dropped** on save.

**Impact:** CT caching will not work. Every `GET /api/certificates/:domain` request will perform a live crt.sh fetch because `ctFetchedAt` is never actually persisted. The CT observations array (`ctObservations`) will be saved (since it's in the schema), but the timestamp needed for TTL checking will not.

**Fix required:** Add `ctFetchedAt: Date` to the `CertificateRecord` schema.

---

## 5. Summary of Issues Found

| # | Severity | Issue | Location |
|---|---|---|---|
| 1 | **High** | `ctFetchedAt` not in `CertificateRecord` schema — cache TTL will never work | `server/src/models/CertificateRecord.js` |
| 2 | **High** | Frontend displays `[object Object]` for CT field | `frontend/index.html` line 420 |
| 3 | Medium | `certificate.js` not updated with CT signal integration | `server/src/modules/certificate.js` |
| 4 | Medium | `threat.js` not updated with CT supporting evidence | `server/src/modules/threat.js` |
| 5 | Medium | `scans.js` not updated with async CT fetch during scans | `server/src/routes/scans.js` |
| 6 | Low | No test file `crtsh.test.js` exists yet | `server/test/` |
| 7 | Low | No documentation updates applied | `API_DOCUMENTATION.md`, `PROJECT_STATUS.md` |

---

## 6. What Works Now

- ✅ `crtshClient.js` is complete and syntactically correct.
- ✅ `certificates.js` route correctly calls `queryCT` for single-domain lookups.
- ✅ Listing endpoint (`GET /api/certificates`) uses legacy fallback gracefully.
- ✅ All 120 existing tests pass without regression.
- ✅ CT fetch errors cannot crash the certificates endpoint (wrapped in try/catch).

---

## 7. Recommended Implementation Order for Remaining Work

1. **Fix `CertificateRecord` schema** — add `ctFetchedAt: Date` field.
2. **Update `frontend/index.html`** — render structured CT object in `V.cert()`.
3. **Update `scans.js`** — async CT fetch after `CertificateRecord` upsert.
4. **Update `certificate.js`** — CT informational findings (no risk score changes).
5. **Update `threat.js`** — CT supporting evidence for brand/impersonation correlation.
6. **Create `crtsh.test.js`** — comprehensive test suite with mock fixtures.
7. **Run full test suite** — verify 120 + new CT tests pass.
8. **Update documentation** — `API_DOCUMENTATION.md`, `PROJECT_STATUS.md`.
9. **Create `PRIORITY_3_9_IMPLEMENTATION_REPORT.md`**.

---

> [!IMPORTANT]
> **Do not proceed with implementation until this report has been reviewed.** The `ctFetchedAt` schema issue (#1) and the frontend rendering bug (#2) are the highest-priority items to address first.
