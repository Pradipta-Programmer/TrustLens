# TRUSTLENS — Priority 6.3 Zod Vulnerability Remediation Plan

**Advisory Identifier:** [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5)
**Package:** `zod`
**Current Installed Version:** `3.25.76` (resolves `^3.23.8`)
**Advisory Severity:** **High** (CVSS:3.1 / 7.5, CWE-770 Allocation of Resources Without Limits or Throttling)
**Date:** 2026-11-09

---

## 1. Advisory Investigation & Version Range Verification

### 1.1 Upstream Metadata Verification
Queried the official npm registry version catalog for `zod` (`npm view zod versions --json`):
- **Latest 3.x Version Available:** `3.25.76` (which is already installed).
- **Patched 3.x Version Existence:** **None.** The maintainers did not backport the fix to the 3.x branch.
- **Affected Version Range:** `< 4.6.6`.
- **First Patched Version:** `4.6.6` (latest available in registry: `4.6.7`).

### 1.2 Vulnerability Mechanism
The vulnerability manifests when parsing deeply recursive, cyclic, or unbounded collection structures (e.g. nested arrays or sets with transformation refinements), allowing an attacker to trigger excessive CPU and memory consumption during AST validation.

---

## 2. TrustLens Usage & Compatibility Analysis

### 2.1 Current Zod Implementations in TrustLens
Zod is used as the schema validator across five backend modules:
1. `server/src/routes/auth.js`: User registration (`name`, `email`, `password`) and login (`email`, `password`).
2. `server/src/routes/reports.js`: Community report payload (`url`, `category`, `description`) and query parameters.
3. `server/src/routes/scans.js`: Scan request URL (`url`).
4. `server/src/routes/certificates.js`: Query parameters (`q`, `page`, `limit`).
5. `server/src/routes/admin.js`: Moderation review actions and audit query parameters.

### 2.2 Schema Structure Characteristics
- All schemas define strictly bounded flat scalar fields (`max(80)`, `max(128)`, `max(2048)`) or small fixed enums (`Report.CATEGORIES`).
- No unbounded array schemas (`z.array()`) or recursive type definitions exist in TrustLens.

### 2.3 Existing Transport Mitigation & Residual Risk
- **Transport Cap:** [`server/src/app.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/app.js#L24) enforces `express.json({ limit: '20kb' })`. Payloads exceeding 20 KB are rejected with HTTP 413 by Express before Zod executes.
- **Rate Limiting:** Auth endpoints enforce 15 req/15min; general API enforces 120 req/min.
- **Residual Risk:** While the 20 KB limit prevents multi-megabyte volumetric flooding, it does not mathematically eliminate the vulnerability if a specially crafted, highly compressed recursive payload fits within 20 KB. True library-level immunity requires an engine-level patch.

---

## 3. Zod 4 Migration Risk Assessment

Running `npm audit fix --force` installs `zod@4.6.7`, which is a major breaking upgrade:
- **Breaking API Changes:** Zod v4 refactors internal parsing logic, error map signatures, and TypeScript type inference.
- **Syntax Compatibility:** Functions such as `z.preprocess()` and `z.coerce` exhibit altered behavior and return shapes in v4.
- **Test Suite Impact:** Forcing Zod v4 immediately breaks schema validation across `auth.js`, `reports.js`, and `admin.js`, causing test regressions across the 176-test suite.
- **Recommendation Rule:** Dependencies must not be upgraded without full regression validation.

---

## 4. Final Recommendation

**RECOMMENDATION: C — No safe upgrade currently available**

### Justification:
1. **Option A (Safe patched Zod 3 upgrade) is IMPOSSIBLE:** No patched 3.x release exists in the npm registry. `3.25.76` is the terminal release of the 3.x line.
2. **Option B (Controlled Zod 4 migration) is a MAJOR PROJECT:** Zod 4 introduces breaking syntax and runtime changes that cannot be safely applied as an in-place patch during release finalization.
3. **Current Action:**
   - Retain `zod@^3.23.8` for release v1.0.0.
   - Rely on the active 20 KB Express body-parser limit and scalar schema boundaries as defense-in-depth mitigations.
   - Schedule a dedicated Zod v4 migration task in the v2.0.0 roadmap with comprehensive schema and middleware refactoring.
