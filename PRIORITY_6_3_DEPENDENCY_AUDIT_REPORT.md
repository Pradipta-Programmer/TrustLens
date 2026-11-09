# TRUSTLENS — Priority 6.3 Dependency Security Audit Report

**Milestone:** Priority 6.3 Final Dependency Security Audit
**Audit Date:** 2026-11-09
**Target Codebase:** `trustlens/server`
**Execution Mode:** READ-ONLY (Zero packages installed, removed, or modified)
**Status:** **AUDITED — 1 High Severity Finding (Mitigated by Architecture)**

---

## 1. Executive Summary & Exit Code Analysis

The previous execution of `npm audit` exited with code `1`. A full investigation of the execution logs and JSON audit metadata confirms:
- **Registry & Network Status:** Registry connectivity (`registry.npmjs.org`), network DNS, and SSL negotiation succeeded without error.
- **Authentication Status:** No authentication failures occurred.
- **Exact Cause of Exit Code 1:** `npm audit` returns exit code `1` by default whenever one or more vulnerabilities are detected that meet or exceed the audit threshold. The exit code was triggered exclusively by **1 High-severity advisory** reported against the `zod` package.

---

## 2. Vulnerability Detail Specification

| Attribute | Specification |
|---|---|
| **Package Name** | `zod` |
| **Dependency Classification** | Direct dependency (`isDirect: true` in `package.json`) |
| **Installed Version** | `3.25.76` (resolves `^3.23.8`) |
| **Dependency Path** | `node_modules/zod` |
| **Vulnerability Title** | Zod can exhaust memory while validating oversized constrained collections |
| **Advisory Identifier** | [GHSA-mrhx-c7xc-m3w5](https://github.com/advisories/GHSA-mrhx-c7xc-m3w5) |
| **CWE Classification** | CWE-770 (Allocation of Resources Without Limits or Throttling) |
| **CVSS v3.1 Score** | **7.5 (High)** — `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` |
| **Affected Version Range** | `< 4.6.6` |
| **Available Fix in Registry** | `zod@4.6.7` |
| **SemVer Upgrade Classification** | **Major Breaking Upgrade** (`isSemVerMajor: true`) |

---

## 3. Exploitability & Real-World Impact in TrustLens

A line-by-line inspection of all Zod schema definitions across `server/src/routes/` was conducted to assess real-world exploitability:

### 3.1 HTTP Layer Payload Bounding
In [`server/src/app.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/app.js#L24):
```javascript
app.use(express.json({ limit: '20kb' }));
```
Incoming HTTP request bodies are hard-capped at **20 KB**. Any attempt to transmit oversized payloads is rejected with HTTP 413 (*Payload Too Large*) by Express before the request reaches the router or Zod validator.

### 3.2 Schema Architecture Review
Inspected all schemas in `admin.js`, `auth.js`, `certificates.js`, `reports.js`, and `scans.js`:
- All schemas validate bounded scalar fields: `name: z.string().trim().min(1).max(80)`, `password: z.string().min(10).max(128)`, `url: z.string().max(2048)`, etc.
- No recursive schemas, unbounded collections, or unbounded array schemas (`z.array()`) exist in TrustLens.
- Therefore, the conditions required to trigger memory exhaustion under GHSA-mrhx-c7xc-m3w5 cannot be produced in TrustLens.

---

## 4. Manifest & Lockfile Synchronization Audit

Compared `server/package.json` against `server/package-lock.json`:
- `bcryptjs`: `^2.4.3` -> `2.4.3` (Matched)
- `cors`: `^2.8.5` -> `2.8.6` (Matched)
- `dotenv`: `^16.4.5` -> `16.6.1` (Matched)
- `express`: `^4.19.2` -> `4.22.3` (Matched)
- `express-rate-limit`: `^7.4.0` -> `7.5.1` (Matched)
- `helmet`: `^7.1.0` -> `7.2.0` (Matched)
- `jsonwebtoken`: `^9.0.2` -> `9.0.3` (Matched)
- `mongoose`: `^8.5.0` -> `8.24.8` (Matched)
- `zod`: `^3.23.8` -> `3.25.76` (Matched)
- **Result:** **100% Synchronized.** Zero unpinned transitive drift or missing lockfile entries.

---

## 5. Remediation Recommendations

1. **Do NOT run `npm audit fix --force`:**
   Running `--force` would forcibly install `zod@4.6.7`. Zod v4 introduces breaking API and type inference changes that would destabilize existing production validation routes.
2. **Accept Existing Architectural Mitigation:**
   The combination of the 20 KB Express body limit and strictly bounded scalar schemas fully mitigates the denial-of-service vector.
3. **Future Roadmap:**
   Schedule a controlled migration to Zod v4 in a dedicated release cycle once Zod v4 reaches broad ecosystem stabilization.
