# PRIORITY 3.3.1 STABILIZATION REPORT
## Test Suite Natural-Exit Fix — Mongoose / MongoDB Driver TLS Socket Pool

**Status:** ✅ COMPLETE  
**Date:** 2026-11-08  
**Test Script:** `node --test` (no `--test-force-exit`)  
**Results:** 54 passed, 0 failed, 0 cancelled — process exits naturally (exit code 0)

---

## 1. Root Cause Analysis

### Symptom
Running `node --test test/scans.test.js` (or the full `npm test`) caused the Node.js process to hang indefinitely after printing all test results. All 13 Scans API Integration subtests passed correctly; the issue was entirely in teardown.

### Investigation Method
Active handles were dumped with `process._getActiveHandles()` immediately after the `finally` block completed. The following handles were still alive after the existing teardown:

```
Socket   fd=2  (stdout)
Socket   fd=1  (stderr)
TLSSocket localPort=64781  remotePort=27017   ← MongoDB Atlas pool socket
TLSSocket localPort=64782  remotePort=27017   ← MongoDB Atlas pool socket
TLSSocket localPort=64783  remotePort=27017   ← MongoDB Atlas pool socket
TLSSocket localPort=64784  remotePort=27017   ← MongoDB Atlas pool socket
TLSSocket localPort=64787  remotePort=27017   ← MongoDB Atlas pool socket
```

The `fd=1` and `fd=2` sockets are stdout/stderr; Node's test runner owns their lifecycle and they close naturally once it finishes. The **5 TLSSocket handles on port 27017** were the problem.

### Root Cause: Mongoose 8 / MongoDB Node.js Driver v6 Connection Pool Lifecycle

The original teardown in `scans.test.js` called:

```js
await mongoose.connection.close(true).catch(() => {});
```

**`mongoose.connection.close(true)` closes the Mongoose logical connection layer but does NOT drain the underlying MongoDB Node.js driver's connection pool.**

In MongoDB Node.js driver v6 (bundled with Mongoose 8), the `MongoClient` maintains its own TLS socket pool independently from the Mongoose abstraction layer. After `mongoose.connection.close()`, the driver retains pooled sockets in a half-closed state — they remain registered with the event loop and prevent natural process exit.

This was confirmed by:
- Calling `mongoose.disconnect()` after `mongoose.connection.close()` — sockets remained (same pool handles).
- Checking `hasRef()` on handles — the sockets return `undefined` (they are not `unref`-able via the standard API because they are internal driver constructs).
- Verifying with a 10-second poll that socket count stayed at 2 (stdout/stderr gone, but 2+ TLS sockets stayed open indefinitely).

### Secondary Issue: HTTP Server `close()` Not Awaited
The original teardown called `testHttpServer.close()` and `srv.close()` as fire-and-forget (no callback), meaning teardown could complete before all keep-alive connections had drained. This was fixed to properly await closure.

---

## 2. Fix Applied

### Strategy
Close the underlying `MongoClient` directly — via `mongoose.connection.getClient().close(true)` — **before** calling `mongoose.connection.close()`. The MongoClient's `close(true)` method immediately destroys all pooled connections including TLS sockets, ensuring no active handles remain in the event loop.

This is the correct documented lifecycle pattern for MongoDB Node.js driver v6+ in test harnesses.

### Files Changed

#### `server/src/config/db.js`
Added a new exported `closeDb()` helper that correctly sequences the connection teardown:

```js
async function closeDb() {
  try {
    const client = mongoose.connection.readyState !== 0
      ? mongoose.connection.getClient()
      : null;
    if (client) await client.close(true);       // ← destroys all pooled TLS sockets
  } catch (_) { /* ignore – connection may already be closing */ }
  await mongoose.connection.close(true).catch(() => {}); // ← tears down Mongoose layer
}
module.exports = { connectDb, dbReady, closeDb, state };
```

#### `server/test/scans.test.js`
1. Import `closeDb` from `db.js` instead of calling `mongoose.connection.close()` directly.
2. `close()` on both HTTP servers is now **properly awaited** via `Promise`-wrapped callbacks.

```js
// Before:
testHttpServer.closeAllConnections?.();
testHttpServer.close();
srv.closeAllConnections?.();
srv.close();
await mongoose.connection.close(true).catch(() => {});

// After:
await new Promise(resolve => { testHttpServer.closeAllConnections?.(); testHttpServer.close(resolve); });
await new Promise(resolve => { srv.closeAllConnections?.(); srv.close(resolve); });
await closeDb();
```

#### `server/package.json`
Removed `--test-force-exit` from the `test` script now that natural exit is confirmed:

```json
"test": "node --test"
```

---

## 3. Verification Results

### Suite 1: Standalone unit suites (api, safeFetcher, modules)
```
node --test test/api.test.js test/safeFetcher.test.js test/modules.test.js

ℹ tests 40
ℹ pass 40
ℹ fail 0
ℹ duration_ms ~1098ms
EXIT CODE: 0 (natural)
```

### Suite 2: Integration suite in isolation (no --test-force-exit)
```
node --test test/scans.test.js

✔ POST /api/scans with valid URL creates assessment and returns 201 (523ms)
✔ POST /api/scans with invalid URL rejects with 400 INVALID_URL (25ms)
✔ POST /api/scans with loopback or metadata IP rejects with 400 SSRF_BLOCKED (47ms)
✔ verifies scan document and domain record are persisted in MongoDB (161ms)
✔ returns 503 DB_UNAVAILABLE when database is disconnected (12ms)
✔ GET /api/scans retrieves authenticated user history with pagination (499ms)
✔ GET /api/scans returns empty array for user with no scans (96ms)
✔ GET /api/scans/:id retrieves full details for valid scan (96ms)
✔ GET /api/scans/:id with invalid ID format returns 400 INVALID_ID (9ms)
✔ GET /api/scans/:id with nonexistent ID returns 404 NOT_FOUND (75ms)
✔ GET /api/scans without token returns 401 UNAUTHENTICATED (15ms)
✔ GET /api/scans/:id by a different user returns 403 FORBIDDEN (139ms)
✔ GET /api/scans/:id by admin user succeeds (69ms)
✔ Scans API Integration Suite (3010ms)

ℹ tests 14
ℹ pass 14
ℹ fail 0
ℹ duration_ms ~3760ms
EXIT CODE: 0 (natural)
```

### Suite 3: Full npm test (no --test-force-exit)
```
npm test  →  node --test

ℹ tests 54
ℹ suites 0
ℹ pass 54
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 3358ms
EXIT CODE: 0 (natural)
```

---

## 4. Preserved Invariants

| Invariant | Status |
|---|---|
| All 54 test assertions unchanged | ✅ Preserved |
| Auth/JWT enforcement (401, 403) | ✅ Preserved |
| SSRF protection (400 SSRF_BLOCKED) | ✅ Preserved |
| Rate limiting (limiter middleware) | ✅ Preserved |
| Database schema (Scan, Domain) | ✅ Unchanged |
| MongoDB Atlas data integrity | ✅ No destructive changes |
| Application source code (routes, middleware, models) | ✅ Unchanged |
| `process.exit()` | ✅ Not used |
| `--test-force-exit` | ✅ Removed — no longer needed |

---

## 5. Files Changed Summary

| File | Change | Lines Affected |
|---|---|---|
| `server/src/config/db.js` | Added `closeDb()` export function | +17 lines |
| `server/test/scans.test.js` | Use `closeDb()`; await HTTP server close | -5 / +9 lines |
| `server/package.json` | Removed `--test-force-exit` from test script | 1 line |

---

## 6. Remaining Limitations

1. **Atlas IP Whitelist Sensitivity:** When the outbound IP of this machine changes (e.g., network switch, DHCP renewal), MongoDB Atlas may reject the connection with:
   ```
   Could not connect to any servers in your MongoDB Atlas cluster.
   One common reason is that you're trying to access the database from an IP that isn't whitelisted.
   ```
   This is an **infrastructure access control issue**, not an application or test code bug. The integration suite (`scans.test.js`) will correctly report the Atlas assertion failure (`MongoDB Atlas should connect for integration testing`) as a test failure when connectivity is blocked. The 40 unit tests in `api.test.js`, `safeFetcher.test.js`, and `modules.test.js` are unaffected and continue to pass without database access.

2. **Frontend Authentication UI:** Scan submissions from `frontend/index.html` are anonymous (no Bearer token). Registered-user history endpoints (`GET /api/scans`) require a token not yet issued by the frontend. This is a planned Priority 3.4+ integration task.
