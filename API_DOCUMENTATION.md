# TRUSTLENS – API_DOCUMENTATION.md

**API Reference Specification**  
**Base URL:** `/api`  
**Authentication Scheme:** `Authorization: Bearer <jwt_token>`  
**Last Updated:** 2026-11-08  

---

## 1. Conventions & Standards

### Standard Success Envelope:
Every successful API response returns HTTP `200` (or `201` for creation) with a structured JSON body:
```json
{
  "ok": true,
  "data": { ... },
  "meta": {
    "mode": "live"
  }
}
```

### Standard Error Envelope:
Errors return standard HTTP status codes (`400`, `401`, `403`, `404`, `409`, `429`, `501`, `503`, `500`) with a structured JSON error object:
```json
{
  "ok": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input.",
    "details": [
      {
        "path": "email",
        "message": "Invalid email"
      }
    ]
  }
}
```

### Standard Error Codes:
- `VALIDATION_ERROR` (400): Request body, query, or path parameters failed Zod schema validation.
- `INVALID_URL` (400): Submitted URL failed `urlGuard` syntax or scheme restrictions.
- `INVALID_ID` (400): MongoDB ObjectId string format is invalid.
- `BAD_JSON` (400): Request payload could not be parsed as valid JSON.
- `UNAUTHENTICATED` (401): Missing, malformed, forged, or expired JWT bearer token.
- `BAD_CREDENTIALS` (401): Incorrect email or password during login.
- `FORBIDDEN` (403): Authenticated user does not possess the required role (e.g., non-admin calling admin endpoints).
- `NOT_FOUND` (404): Requested entity or route does not exist.
- `EMAIL_IN_USE` (409): Attempted registration with an already registered email.
- `DUPLICATE_REPORT` (409): Caller has already submitted a report for this domain under this category.
- `RATE_LIMITED` (429): Request threshold exceeded for client IP.
- `NOT_IMPLEMENTED` (501): Honest stub for planned feature.
- `DB_UNAVAILABLE` (503): MongoDB is disconnected or offline (`requireDb` middleware).
- `AUTH_NOT_CONFIGURED` (503): Server `JWT_SECRET` is missing or shorter than 32 characters.
- `INTERNAL_ERROR` (500): Unhandled server exception.

---

## 2. Implemented & Registered API Endpoints

There are **14 functional endpoints registered and active** in the Express application:
- Health check: `GET /api/health`
- Authentication & Sessions: `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/guest`
- User Profiles: `GET /api/users/me`
- Community Intelligence & Threat Explorer: `GET /api/reports`, `GET /api/threats`, `POST /api/reports`, `GET /api/reports/mine`
- Administration & Review: `GET /api/admin/reports`, `PATCH /api/admin/reports/:id`
- Metrics: `GET /api/dashboard/stats`
- Website Security Scans: `POST /api/scans`, `GET /api/scans`, `GET /api/scans/:id`

### 2.1 System & Health

#### `GET /api/health`
- **Purpose:** Service health check and database connectivity reporting.
- **Authentication:** None (Public).
- **Database Dependency:** Non-blocking. Responds even when database is disconnected.
- **Responses:**
  - **HTTP 200 (Database Connected):**
    ```json
    {
      "ok": true,
      "data": {
        "service": "trustlens-server",
        "uptimeSec": 142,
        "database": "connected"
      }
    }
    ```
  - **HTTP 503 (Database Offline):**
    ```json
    {
      "ok": false,
      "data": {
        "service": "trustlens-server",
        "uptimeSec": 12,
        "database": "unavailable",
        "databaseNote": "MONGODB_URI not set"
      }
    }
    ```

---

### 2.2 Authentication

*Rate Limit: 30 requests per 15 minutes per IP.*  
*Database Dependency: Requires active database (`requireDb`). Returns 503 if offline.*

#### `POST /api/auth/register`
- **Purpose:** Register a new user account with default role `user`.
- **Authentication:** None (Public).
- **Request Body (JSON):**
  ```json
  {
    "name": "Jane Doe",
    "email": "jane@example.com",
    "password": "SecretPassword123!"
  }
  ```
  *Validation Rules:*
  - `name`: string, trimmed, 1 to 80 characters.
  - `email`: valid email address, max 254 characters (normalized to lowercase).
  - `password`: string, 10 to 128 characters.
- **Responses:**
  - **HTTP 201 Created:**
    ```json
    {
      "ok": true,
      "data": {
        "token": "eyJhbGciOiJIUzI1NiIsIn...",
        "user": {
          "id": "672e12f0a1b2c3d4e5f60718",
          "name": "Jane Doe",
          "role": "user"
        }
      }
    }
    ```
  - **HTTP 409 Conflict:** `{"ok": false, "error": {"code": "EMAIL_IN_USE", "message": "Email already registered."}}`

#### `POST /api/auth/login`
- **Purpose:** Authenticate existing user and receive JWT.
- **Authentication:** None (Public).
- **Request Body (JSON):**
  ```json
  {
    "email": "jane@example.com",
    "password": "SecretPassword123!"
  }
  ```
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "token": "eyJhbGciOiJIUzI1NiIsIn...",
        "user": {
          "id": "672e12f0a1b2c3d4e5f60718",
          "name": "Jane Doe",
          "role": "user"
        }
      }
    }
    ```
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "BAD_CREDENTIALS", "message": "Incorrect email or password."}}`

---

### 2.3 User Profile

#### `GET /api/users/me`
- **Purpose:** Retrieve caller's user account profile.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `user` or `admin`.
- **Database Dependency:** Requires active database.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "id": "672e12f0a1b2c3d4e5f60718",
        "name": "Jane Doe",
        "email": "jane@example.com",
        "role": "user",
        "createdAt": "2026-11-08T10:15:30.000Z"
      }
    }
    ```
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required."}}`

---

### 2.4 Community Threat Reporting & Threat Exploration

*Database Dependency: Requires active database.*

#### `GET /api/reports` & `GET /api/threats`
- **Purpose:** Public endpoint for searching and exploring community threat intelligence reports. Returns safe public fields only; never exposes reporter identities, reviewer identities, or private session tokens.
- **Authentication:** None (Public).
- **Rate Limit:** 60 requests per minute per IP.
- **Query Parameters:**
  - `q` or `domain` (optional): Search query matching domain name substring (case-insensitive).
  - `category` (optional): Filter by report category (`phishing`, `fake_recruitment`, `fake_banking`, `fake_payment`, `brand_impersonation`, `suspicious_redirect`, `other`).
  - `status` (optional): Filter by review status (`pending_review`, `under_verification`, `verified`, `rejected`).
  - `page` (optional, default: 1): Page number.
  - `limit` (optional, default: 20, max: 100): Results per page.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "reports": [
          {
            "id": "672e15a9c3d4e5f6a1b2c3d4",
            "domain": "suspicious-login-portal.example",
            "category": "phishing",
            "status": "pending_review",
            "description": "Asked for banking PIN",
            "createdAt": "2026-11-08T10:20:00.000Z"
          }
        ],
        "pagination": {
          "page": 1,
          "limit": 20,
          "total": 1,
          "totalPages": 1
        }
      },
      "meta": {
        "mode": "live"
      }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "VALIDATION_ERROR", "message": "Invalid input."}}`
  - **HTTP 503 Service Unavailable:** `{"ok": false, "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}}`

*Rate Limit on Submission: 20 requests per hour per IP.*

#### `POST /api/reports`
- **Purpose:** Submit a community threat report for a suspicious domain.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `user` or `admin`.
- **Request Body (JSON):**
  ```json
  {
    "url": "https://suspicious-login-portal.example/auth",
    "category": "phishing",
    "description": "Mimicked online banking login form asking for debit card PIN."
  }
  ```
  *Allowed Categories:*
  `phishing`, `fake_recruitment`, `fake_banking`, `fake_payment`, `brand_impersonation`, `suspicious_redirect`, `other`.
- **Responses:**
  - **HTTP 201 Created:**
    ```json
    {
      "ok": true,
      "data": {
        "id": "672e15a9c3d4e5f6a1b2c3d4",
        "domain": "suspicious-login-portal.example",
        "category": "phishing",
        "status": "pending_review",
        "createdAt": "2026-11-08T10:20:00.000Z"
      },
      "meta": {
        "mode": "live"
      }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "INVALID_URL", "message": "Private or reserved address"}}`
  - **HTTP 409 Conflict:** `{"ok": false, "error": {"code": "DUPLICATE_REPORT", "message": "You already reported this domain in this category."}}`

#### `GET /api/reports/mine`
- **Purpose:** Retrieve reports submitted by the caller (reporter ID is kept private).
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `user` or `admin`.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": [
        {
          "id": "672e15a9c3d4e5f6a1b2c3d4",
          "domain": "suspicious-login-portal.example",
          "category": "phishing",
          "status": "pending_review",
          "createdAt": "2026-11-08T10:20:00.000Z"
        }
      ],
      "meta": {
        "mode": "live"
      }
    }
    ```

---

### 2.5 Administration & Moderation

*Database Dependency: Requires active database.*

#### `GET /api/admin/reports`
- **Purpose:** List submitted community reports for review (limited to latest 100).
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Query Parameters:**
  - `status` (optional): Filter by report status (`pending_review`, `under_verification`, `verified`, `rejected`).
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": [
        {
          "id": "672e15a9c3d4e5f6a1b2c3d4",
          "domain": "suspicious-login-portal.example",
          "category": "phishing",
          "status": "pending_review",
          "description": "Mimicked online banking login form asking for debit card PIN.",
          "createdAt": "2026-11-08T10:20:00.000Z"
        }
      ],
      "meta": {
        "mode": "live"
      }
    }
    ```
  - **HTTP 403 Forbidden:** `{"ok": false, "error": {"code": "FORBIDDEN", "message": "Insufficient permissions."}}`

#### `PATCH /api/admin/reports/:id`
- **Purpose:** Update status of a report, synchronize `VerifiedThreat` records, and record an immutable `AuditLog` entry.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Request Body (JSON):**
  ```json
  {
    "status": "verified",
    "notes": "Confirmed credential phishing form mimicking bank login."
  }
  ```
  *Allowed Statuses:* `under_verification`, `verified`, `rejected`.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "id": "672e15a9c3d4e5f6a1b2c3d4",
        "domain": "suspicious-login-portal.example",
        "status": "verified",
        "reviewedAt": "2026-11-09T02:00:00.000Z"
      }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "INVALID_ID", "message": "Invalid report id format."}}`
  - **HTTP 404 Not Found:** `{"ok": false, "error": {"code": "NOT_FOUND", "message": "Report not found."}}`

#### `GET /api/admin/audit`
- **Purpose:** Retrieve immutable system audit trail entries with pagination and actor population.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Query Parameters:**
  - `page` (optional, default: 1): Page number.
  - `limit` (optional, default: 20, max: 100): Results per page.
  - `action` (optional): Filter by audit action (e.g. `report.status_changed`, `threat_intel.feed_sync`).
  - `targetType` (optional): Filter by target model (e.g. `CommunityReport`, `ThreatIntel`).
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "auditLogs": [
          {
            "id": "672e2001c3d4e5f6a1b2c3d4",
            "actor": {
              "id": "672e18b0c3d4e5f6a1b2c3d4",
              "name": "SecOps Analyst",
              "role": "admin"
            },
            "action": "report.status_changed",
            "targetType": "CommunityReport",
            "targetId": "672e15a9c3d4e5f6a1b2c3d4",
            "detail": {
              "domainName": "suspicious-portal.example",
              "oldStatus": "pending_review",
              "newStatus": "verified"
            },
            "createdAt": "2026-11-09T02:00:00.000Z"
          }
        ],
        "pagination": {
          "page": 1,
          "limit": 20,
          "total": 1,
          "totalPages": 1
        }
      }
    }
    ```
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required."}}`
  - **HTTP 403 Forbidden:** `{"ok": false, "error": {"code": "FORBIDDEN", "message": "Insufficient permissions."}}`

#### `GET /api/admin/stats`
- **Purpose:** Aggregate moderation queue metrics, verified threat totals, external threat indicator counts, and recent audit activity.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "reports": {
          "pending": 12,
          "underVerification": 5,
          "verified": 8,
          "rejected": 3,
          "total": 28
        },
        "threats": {
          "verifiedThreats": 8,
          "externalThreatIntel": 240
        },
        "recentAudits": [
          {
            "id": "672e2001c3d4e5f6a1b2c3d4",
            "action": "report.status_changed",
            "actor": "SecOps Analyst",
            "targetId": "672e15a9c3d4e5f6a1b2c3d4",
            "createdAt": "2026-11-09T02:00:00.000Z"
          }
        ]
      },
      "meta": { "mode": "live" }
    }
    ```

#### `POST /api/admin/threat-intel/sync`
- **Purpose:** Trigger on-demand external threat intelligence feed synchronization (URLhaus & OpenPhish) with safe network controls and deduplication.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Request Body (JSON, optional):**
  ```json
  {
    "source": "all",
    "limit": 500
  }
  ```
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "startedAt": "2026-11-09T02:00:00.000Z",
        "completedAt": "2026-11-09T02:00:02.000Z",
        "totalIngested": 185,
        "sources": {
          "urlhaus": { "status": "success", "processed": 100, "upserted": 100 },
          "openphish": { "status": "success", "processed": 85, "upserted": 85 }
        },
        "errors": []
      },
      "meta": { "mode": "live" }
    }
    ```

#### `GET /api/admin/threat-intel/status`
- **Purpose:** Retrieve external threat feed configuration, active indicator totals, and synchronization history.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Authorization:** `admin` role strictly required.
- **Responses:**
  - **HTTP 200 OK:** Summary of feed endpoints, terms/licenses, and indicator counts by source.

---

### 2.6 Dashboard Metrics

#### `GET /api/dashboard/stats`
- **Purpose:** Aggregate live platform trust metrics, risk distribution, category breakdowns, and recent activity from the database.
- **Authentication:** Optional (Public access supported; authenticated users with `role: 'user'` additionally receive `userScans`).
- **Rate Limit:** 60 requests per minute per IP.
- **Database Dependency:** Requires active database (`requireDb`). Returns 503 `DB_UNAVAILABLE` when offline.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "scans": 142,
        "highRiskScans": 28,
        "criticalScans": 12,
        "reports": 45,
        "verifiedReports": 18,
        "pendingReports": 24,
        "riskDistribution": {
          "low": 94,
          "moderate": 20,
          "high": 16,
          "critical": 12
        },
        "categories": {
          "phishing": 22,
          "fake_banking": 14,
          "fake_recruitment": 9
        },
        "recentScans": [
          {
            "id": "672e18b0c3d4e5f6a1b2c3d4",
            "domain": "example.com",
            "domainName": "example.com",
            "url": "https://example.com/",
            "riskScore": 5,
            "classification": "Low Risk",
            "createdAt": "2026-11-09T01:00:00.000Z"
          }
        ],
        "recentReports": [
          {
            "id": "672e15a9c3d4e5f6a1b2c3d4",
            "domain": "suspicious-portal.example",
            "domainName": "suspicious-portal.example",
            "category": "phishing",
            "status": "pending_review",
            "createdAt": "2026-11-09T00:50:00.000Z"
          }
        ],
        "userScans": 8
      },
      "meta": {
        "mode": "live"
      }
    }
    ```
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Invalid or expired token."}}` (when a forged/malformed Bearer token is provided).
  - **HTTP 503 Service Unavailable:** `{"ok": false, "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}}`

---

### 2.7 Website Scanning Endpoints

Mounted in [`server/src/routes/scans.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/scans.js):

*Database Dependency: Requires active database (`requireDb`).*  
*Rate Limit on Submission: 30 requests per minute per IP.*

#### `POST /api/scans`
- **Purpose:** Submit a website URL for multi-layer security assessment (threat heuristics, security headers, TLS certificate intelligence, and community reports).
- **Authentication:** Optional (authenticated scans are linked to `req.user.id`; unauthenticated scans proceed anonymously).
- **Request Body (JSON):**
  ```json
  {
    "url": "https://example.com"
  }
  ```
- **Responses:**
  - **HTTP 201 Created:**
    ```json
    {
      "ok": true,
      "data": {
        "id": "672e18b0c3d4e5f6a1b2c3d4",
        "url": "https://example.com/",
        "domain": "example.com",
        "score": 0,
        "riskLevel": "low",
        "classification": "Low Risk",
        "confidence": 73,
        "coverage": 100,
        "modules": { ... },
        "findings": [ ... ],
        "recommendations": [ ... ]
      },
      "meta": { "mode": "live" }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "INVALID_URL", "message": "Malformed URL"}}`
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "SSRF_BLOCKED", "message": "Private or reserved address"}}`
  - **HTTP 503 Service Unavailable:** `{"ok": false, "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}}`

#### `GET /api/scans`
- **Purpose:** Retrieve caller's historical scan records with pagination.
- **Authentication:** Required (`Authorization: Bearer <jwt>`).
- **Query Parameters:**
  - `page` (optional, default: 1): Page number.
  - `limit` (optional, default: 20, max: 100): Results per page.
  - `domain` (optional): Filter history by domain name.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "scans": [
          {
            "id": "672e18b0c3d4e5f6a1b2c3d4",
            "url": "https://example.com/",
            "domain": "example.com",
            "score": 0,
            "classification": "Low Risk",
            "confidence": 73,
            "status": "completed",
            "createdAt": "2026-11-08T15:37:00.000Z"
          }
        ],
        "pagination": {
          "page": 1,
          "limit": 20,
          "total": 1,
          "totalPages": 1
        }
      },
      "meta": { "mode": "live" }
    }
    ```
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required."}}`

#### `GET /api/scans/:id`
- **Purpose:** Retrieve detailed assessment findings of a completed scan.
- **Authentication:** Optional for public scans; required if scan was created by a registered user.
- **Authorization:** Only the scan owner or an admin can view private user scans.
- **Responses:**
  - **HTTP 200 OK:** Full scan assessment object including all module breakdowns and recommendations.
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "INVALID_ID", "message": "Invalid scan ID format."}}`
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Authentication required to view this scan."}}`
  - **HTTP 403 Forbidden:** `{"ok": false, "error": {"code": "FORBIDDEN", "message": "You do not have permission to access this scan."}}`
  - **HTTP 404 Not Found:** `{"ok": false, "error": {"code": "NOT_FOUND", "message": "Scan record not found."}}`

---

### 2.8 Certificate Intelligence Endpoints

Mounted in [`server/src/routes/certificates.js`](file:///C:/Users/Pradipta/.gemini/antigravity/scratch/trustlens/server/src/routes/certificates.js):

*Database Dependency: Requires active database (`requireDb`).*  
*Rate Limit: 60 requests per minute per IP.*

#### `GET /api/certificates/:domain`
- **Purpose:** Retrieve live TLS certificate intelligence, validity status, issuer authority, hostname matching, and Certificate Transparency log observations for a target domain.
- **Authentication:** Optional (Public access supported).
- **Authorization:** None (Public).
- **Path Parameters:**
  - `domain`: Domain name to inspect (e.g. `example.com`, normalizes scheme and trailing paths).
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "domain": "example.com",
        "domainName": "example.com",
        "issuer": "DigiCert Global Root G2",
        "subject": "example.com",
        "san": ["example.com", "www.example.com"],
        "validFrom": "2026-01-01T00:00:00.000Z",
        "validTo": "2026-12-31T23:59:59.000Z",
        "daysRemaining": 235,
        "hostnameMatch": true,
        "chainValid": true,
        "status": "valid",
        "ct": {
          "status": "available",
          "source": "crt.sh",
          "totalLogged": 14,
          "earliest": "2023-04-12T00:00:00.000Z",
          "latest": "2026-10-01T00:00:00.000Z",
          "discoveredSANs": ["example.com", "www.example.com", "api.example.com"],
          "note": null,
          "disclaimer": "Certificate Transparency logs show publicly recorded certificate issuance. They do not establish that a website is safe or malicious."
        },
        "observedAt": "2026-11-09T01:00:00.000Z"
      },
      "meta": { "mode": "live" }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "INVALID_DOMAIN", "message": "Invalid domain parameter format."}}`
  - **HTTP 401 Unauthorized:** `{"ok": false, "error": {"code": "UNAUTHENTICATED", "message": "Invalid or expired token."}}` (when a forged/malformed Bearer token is provided).
  - **HTTP 404 Not Found:** `{"ok": false, "error": {"code": "NOT_FOUND", "message": "No certificate record found for domain \"example.com\". Run a website scan first."}}`
  - **HTTP 503 Service Unavailable:** `{"ok": false, "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}}`

#### `GET /api/certificates`
- **Purpose:** Search and list verified certificate intelligence records with pagination.
- **Authentication:** Optional (Public access supported).
- **Query Parameters:**
  - `q` (optional): Filter certificates by domain substring.
  - `page` (optional, default: 1): Page number.
  - `limit` (optional, default: 20, max: 100): Results per page.
- **Responses:**
  - **HTTP 200 OK:**
    ```json
    {
      "ok": true,
      "data": {
        "certificates": [
          {
            "domain": "example.com",
            "domainName": "example.com",
            "issuer": "DigiCert Global Root G2",
            "subject": "example.com",
            "san": ["example.com", "www.example.com"],
            "validFrom": "2026-01-01T00:00:00.000Z",
            "validTo": "2026-12-31T23:59:59.000Z",
            "daysRemaining": 235,
            "hostnameMatch": true,
            "chainValid": true,
            "status": "valid",
            "ct": {
              "status": "not_fetched",
              "source": null,
              "totalLogged": null,
              "earliest": null,
              "latest": null,
              "discoveredSANs": [],
              "note": "CT intelligence not yet fetched for this record. Run a new scan to populate.",
              "disclaimer": "Certificate Transparency logs show publicly recorded certificate issuance. They do not establish that a website is safe or malicious."
            },
            "observedAt": "2026-11-09T01:00:00.000Z"
          }
        ],
        "pagination": {
          "page": 1,
          "limit": 20,
          "total": 1,
          "totalPages": 1
        }
      },
      "meta": { "mode": "live" }
    }
    ```
  - **HTTP 400 Bad Request:** `{"ok": false, "error": {"code": "VALIDATION_ERROR", "message": "Invalid query parameters."}}`
  - **HTTP 503 Service Unavailable:** `{"ok": false, "error": {"code": "DB_UNAVAILABLE", "message": "Database is unavailable."}}`

---

## 3. Planned Endpoints (Not Yet Routed)

These endpoints are designed as part of future platform phases and are **not yet registered** in the Express router:

| HTTP Method | Target Endpoint | Planned Module | Planned Purpose | Planned Auth |
|---|---|---|---|---|
| `POST` | `/api/scans/:id/export` | Core Platform | Generate downloadable PDF audit summary | `user` or `admin` |
