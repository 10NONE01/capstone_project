# SecureAuto Security Review

**Reviewed and remediated:** 2026-11-22
**Scope:** `server.js`, `audit.js`, `session-store.js`, frontend JavaScript, database, utility scripts, and dependencies.
**Method:** code review, automated tests against throwaway databases, live probes against a copy of the demo database, and a browser check of the main pages.

## Summary

The review found 16 weaknesses. **14 are fixed**, and 2 remain by decision or as a known limit. All 116 automated tests pass, and `npm audit` reports 0 known vulnerabilities.

| Severity | Found | Fixed | Remaining |
|---|---|---|---|
| High | 4 | 3 | 1 (H-3, accepted for this class project) |
| Medium | 7 | 7 | 0 |
| Low | 5 | 4 | 1 (L-4, partly addressed) |

## High

| ID | Weakness | Before | Fix | Status |
|---|---|---|---|---|
| H-1 | No login rate limiting | 100 wrong passwords in 5.4 s, none blocked | 10 failed attempts per account and 20 per IP every 15 minutes, then HTTP 429 | Fixed |
| H-2 | Scripts accepted 4-character passwords | Checks used `length < 4` | Both scripts require 12 characters | Fixed |
| H-3 | Password hashes are in the public repository | Database is tracked on `main` | None. The team accepted this because the project uses fictional demo accounts | **Accepted** |
| H-4 | Password hashing blocked the server | Health check took 2,124 ms during 40 concurrent logins | Asynchronous hashing with at most 8 running at once. Worst health check measured 41 ms | Fixed |

## Medium

| ID | Weakness | Fix | Status |
|---|---|---|---|
| M-1 | Password changes did not end sessions | Sessions are tied to a fingerprint of the current password hash | Fixed |
| M-2 | Login timing revealed which emails exist (52.0 ms vs 4.4 ms) | Unknown emails are checked against a dummy hash (now 53.9 ms vs 50.0 ms) | Fixed |
| M-3 | Errors leaked stack traces and local paths | Final error handler returns a generic message | Fixed |
| M-4 | No security headers | `helmet` with a strict Content Security Policy | Fixed |
| M-5 | `X-Powered-By: Express` was sent | Header disabled | Fixed |
| M-6 | Session cookie was never `Secure` | `Secure` and HSTS turn on when `NODE_ENV=production` | Fixed |
| M-7 | Sessions were held in memory | SQLite session store with expiry, hashed session IDs, and survival across restarts | Fixed |

## Low

| ID | Weakness | Fix | Status |
|---|---|---|---|
| L-1 | Appointment IDs accepted `1e0` and `0x1` | Only plain positive digits are accepted | Fixed |
| L-2 | Email matching was case-sensitive | Login ignores case, and a database index blocks case-only duplicates | Fixed |
| L-3 | `SECRET.env` was not ignored by Git | Added `*.env` to `.gitignore` | Fixed |
| L-4 | Audit log has no retention policy | Rate limits and log throttling bound the growth from attacks. Retention or archiving is still not implemented | **Partly addressed** |
| L-5 | CSRF defense relied only on `SameSite` | Cross-origin POST requests are rejected using `Origin` and `Sec-Fetch-Site` | Fixed |

## What passed from the start

- **Role enforcement:** all 28 combinations of role and protected route returned the expected status.
- **Ownership:** customers and mechanics saw only their own records.
- **Injection:** SQL and object injection attempts at login failed, and all queries are parameterized.
- **Sessions:** session IDs rotate at login, forged cookies fail, and logout ends the session.
- **File exposure:** source, `.env`, database, and path traversal requests were not served.
- **Stored XSS:** the dashboard renders data with `textContent`.

## Audit logging

Implemented in `audit.js` and connected to all protected routes.

- **Events:** login success, failure, rejection, rate limiting and overload, logout, unauthenticated access, invalid sessions, role denials, IDOR attempts, invalid input, blocked CSRF, customer data views, audit log views, integrity checks, and request errors.
- **Fields:** timestamp, actor, role, event, outcome, HTTP method, resource, IP address, and details.
- **Privacy:** passwords are never logged. Failed login emails are stored as a keyed pseudonym so repeated attempts can still be correlated.
- **Tamper resistance:** database triggers block updates and deletes, and each row carries an HMAC chained to the previous row. Admins can check the chain at `GET /api/admin/audit-logs/verify`.
- **Flood protection:** repeated anonymous events are limited to one row per client and scope per minute.

**Known limits:** someone with both database write access and the HMAC key can rewrite the chain. Deleting only the newest rows is not detectable unless the latest hash is also stored elsewhere.

## Operating notes

- Copy `.env.example` to `.env` and set `SESSION_SECRET` and `AUDIT_HMAC_KEY`.
- Too many wrong passwords during a demo will lock that account for up to 15 minutes. Restarting the server clears the limit.
- An attacker who knows an email can deliberately trigger that account's temporary lockout. This is the tradeoff for per-account protection.
- Sessions are stored in `database/sessions.db`, which Git ignores.
- The first server start adds audit columns and an email index to `database/mobile_auto_basics.db`.
- Set `NODE_ENV=production` only behind HTTPS, because `Secure` cookies are not sent over plain HTTP. Set `TRUST_PROXY=1` only behind a single reverse proxy you control.

## Running the tests

```powershell
npm test
```

The tests build temporary databases and never open `database/mobile_auto_basics.db`.
