
const express = require("express");
const session = require("express-session");
const path = require("node:path");

const { DatabaseSync } = require("node:sqlite");

const {
    createHmac,
    randomBytes,
    scrypt,
    scryptSync,
    timingSafeEqual
} = require("node:crypto");

const { promisify } = require("node:util");

const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");

const { createAuditLog } = require("./audit");
const { SqliteSessionStore } = require("./session-store");

// ========================================
// 1. EXPRESS SERVER SETUP
// ========================================

const app = express();
const PORT = Number(process.env.PORT) || 4100;

// Connect to our existing SQLite database
const dbPath =
    process.env.DB_PATH ||
    path.join(__dirname, "database", "mobile_auto_basics.db");

const db = new DatabaseSync(dbPath);

db.exec("PRAGMA foreign_keys = ON");

// Emails are unique regardless of letter case
db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower
        ON users (lower(email))
`);

// ========================================
// 2. CREATE SECURITY AUDIT LOG TABLE
// ========================================

// This does not erase existing records.
// The table is created only if it does not exist.

db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        resource TEXT,
        details TEXT,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

        FOREIGN KEY (user_id)
            REFERENCES users(id)
            ON DELETE SET NULL
    )
`);

// ========================================
// 3. EXPRESS MIDDLEWARE AND SESSIONS
// ========================================

const isProduction = process.env.NODE_ENV === "production";

app.disable("x-powered-by");

// Only enable behind a reverse proxy you control. Otherwise
// clients could forge their IP address in audit logs.
if (process.env.TRUST_PROXY === "1") {
    app.set("trust proxy", 1);
}

app.use(helmet({
    contentSecurityPolicy: {
        useDefaults: false,
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'"],
            styleSrc: ["'self'"],
            imgSrc: ["'self'"],
            fontSrc: ["'self'"],
            connectSrc: ["'self'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"]
        }
    },
    strictTransportSecurity: isProduction
}));

// CSRF defense: state-changing requests must be same-origin
app.use((req, res, next) => {

    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
        return next();
    }

    const origin = req.get("origin");
    const fetchSite = req.get("sec-fetch-site");

    let sameOrigin =
        fetchSite === undefined ||
        ["same-origin", "none"].includes(fetchSite);

    if (origin) {
        try {
            sameOrigin = sameOrigin &&
                new URL(origin).host === req.get("host");
        } catch {
            sameOrigin = false;
        }
    }

    if (sameOrigin) {
        return next();
    }

    logThrottled(req, "CSRF_BLOCKED", "all", {
        user: null,
        details: "Cross-origin state-changing request blocked"
    });

    res.status(403).json({
        error: "Access denied"
    });
});

app.use(express.json({ limit: "10kb" }));

if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing");
}

// Set AUDIT_HMAC_KEY separately so SESSION_SECRET can be rotated
// without invalidating the audit log's integrity chain.
const auditLog = createAuditLog(
    db,
    process.env.AUDIT_HMAC_KEY || process.env.SESSION_SECRET
);

const sessionStore = new SqliteSessionStore(
    process.env.SESSION_DB_PATH ||
    path.join(path.dirname(dbPath), "sessions.db")
);

app.use(session({
    name: "mab.sid",
    store: sessionStore,
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: isProduction, // Requires HTTPS in production
        maxAge: 60 * 60 * 1000
    }
}));

// ========================================
// 4. HEALTH CHECK
// ========================================

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        message: "Mobile Auto Basics backend is running!"
    });
});

// ========================================
// 5. PASSWORD VERIFICATION
// ========================================

const scryptAsync = promisify(scrypt);

// Hashing is deliberately slow, so cap how many run at once.
const MAX_CONCURRENT_HASHES = 8;
let activeHashes = 0;

// Checked when an email is unknown, so both cases take equal time.
const dummySalt = randomBytes(16).toString("hex");
const DUMMY_PASSWORD_HASH = `${dummySalt}:${
    scryptSync(randomBytes(32), dummySalt, 64).toString("hex")
}`;

async function verifyPassword(password, storedPassword) {

    try {
        const [salt, hash] = storedPassword.split(":");

        if (
            !salt ||
            !/^[0-9a-f]{128}$/i.test(hash || "")
        ) {
            return false;
        }

        const storedHash = Buffer.from(hash, "hex");

        const suppliedHash = await scryptAsync(
            password,
            salt,
            64
        );

        return timingSafeEqual(
            storedHash,
            suppliedHash
        );

    } catch {
        return false;
    }
}

// Changes whenever the password changes, ending older sessions.
function credentialFingerprint(passwordHash) {

    return createHmac("sha256", process.env.SESSION_SECRET)
        .update(`session-credential:${passwordHash}`)
        .digest("hex");
}

// ========================================
// 6. SECURITY AUDIT LOGGING
// ========================================

function logAudit(req, eventType, options = {}) {

    const user = options.user === undefined
        ? req.user
        : options.user;

    return auditLog.write({
        userId: user?.id ?? null,
        role: user?.role ?? null,
        eventType,
        outcome: options.outcome ?? "failure",
        resource: options.resource ?? req.path,
        method: req.method,
        ip: req.ip,
        details: options.details ?? null
    });
}

// Anonymous requests are cheap to send, so each client and scope
// writes at most one row per window. This stops unauthenticated
// traffic from growing the audit table without limit.
const THROTTLED_LOG_WINDOW_MS = 60 * 1000;
const THROTTLED_LOG_MAX_KEYS = 10000;
const throttledLogWindows = new Map();

function logThrottled(req, eventType, scope, options) {

    const key = `${eventType}|${req.ip}|${scope}`;
    const now = Date.now();
    const current = throttledLogWindows.get(key);

    if (current && now - current.startedAt < THROTTLED_LOG_WINDOW_MS) {
        current.suppressed += 1;
        return;
    }

    if (throttledLogWindows.size >= THROTTLED_LOG_MAX_KEYS) {
        throttledLogWindows.clear();
    }

    throttledLogWindows.set(key, { startedAt: now, suppressed: 0 });

    const repeats = current?.suppressed
        ? `; ${current.suppressed} repeats in previous window`
        : "";

    logAudit(req, eventType, {
        ...options,
        details: `${options.details}${repeats}`
    });
}

// ========================================
// 7. LOGIN AUTHENTICATION
// ========================================

const LOGIN_WINDOW_MS = 15 * 60 * 1000;

function loginLimiter(limit, keyOptions = {}) {

    return rateLimit({
        windowMs: LOGIN_WINDOW_MS,
        limit,
        standardHeaders: true,
        legacyHeaders: false,
        skipSuccessfulRequests: true,
        // Forwarded headers are intentionally ignored unless
        // TRUST_PROXY is enabled.
        validate: { xForwardedForHeader: false },
        ...keyOptions,
        handler: (req, res) => {

            logThrottled(req, "LOGIN_RATE_LIMITED", "login", {
                user: null,
                resource: "/api/login",
                details: "Too many failed login attempts"
            });

            res.status(429).json({
                error: "Too many login attempts. Please try again later."
            });
        }
    });
}

const loginIpLimiter = loginLimiter(
    Number(process.env.LOGIN_MAX_ATTEMPTS_IP) || 20
);

const loginAccountLimiter = loginLimiter(
    Number(process.env.LOGIN_MAX_ATTEMPTS_ACCOUNT) || 10,
    {
        keyGenerator: (req) => {
            const email = req.body?.email;

            return typeof email === "string"
                ? auditLog.pseudonymize(email)
                : "invalid-login";
        }
    }
);

app.post("/api/login", loginIpLimiter, loginAccountLimiter, async (req, res, next) => {

    const {
        email,
        password,
        selectedRole
    } = req.body || {};

    // Validate email and password
    if (
        typeof email !== "string" ||
        typeof password !== "string" ||
        !email.trim() ||
        !password ||
        email.length > 254 ||
        password.length > 1024
    ) {
        logAudit(req, "LOGIN_REJECTED", {
            user: null,
            details: "Malformed login request"
        });

        return res.status(400).json({
            error: "Valid email and password are required."
        });
    }

    // Capstone role selection
    const allowedRoles = ["customer", "mechanic", "admin"];

    if (!allowedRoles.includes(selectedRole)) {
        logAudit(req, "LOGIN_REJECTED", {
            user: null,
            details: "Invalid account type selected"
        });

        return res.status(400).json({
            error: "Please select a valid account type."
        });
    }

    // Find account in SQLite
    const user = db.prepare(`
        SELECT
            id,
            name,
            email,
            password_hash,
            role
        FROM users
        WHERE lower(email) = ?
    `).get(email.trim().toLowerCase());

    // Shed load rather than queue unlimited password hashing
    if (activeHashes >= MAX_CONCURRENT_HASHES) {

        logThrottled(req, "LOGIN_BUSY", "login", {
            user: null,
            details: "Login capacity exceeded"
        });

        res.set("Retry-After", "1");

        return res.status(503).json({
            error: "Server is busy. Please try again."
        });
    }

    let passwordValid = false;

    activeHashes += 1;

    try {
        passwordValid = await verifyPassword(
            password,
            user?.password_hash ?? DUMMY_PASSWORD_HASH
        );
    } finally {
        activeHashes -= 1;
    }

    // Check the password
    if (!user || !passwordValid) {
        // Same event for unknown email and wrong password.
        logAudit(req, "LOGIN_FAILED", {
            user: null,
            details: `Invalid credentials; identifier=${auditLog.pseudonymize(email)}`
        });

        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Verify selected role against SQLite
    if (selectedRole !== user.role) {

        logAudit(req, "LOGIN_FAILED", {
            user,
            details: `Selected role ${selectedRole} does not match account role`
        });

        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Create a new session after authentication
    req.session.regenerate((err) => {

        if (err) return next(err);

        req.session.userId = user.id;
        req.session.credential =
            credentialFingerprint(user.password_hash);

        req.session.save((err) => {

            if (err) return next(err);

            // NEW: Log successful authentication
            logAudit(req, "LOGIN_SUCCESS", {
                user,
                outcome: "success",
                details: `User authenticated as ${user.role}`
            });

            res.json({
                message: "Login successful",
                user: {
                    id: user.id,
                    name: user.name,
                    role: user.role
                }
            });
        });
    });
});

// ========================================
// 8. AUTHENTICATION MIDDLEWARE
// ========================================

// Ends a session that is no longer valid
function endSession(req, res) {

    req.session.destroy(() => {

        res.clearCookie("mab.sid");

        res.status(401).json({
            error: "Authentication required"
        });
    });
}

function requireAuth(req, res, next) {

    if (!req.session.userId) {
        const route = req.route?.path ?? req.path;

        logThrottled(req, "AUTH_REQUIRED", route, {
            user: null,
            resource: route,
            details: "Unauthenticated request to protected route"
        });

        return res.status(401).json({
            error: "Authentication required"
        });
    }

    const account = db.prepare(`
        SELECT id, name, email, role, password_hash
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!account) {
        logAudit(req, "SESSION_INVALID", {
            user: null,
            details: `Session references missing user ${req.session.userId}`
        });

        return endSession(req, res);
    }

    // Never attach the password hash to req.user
    const { password_hash: passwordHash, ...user } = account;

    if (credentialFingerprint(passwordHash) !== req.session.credential) {

        logAudit(req, "SESSION_INVALID", {
            user,
            details: "Session ended because the password changed"
        });

        return endSession(req, res);
    }

    req.user = user;
    next();
}

// ========================================
// 9. ROLE-BASED ACCESS CONTROL (RBAC)
// ========================================

function requireRole(role) {

    return (req, res, next) => {

        if (req.user.role !== role) {

            // NEW: Record unauthorized access
            logAudit(req, "ACCESS_DENIED", {
                details: `Role ${req.user.role} attempted ${role} access`
            });

            return res.status(403).json({
                error: "Access denied"
            });
        }

        next();
    };
}

// ========================================
// 10. CURRENT AUTHENTICATED USER
// ========================================

app.get("/api/me", requireAuth, (req, res) => {

    res.json({
        user: req.user
    });
});

// ========================================
// 11. CUSTOMER DASHBOARD API
// ========================================

app.get(
    "/api/customer/dashboard",
    requireAuth,
    requireRole("customer"),
    (req, res) => {

        res.json({
            message: "Customer dashboard access granted",
            user: req.user.name
        });
    }
);

// ========================================
// 12. CUSTOMER APPOINTMENT LIST
// ========================================

app.get(
    "/api/customer/appointments",
    requireAuth,
    requireRole("customer"),
    (req, res) => {

        // Only return the logged-in customer's records
        const appointments = db.prepare(`
            SELECT
                id,
                service,
                vehicle,
                status
            FROM demo_appointments
            WHERE customer_id = ?
            ORDER BY id
        `).all(req.user.id);

        res.json({
            appointments: appointments
        });
    }
);

// ========================================
// 13. SINGLE CUSTOMER APPOINTMENT
// ========================================

app.get(
    "/api/customer/appointments/:id",
    requireAuth,
    requireRole("customer"),
    (req, res) => {

        const appointmentId = Number(req.params.id);

        // Validate appointment ID
        if (
            !/^[1-9][0-9]*$/.test(req.params.id) ||
            !Number.isSafeInteger(appointmentId) ||
            appointmentId <= 0
        ) {
            logAudit(req, "INVALID_INPUT", {
                resource: "/api/customer/appointments/:id",
                details: "Invalid appointment ID"
            });

            return res.status(400).json({
                error: "Invalid appointment ID"
            });
        }

        // Check ID and ownership together
        const appointment = db.prepare(`
            SELECT
                id,
                service,
                vehicle,
                status
            FROM demo_appointments
            WHERE id = ?
              AND customer_id = ?
        `).get(appointmentId, req.user.id);

        if (!appointment) {

            // NEW: Log failed appointment access
            logAudit(req, "APPOINTMENT_ACCESS_DENIED", {
                resource: "/api/customer/appointments/:id",
                details: `Appointment ${appointmentId} unavailable to user`
            });

            return res.status(404).json({
                error: "Appointment not found"
            });
        }

        res.json({
            appointment: appointment
        });
    }
);

// ========================================
// 14. MECHANIC WORK TICKETS
// ========================================

app.get(
    "/api/mechanic/tickets",
    requireAuth,
    requireRole("mechanic"),
    (req, res) => {

        // Only jobs assigned to this mechanic
        const tickets = db.prepare(`
            SELECT
                wt.id,
                wt.appointment_id,
                wt.status,
                a.service,
                a.vehicle,
                u.name AS customer_name

            FROM demo_work_tickets AS wt

            JOIN demo_appointments AS a
                ON a.id = wt.appointment_id

            JOIN users AS u
                ON u.id = a.customer_id

            WHERE wt.mechanic_id = ?

            ORDER BY wt.id
        `).all(req.user.id);

        // These records include customer names
        logAudit(req, "CUSTOMER_DATA_VIEWED", {
            outcome: "success",
            details: `Viewed ${tickets.length} assigned work tickets`
        });

        res.json({
            tickets: tickets
        });
    }
);

// ========================================
// 15. LOGOUT WITH AUDIT LOGGING
// ========================================

app.post(
    "/api/logout",
    requireAuth,
    (req, res, next) => {

        const user = req.user;

        req.session.destroy((err) => {

            if (err) return next(err);

            // NEW: Record successful logout
            logAudit(req, "LOGOUT", {
                user,
                outcome: "success",
                details: "User logged out successfully"
            });

            res.clearCookie("mab.sid");

            res.json({
                message: "Logged out successfully"
            });
        });
    }
);


// ========================================
// ADMINISTRATOR - SECURITY AUDIT LOGS
// ========================================

app.get(
    "/api/admin/audit-logs",
    requireAuth,
    requireRole("admin"),
    (req, res) => {

        // Retrieve the 50 most recent security events
        const logs = db.prepare(`
            SELECT
                id,
                COALESCE(actor_id, user_id) AS user_id,
                actor_role,
                event_type,
                outcome,
                http_method,
                resource,
                ip_address,
                details,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 50
        `).all();

        // Reading the audit trail is itself audited
        logAudit(req, "AUDIT_LOG_VIEWED", {
            outcome: "success",
            details: `Viewed ${logs.length} audit entries`
        });

        res.json({
            logs: logs
        });
    }
);

app.get(
    "/api/admin/audit-logs/verify",
    requireAuth,
    requireRole("admin"),
    (req, res) => {

        const result = auditLog.verify();

        logAudit(req, "AUDIT_INTEGRITY_CHECK", {
            outcome: result.valid ? "success" : "failure",
            details: result.valid
                ? `Verified ${result.checked} entries`
                : `Chain broken at entry ${result.brokenAt}: ${result.reason}`
        });

        res.json(result);
    }
);

// ========================================
// 16. SERVE FRONTEND FILES
// ========================================

app.use(express.static(
    path.join(__dirname, "public")
));

// ========================================
// 17. RECORD REQUEST ERRORS
// ========================================

app.use((err, req, res, next) => {

    const status = err.status >= 400 && err.status < 600
        ? err.status
        : 500;

    logThrottled(req, "REQUEST_ERROR", String(status), {
        outcome: "error",
        details: `${err.type || err.name}; status ${status}`
    });

    if (status >= 500) {
        console.error("Request error:", err);
    }

    if (res.headersSent) {
        return next(err);
    }

    // Never send stack traces or internal details to the client
    res.status(status).json({
        error: status >= 500 ? "Internal server error" : "Invalid request"
    });
});

// ========================================
// 18. START SERVER
// ========================================

if (require.main === module) {

    app.listen(PORT, "127.0.0.1", () => {

        console.log(
            `Server running at http://127.0.0.1:${PORT}`
        );
    });
}

module.exports = { app, db, auditLog, sessionStore };
