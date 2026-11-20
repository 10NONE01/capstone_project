
const express = require("express");
const session = require("express-session");
const path = require("node:path");

const { DatabaseSync } = require("node:sqlite");

const {
    scryptSync,
    timingSafeEqual
} = require("node:crypto");

// ========================================
// 1. EXPRESS SERVER SETUP
// ========================================

const app = express();
const PORT = 4100;

// Connect to our existing SQLite database
const db = new DatabaseSync(
    path.join(__dirname, "database", "mobile_auto_basics.db")
);

db.exec("PRAGMA foreign_keys = ON");

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

app.use(express.json({ limit: "10kb" }));

if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing");
}

app.use(session({
    name: "mab.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // Local HTTP testing only
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

function verifyPassword(password, storedPassword) {

    try {
        const [salt, hash] = storedPassword.split(":");

        if (
            !salt ||
            !/^[0-9a-f]{128}$/i.test(hash || "")
        ) {
            return false;
        }

        const storedHash = Buffer.from(hash, "hex");

        const suppliedHash = scryptSync(
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

// ========================================
// 6. SECURITY AUDIT LOGGING
// ========================================

function logAudit(userId, eventType, resource, details) {

    try {
        const insert = db.prepare(`
            INSERT INTO audit_logs (
                user_id,
                event_type,
                resource,
                details
            )
            VALUES (?, ?, ?, ?)
        `);

        insert.run(
            userId,
            eventType,
            resource,
            details
        );

        console.log(
            `[AUDIT] ${eventType}: ${details}`
        );

    } catch (error) {
        console.error(
            "Audit logging failed:",
            error.message
        );
    }
}

// ========================================
// 7. LOGIN AUTHENTICATION
// ========================================

app.post("/api/login", (req, res, next) => {

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
        return res.status(400).json({
            error: "Valid email and password are required."
        });
    }

    // Capstone role selection
    const allowedRoles = ["customer", "mechanic", "admin"];

    if (!allowedRoles.includes(selectedRole)) {
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
        WHERE email = ?
    `).get(email.trim());

    // Check the password
    if (
        !user ||
        !verifyPassword(password, user.password_hash)
    ) {
        logAudit(
            null,
            "LOGIN_FAILED",
            "/api/login",
            "Invalid login credentials"
        );

        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Verify selected role against SQLite
    if (selectedRole !== user.role) {

        logAudit(
            user.id,
            "LOGIN_FAILED",
            "/api/login",
            "Selected role does not match account role"
        );

        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Create a new session after authentication
    req.session.regenerate((err) => {

        if (err) return next(err);

        req.session.userId = user.id;

        req.session.save((err) => {

            if (err) return next(err);

            // NEW: Log successful authentication
            logAudit(
                user.id,
                "LOGIN_SUCCESS",
                "/api/login",
                `User authenticated as ${user.role}`
            );

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

function requireAuth(req, res, next) {

    if (!req.session.userId) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    const user = db.prepare(`
        SELECT id, name, email, role
        FROM users
        WHERE id = ?
    `).get(req.session.userId);

    if (!user) {
        return res.status(401).json({
            error: "Authentication required"
        });
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
            logAudit(
                req.user.id,
                "ACCESS_DENIED",
                req.path,
                `Role ${req.user.role} attempted ${role} access`
            );

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
            !Number.isSafeInteger(appointmentId) ||
            appointmentId <= 0
        ) {
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
            logAudit(
                req.user.id,
                "APPOINTMENT_ACCESS_DENIED",
                "/api/customer/appointments/:id",
                `Appointment ${appointmentId} unavailable to user`
            );

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

        const userId = req.user.id;

        req.session.destroy((err) => {

            if (err) return next(err);

            // NEW: Record successful logout
            logAudit(
                userId,
                "LOGOUT",
                "/api/logout",
                "User logged out successfully"
            );

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
                user_id,
                event_type,
                resource,
                details,
                created_at
            FROM audit_logs
            ORDER BY id DESC
            LIMIT 50
        `).all();

        res.json({
            logs: logs
        });
    }
);

// ========================================
// 16. SERVE FRONTEND FILES
// ========================================

app.use(express.static(
    path.join(__dirname, "public")
));

// ========================================
// 17. START SERVER
// ========================================

app.listen(PORT, "127.0.0.1", () => {

    console.log(
        `Server running at http://127.0.0.1:${PORT}`
    );
});
