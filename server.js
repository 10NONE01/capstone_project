
const express = require("express");
const session = require("express-session");
const path = require("node:path");

const { DatabaseSync } = require("node:sqlite");

const {
    scryptSync,
    timingSafeEqual
} = require("node:crypto");

// =======================================
// 1. EXPRESS SERVER SETUP
// =======================================

const app = express();
const PORT = 4100;

// Connect to the existing SQLite database
const db = new DatabaseSync(
    path.join(__dirname, "database", "mobile_auto_basics.db")
);

db.exec("PRAGMA foreign_keys = ON");

// Allow the server to receive JSON
app.use(express.json({ limit: "10kb" }));

// Session secret must be stored in .env
if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing");
}

// Configure login sessions
app.use(session({
    name: "mab.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false, // Local development only
        maxAge: 60 * 60 * 1000
    }
}));

// =======================================
// 2. SERVER HEALTH CHECK
// =======================================

app.get("/api/health", (req, res) => {
    res.json({
        status: "ok",
        message: "Mobile Auto Basics backend is running!"
    });
});

// =======================================
// 3. PASSWORD VERIFICATION
// =======================================

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

// =======================================
// 4. LOGIN AUTHENTICATION
// =======================================

app.post("/api/login", (req, res, next) => {

    const {
        email,
        password,
        selectedRole
    } = req.body || {};

    // Validate login information
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

    // Validate the dropdown selection
    const allowedRoles = ["customer", "mechanic"];

    if (!allowedRoles.includes(selectedRole)) {
        return res.status(400).json({
            error: "Please select a valid account type."
        });
    }

    // Look up account in SQLite
    const user = db.prepare(`
        SELECT id, name, email, password_hash, role
        FROM users
        WHERE email = ?
    `).get(email.trim());

    // Verify account password
    if (
        !user ||
        !verifyPassword(password, user.password_hash)
    ) {
        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Capstone role-selection test
    if (selectedRole !== user.role) {
        return res.status(401).json({
            error: "Invalid credentials or account type."
        });
    }

    // Create a new authenticated session
    req.session.regenerate((err) => {

        if (err) return next(err);

        req.session.userId = user.id;

        req.session.save((err) => {

            if (err) return next(err);

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

// =======================================
// 5. AUTHENTICATION MIDDLEWARE
// =======================================

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

// =======================================
// 6. ROLE-BASED ACCESS CONTROL
// =======================================

function requireRole(role) {

    return (req, res, next) => {

        if (req.user.role !== role) {
            return res.status(403).json({
                error: "Access denied"
            });
        }

        next();
    };
}

// =======================================
// 7. CURRENT LOGGED-IN USER
// =======================================

app.get("/api/me", requireAuth, (req, res) => {

    res.json({
        user: req.user
    });
});

// =======================================
// 8. CUSTOMER DASHBOARD API
// =======================================

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

// =======================================
// 9. MECHANIC DASHBOARD API
// =======================================

app.get(
    "/api/mechanic/tickets",
    requireAuth,
    requireRole("mechanic"),
    (req, res) => {

        res.json({
            message: "Mechanic access granted",
            tickets: []
        });
    }
);

// =======================================
// 10. CUSTOMER APPOINTMENT LIST
// =======================================

app.get(
    "/api/customer/appointments",
    requireAuth,
    requireRole("customer"),
    (req, res) => {

        // Only retrieve appointments
        // belonging to the logged-in customer
        const appointments = db.prepare(`
            SELECT id, service, vehicle, status
            FROM demo_appointments
            WHERE customer_id = ?
            ORDER BY id
        `).all(req.user.id);

        res.json({
            appointments: appointments
        });
    }
);

// =======================================
// 11. SINGLE APPOINTMENT ACCESS
// =======================================

app.get(
    "/api/customer/appointments/:id",
    requireAuth,
    requireRole("customer"),
    (req, res) => {

        const appointmentId = Number(req.params.id);

        // Ensure the ID is a valid positive integer
        if (
            !Number.isSafeInteger(appointmentId) ||
            appointmentId <= 0
        ) {
            return res.status(400).json({
                error: "Invalid appointment ID"
            });
        }

        // Verify both appointment ID
        // and authenticated customer ID
        const appointment = db.prepare(`
            SELECT id, service, vehicle, status
            FROM demo_appointments
            WHERE id = ?
              AND customer_id = ?
        `).get(appointmentId, req.user.id);

        if (!appointment) {
            return res.status(404).json({
                error: "Appointment not found"
            });
        }

        res.json({
            appointment: appointment
        });
    }
);

// =======================================
// 12. LOGOUT
// =======================================

app.post("/api/logout", requireAuth, (req, res, next) => {

    req.session.destroy((err) => {

        if (err) return next(err);

        res.clearCookie("mab.sid");

        res.json({
            message: "Logged out successfully"
        });
    });
});

// =======================================
// 13. SERVE WEBSITE FILES
// =======================================

app.use(express.static(
    path.join(__dirname, "public")
));

// =======================================
// 14. START SERVER
// =======================================

app.listen(PORT, "127.0.0.1", () => {

    console.log(
        `Server running at http://127.0.0.1:${PORT}`
    );
});
