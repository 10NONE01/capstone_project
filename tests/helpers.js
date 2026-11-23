const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { randomBytes, scryptSync } = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

// Every test run uses a throwaway database with generated
// passwords. The real demo database is never opened.

const PASSWORD = randomBytes(18).toString("hex");

const USERS = {
    john: { id: 1, email: "john@test.invalid", role: "customer" },
    mike: { id: 2, email: "mike@test.invalid", role: "mechanic" },
    jane: { id: 3, email: "jane@test.invalid", role: "customer" },
    alex: { id: 4, email: "alex@test.invalid", role: "admin" },
    mo: { id: 5, email: "mo@test.invalid", role: "mechanic" }
};

function hash(password) {
    const salt = randomBytes(16).toString("hex");
    return `${salt}:${scryptSync(password, salt, 64).toString("hex")}`;
}

function buildDatabase(file) {

    const db = new DatabaseSync(file);

    db.exec(fs.readFileSync(
        path.join(__dirname, "..", "database", "schema.sql"),
        "utf8"
    ));

    db.exec(`
        CREATE TABLE demo_appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL REFERENCES users(id),
            service TEXT NOT NULL,
            vehicle TEXT NOT NULL,
            status TEXT NOT NULL,
            demo_key TEXT UNIQUE NOT NULL
        );
        CREATE TABLE demo_work_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL UNIQUE REFERENCES demo_appointments(id),
            mechanic_id INTEGER NOT NULL REFERENCES users(id),
            status TEXT NOT NULL DEFAULT 'Assigned'
        );
    `);

    const insertUser = db.prepare(
        "INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)"
    );
    const passwordHash = hash(PASSWORD);

    for (const [name, user] of Object.entries(USERS)) {
        insertUser.run(user.id, name, user.email, passwordHash, user.role);
    }

    db.exec(`
        INSERT INTO demo_appointments (id, customer_id, service, vehicle, status, demo_key) VALUES
            (1, 1, 'Oil Change', 'Car A', 'Scheduled', 'a'),
            (2, 1, 'Battery', 'Car A', 'Completed', 'b'),
            (3, 3, 'Brakes', 'Car B', 'Scheduled', 'c');
        INSERT INTO demo_work_tickets (id, appointment_id, mechanic_id) VALUES
            (1, 3, 2),
            (2, 1, 2),
            (3, 2, 5);
    `);

    db.close();
}

async function startServer(options = {}) {

    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mab-test-"));
    const dbPath = path.join(dir, "test.db");

    buildDatabase(dbPath);

    process.env.DB_PATH = dbPath;
    process.env.SESSION_SECRET = randomBytes(32).toString("hex");
    delete process.env.AUDIT_HMAC_KEY;

    // Most suites make many failed logins on purpose
    process.env.LOGIN_MAX_ATTEMPTS_IP = String(options.ipLimit ?? 100000);
    process.env.LOGIN_MAX_ATTEMPTS_ACCOUNT = String(options.accountLimit ?? 100000);

    const realLog = console.log;
    console.log = () => {};

    const { app, db, auditLog, sessionStore } = require("../server");

    const server = await new Promise((resolve) => {
        const listener = app.listen(0, "127.0.0.1", () => resolve(listener));
    });

    const base = `http://127.0.0.1:${server.address().port}`;

    async function stop() {
        server.closeAllConnections();
        await new Promise((resolve) => server.close(resolve));
        sessionStore.close();
        db.close();
        console.log = realLog;
        fs.rmSync(dir, { recursive: true, force: true });
    }

    return { base, db, auditLog, stop };
}

// A minimal cookie-keeping HTTP client
function client(base) {

    let cookie = null;

    async function request(method, url, body, headers = {}) {

        const response = await fetch(base + url, {
            method,
            redirect: "manual",
            headers: {
                ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
                ...(cookie ? { Cookie: cookie } : {}),
                ...headers
            },
            body: body === undefined
                ? undefined
                : typeof body === "string" ? body : JSON.stringify(body)
        });

        const setCookie = response.headers.get("set-cookie");

        if (setCookie) {
            const value = setCookie.split(";")[0];
            cookie = value.endsWith("=") ? null : value;
        }

        const text = await response.text();
        let json = null;

        try { json = JSON.parse(text); } catch { /* not JSON */ }

        return { status: response.status, json, text, headers: response.headers };
    }

    return {
        get: (url, headers) => request("GET", url, undefined, headers),
        post: (url, body, headers) => request("POST", url, body, headers),
        request,
        cookie: () => cookie,
        setCookie: (value) => { cookie = value; },
        login: (user, password = PASSWORD, selectedRole = user.role) =>
            request("POST", "/api/login", {
                email: user.email,
                password,
                selectedRole
            })
    };
}

async function loggedIn(base, user) {
    const c = client(base);
    const result = await c.login(user);
    if (result.status !== 200) {
        throw new Error(`Login failed for ${user.email}: ${result.status}`);
    }
    return c;
}

module.exports = { PASSWORD, USERS, startServer, client, loggedIn };
