const { test, before, after, describe } = require("node:test");
const assert = require("node:assert/strict");
const { spawn } = require("node:child_process");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { PASSWORD, USERS, startServer, client, loggedIn } = require("./helpers");
const { SqliteSessionStore } = require("../session-store");

// Regression tests for findings in SECURITY_REVIEW.md

let ctx;

before(async () => { ctx = await startServer(); });
after(() => ctx.stop());

const root = path.join(__dirname, "..");
const read = (file) => fs.readFileSync(path.join(root, file), "utf8");

describe("fixed weaknesses", () => {

    test("H-2 password scripts enforce the 12-character minimum", () => {
        for (const file of ["scripts/create-admin.js", "scripts/reset-password.js"]) {
            assert.match(read(file), /length < 12/);
            assert.doesNotMatch(read(file), /length < 4/);
        }
    });

    test("H-4 health checks stay responsive during password hashing", async () => {
        // Runs in its own process so the test client's work
        // does not count against the server's response time.
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mab-load-"));
        const port = 42000 + Math.floor(Math.random() * 2000);
        const base = `http://127.0.0.1:${port}`;
        const child = spawn(process.execPath, ["--disable-warning=ExperimentalWarning", "server.js"], {
            cwd: root,
            env: { ...process.env, PORT: String(port), SESSION_DB_PATH: path.join(dir, "s.db") },
            stdio: "ignore"
        });

        try {
            let ready = false;
            for (let i = 0; i < 80 && !ready; i += 1) {
                try {
                    ready = (await fetch(`${base}/api/health`)).ok;
                } catch {
                    await new Promise((resolve) => setTimeout(resolve, 100));
                }
            }
            assert.ok(ready, "server did not start");

            const logins = Array.from({ length: 30 }, () =>
                client(base).login(USERS.john, "x".repeat(1024)));
            await new Promise((resolve) => setTimeout(resolve, 10));
            const start = performance.now();
            await client(base).get("/api/health");
            const elapsed = performance.now() - start;
            const results = await Promise.all(logins);

            assert.ok(elapsed < 500, `health check took ${elapsed.toFixed(0)}ms`);
            assert.ok(results.every((r) => [401, 503].includes(r.status)));
        } finally {
            await new Promise((resolve) => {
                child.once("exit", resolve);
                child.kill();
            });
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    test("M-1 password change ends existing sessions", async () => {
        const c = await loggedIn(ctx.base, USERS.mo);
        const original = ctx.db.prepare("SELECT password_hash FROM users WHERE id = ?").get(USERS.mo.id);
        ctx.db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run("00:00", USERS.mo.id);
        const status = (await c.get("/api/me")).status;
        ctx.db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(original.password_hash, USERS.mo.id);
        assert.equal(status, 401);
    });

    test("M-2 unknown and known emails take similar time", async () => {
        const time = async (email) => {
            const samples = [];
            for (let i = 0; i < 8; i += 1) {
                const start = performance.now();
                await client(ctx.base).post("/api/login", { email, password: "wrong-password", selectedRole: "customer" });
                samples.push(performance.now() - start);
            }
            return samples.sort((a, b) => a - b)[4];
        };
        const known = await time(USERS.john.email);
        const unknown = await time("nobody@test.invalid");
        assert.ok(known < unknown * 3 && unknown < known * 3, `known ${known.toFixed(1)}ms, unknown ${unknown.toFixed(1)}ms`);
    });

    test("M-3 errors do not reveal stack traces", async () => {
        const res = await client(ctx.base).post("/api/login", "{not-json");
        assert.equal(res.status, 400);
        assert.deepEqual(res.json, { error: "Invalid request" });
    });

    test("M-4 security headers are set", async () => {
        const res = await client(ctx.base).get("/login.html");
        const csp = res.headers.get("content-security-policy");
        assert.match(csp, /script-src 'self'/);
        assert.match(csp, /frame-ancestors 'none'/);
        assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    });

    test("M-5 framework is not advertised", async () => {
        const res = await client(ctx.base).get("/api/health");
        assert.equal(res.headers.get("x-powered-by"), null);
    });

    test("M-7 session store saves, expires, and destroys sessions", async () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), "mab-store-"));
        const file = path.join(dir, "s.db");
        const call = (store, method, ...args) => new Promise((resolve, reject) =>
            store[method](...args, (err, value) => (err ? reject(err) : resolve(value))));
        const future = new Date(Date.now() + 60000).toISOString();

        let store = new SqliteSessionStore(file);
        await call(store, "set", "live-id", { userId: 1, cookie: { expires: future } });
        await call(store, "set", "old-id", { userId: 2, cookie: { expires: new Date(Date.now() - 1000).toISOString() } });
        store.close();

        store = new SqliteSessionStore(file);
        assert.equal((await call(store, "get", "live-id")).userId, 1);
        assert.equal(await call(store, "get", "old-id"), null);
        const raw = store.db.prepare("SELECT sid_hash FROM sessions").all();
        assert.ok(raw.every((row) => row.sid_hash !== "live-id"));
        await call(store, "destroy", "live-id");
        assert.equal(await call(store, "get", "live-id"), null);
        store.close();
        fs.rmSync(dir, { recursive: true, force: true });
    });

    for (const id of ["1e0", "0x1", "1.0", "%201", "+1", "01"]) {
        test(`L-1 appointment ID form rejected: ${id}`, async () => {
            const c = await loggedIn(ctx.base, USERS.john);
            assert.equal((await c.get(`/api/customer/appointments/${id}`)).status, 400);
        });
    }

    test("L-2 email login is case-insensitive", async () => {
        const res = await client(ctx.base).post("/api/login", {
            email: USERS.john.email.toUpperCase(),
            password: PASSWORD,
            selectedRole: "customer"
        });
        assert.equal(res.status, 200);
    });

    test("L-2 duplicate emails differing by case are rejected", () => {
        assert.throws(() => ctx.db.prepare(
            "INSERT INTO users (name, email, password_hash, role) VALUES ('X', ?, 'x:y', 'customer')"
        ).run(USERS.john.email.toUpperCase()));
    });

    test("L-3 env files are ignored", () => {
        assert.match(read(".gitignore"), /^\*\.env\r?$/m);
    });

    test("L-5 cross-origin POST is blocked", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        assert.equal((await c.post("/api/logout", undefined, { Origin: "https://evil.example" })).status, 403);
        assert.equal((await c.post("/api/logout", undefined, { "Sec-Fetch-Site": "cross-site" })).status, 403);
        assert.equal((await c.get("/api/me")).status, 200);
    });

    test("L-5 same-origin POST still works", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        const res = await c.post("/api/logout", undefined, {
            Origin: ctx.base,
            "Sec-Fetch-Site": "same-origin"
        });
        assert.equal(res.status, 200);
    });
});
