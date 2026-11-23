const { test, before, after, describe } = require("node:test");
const assert = require("node:assert/strict");
const { PASSWORD, USERS, startServer, client, loggedIn } = require("./helpers");

let ctx;
let sessions;

before(async () => {
    ctx = await startServer();
    sessions = {
        customer: await loggedIn(ctx.base, USERS.john),
        mechanic: await loggedIn(ctx.base, USERS.mike),
        admin: await loggedIn(ctx.base, USERS.alex)
    };
});

after(() => ctx.stop());

// Expected status for every protected route and role
const MATRIX = [
    ["/api/me", { anonymous: 401, customer: 200, mechanic: 200, admin: 200 }],
    ["/api/customer/dashboard", { anonymous: 401, customer: 200, mechanic: 403, admin: 403 }],
    ["/api/customer/appointments", { anonymous: 401, customer: 200, mechanic: 403, admin: 403 }],
    ["/api/customer/appointments/1", { anonymous: 401, customer: 200, mechanic: 403, admin: 403 }],
    ["/api/mechanic/tickets", { anonymous: 401, customer: 403, mechanic: 200, admin: 403 }],
    ["/api/admin/audit-logs", { anonymous: 401, customer: 403, mechanic: 403, admin: 200 }],
    ["/api/admin/audit-logs/verify", { anonymous: 401, customer: 403, mechanic: 403, admin: 200 }]
];

describe("role matrix", () => {
    for (const [route, expected] of MATRIX) {
        for (const [role, status] of Object.entries(expected)) {
            test(`${role} GET ${route} -> ${status}`, async () => {
                const c = role === "anonymous" ? client(ctx.base) : sessions[role];
                assert.equal((await c.get(route)).status, status);
            });
        }
    }
});

describe("object-level authorization", () => {

    test("customer reads only their own appointment list", async () => {
        const { json } = await sessions.customer.get("/api/customer/appointments");
        assert.deepEqual(json.appointments.map((a) => a.id), [1, 2]);
    });

    test("customer cannot read another customer's appointment (IDOR)", async () => {
        const res = await sessions.customer.get("/api/customer/appointments/3");
        assert.equal(res.status, 404);
        assert.ok(!res.text.includes("Brakes"));
    });

    test("another customer's record and a missing record look identical", async () => {
        const other = await sessions.customer.get("/api/customer/appointments/3");
        const missing = await sessions.customer.get("/api/customer/appointments/9999");
        assert.equal(other.status, missing.status);
        assert.deepEqual(other.json, missing.json);
    });

    test("query and body parameters cannot change the record owner", async () => {
        const { json } = await sessions.customer.get(
            `/api/customer/appointments?customer_id=${USERS.jane.id}&id=3`
        );
        assert.deepEqual(json.appointments.map((a) => a.id), [1, 2]);
    });

    for (const id of ["0", "-1", "abc", "1.5", "1%20OR%201=1", "1;DROP", "9007199254740993"]) {
        test(`rejects malformed appointment ID ${id}`, async () => {
            const res = await sessions.customer.get(`/api/customer/appointments/${id}`);
            assert.equal(res.status, 400);
        });
    }

    test("mechanic sees only assigned tickets", async () => {
        const { json } = await sessions.mechanic.get("/api/mechanic/tickets");
        assert.deepEqual(json.tickets.map((t) => t.id), [1, 2]);
    });

    test("a different mechanic sees a different ticket set", async () => {
        const other = await loggedIn(ctx.base, USERS.mo);
        const { json } = await other.get("/api/mechanic/tickets");
        assert.deepEqual(json.tickets.map((t) => t.id), [3]);
    });

    test("/api/me never exposes the password hash", async () => {
        const res = await sessions.customer.get("/api/me");
        assert.ok(!("password_hash" in res.json.user));
        assert.ok(!res.text.includes(":"+"scrypt"));
    });
});

describe("authentication and sessions", () => {

    test("wrong password is rejected", async () => {
        assert.equal((await client(ctx.base).login(USERS.john, "wrong-password")).status, 401);
    });

    test("correct password with the wrong role is rejected", async () => {
        const c = client(ctx.base);
        const res = await c.login(USERS.john, PASSWORD, "admin");
        assert.equal(res.status, 401);
        assert.equal(c.cookie(), null);
    });

    test("client cannot self-assign a role at login", async () => {
        const c = client(ctx.base);
        await c.post("/api/login", {
            email: USERS.john.email,
            password: PASSWORD,
            selectedRole: "customer",
            role: "admin",
            userId: USERS.alex.id
        });
        assert.equal((await c.get("/api/me")).json.user.role, "customer");
        assert.equal((await c.get("/api/admin/audit-logs")).status, 403);
    });

    for (const body of [
        { email: { $ne: "" }, password: "x", selectedRole: "admin" },
        { email: "' OR 1=1 --", password: "x", selectedRole: "admin" },
        { email: ["a"], password: ["b"], selectedRole: "admin" },
        { email: USERS.alex.email, password: { a: 1 }, selectedRole: "admin" }
    ]) {
        test(`login injection rejected: ${JSON.stringify(body).slice(0, 40)}`, async () => {
            const res = await client(ctx.base).post("/api/login", body);
            assert.ok([400, 401].includes(res.status));
        });
    }

    test("session ID changes at login (fixation defense)", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        const first = c.cookie();
        await c.login(USERS.jane);
        assert.notEqual(c.cookie(), first);
    });

    test("forged and tampered cookies are rejected", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        const tampered = c.cookie().slice(0, -2) + "xx";
        const attacker = client(ctx.base);
        attacker.setCookie(tampered);
        assert.equal((await attacker.get("/api/me")).status, 401);
        attacker.setCookie("mab.sid=s%3Aforged.signature");
        assert.equal((await attacker.get("/api/me")).status, 401);
    });

    test("session cookie is HttpOnly and SameSite=Lax", async () => {
        const res = await client(ctx.base).login(USERS.jane);
        const header = res.headers.get("set-cookie");
        assert.match(header, /HttpOnly/i);
        assert.match(header, /SameSite=Lax/i);
    });

    test("old cookie is dead after logout", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        const old = c.cookie();
        assert.equal((await c.post("/api/logout")).status, 200);
        const replay = client(ctx.base);
        replay.setCookie(old);
        assert.equal((await replay.get("/api/me")).status, 401);
    });

    test("role changes apply to live sessions immediately", async () => {
        const c = await loggedIn(ctx.base, USERS.mo);
        ctx.db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(USERS.mo.id);
        assert.equal((await c.get("/api/admin/audit-logs")).status, 200);
        ctx.db.prepare("UPDATE users SET role = 'mechanic' WHERE id = ?").run(USERS.mo.id);
        assert.equal((await c.get("/api/admin/audit-logs")).status, 403);
    });
});

describe("routing and file exposure", () => {

    for (const route of [
        "/API/ADMIN/AUDIT-LOGS",
        "/api/admin/audit-logs/",
        "/api//admin/audit-logs",
        "/api/admin/%61udit-logs"
    ]) {
        test(`path variant cannot bypass admin check: ${route}`, async () => {
            const res = await sessions.customer.get(route);
            assert.notEqual(res.status, 200);
        });
    }

    for (const file of [
        "/server.js",
        "/audit.js",
        "/package.json",
        "/.env",
        "/SECRET.env",
        "/database/mobile_auto_basics.db",
        "/../database/mobile_auto_basics.db",
        "/..%2fdatabase%2fmobile_auto_basics.db",
        "/%2e%2e/server.js",
        "/scripts/create-admin.js"
    ]) {
        test(`private file is not served: ${file}`, async () => {
            assert.notEqual((await client(ctx.base).get(file)).status, 200);
        });
    }

    test("X-Forwarded-For cannot spoof the audited IP", async () => {
        await client(ctx.base).post(
            "/api/login",
            { email: "spoof@test.invalid", password: "x", selectedRole: "customer" },
            { "X-Forwarded-For": "203.0.113.9" }
        );
        const row = ctx.db.prepare(
            "SELECT ip_address FROM audit_logs WHERE event_type = 'LOGIN_FAILED' ORDER BY id DESC LIMIT 1"
        ).get();
        assert.ok(row.ip_address);
        assert.notEqual(row.ip_address, "203.0.113.9");
    });
});
