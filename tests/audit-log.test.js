const { test, before, after, describe } = require("node:test");
const assert = require("node:assert/strict");
const { PASSWORD, USERS, startServer, client, loggedIn } = require("./helpers");

let ctx;

before(async () => { ctx = await startServer(); });
after(() => ctx.stop());

const latest = (eventType) => ctx.db.prepare(
    "SELECT * FROM audit_logs WHERE event_type = ? ORDER BY id DESC LIMIT 1"
).get(eventType);

const count = () => ctx.db.prepare("SELECT COUNT(*) AS n FROM audit_logs").get().n;

describe("events are recorded", () => {

    test("successful login", async () => {
        await loggedIn(ctx.base, USERS.john);
        const row = latest("LOGIN_SUCCESS");
        assert.equal(row.actor_id, USERS.john.id);
        assert.equal(row.actor_role, "customer");
        assert.equal(row.outcome, "success");
        assert.equal(row.http_method, "POST");
        assert.ok(row.ip_address);
        assert.match(row.created_at, /^\d{4}-\d\d-\d\dT.*Z$/);
    });

    test("failed login stores neither password nor email", async () => {
        const secret = "typed-Secret-Value-123";
        await client(ctx.base).login({ ...USERS.john, role: "customer" }, secret);
        const row = latest("LOGIN_FAILED");
        assert.equal(row.actor_id, null);
        assert.match(row.details, /identifier=[0-9a-f]{16}/);
        const everything = JSON.stringify(ctx.db.prepare("SELECT * FROM audit_logs").all());
        assert.ok(!everything.includes(secret));
        assert.ok(!everything.includes(PASSWORD));
        assert.ok(!row.details.includes(USERS.john.email));
    });

    test("repeat attempts on one account correlate", async () => {
        await client(ctx.base).login(USERS.jane, "wrong-1");
        const first = latest("LOGIN_FAILED").details;
        await client(ctx.base).login(USERS.jane, "wrong-2");
        assert.equal(latest("LOGIN_FAILED").details, first);
    });

    test("role mismatch", async () => {
        await client(ctx.base).login(USERS.john, PASSWORD, "admin");
        assert.match(latest("LOGIN_FAILED").details, /does not match/);
    });

    test("malformed login", async () => {
        await client(ctx.base).post("/api/login", { email: 1 });
        assert.ok(latest("LOGIN_REJECTED"));
    });

    test("anonymous access to a protected route", async () => {
        await client(ctx.base).get("/api/admin/audit-logs");
        assert.equal(latest("AUTH_REQUIRED").resource, "/api/admin/audit-logs");
    });

    test("anonymous floods cannot grow the log", async () => {
        const before = count();
        await Promise.all(Array.from({ length: 50 }, () =>
            client(ctx.base).get("/api/customer/dashboard")));
        assert.ok(count() - before <= 1);
    });

    test("varying the URL cannot evade the anonymous limit", async () => {
        const before = count();
        for (let id = 1000; id < 1020; id += 1) {
            await client(ctx.base).get(`/api/customer/appointments/${id}`);
        }
        assert.ok(count() - before <= 1);
    });

    test("forbidden role", async () => {
        const c = await loggedIn(ctx.base, USERS.john);
        await c.get("/api/admin/audit-logs");
        const row = latest("ACCESS_DENIED");
        assert.equal(row.actor_id, USERS.john.id);
        assert.equal(row.resource, "/api/admin/audit-logs");
    });

    test("IDOR attempt", async () => {
        const c = await loggedIn(ctx.base, USERS.john);
        await c.get("/api/customer/appointments/3");
        assert.match(latest("APPOINTMENT_ACCESS_DENIED").details, /Appointment 3/);
    });

    test("invalid object ID", async () => {
        const c = await loggedIn(ctx.base, USERS.john);
        await c.get("/api/customer/appointments/abc");
        assert.ok(latest("INVALID_INPUT"));
    });

    test("mechanic viewing customer data", async () => {
        const c = await loggedIn(ctx.base, USERS.mike);
        await c.get("/api/mechanic/tickets");
        assert.equal(latest("CUSTOMER_DATA_VIEWED").actor_id, USERS.mike.id);
    });

    test("admin viewing the audit log", async () => {
        const c = await loggedIn(ctx.base, USERS.alex);
        await c.get("/api/admin/audit-logs");
        assert.equal(latest("AUDIT_LOG_VIEWED").actor_id, USERS.alex.id);
    });

    test("logout", async () => {
        const c = await loggedIn(ctx.base, USERS.jane);
        await c.post("/api/logout");
        assert.equal(latest("LOGOUT").actor_id, USERS.jane.id);
    });

    test("malformed JSON request", async () => {
        await client(ctx.base).post("/api/login", "{not-json");
        assert.match(latest("REQUEST_ERROR").details, /parse/);
    });

    test("log injection is neutralized", async () => {
        const before = count();
        ctx.auditLog.write({
            eventType: "INJECTION_TEST",
            outcome: "failure",
            resource: "/x\r\n[AUDIT] forged",
            details: "a\nb\u2028c\u0000d"
        });
        assert.equal(count(), before + 1);
        const row = latest("INJECTION_TEST");
        assert.ok(!/[\r\n\u2028\u0000]/.test(row.resource + row.details));
    });
});

describe("tamper resistance", () => {

    test("UPDATE is blocked", () => {
        assert.throws(
            () => ctx.db.exec("UPDATE audit_logs SET details = 'x' WHERE id = 1"),
            /append-only/
        );
    });

    test("DELETE is blocked", () => {
        assert.throws(
            () => ctx.db.exec("DELETE FROM audit_logs WHERE id = 1"),
            /append-only/
        );
    });

    test("deleting a user keeps their audit history valid", () => {
        const id = 99;
        ctx.db.prepare(
            "INSERT INTO users (id, name, email, password_hash, role) VALUES (?, 'T', 't@test.invalid', 'x:y', 'customer')"
        ).run(id);
        ctx.auditLog.write({ userId: id, role: "customer", eventType: "FK_TEST", outcome: "success" });
        ctx.db.prepare("DELETE FROM users WHERE id = ?").run(id);
        const row = latest("FK_TEST");
        assert.equal(row.user_id, null);
        assert.equal(row.actor_id, id);
        assert.equal(ctx.auditLog.verify().valid, true);
    });

    test("verify endpoint reports an intact chain", async () => {
        const c = await loggedIn(ctx.base, USERS.alex);
        const { json } = await c.get("/api/admin/audit-logs/verify");
        assert.equal(json.valid, true);
        assert.ok(json.checked > 0);
    });

    // These bypass the triggers as an attacker with file access would.
    // They run last because they deliberately damage the chain.
    function withoutTriggers(sql) {
        ctx.db.exec(`
            DROP TRIGGER audit_logs_no_update;
            DROP TRIGGER audit_logs_no_delete;
        `);
        ctx.db.exec(sql);
    }

    test("direct edit and row deletion are detected", () => {
        withoutTriggers("UPDATE audit_logs SET details = 'edited' WHERE id = 3");
        let result = ctx.auditLog.verify();
        assert.equal(result.valid, false);
        assert.equal(result.brokenAt, 3);
        assert.equal(result.reason, "content_modified");

        ctx.db.exec("DELETE FROM audit_logs WHERE id = 3");
        result = ctx.auditLog.verify();
        assert.equal(result.valid, false);
        assert.equal(result.brokenAt, 4);
        assert.equal(result.reason, "missing_entry");
    });
});
