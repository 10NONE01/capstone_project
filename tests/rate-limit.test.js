const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { USERS, startServer, client, loggedIn } = require("./helpers");

// H-1: uses low limits and its own server

let ctx;

before(async () => { ctx = await startServer({ ipLimit: 8, accountLimit: 3 }); });
after(() => ctx.stop());

const fail = (user) => client(ctx.base).login(user, "wrong-password");

test("successful logins do not use up the limit", async () => {
    for (let i = 0; i < 5; i += 1) {
        await loggedIn(ctx.base, USERS.mike);
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal((await fail(USERS.mike)).status, 401);
});

test("an account locks after repeated failures", async () => {
    const statuses = [];
    for (let i = 0; i < 4; i += 1) {
        statuses.push((await fail(USERS.jane)).status);
    }
    assert.deepEqual(statuses, [401, 401, 401, 429]);
});

test("the correct password is also blocked while locked", async () => {
    assert.equal((await client(ctx.base).login(USERS.jane)).status, 429);
});

test("other accounts are unaffected by one account's lock", async () => {
    assert.equal((await client(ctx.base).login(USERS.john)).status, 200);
});

test("blocks are audited without flooding the log", () => {
    const rows = ctx.db.prepare(
        "SELECT COUNT(*) AS n FROM audit_logs WHERE event_type = 'LOGIN_RATE_LIMITED'"
    ).get();
    assert.equal(rows.n, 1);
});

test("one IP is limited across many accounts", async () => {
    let blocked = false;
    for (let i = 0; i < 10 && !blocked; i += 1) {
        const res = await client(ctx.base).post("/api/login", {
            email: `spray-${i}@test.invalid`,
            password: "wrong-password",
            selectedRole: "customer"
        });
        blocked = res.status === 429;
    }
    assert.ok(blocked);
});
