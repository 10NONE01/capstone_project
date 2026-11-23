const { test, before, after } = require("node:test");
const assert = require("node:assert/strict");
const { PASSWORD, USERS, startServer, client } = require("./helpers");

// M-6: production mode behind an HTTPS reverse proxy

let ctx;

before(async () => {
    process.env.NODE_ENV = "production";
    process.env.TRUST_PROXY = "1";
    ctx = await startServer();
});

after(() => ctx.stop());

test("session cookie is Secure and HSTS is enabled", async () => {
    const res = await client(ctx.base).post("/api/login", {
        email: USERS.john.email,
        password: PASSWORD,
        selectedRole: "customer"
    }, { "X-Forwarded-Proto": "https" });

    assert.equal(res.status, 200);
    assert.match(res.headers.get("set-cookie"), /;\s*Secure/i);
    assert.ok(res.headers.get("strict-transport-security"));
});
