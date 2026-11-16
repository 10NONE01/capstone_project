
const { DatabaseSync } = require("node:sqlite");
const { randomBytes, scryptSync } = require("node:crypto");
const path = require("node:path");

const email = process.argv[2];
const password = process.env.NEW_PASSWORD;

const allowedEmails = [
    "customer@demo.invalid",
    "mechanic@demo.invalid"
];

if (!allowedEmails.includes(email)) {
    console.error("Please specify a valid demo account.");
    process.exit(1);
}

if (!password || password.length < 10) {
    console.error("Password must be at least 12 characters.");
    process.exit(1);
}

const db = new DatabaseSync(
    path.join(__dirname, "..", "database", "mobile_auto_basics.db")
);

try {
    const salt = randomBytes(16).toString("hex");
    const hash = scryptSync(password, salt, 64).toString("hex");

    const result = db.prepare(`
        UPDATE users
        SET password_hash = ?
        WHERE email = ?
    `).run(`${salt}:${hash}`, email);

    if (result.changes === 0) {
        console.error("Account not found.");
        process.exitCode = 1;
    } else {
        console.log(`Password updated for ${email}`);
    }
} finally {
    db.close();
}
