
const { DatabaseSync } = require("node:sqlite");
const { scryptSync, timingSafeEqual } = require("node:crypto");
const path = require("node:path");
const readline = require("node:readline");

const db = new DatabaseSync(
    path.join(__dirname, "database", "mobile_auto_basics.db")
);

// Ask for the account email
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

rl.question("Account email: ", (email) => {
    rl.close();

    const user = db.prepare(
        "SELECT password_hash FROM users WHERE email = ?"
    ).get(email.trim());

    db.close();

    if (!user) {
        console.log("Account not found.");
        return;
    }

    const [salt, storedHash] = user.password_hash.split(":");

    const suppliedHash = scryptSync(
        process.env.TEST_PASSWORD || "",
        salt,
        64
    );

    const originalHash = Buffer.from(storedHash, "hex");

    const matches = timingSafeEqual(
        suppliedHash,
        originalHash
    );

    console.log(
        matches
            ? "Password is correct!"
            : "Incorrect password."
    );
});
