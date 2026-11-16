
const { DatabaseSync } = require("node:sqlite");
const { randomBytes, scryptSync } = require("node:crypto");
const path = require("node:path");

// Open our SQLite database
const db = new DatabaseSync(
    path.join(__dirname, "..", "database", "mobile_auto_basics.db")
);

// Create a salted password hash
function hashPassword(password) {
    const salt = randomBytes(16).toString("hex");

    const hash = scryptSync(password, salt, 64)
        .toString("hex");

    return `${salt}:${hash}`;
}

// Fictional demo accounts
const demoUsers = [
    {
        name: "John Customer",
        email: "customer@demo.invalid",
        role: "customer",
        password: process.env.CUSTOMER_PASS
    },
    {
        name: "Mike Mechanic",
        email: "mechanic@demo.invalid",
        role: "mechanic",
        password: process.env.MECHANIC_PASS
    }
];

// Insert only accounts that don't exist yet
const findUser = db.prepare(
    "SELECT id FROM users WHERE email = ?"
);

const insertUser = db.prepare(`
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
`);

try {
    for (const user of demoUsers) {
        if (findUser.get(user.email)) {
            console.log(`Already exists: ${user.email}`);
            continue;
        }

        if (!user.password || user.password.length < 12) {
            throw new Error(
                `A demo password of at least 12 characters is required for ${user.role}`
            );
        }

        const passwordHash = hashPassword(user.password);

        insertUser.run(
            user.name,
            user.email,
            passwordHash,
            user.role
        );

        console.log(`Created ${user.role} account`);
    }
} finally {
    db.close();
}
