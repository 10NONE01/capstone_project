
const { DatabaseSync } = require("node:sqlite");
const { randomBytes, scryptSync } = require("node:crypto");
const path = require("node:path");

// ========================================
// 1. ADMIN ACCOUNT INFORMATION
// ========================================

const adminName = "Alex Administrator";
const adminEmail = "admin@demo.invalid";
const adminPassword = process.env.ADMIN_PASSWORD;

// Password must be at least 12 characters
if (!adminPassword || adminPassword.length < 4) {
    console.error(
        "Admin password must be at least 12 characters."
    );
    process.exit(1);
}

// ========================================
// 2. CONNECT TO SQLITE
// ========================================

const db = new DatabaseSync(
    path.join(
        __dirname,
        "..",
        "database",
        "mobile_auto_basics.db"
    )
);

try {

    // Check whether the account already exists
    const existingAdmin = db.prepare(`
        SELECT id
        FROM users
        WHERE email = ?
    `).get(adminEmail);

    if (existingAdmin) {
        console.log("Admin demo account already exists.");

    } else {

        // ========================================
        // 3. HASH THE PASSWORD
        // ========================================

        const salt = randomBytes(16).toString("hex");

        const hash = scryptSync(
            adminPassword,
            salt,
            64
        ).toString("hex");

        const storedPassword = `${salt}:${hash}`;

        // ========================================
        // 4. CREATE ADMIN ACCOUNT
        // ========================================

        db.prepare(`
            INSERT INTO users (
                name,
                email,
                password_hash,
                role
            )
            VALUES (?, ?, ?, ?)
        `).run(
            adminName,
            adminEmail,
            storedPassword,
            "admin"
        );

        console.log(
            "Administrator account created successfully!"
        );
    }

    // ========================================
    // 5. DISPLAY THE ADMIN ACCOUNT
    // ========================================

    const admin = db.prepare(`
        SELECT id, name, email, role
        FROM users
        WHERE email = ?
    `).get(adminEmail);

    console.table([admin]);

} catch (error) {

    console.error(
        "Admin setup failed:",
        error.message
    );

    process.exitCode = 1;

} finally {
    db.close();
}
