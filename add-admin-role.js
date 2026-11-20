
const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");

// ========================================
// 1. CONNECT TO EXISTING DATABASE
// ========================================

const db = new DatabaseSync(
    path.join(__dirname, "database", "mobile_auto_basics.db")
);

let transactionStarted = false;

try {

    // ========================================
    // 2. VERIFY USERS TABLE
    // ========================================

    const table = db.prepare(`
        SELECT sql
        FROM sqlite_master
        WHERE type = 'table'
          AND name = 'users'
    `).get();

    if (!table) {
        throw new Error("Users table not found.");
    }

    // Prevent unnecessary repeat migrations
    if (table.sql.includes("'admin'")) {

        console.log("Admin role is already supported.");

    } else {

        // This migration expects our original
        // simple users table.
        const columns = db.prepare(`
            PRAGMA table_info(users)
        `).all();

        const expected = [
            "id",
            "name",
            "email",
            "password_hash",
            "role"
        ];

        const actual = columns.map(column => column.name);

        if (
            JSON.stringify(actual) !==
            JSON.stringify(expected)
        ) {
            throw new Error(
                "Unexpected users table structure. " +
                "Migration stopped to protect your data."
            );
        }

        const customObjects = db.prepare(`
            SELECT name
            FROM sqlite_master
            WHERE tbl_name = 'users'
              AND type IN ('trigger', 'index')
              AND sql IS NOT NULL
        `).all();

        if (customObjects.length > 0) {
            throw new Error(
                "Custom users indexes or triggers found. " +
                "Migration requires review."
            );
        }

        // ========================================
        // 3. BEGIN DATABASE MIGRATION
        // ========================================

        // Required while rebuilding a table
        // referenced by other tables.
        db.exec("PRAGMA foreign_keys = OFF");

        db.exec("BEGIN TRANSACTION");
        transactionStarted = true;

        // Create the replacement users table
        db.exec(`
            CREATE TABLE users_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (
                    role IN ('customer', 'mechanic', 'admin')
                )
            )
        `);

        // Preserve existing account information
        db.exec(`
            INSERT INTO users_new (
                id,
                name,
                email,
                password_hash,
                role
            )
            SELECT
                id,
                name,
                email,
                password_hash,
                role
            FROM users
        `);

        // Replace the original users table
        db.exec("DROP TABLE users");

        db.exec(`
            ALTER TABLE users_new
            RENAME TO users
        `);

        // ========================================
        // 4. VERIFY DATABASE INTEGRITY
        // ========================================

        const foreignKeyErrors = db.prepare(`
            PRAGMA foreign_key_check
        `).all();

        if (foreignKeyErrors.length > 0) {
            throw new Error(
                "Foreign key check failed."
            );
        }

        const integrity = db.prepare(`
            PRAGMA integrity_check
        `).get();

        if (integrity.integrity_check !== "ok") {
            throw new Error(
                "Database integrity check failed."
            );
        }

        // Save all changes
        db.exec("COMMIT");
        transactionStarted = false;

        console.log(
            "Admin role added successfully!"
        );
    }

    // ========================================
    // 5. DISPLAY EXISTING ACCOUNTS
    // ========================================

    const users = db.prepare(`
        SELECT id, name, email, role
        FROM users
        ORDER BY id
    `).all();

    console.table(users);

} catch (error) {

    if (transactionStarted) {
        db.exec("ROLLBACK");
    }

    console.error(
        "Migration failed:",
        error.message
    );

    process.exitCode = 1;

} finally {

    db.exec("PRAGMA foreign_keys = ON");
    db.close();

}
