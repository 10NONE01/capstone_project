
const { DatabaseSync } = require("node:sqlite");
const { randomBytes, scryptSync } = require("node:crypto");
const path = require("node:path");

const db = new DatabaseSync(
    path.join(__dirname, "..", "database", "mobile_auto_basics.db")
);

db.exec("PRAGMA foreign_keys = ON");

try {
    // Locate our existing customer
    const john = db.prepare(`
        SELECT id FROM users WHERE email = ?
    `).get("customer@demo.invalid");

    if (!john) {
        throw new Error("John Customer account not found.");
    }

    // Find or create our second customer
    let jane = db.prepare(`
        SELECT id FROM users WHERE email = ?
    `).get("jane@demo.invalid");

    if (!jane) {
        const password = process.env.JANE_PASS;

        if (!password || password.length < 12) {
            throw new Error(
                "Set JANE_PASS to at least 12 characters."
            );
        }

        const salt = randomBytes(16).toString("hex");

        const hash = scryptSync(
            password, salt, 64
        ).toString("hex");

        const result = db.prepare(`
            INSERT INTO users
                (name, email, password_hash, role)
            VALUES (?, ?, ?, ?)
        `).run(
            "Jane Customer",
            "jane@demo.invalid",
            `${salt}:${hash}`,
            "customer"
        );

        jane = { id: Number(result.lastInsertRowid) };
    }

    // Create a separate appointment table for RBAC tests
    db.exec(`
        CREATE TABLE IF NOT EXISTS demo_appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            customer_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            vehicle TEXT NOT NULL,
            status TEXT NOT NULL,
            demo_key TEXT UNIQUE NOT NULL,

            FOREIGN KEY (customer_id)
                REFERENCES users(id)
        )
    `);

    // Prepare safe database inserts
    const insert = db.prepare(`
        INSERT OR IGNORE INTO demo_appointments
            (customer_id, service, vehicle, status, demo_key)
        VALUES (?, ?, ?, ?, ?)
    `);

    // John's appointments
    insert.run(
        john.id,
        "Oil Change",
        "2017 Hyundai Elantra",
        "Scheduled",
        "john-oil-demo"
    );

    insert.run(
        john.id,
        "Battery Replacement",
        "2017 Hyundai Elantra",
        "Completed",
        "john-battery-demo"
    );

    // Jane's appointment
    insert.run(
        jane.id,
        "Brake Replacement",
        "2012 Honda Civic",
        "Scheduled",
        "jane-brakes-demo"
    );

    // Print the demo records
    const appointments = db.prepare(`
        SELECT id, customer_id, service, vehicle, status
        FROM demo_appointments
        ORDER BY id
    `).all();

    console.table(appointments);

    console.log("RBAC demo records are ready!");

} finally {
    db.close();
}
