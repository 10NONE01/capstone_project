
const { DatabaseSync } = require("node:sqlite");
const path = require("node:path");

const db = new DatabaseSync(
    path.join(__dirname, "database", "mobile_auto_basics.db")
);

db.exec("PRAGMA foreign_keys = ON");

try {
    // Find our demo mechanic
    const mechanic = db.prepare(`
        SELECT id
        FROM users
        WHERE email = ? AND role = 'mechanic'
    `).get("mechanic@demo.invalid");

    if (!mechanic) {
        throw new Error("Demo mechanic account not found.");
    }

    // Create the work tickets table
    db.exec(`
        CREATE TABLE IF NOT EXISTS demo_work_tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            appointment_id INTEGER NOT NULL UNIQUE,
            mechanic_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Assigned',

            FOREIGN KEY (appointment_id)
                REFERENCES demo_appointments(id),

            FOREIGN KEY (mechanic_id)
                REFERENCES users(id)
        )
    `);

    // Find the existing demo appointments
    const appointments = db.prepare(`
        SELECT id, demo_key
        FROM demo_appointments
        WHERE demo_key IN (
            'john-oil-demo',
            'jane-brakes-demo'
        )
    `).all();

    // Assign these jobs to Mike Mechanic
    const insertTicket = db.prepare(`
        INSERT OR IGNORE INTO demo_work_tickets
            (appointment_id, mechanic_id, status)
        VALUES (?, ?, ?)
    `);

    for (const appointment of appointments) {
        insertTicket.run(
            appointment.id,
            mechanic.id,
            "Assigned"
        );
    }

    const tickets = db.prepare(`
        SELECT
            wt.id,
            wt.appointment_id,
            wt.mechanic_id,
            wt.status
        FROM demo_work_tickets AS wt
        ORDER BY wt.id
    `).all();

    console.table(tickets);
    console.log("Mechanic demo tickets are ready!");

} catch (error) {
    console.error("Setup failed:", error.message);
    process.exitCode = 1;
} finally {
    db.close();
}
