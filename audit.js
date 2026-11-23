const { createHmac, hkdfSync } = require("node:crypto");

// ========================================
// TAMPER-EVIDENT SECURITY AUDIT LOG
// ========================================
//
// - Rows are append-only (enforced by database triggers).
// - Each row stores an HMAC covering its contents and the
//   previous row's HMAC, so edits, removals and reordering
//   are detected by verify().
// - Passwords and raw login identifiers are never stored.
//
// Limitation: someone holding both database write access and
// the HMAC key can rewrite the chain. Removing the newest rows
// is also not detectable without an off-site copy of the
// latest hash.

const GENESIS_HASH = "0".repeat(64);
const MAX_FIELD_LENGTH = 500;

const NEW_COLUMNS = [
    ["actor_id", "INTEGER"],
    ["actor_role", "TEXT"],
    ["outcome", "TEXT"],
    ["http_method", "TEXT"],
    ["ip_address", "TEXT"],
    ["prev_hash", "TEXT"],
    ["entry_hash", "TEXT"]
];

// Removes control characters so user-controlled values
// cannot forge extra lines in console or file logs.
function clean(value, maxLength = MAX_FIELD_LENGTH) {

    if (value === null || value === undefined) {
        return null;
    }

    return String(value)
        .replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, " ")
        .slice(0, maxLength);
}

function migrate(db) {

    const existing = new Set(
        db.prepare("PRAGMA table_info(audit_logs)")
            .all()
            .map((column) => column.name)
    );

    const missing = NEW_COLUMNS.filter(
        ([name]) => !existing.has(name)
    );

    db.exec("BEGIN IMMEDIATE");

    try {
        for (const [name, type] of missing) {
            db.exec(`ALTER TABLE audit_logs ADD COLUMN ${name} ${type}`);
        }

        // Keep the original actor on rows written before this
        // migration. Runs before the append-only triggers exist.
        if (!existing.has("actor_id")) {
            db.exec("UPDATE audit_logs SET actor_id = user_id");
        }

        db.exec(`
            CREATE INDEX IF NOT EXISTS idx_audit_logs_event
                ON audit_logs (event_type, created_at);

            CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
            BEFORE DELETE ON audit_logs
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;

            -- The only permitted update is the foreign key's
            -- ON DELETE SET NULL. actor_id preserves who acted.
            CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
            BEFORE UPDATE ON audit_logs
            WHEN NEW.id IS NOT OLD.id
              OR NEW.event_type IS NOT OLD.event_type
              OR NEW.resource IS NOT OLD.resource
              OR NEW.details IS NOT OLD.details
              OR NEW.created_at IS NOT OLD.created_at
              OR NEW.actor_id IS NOT OLD.actor_id
              OR NEW.actor_role IS NOT OLD.actor_role
              OR NEW.outcome IS NOT OLD.outcome
              OR NEW.http_method IS NOT OLD.http_method
              OR NEW.ip_address IS NOT OLD.ip_address
              OR NEW.prev_hash IS NOT OLD.prev_hash
              OR NEW.entry_hash IS NOT OLD.entry_hash
              OR (NEW.user_id IS NOT OLD.user_id AND NEW.user_id IS NOT NULL)
            BEGIN
                SELECT RAISE(ABORT, 'audit_logs is append-only');
            END;
        `);

        db.exec("COMMIT");

    } catch (error) {
        db.exec("ROLLBACK");
        throw error;
    }
}

function createAuditLog(db, secret) {

    migrate(db);

    const hmacKey = Buffer.from(hkdfSync(
        "sha256",
        secret,
        "mobile-auto-basics",
        "audit-log-integrity-v1",
        32
    ));

    const signEntry = (row) => createHmac("sha256", hmacKey)
        .update(JSON.stringify([
            row.id,
            row.actor_id,
            row.actor_role,
            row.event_type,
            row.outcome,
            row.resource,
            row.http_method,
            row.ip_address,
            row.details,
            row.created_at,
            row.prev_hash
        ]))
        .digest("hex");

    const selectLast = db.prepare(`
        SELECT id, entry_hash
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 1
    `);

    const insert = db.prepare(`
        INSERT INTO audit_logs (
            id, user_id, actor_id, actor_role, event_type,
            outcome, resource, http_method, ip_address,
            details, created_at, prev_hash, entry_hash
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // Never throws: a logging fault must not crash a request.
    function write(entry) {

        let transactionOpen = false;

        try {
            db.exec("BEGIN IMMEDIATE");
            transactionOpen = true;

            const last = selectLast.get();

            const row = {
                id: (last?.id ?? 0) + 1,
                actor_id: entry.userId ?? null,
                actor_role: clean(entry.role, 20),
                event_type: clean(entry.eventType, 60),
                outcome: clean(entry.outcome, 20),
                resource: clean(entry.resource, 200),
                http_method: clean(entry.method, 10),
                ip_address: clean(entry.ip, 64),
                details: clean(entry.details),
                created_at: new Date().toISOString(),
                prev_hash: last?.entry_hash ?? GENESIS_HASH
            };

            row.entry_hash = signEntry(row);

            insert.run(
                row.id, row.actor_id, row.actor_id, row.actor_role,
                row.event_type, row.outcome, row.resource,
                row.http_method, row.ip_address, row.details,
                row.created_at, row.prev_hash, row.entry_hash
            );

            db.exec("COMMIT");
            transactionOpen = false;

            console.log(`[AUDIT] ${JSON.stringify({
                id: row.id,
                event: row.event_type,
                outcome: row.outcome,
                actor: row.actor_id,
                resource: row.resource,
                ip: row.ip_address,
                details: row.details
            })}`);

            return true;

        } catch (error) {

            if (transactionOpen) {
                try { db.exec("ROLLBACK"); } catch { /* already closed */ }
            }

            console.error("Audit logging failed:", error.message);
            return false;
        }
    }

    function verify() {

        let expectedPrev = GENESIS_HASH;
        let previousId = null;
        let chainStarted = false;
        let checked = 0;
        let legacy = 0;

        const rows = db.prepare(
            "SELECT * FROM audit_logs ORDER BY id"
        ).iterate();

        const broken = (id, reason) => ({
            valid: false, checked, legacy, brokenAt: id, reason
        });

        for (const row of rows) {

            if (row.entry_hash === null) {

                if (chainStarted) {
                    return broken(row.id, "missing_hash");
                }

                legacy += 1;
                previousId = row.id;
                continue;
            }

            if (chainStarted && row.id !== previousId + 1) {
                return broken(row.id, "missing_entry");
            }

            if (row.prev_hash !== expectedPrev) {
                return broken(row.id, "chain_mismatch");
            }

            if (signEntry(row) !== row.entry_hash) {
                return broken(row.id, "content_modified");
            }

            chainStarted = true;
            expectedPrev = row.entry_hash;
            previousId = row.id;
            checked += 1;
        }

        return { valid: true, checked, legacy, brokenAt: null, reason: null };
    }

    // Lets analysts correlate repeated attempts on one login
    // without storing what was typed (users sometimes enter a
    // password into the email field by mistake).
    function pseudonymize(value) {
        return createHmac("sha256", hmacKey)
            .update(`identifier:${String(value).trim().toLowerCase()}`)
            .digest("hex")
            .slice(0, 16);
    }

    return { write, verify, pseudonymize };
}

module.exports = { createAuditLog, clean };
