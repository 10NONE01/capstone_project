const session = require("express-session");
const { createHash } = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");

// ========================================
// PERSISTENT SESSION STORE
// ========================================
//
// Keeps sessions in their own SQLite file, separate from the
// application database, so they survive restarts and expired
// sessions are removed. Session IDs are stored only as hashes.

const DEFAULT_TTL_MS = 60 * 60 * 1000;
const PURGE_INTERVAL_MS = 10 * 60 * 1000;

const hashId = (sid) =>
    createHash("sha256").update(sid).digest("hex");

function expiryOf(sess) {

    const expires = sess?.cookie?.expires;

    return expires
        ? new Date(expires).getTime()
        : Date.now() + DEFAULT_TTL_MS;
}

class SqliteSessionStore extends session.Store {

    constructor(file) {

        super();

        this.db = new DatabaseSync(file);

        this.db.exec(`
            CREATE TABLE IF NOT EXISTS sessions (
                sid_hash TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_expiry
                ON sessions (expires_at);
        `);

        this.selectStatement = this.db.prepare(
            "SELECT data, expires_at FROM sessions WHERE sid_hash = ?"
        );

        this.upsertStatement = this.db.prepare(`
            INSERT INTO sessions (sid_hash, data, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT (sid_hash) DO UPDATE SET
                data = excluded.data,
                expires_at = excluded.expires_at
        `);

        this.touchStatement = this.db.prepare(
            "UPDATE sessions SET expires_at = ? WHERE sid_hash = ?"
        );

        this.deleteStatement = this.db.prepare(
            "DELETE FROM sessions WHERE sid_hash = ?"
        );

        this.purgeStatement = this.db.prepare(
            "DELETE FROM sessions WHERE expires_at <= ?"
        );

        this.purge();

        this.purgeTimer = setInterval(
            () => this.purge(),
            PURGE_INTERVAL_MS
        );

        this.purgeTimer.unref();
    }

    purge() {

        try {
            this.purgeStatement.run(Date.now());
        } catch (error) {
            console.error("Session cleanup failed:", error.message);
        }
    }

    get(sid, callback) {

        let result = null;

        try {
            const key = hashId(sid);
            const row = this.selectStatement.get(key);

            if (row && row.expires_at > Date.now()) {
                result = JSON.parse(row.data);
            } else if (row) {
                this.deleteStatement.run(key);
            }
        } catch (error) {
            return callback(error);
        }

        callback(null, result);
    }

    set(sid, sess, callback = () => {}) {

        try {
            this.upsertStatement.run(
                hashId(sid),
                JSON.stringify(sess),
                expiryOf(sess)
            );
        } catch (error) {
            return callback(error);
        }

        callback(null);
    }

    touch(sid, sess, callback = () => {}) {

        try {
            this.touchStatement.run(expiryOf(sess), hashId(sid));
        } catch (error) {
            return callback(error);
        }

        callback(null);
    }

    destroy(sid, callback = () => {}) {

        try {
            this.deleteStatement.run(hashId(sid));
        } catch (error) {
            return callback(error);
        }

        callback(null);
    }

    close() {
        clearInterval(this.purgeTimer);
        this.db.close();
    }
}

module.exports = { SqliteSessionStore };
