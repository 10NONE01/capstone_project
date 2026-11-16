
const { DatabaseSync } = require("node:sqlite");
const fs = require("node:fs");
const path = require("node:path");

// Location of our database folder
const databaseFolder = path.join(__dirname, "..", "database");

// Location of our SQLite database file
const databasePath = path.join(
    databaseFolder,
    "mobile_auto_basics.db"
);

// Location of our SQL schema
const schemaPath = path.join(
    databaseFolder,
    "schema.sql"
);

// Read the SQL commands
const schema = fs.readFileSync(schemaPath, "utf8");

// Open or create the SQLite database
const db = new DatabaseSync(databasePath);

// Enforce foreign keys for this connection
db.exec("PRAGMA foreign_keys = ON;");

// Create our tables
db.exec(schema);

console.log("Mobile Auto Basics database initialized!");

// Close the database connection
db.close();
