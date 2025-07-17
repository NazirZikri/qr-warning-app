// db.js
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./qr_scans.db');

// Create table if not exists
db.run(`
  CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    qr_id TEXT,
    user_agent TEXT,
    datetime TEXT,
    ipv6 TEXT,
    ipv4 TEXT
  )
`);

module.exports = db;
