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
    ipv4 TEXT,
    anon_id TEXT,
    user_name TEXT,
    name_consent_at TEXT
  )
`);

// ensure reports table exists
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS reports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      anon_id TEXT,
      qr_id TEXT,
      qr_link TEXT,
      reporter_name TEXT,
      reporter_email TEXT,
      description TEXT,
      created_at TEXT
    )
  `, (err) => {
    if (err) console.error('Failed to create reports table:', err.message);
  });
});

module.exports = db;
