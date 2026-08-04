const path = require('node:path');
const fs = require('node:fs');
const { DatabaseSync } = require('node:sqlite');

const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, 'app.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    name TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS snapshot_values (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
    label TEXT NOT NULL,
    value TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_snapshots_user ON snapshots(user_id);
  CREATE INDEX IF NOT EXISTS idx_snapshot_values_snapshot ON snapshot_values(snapshot_id);
  CREATE INDEX IF NOT EXISTS idx_snapshot_values_label ON snapshot_values(label);
`);

function createUser(username, passwordHash) {
  const stmt = db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)');
  const result = stmt.run(username, passwordHash);
  return Number(result.lastInsertRowid);
}

function findUserByUsername(username) {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
}

function findUserById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id) || null;
}

function createSnapshot(userId, name, values) {
  const insertSnapshot = db.prepare('INSERT INTO snapshots (user_id, name) VALUES (?, ?)');
  const insertValue = db.prepare('INSERT INTO snapshot_values (snapshot_id, label, value) VALUES (?, ?, ?)');

  const result = insertSnapshot.run(userId, name);
  const snapshotId = Number(result.lastInsertRowid);
  for (const { label, value } of values) {
    insertValue.run(snapshotId, label, value);
  }
  return snapshotId;
}

function listSnapshotsForUser(userId) {
  return db.prepare('SELECT id, name, created_at FROM snapshots WHERE user_id = ? ORDER BY created_at DESC, id DESC').all(userId);
}

function getSnapshotForUser(userId, snapshotId) {
  const snapshot = db.prepare('SELECT id, name, created_at FROM snapshots WHERE user_id = ? AND id = ?').get(userId, snapshotId);
  if (!snapshot) return null;
  const values = db.prepare('SELECT label, value FROM snapshot_values WHERE snapshot_id = ? ORDER BY id ASC').all(snapshotId);
  return { ...snapshot, values };
}

function countSnapshotsForUser(userId) {
  const row = db.prepare('SELECT COUNT(*) AS count FROM snapshots WHERE user_id = ?').get(userId);
  return Number(row.count);
}

function countLabelValueMatchesForUser(userId, label, value) {
  const row = db.prepare(`
    SELECT COUNT(*) AS count
    FROM snapshot_values sv
    JOIN snapshots s ON s.id = sv.snapshot_id
    WHERE s.user_id = ? AND sv.label = ? AND sv.value = ?
  `).get(userId, label, value);
  return Number(row.count);
}

module.exports = {
  createUser,
  findUserByUsername,
  findUserById,
  createSnapshot,
  listSnapshotsForUser,
  getSnapshotForUser,
  countSnapshotsForUser,
  countLabelValueMatchesForUser,
};
