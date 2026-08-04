const path = require('node:path');
const express = require('express');
const session = require('express-session');

const db = require('./db');
const { hashPassword, verifyPassword, requireAuth } = require('./auth');

const app = express();
const port = process.env.PORT || 8080;

// Behind a reverse proxy (e.g. in Docker/behind nginx), trust the
// X-Forwarded-For header so req.ip reflects the real client, not the proxy.
app.set('trust proxy', true);

app.use(express.json());
app.use(session({
  name: 'bft.sid',
  secret: process.env.SESSION_SECRET || 'dev-only-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, maxAge: 1000 * 60 * 60 * 24 * 7 },
}));

app.get('/api/ip', (req, res) => {
  res.json({
    ip: req.ip,
    forwardedFor: req.headers['x-forwarded-for'] || null,
  });
});

app.get('/api/headers', (req, res) => {
  res.json(req.headers);
});

app.get('/api/session', (req, res) => {
  if (!req.session.userId) return res.json({ loggedIn: false });
  res.json({ loggedIn: true, username: req.session.username });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password) {
    return res.status(400).json({ error: 'username and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'password must be at least 8 characters' });
  }
  if (db.findUserByUsername(username)) {
    return res.status(409).json({ error: 'username is already taken' });
  }

  const userId = db.createUser(username, hashPassword(password));
  req.session.userId = userId;
  req.session.username = username;
  res.status(201).json({ loggedIn: true, username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password are required' });
  }

  const user = db.findUserByUsername(username);
  if (!user || !verifyPassword(password, user.password_hash)) {
    return res.status(401).json({ error: 'invalid username or password' });
  }

  req.session.userId = user.id;
  req.session.username = user.username;
  res.json({ loggedIn: true, username: user.username });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('bft.sid');
    res.json({ loggedIn: false });
  });
});

app.post('/api/snapshots', requireAuth, (req, res) => {
  const { name, values } = req.body || {};
  if (typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ error: 'name is required' });
  }
  if (!Array.isArray(values) || values.length === 0) {
    return res.status(400).json({ error: 'values must be a non-empty array' });
  }
  const cleanValues = values
    .filter((v) => v && typeof v.label === 'string' && typeof v.value === 'string')
    .map(({ label, value }) => ({ label, value }));
  if (cleanValues.length === 0) {
    return res.status(400).json({ error: 'no valid values provided' });
  }

  const snapshotId = db.createSnapshot(req.session.userId, name.trim(), cleanValues);
  res.status(201).json({ id: snapshotId });
});

app.get('/api/snapshots', requireAuth, (req, res) => {
  res.json(db.listSnapshotsForUser(req.session.userId));
});

app.get('/api/snapshots/:id', requireAuth, (req, res) => {
  const snapshot = db.getSnapshotForUser(req.session.userId, Number(req.params.id));
  if (!snapshot) return res.status(404).json({ error: 'snapshot not found' });
  res.json(snapshot);
});

app.post('/api/match-scores', requireAuth, (req, res) => {
  const { values } = req.body || {};
  if (!Array.isArray(values)) {
    return res.status(400).json({ error: 'values must be an array' });
  }

  const totalSnapshots = db.countSnapshotsForUser(req.session.userId);
  const scores = values
    .filter((v) => v && typeof v.label === 'string' && typeof v.value === 'string')
    .map(({ label, value }) => {
      const matches = totalSnapshots > 0
        ? db.countLabelValueMatchesForUser(req.session.userId, label, value)
        : 0;
      const percent = totalSnapshots > 0 ? (matches / totalSnapshots) * 100 : null;
      return { label, matches, totalSnapshots, percent };
    });

  res.json({ totalSnapshots, scores });
});

app.use(express.static(path.join(__dirname, 'src')));

app.listen(port, () => {
  console.log(`Browser fingerprint tester listening on port ${port}`);
});
