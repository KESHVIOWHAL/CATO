// Clean Express app — safe patterns throughout
const express = require('express');
const helmet = require('helmet');
const crypto = require('crypto');
const { execFile } = require('child_process');

const app = express();
app.use(express.json());
app.use(helmet());

// JWT secret from environment variable — never hardcoded
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error('JWT_SECRET environment variable is required');
}

// Safe: parameterized query (placeholder — real app uses a DB client)
function getUser(db, userId) {
  // db.prepare('SELECT * FROM users WHERE id = ?').get(userId)
  return { id: userId, name: 'example' };
}

// Safe: execFile with args array — no shell injection
function runDiagnostic(host, callback) {
  execFile('ping', ['-c', '1', host], { timeout: 5000 }, callback);
}

// Safe: crypto.randomUUID for tokens
function generateSessionToken() {
  return crypto.randomUUID();
}

// Safe: textContent instead of innerHTML
function renderSafe(element, text) {
  element.textContent = text;
}

// CORS restricted to known origin
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '').split(',');

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/user/:id', (req, res) => {
  const userId = parseInt(req.params.id, 10);
  if (isNaN(userId) || userId < 1) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }
  res.json(getUser(null, userId));
});

module.exports = app;
