// Intentionally vulnerable Express app — for CATO testing only
const express = require('express');
const { exec, execSync } = require('child_process');
const jwt = require('jsonwebtoken');
const app = express();

app.use(express.json());

// CRITICAL: Hardcoded JWT secret
const jwt_secret = "supersecretkey12345";

// CRITICAL: Hardcoded API key
const api_key = "sk-prod-abc123def456ghi789jkl0";

// HIGH: eval on user input — RCE
app.post('/calculate', (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

// HIGH: execSync with template literal — command injection
app.get('/ping', (req, res) => {
  const output = execSync(`ping -c 1 ${req.query.host}`);
  res.send(output.toString());
});

// HIGH: SQL built with string concatenation
const db = require('better-sqlite3')('test.db');
app.get('/user', (req, res) => {
  const row = db.prepare("SELECT * FROM users WHERE name = '" + req.query.name + "'").get();
  res.json(row);
});

// HIGH: innerHTML with user data — XSS (frontend pattern for illustration)
function renderUserName(name) {
  document.getElementById('user').innerHTML = name;
}

// HIGH: spawn with shell:true
const { spawn } = require('child_process');
function runTool(cmd) {
  return spawn(cmd, [], { shell: true });
}

// HIGH: new Function — dynamic code
function dynamicCalc(expression) {
  return new Function('return ' + expression)();
}

// MEDIUM: CORS wildcard
const cors = require('cors');
app.use(cors({ origin: '*' }));

// MEDIUM: insecure random for session token
function generateToken() {
  return Math.random().toString(36).substring(2);
}

// Sign JWT with hardcoded secret
app.post('/login', (req, res) => {
  const token = jwt.sign({ user: req.body.username }, jwt_secret);
  res.json({ token });
});

app.listen(3000);
