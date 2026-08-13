/**
 * ⚠️  INTENTIONALLY VULNERABLE. Teaching material for aiopsone.com.
 *
 *  Every flaw below is deliberate and is the subject of a lesson. Do not copy
 *  any of this into anything real, and do not run it on a public address.
 *
 *  Binds to 127.0.0.1 on purpose — see the listen() call at the bottom.
 */

const express = require('express');
const sqlite3 = require('sqlite3');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ---------------------------------------------------------------------------
// FLAW 1 — Hardcoded credentials.
// Target of: the Gitleaks pre-commit lesson, TruffleHog history lesson.
// These are AWS's own published example values. They are inert and resolve to
// nothing. A scanner still matches them, which is the point.
// ---------------------------------------------------------------------------
const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET_ACCESS_KEY = 'wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY';
const DB_PASSWORD = 'hunter2';
const JWT_SIGNING_KEY = 'dev-secret-do-not-use';

const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run('CREATE TABLE products (id INTEGER, name TEXT, price REAL)');
  const seed = db.prepare('INSERT INTO products VALUES (?, ?, ?)');
  [
    [1, 'Widget', 9.99],
    [2, 'Gadget', 24.5],
    [3, 'Doohickey', 3.75],
  ].forEach((row) => seed.run(row));
  seed.finalize();
});

app.get('/', (req, res) => {
  res.render('index', { results: null, query: '' });
});

// ---------------------------------------------------------------------------
// FLAW 2 — SQL injection via string concatenation.
// Target of: the Semgrep / CodeQL / Snyk Code SAST lessons.
// The fix is parameterised queries; the fixed version lives on the `fixed`
// branch so lessons can diff against it.
// ---------------------------------------------------------------------------
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  const sql = "SELECT * FROM products WHERE name LIKE '%" + query + "%'";

  db.all(sql, (err, rows) => {
    if (err) {
      // FLAW 3 — verbose error disclosure: leaks the query and the schema.
      return res.status(500).send('<pre>' + err.message + '\n' + sql + '</pre>');
    }
    res.render('index', { results: rows, query });
  });
});

// ---------------------------------------------------------------------------
// FLAW 4 — Reflected XSS. The template renders this unescaped (see views/).
// Target of: the OWASP ZAP and Nuclei DAST lessons.
// ---------------------------------------------------------------------------
app.get('/greet', (req, res) => {
  const name = req.query.name || 'stranger';
  res.send('<h1>Hello, ' + name + '</h1><p><a href="/">back</a></p>');
});

// ---------------------------------------------------------------------------
// FLAW 5 — Debug endpoint exposing configuration.
// A stand-in for the "someone left an admin route in" class of finding.
// ---------------------------------------------------------------------------
app.get('/debug/config', (req, res) => {
  res.json({
    note: 'This endpoint should never exist in a real app.',
    awsAccessKeyId: AWS_ACCESS_KEY_ID,
    dbPassword: DB_PASSWORD,
    jwtKey: JWT_SIGNING_KEY,
    nodeVersion: process.version,
  });
});

app.get('/health', (req, res) => res.json({ ok: true }));

// ---------------------------------------------------------------------------
// Bound to loopback deliberately. If you find yourself changing this to
// 0.0.0.0 to "make it work", stop — that is the one thing the README asks you
// not to do. Use a port forward or run the exercise on the machine itself.
// ---------------------------------------------------------------------------
const PORT = process.env.PORT || 3000;
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[range] INTENTIONALLY VULNERABLE app on http://127.0.0.1:${PORT}`);
  console.log('[range] Local use only. Do not expose this.');
});
