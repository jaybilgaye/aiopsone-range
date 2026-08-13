/**
 * ⚠️  INTENTIONALLY VULNERABLE. Teaching material for aiopsone.com.
 *
 *  Every flaw below is deliberate and is the subject of a lesson. Do not copy
 *  any of this into anything real, and do not run it on a public address.
 *
 *  Binds to 127.0.0.1 on purpose — see the listen() call at the bottom.
 */

const express = require('express');
const initSqlJs = require('sql.js');
const app = express();

app.use(express.urlencoded({ extended: true }));
app.set('view engine', 'ejs');
app.set('views', __dirname + '/views');

// ---------------------------------------------------------------------------
// FLAW 1 — Hardcoded credentials.
// Target of: the Gitleaks pre-commit lesson, TruffleHog history lesson.
// Fabricated values that resolve to nothing. NOT AWS's published example
// key — gitleaks allowlists those by default, so a lab built on them would
// silently find nothing. Verified to trigger gitleaks 8.30.1.
// ---------------------------------------------------------------------------
const AWS_ACCESS_KEY_ID = 'AKIA3XZP7QK2WVNR8TLM';
const AWS_SECRET_ACCESS_KEY = 'kR8fT2wPmZ4vN7bXcQ1yJ6hL0sD3gA5eU9iO2pWn';
const DB_PASSWORD = 'hunter2';
const JWT_SIGNING_KEY = 'dev-secret-do-not-use';

// sql.js is SQLite compiled to WebAssembly: real SQL, real injection, and no
// native toolchain — so the lab installs on any architecture.
let db = null;
initSqlJs().then((SQL) => {
  db = new SQL.Database();
  db.run('CREATE TABLE products (id INTEGER, name TEXT, price REAL)');
  db.run(
    "INSERT INTO products VALUES (1,'Widget',9.99),(2,'Gadget',24.5),(3,'Doohickey',3.75)"
  );
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

  try {
    const out = db.exec(sql);
    const rows = out.length
      ? out[0].values.map(([id, name, price]) => ({ id, name, price }))
      : [];
    res.render('index', { results: rows, query });
  } catch (err) {
    // FLAW 3 — verbose error disclosure: leaks the query and the schema.
    res.status(500).send('<pre>' + err.message + '\n' + sql + '</pre>');
  }
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
// Loopback by default. Inside a container 127.0.0.1 is the container's own
// loopback, so the image sets HOST=0.0.0.0 — the container is already an
// isolation boundary, and the guard that matters there is publishing the port
// to the host's loopback only:  docker run -p 127.0.0.1:3100:3000
const HOST = process.env.HOST || '127.0.0.1';
app.listen(PORT, HOST, () => {
  console.log(`[range] INTENTIONALLY VULNERABLE app on http://${HOST}:${PORT}`);
  console.log('[range] Local use only. Do not expose this.');
});
