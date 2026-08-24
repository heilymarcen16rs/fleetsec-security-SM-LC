/**
 * DELIBERATELY VULNERABLE ENDPOINTS — VAPT lab surface (V-01 .. V-10).
 * Mounted under /vuln. NEVER enable in production; guarded by LAB_MODE.
 * Each handler maps 1:1 to a finding in vapt/vapt-report and to a secure twin
 * in routes/secure.js.
 */
import express from 'express';
import { getDb } from '../lib/db.js';
import { verifyVulnerable } from '../lib/jwt.js';
import { vulnLog } from '../lib/logger.js';
import { config } from '../config.js';
import fs from 'node:fs';
import path from 'node:path';

export const vulnerableRouter = express.Router();

// V-01 · SQL Injection (CWE-89) — string-concatenated query.
vulnerableRouter.get('/items', (req, res) => {
  const db = getDb();
  const q = `SELECT id, email, role FROM users WHERE id = ${req.query.id}`;
  try {
    const rows = db.exec(q); // unparameterized — injectable
    res.json({ query: q, result: rows[0] ? rows[0].values : [] });
  } catch (e) {
    res.status(500).json({ query: q, error: String(e) });
  }
});

// V-02 · Broken Auth / JWT alg:none (CWE-345).
vulnerableRouter.get('/account', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const claims = verifyVulnerable(token);
    res.json({ authenticatedAs: claims.sub, role: claims.role, claims });
  } catch (e) {
    res.status(401).json({ error: String(e) });
  }
});

// V-03 · SSRF (CWE-918) — fetches any client-supplied URL, no validation.
vulnerableRouter.get('/fetch', async (req, res) => {
  const url = req.query.url;
  try {
    const r = await fetch(url); // no scheme/host/IP validation
    const body = await r.text();
    res.json({ fetched: url, status: r.status, body: body.slice(0, 500) });
  } catch (e) {
    res.status(502).json({ fetched: url, error: String(e) });
  }
});

// V-04 · XXE (CWE-611) — naive parser that resolves SYSTEM external entities.
// This mirrors a misconfigured XML parser (e.g. libxml with noent+network on).
vulnerableRouter.post('/xml', express.text({ type: '*/*' }), (req, res) => {
  const xml = req.body || '';
  const entities = {};
  // parse <!ENTITY name SYSTEM "file://..."> declarations and resolve them
  const re = /<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"\s*>/g;
  let m;
  while ((m = re.exec(xml))) {
    const [, name, uri] = m;
    try {
      const p = uri.replace(/^file:\/\//, '');
      entities[name] = fs.readFileSync(p, 'utf8'); // external entity read
    } catch (e) {
      entities[name] = `ERR:${e.code}`;
    }
  }
  let out = xml.replace(/<[^>]+>/g, '').trim();
  for (const [name, val] of Object.entries(entities)) {
    out = out.replaceAll(`&${name};`, val);
  }
  res.json({ parsed: out.slice(0, 500), entitiesResolved: Object.keys(entities) });
});

// V-05 · Mass Assignment (CWE-915) — binds the whole body, role included.
const massUsers = [];
vulnerableRouter.post('/users', express.json(), (req, res) => {
  const user = { id: massUsers.length + 10, ...req.body }; // trusts client fields
  massUsers.push(user);
  res.status(201).json({ created: user });
});

// V-06 · Path Traversal (CWE-22) — joins user input onto a base with no check.
vulnerableRouter.get('/download', (req, res) => {
  const file = req.query.file || '';
  const target = path.join(config.publicDir, file); // ../ escapes the base
  try {
    const content = fs.readFileSync(target, 'utf8');
    res.type('text/plain').send(content.slice(0, 500));
  } catch (e) {
    res.status(404).json({ target, error: e.code });
  }
});

// V-07 · Missing Rate Limiting (CWE-307) — login with no throttle/lockout.
let bruteAttempts = 0;
vulnerableRouter.post('/login', express.json(), (req, res) => {
  bruteAttempts += 1;
  const ok = req.body?.user === 'admin' && req.body?.pass === 'correct-horse';
  res.status(ok ? 200 : 401).json({ ok, attemptsSeen: bruteAttempts });
});

// V-08 · Logging of PII (CWE-359 / Ley 1581) — logs raw PII in plaintext.
vulnerableRouter.post('/register', express.json(), (req, res) => {
  const { email, cedula, phone } = req.body || {};
  vulnLog.info(`register email=${email} cedula=${cedula} phone=${phone}`);
  res.status(201).json({ registered: true });
});

// V-09 · IDOR (CWE-639) — returns any order by id, no ownership check.
vulnerableRouter.get('/orders/:id', (req, res) => {
  const db = getDb();
  const stmt = db.prepare('SELECT * FROM orders WHERE id = ?');
  stmt.bind([req.params.id]);
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  if (!row) return res.status(404).json({ error: 'not found' });
  res.json(row); // no check that req user owns this order
});

// V-10 · Hardcoded Credentials (CWE-798) — uses the secret baked into config.
vulnerableRouter.get('/debug/config', (_req, res) => {
  res.json({
    dbPassword: config.vulnerable.dbPassword, // leaks the hardcoded secret
    awsAccessKeyId: config.vulnerable.awsAccessKeyId,
  });
});
