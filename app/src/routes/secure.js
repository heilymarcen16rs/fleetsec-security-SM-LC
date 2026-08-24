/**
 * REMEDIATED ENDPOINTS — the secure twin of every /vuln handler.
 * Mounted under /secure. Each fix follows the OWASP Proactive Controls order:
 * framework-native primitive → allowlist validation → defense in depth.
 */
import express from 'express';
import rateLimit from 'express-rate-limit';
import Joi from 'joi';
import { XMLParser } from 'fast-xml-parser';
import dns from 'node:dns/promises';
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { getDb } from '../lib/db.js';
import { verifySecure, signHs256 } from '../lib/jwt.js';
import { secureLog } from '../lib/logger.js';
import { config } from '../config.js';

export const secureRouter = express.Router();

// V-01 FIX · parameterized query (prepared statement).
secureRouter.get('/items', (req, res) => {
  const raw = String(req.query.id ?? '');
  if (!/^\d+$/.test(raw)) return res.status(400).json({ error: 'id must be a positive integer' });
  const id = Number.parseInt(raw, 10);
  const db = getDb();
  const stmt = db.prepare('SELECT id, email, role FROM users WHERE id = ?');
  stmt.bind([id]);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  res.json({ result: rows });
});

// V-02 FIX · algorithm allowlist, no 'none'.
secureRouter.get('/account', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  try {
    const claims = verifySecure(token);
    res.json({ authenticatedAs: claims.sub, role: claims.role });
  } catch (e) {
    res.status(401).json({ error: 'invalid token' });
  }
});
// Helper to mint a legitimate token for the remediation regression test.
secureRouter.post('/token', express.json(), (req, res) => {
  res.json({ token: signHs256({ sub: req.body?.sub || 'alice', role: 'user' }) });
});

// V-03 FIX · scheme + allowlist + private/link-local block, resolve-then-check.
function isPrivate(ip) {
  if (net.isIP(ip) === 0) return true;
  if (ip.startsWith('169.254.') || ip.startsWith('127.') || ip === '::1') return true;
  if (ip.startsWith('10.') || ip.startsWith('192.168.')) return true;
  const m = ip.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  return false;
}
secureRouter.get('/fetch', async (req, res) => {
  let uri;
  try {
    uri = new URL(req.query.url);
  } catch {
    return res.status(400).json({ error: 'invalid url' });
  }
  if (!['http:', 'https:'].includes(uri.protocol))
    return res.status(400).json({ error: 'scheme not allowed' });
  if (!config.ssrfAllowedHosts.includes(uri.hostname))
    return res.status(403).json({ error: 'host not in allowlist' });
  try {
    const { address } = await dns.lookup(uri.hostname);
    if (isPrivate(address)) return res.status(403).json({ error: 'private address blocked' });
  } catch {
    return res.status(400).json({ error: 'dns resolution failed' });
  }
  return res.json({ allowed: uri.hostname }); // would fetch the resolved IP here
});

// V-04 FIX · parser that never resolves external entities.
const safeXml = new XMLParser({ ignoreAttributes: false, processEntities: false });
secureRouter.post('/xml', express.text({ type: '*/*' }), (req, res) => {
  const xml = req.body || '';
  if (/<!DOCTYPE/i.test(xml) || /<!ENTITY/i.test(xml))
    return res.status(400).json({ error: 'DOCTYPE/ENTITY declarations are rejected' });
  const parsed = safeXml.parse(xml);
  res.json({ parsed });
});

// V-05 FIX · explicit DTO allowlist; server assigns privileged fields.
const createUserSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(12).required(),
});
secureRouter.post('/users', express.json(), (req, res) => {
  const { value, error } = createUserSchema.validate(req.body, { stripUnknown: true });
  if (error) return res.status(400).json({ error: error.message });
  const user = { id: 999, email: value.email, role: 'user' }; // role set server-side
  res.status(201).json({ created: user });
});

// V-06 FIX · canonicalize + base-dir containment + filename allowlist.
secureRouter.get('/download', (req, res) => {
  const file = req.query.file || '';
  if (!/^[A-Za-z0-9._-]+$/.test(file))
    return res.status(400).json({ error: 'invalid filename' });
  const baseDir = path.resolve(config.publicDir);
  const target = path.resolve(baseDir, file);
  if (!target.startsWith(baseDir + path.sep))
    return res.status(400).json({ error: 'path traversal blocked' });
  try {
    res.type('text/plain').send(fs.readFileSync(target, 'utf8').slice(0, 500));
  } catch {
    return res.status(404).json({ error: 'not found' });
  }
});

// V-07 FIX · rate limiter (per IP) + would add per-username lockout & CAPTCHA.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'too many attempts, retry later' },
});
secureRouter.post('/login', loginLimiter, express.json(), (req, res) => {
  const ok = req.body?.user === 'admin' && req.body?.pass === 'correct-horse';
  res.status(ok ? 200 : 401).json({ ok });
});

// V-08 FIX · PII masked at the sink for every log level.
secureRouter.post('/register', express.json(), (req, res) => {
  const { email, cedula, phone } = req.body || {};
  secureLog.info(`register email=${email} cedula=${cedula} phone=${phone}`);
  res.status(201).json({ registered: true });
});

// V-09 FIX · ownership check (query scoped to the authenticated user).
secureRouter.get('/orders/:id', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
  let claims;
  try {
    claims = verifySecure(token);
  } catch {
    return res.status(401).json({ error: 'authentication required' });
  }
  const userId = { alice: 1, bob: 2, root: 3 }[claims.sub] ?? -1;
  const isAdmin = claims.role === 'admin';
  const db = getDb();
  const stmt = db.prepare('SELECT * FROM orders WHERE id = ?');
  stmt.bind([Number.parseInt(req.params.id, 10)]);
  const row = stmt.step() ? stmt.getAsObject() : null;
  stmt.free();
  if (!row) return res.status(404).json({ error: 'not found' });
  if (row.owner_id !== userId && !isAdmin)
    return res.status(403).json({ error: 'forbidden — not your resource' });
  res.json(row);
});

// V-10 FIX · secret comes from the environment (Secrets Manager in AWS).
secureRouter.get('/debug/config', (_req, res) => {
  res.json({
    dbPasswordConfigured: Boolean(config.secure.dbPassword),
    source: 'env / AWS Secrets Manager (never in source)',
  });
});
