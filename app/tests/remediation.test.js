/**
 * Remediation suite — for every finding, proves:
 *   (1) the malicious payload is now REJECTED, and
 *   (2) the legitimate flow still WORKS (no over-restrictive regression).
 * Run: npm run test:remediation
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import request from 'supertest';
import { buildApp } from '../src/app.js';
import { signHs256 } from '../src/lib/jwt.js';
import { logSink, clearLogSink } from '../src/lib/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
let app;
let internalServer;
let internalPort;

before(async () => {
  app = await buildApp();
  internalServer = http.createServer((_req, res) => res.end('INTERNAL'));
  await new Promise((r) => internalServer.listen(0, '127.0.0.1', r));
  internalPort = internalServer.address().port;
});
after(() => internalServer && internalServer.close());

test('V-01 fixed: injection rejected, legit id works', async () => {
  const bad = await request(app).get('/secure/items').query({ id: '0 UNION SELECT api_secret,1,1 FROM users--' });
  assert.equal(bad.status, 400); // non-integer rejected
  const ok = await request(app).get('/secure/items').query({ id: '1' });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.result[0].email, 'alice@fleetsec.co');
  assert.doesNotMatch(JSON.stringify(ok.body), /SECRET_/);
});

test('V-02 fixed: alg:none rejected, real HS256 token works', async () => {
  const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const forged = `${b64({ alg: 'none' })}.${b64({ sub: 'attacker', role: 'admin' })}.`;
  const bad = await request(app).get('/secure/account').set('Authorization', `Bearer ${forged}`);
  assert.equal(bad.status, 401);
  const good = signHs256({ sub: 'alice', role: 'user' });
  const ok = await request(app).get('/secure/account').set('Authorization', `Bearer ${good}`);
  assert.equal(ok.status, 200);
  assert.equal(ok.body.role, 'user');
});

test('V-03 fixed: private/non-allowlisted host blocked, allowlisted host passes checks', async () => {
  const bad = await request(app).get('/secure/fetch').query({ url: `http://127.0.0.1:${internalPort}/` });
  assert.equal(bad.status, 403);
  const meta = await request(app).get('/secure/fetch').query({ url: 'http://169.254.169.254/latest/meta-data/' });
  assert.equal(meta.status, 403);
  const ok = await request(app).get('/secure/fetch').query({ url: 'https://example.com/data' });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.allowed, 'example.com');
});

test('V-04 fixed: DOCTYPE/ENTITY rejected, plain XML parses', async () => {
  const xxe = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>`;
  const bad = await request(app).post('/secure/xml').set('Content-Type', 'application/xml').send(xxe);
  assert.equal(bad.status, 400);
  const ok = await request(app).post('/secure/xml').set('Content-Type', 'application/xml').send('<r><speed>54</speed></r>');
  assert.equal(ok.status, 200);
  assert.equal(ok.body.parsed.r.speed, 54);
});

test('V-05 fixed: extra fields stripped, role forced to user', async () => {
  const res = await request(app)
    .post('/secure/users')
    .send({ email: 'e@e.co', password: 'a-strong-password', role: 'admin', isVerified: true });
  assert.equal(res.status, 201);
  assert.equal(res.body.created.role, 'user');
  assert.equal(res.body.created.isVerified, undefined);
});

test('V-06 fixed: traversal blocked, allowlisted filename served', async () => {
  const bad = await request(app).get('/secure/download').query({ file: '../secret.txt' });
  assert.equal(bad.status, 400);
  const ok = await request(app).get('/secure/download').query({ file: 'telemetry-sample.txt' });
  assert.equal(ok.status, 200);
  assert.match(ok.text, /vehicle=ABC123/);
});

test('V-07 fixed: 6th attempt in window is throttled (429), first ones allowed', async () => {
  let got429 = false;
  let got401or200 = 0;
  for (let i = 0; i < 8; i++) {
    const res = await request(app).post('/secure/login').send({ user: 'admin', pass: 'nope' });
    if (res.status === 429) got429 = true;
    else got401or200++;
  }
  assert.equal(got429, true, 'rate limiter kicked in');
  assert.ok(got401or200 >= 5, 'first 5 attempts were served');
});

test('V-08 fixed: PII redacted in the log sink', async () => {
  clearLogSink();
  await request(app)
    .post('/secure/register')
    .send({ email: 'victim@fleetsec.co', cedula: '1020304050', phone: '3001234567' });
  const logged = logSink.join('\n');
  assert.doesNotMatch(logged, /1020304050/);
  assert.doesNotMatch(logged, /victim@fleetsec\.co/);
  assert.match(logged, /REDACTED/);
});

test('V-09 fixed: cross-tenant read forbidden, own resource allowed', async () => {
  const aliceToken = signHs256({ sub: 'alice', role: 'user' });
  const foreign = await request(app).get('/secure/orders/102').set('Authorization', `Bearer ${aliceToken}`);
  assert.equal(foreign.status, 403);
  const own = await request(app).get('/secure/orders/100').set('Authorization', `Bearer ${aliceToken}`);
  assert.equal(own.status, 200);
  assert.equal(own.body.vehicle_plate, 'ABC123');
});

test('V-10 fixed: no secret leaked; source is env/Secrets Manager', async () => {
  const res = await request(app).get('/secure/debug/config');
  assert.equal(res.status, 200);
  assert.doesNotMatch(JSON.stringify(res.body), /FleetSec_Pr0d_DB_2024!/);
  assert.match(res.body.source, /Secrets Manager/);
});
