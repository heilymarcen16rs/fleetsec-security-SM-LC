/**
 * JWT verification — V-02 / CWE-345 (alg:none & algorithm confusion).
 */
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

function b64urlJson(part) {
  return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

/**
 * VULNERABLE verifier: trusts the `alg` header sent by the client. If the token
 * says `alg:none`, it accepts it with no signature. This is the classic
 * algorithm-confusion / alg:none bypass.
 */
export function verifyVulnerable(token) {
  const [h, p, s] = token.split('.');
  const header = b64urlJson(h);

  if (header.alg === 'none') {
    return b64urlJson(p); // no signature required — attacker wins
  }
  // Even for HS256 it uses a client-selectable algorithm and a weak check.
  const expected = crypto
    .createHmac('sha256', config.vulnerable.jwtSecret)
    .update(`${h}.${p}`)
    .digest('base64url');
  if (expected !== s) throw new Error('bad signature');
  return b64urlJson(p);
}

/**
 * SECURE verifier: pins the algorithm allowlist, rejects `none`, and validates
 * standard claims. Uses the maintained jsonwebtoken library.
 */
export function verifySecure(token) {
  return jwt.verify(token, config.secure.jwtSecret, {
    algorithms: ['HS256'], // explicit allowlist; 'none' can never be selected
    // issuer / audience would be pinned here in production:
    // issuer: 'https://auth.fleetsec.co', audience: 'fleetsec-api',
  });
}

export function signHs256(payload) {
  return jwt.sign(payload, config.secure.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: '15m',
  });
}
