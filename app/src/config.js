/**
 * Central configuration.
 *
 * SECURITY NOTE (V-10 / CWE-798):
 * The `vulnerable` block below intentionally hardcodes a secret to reproduce the
 * "Hardcoded Credentials" finding in a controlled lab. The `secure` block shows
 * the remediation: every secret is read from the environment (which in AWS is
 * injected from Secrets Manager into the ECS task — never committed to the repo).
 *
 * The remediation commit for V-10 removes the hardcoded literal entirely; it is
 * kept here ONLY so the VAPT PoC (gitleaks / trufflehog) has something to detect
 * and so the before/after is auditable in a single reviewable file.
 */

export const config = {
  port: Number(process.env.PORT || 3000),
  env: process.env.NODE_ENV || 'development',

  // --- V-10 VULNERABLE (CWE-798): secret embedded in source -----------------
  vulnerable: {
    // gitleaks/trufflehog will flag the next lines. That is the point.
    // Documented suppression (razón: VAPT lab V-10 · fecha: 2026-08-23 · responsable: SecEng):
    // nosemgrep: fleetsec-hardcoded-secret
    dbPassword: 'FleetSec_Pr0d_DB_2024!', // hardcoded DB credential
    // nosemgrep: fleetsec-hardcoded-secret
    jwtSecret: 'super-secret-hs256-key-do-not-ship', // hardcoded signing key
    awsAccessKeyId: 'AKIAIOSFODNN7EXAMPLE', // example-format AWS key (non-live)
  },

  // --- SECURE: secrets sourced from the environment / Secrets Manager --------
  secure: {
    dbPassword: process.env.DB_PASSWORD || null,
    jwtSecret: process.env.JWT_SECRET || 'dev-only-rotate-me',
    // No AWS static keys — ECS task assumes an IAM role (STS), see terraform/.
  },

  // Where the download endpoint is allowed to serve files from (V-06).
  publicDir: process.env.PUBLIC_DIR || './data/public',

  // SSRF allowlist (V-03 secure path).
  ssrfAllowedHosts: (process.env.SSRF_ALLOWED_HOSTS || 'api.partner.com,example.com')
    .split(',')
    .map((h) => h.trim())
    .filter(Boolean),
};
