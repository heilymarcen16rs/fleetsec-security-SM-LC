/**
 * PII masking (V-08 / CWE-359 / Ley 1581 Art. 4 "principio de seguridad").
 * Redacts Colombian cédula, email, phone, credit-card and JWT-looking strings
 * from any string BEFORE it reaches a log sink. Applied at every log level.
 */
const PATTERNS = [
  [/\b\d{16}\b/g, '[REDACTED_CARD]'], // card first (before cedula 6-10)
  [/\b\d{6,10}\b/g, '[REDACTED_ID]'], // cédula / NIT
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[REDACTED_EMAIL]'],
  [/\b(?:\+?57)?\s?3\d{9}\b/g, '[REDACTED_PHONE]'], // CO mobile
  [/eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, '[REDACTED_JWT]'],
];

export function maskPii(input) {
  let s = typeof input === 'string' ? input : JSON.stringify(input);
  for (const [re, repl] of PATTERNS) s = s.replace(re, repl);
  return s;
}
