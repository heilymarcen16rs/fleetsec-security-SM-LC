import pino from 'pino';
import { maskPii } from './pii.js';

// Structured JSON logging. In-memory ring buffer lets the VAPT PoC assert on
// what actually reached the log sink (proving PII leakage / redaction).
export const logSink = [];

function push(entry) {
  logSink.push(entry);
  if (logSink.length > 500) logSink.shift();
}

const base = pino({ level: process.env.LOG_LEVEL || 'info' });

// VULNERABLE logger (V-08): writes the raw message, PII and all.
export const vulnLog = {
  info: (msg) => {
    push(msg);
    base.info(msg);
  },
};

// SECURE logger: every message passes through the PII masker first.
export const secureLog = {
  info: (msg) => {
    const clean = maskPii(msg);
    push(clean);
    base.info(clean);
  },
};

export function clearLogSink() {
  logSink.length = 0;
}
